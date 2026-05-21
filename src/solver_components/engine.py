"""Trajectory judging and public solver wrapper."""

from __future__ import annotations

import copy
from typing import Any

from .constants import *
from .models import *
from .parsing import *
from .semantics import *
from .expectations import *
from .transitions import *


def compare_expected_actual(expected: ExpectedResponse, target: Event) -> str:
    if target.kind == "host_io" and target.method == "Read":
        if expected.forbid_read_result_presence and target.read_result is not None:
            return "FAIL"
        if expected.forbidden_read_result is not None and target.read_result == expected.forbidden_read_result:
            return "FAIL"
        if expected.expected_read_result is not None:
            return "PASS" if target.read_result == expected.expected_read_result else "FAIL"

    actual = target.status
    if actual in expected.forbidden_statuses:
        return "FAIL"
    if actual in expected.allowed_statuses:
        actual_return_bool = _return_bool(target.raw) if actual == SUCCESS else None
        if expected.expected_return_bool is not None and actual_return_bool is not None and actual_return_bool != expected.expected_return_bool:
            return "FAIL"
        if expected.forbidden_return_bool is not None and actual_return_bool is not None and actual_return_bool == expected.forbidden_return_bool:
            return "FAIL"
        if actual == SUCCESS and expected.expected_return_length is not None:
            actual_length = _return_payload_length(_output_return_values(target.raw))
            if actual_length is not None and actual_length != expected.expected_return_length:
                return "FAIL"
        return "PASS"
    failure_statuses = {FAIL, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS}
    if actual in failure_statuses and expected.allowed_statuses & failure_statuses:
        return "PASS"
    if actual in failure_statuses and SUCCESS in expected.forbidden_statuses:
        return "PASS"
    return "FAIL"


def _method_default_authas_authority(event: Event) -> str | None:
    raw_args = _method_raw_args(event)
    value = _raw_arg_value(
        event.required,
        event.optional,
        raw_args,
        "auth",
        "Auth",
        "defAuth",
        "DefAuth",
        "defaultAuth",
        "DefaultAuth",
        "defaultAuthority",
        "DefaultAuthority",
    )
    return _authority_from_value(value)


def _authority_would_satisfy(state: State, authority: str, required: str) -> bool:
    already_present = authority in state.session.authenticated
    state.session.authenticated.add(authority)
    try:
        return _has_authority(state, required)
    finally:
        if not already_present:
            state.session.authenticated.discard(authority)


def _get_required_authorities_for_relevance(event: Event) -> set[str]:
    symbol = event.invoking_symbol
    if symbol == "C_PIN_SID":
        if not event.columns or PIN_COLUMN in event.columns:
            return set()
        return {"Admins", "SID"}
    if symbol.startswith("C_PIN_"):
        if not event.columns or PIN_COLUMN in event.columns:
            return set()
        return {"Admins"}
    if symbol.startswith("Locking_"):
        return {"Admins"}
    if symbol.startswith("DataStore"):
        return {"Admins", "Users"}
    if symbol.startswith(("Authority_", "ACE_")):
        return {"Admins"}
    return set()


def _target_required_authorities_for_relevance(state: State, event: Event) -> set[str]:
    if event.method == "Set":
        return _set_required_authorities(state, event)
    if event.method in {"CreateTable", "CreateRow", "DeleteRow", "Delete", "DeleteSP", "DeleteMethod", "AddACE", "RemoveACE", "SetACL", "GenKey", "GetPackage", "SetPackage"}:
        return {"Admins"}
    if event.method == "Activate":
        return {"SID"}
    if event.method == "Erase":
        return {"EraseMaster"}
    if event.method in {"Revert", "RevertSP"}:
        if event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP":
            return {"PSID"}
        if state.session.sp == "LockingSP":
            return {"Admins"}
        return {"SID", "PSID", "Admins"}
    if event.method == "Get":
        return _get_required_authorities_for_relevance(event)
    return set()


def _authority_relevant_for_target(state: State, event: Event, authority: str) -> bool:
    required = _target_required_authorities_for_relevance(state, event)
    if any(_authority_would_satisfy(state, authority, item) for item in required):
        return True

    already_present = authority in state.session.authenticated
    state.session.authenticated.add(authority)
    try:
        if event.method in {"Get", "Set"}:
            symbol = event.invoking_symbol
            if symbol.startswith("Locking_") and _range_master_authorizes(state, _range_id_from_symbol(symbol)):
                return True
            if symbol.startswith("DataStore") and _datastore_master_authorizes(state):
                return True
        if event.method == "Set" and _ace_authorizes_set(state, event):
            return True
        if event.method == "Get":
            symbol = event.invoking_symbol
            range_id = _range_id_from_symbol(symbol)
            if range_id is not None and _ace_satisfied(state, _locking_ace_symbol(0xD000, range_id)):
                return True
            if symbol.startswith("DataStore") and _user_acl_allows_datastore(state, write=False):
                return True
    finally:
        if not already_present:
            state.session.authenticated.discard(authority)

    return not required


def _add_authority_candidate(candidates: list[str], authority: str | None) -> None:
    if authority and authority not in candidates:
        candidates.append(authority)


def _owner_fallback_credential_plausible(state: State, owner: str, credential_text: str) -> bool:
    if owner in state.pins:
        return True
    if owner == "SID" or owner == "EraseMaster" or _is_band_master(owner):
        msid_pin = state.pins.get("MSID")
        if msid_pin is not None and credential_text:
            return credential_text == msid_pin
    return True


def _authas_default_authority_candidates(state: State, event: Event, credential: Any) -> list[str]:
    explicit_default = _method_default_authas_authority(event)
    if explicit_default is not None:
        return [explicit_default]

    candidates: list[str] = []
    credential_text = _credential_text(credential)
    if credential_text:
        for authority, pin in state.pins.items():
            if pin != credential_text:
                continue
            if not _authority_allowed_for_target_method(state, event, authority):
                continue
            if not _authority_is_enabled(state, state.session.sp, authority):
                continue
            if _authority_locked_out(state, authority):
                continue
            if _authority_relevant_for_target(state, event, authority):
                _add_authority_candidate(candidates, authority)
    if candidates:
        return candidates

    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner and owner != "MSID" and _owner_fallback_credential_plausible(state, owner, credential_text):
        _add_authority_candidate(candidates, owner)

    required = _target_required_authorities_for_relevance(state, event)
    if "Admins" in required:
        _add_authority_candidate(candidates, "Admin1" if state.session.sp == "LockingSP" else "SID")
    for authority in sorted(required):
        if authority not in {"Anybody", "Admins", "Users"}:
            if _owner_fallback_credential_plausible(state, authority, credential_text):
                _add_authority_candidate(candidates, authority)
    if "Users" in required:
        _add_authority_candidate(candidates, "User1")
    return candidates


def _apply_invocation_auth_for_target(state: State, event: Event) -> tuple[str | None, bool]:
    if event.method in {"StartSession", "Authenticate"} or not state.session.open:
        return None, False
    candidates = _authas_pairs(event.required, event.optional, _method_raw_args(event))
    if event.authority is not None:
        candidates.insert(0, (event.authority, event.challenge))

    for authority, credential in candidates:
        authorities = [authority] if authority is not None else _authas_default_authority_candidates(state, event, credential)
        for resolved_authority in authorities:
            if resolved_authority in {"Anybody", "Admins", "Users"} or _has_authority(state, resolved_authority):
                continue
            if not _authority_allowed_for_target_method(state, event, resolved_authority):
                continue
            if not _authority_is_enabled(state, state.session.sp, resolved_authority):
                continue
            if _authority_locked_out(state, resolved_authority):
                continue
            if not credential:
                continue
            known_pin = state.pins.get(resolved_authority)
            if known_pin is not None and _credential_text(credential) != known_pin:
                continue
            if not _authority_relevant_for_target(state, event, resolved_authority):
                continue
            state.session.authenticated.add(resolved_authority)
            return resolved_authority, known_pin is None
    return None, False


def _explicit_authas_known_wrong(state: State, event: Event) -> bool:
    if event.method in {"StartSession", "Authenticate"} or not state.session.open:
        return False
    for authority, credential in _authas_pairs(event.required, event.optional, _method_raw_args(event)):
        if authority in {None, "Anybody", "Admins", "Users"} or not credential:
            continue
        if _has_authority(state, authority):
            continue
        if not _authority_allowed_for_target_method(state, event, authority):
            continue
        if _authority_locked_out(state, authority):
            return True
        known_pin = state.pins.get(authority)
        if known_pin is not None and _credential_text(credential) != known_pin:
            return True
    return False


def judge_target(state: State, event: Event) -> str:
    working_state = state
    if event.implicit_session and not state.session.open and event.kind == "tcg_method":
        working_state = copy.deepcopy(state)
        working_state.session = _implicit_session_for_event(working_state, event, assume_authenticated=False)
    added_authority, credential_unknown = _apply_invocation_auth_for_target(working_state, event)
    try:
        expected = expected_status(working_state, event)
        if _explicit_authas_known_wrong(working_state, event):
            expected.allowed_statuses = {NOT_AUTHORIZED, FAIL}
            expected.forbidden_statuses = set(expected.forbidden_statuses) | {SUCCESS}
        if added_authority is not None and credential_unknown:
            expected.allowed_statuses = set(expected.allowed_statuses) | {NOT_AUTHORIZED}
        return compare_expected_actual(expected, event)
    finally:
        if added_authority is not None:
            working_state.session.authenticated.discard(added_authority)


def predict_trajectory(trajectory: list[dict[str, Any]]) -> str:
    if not trajectory:
        return "FAIL"
    state = State()
    for raw in trajectory[:-1]:
        apply_transition(state, parse_event(raw))
    return judge_target(state, parse_event(trajectory[-1]))


class Solver:
    def predict(self, dataset):
        return {item["id"]: self.predict_one(item["steps"]) for item in dataset}

    def predict_one(self, steps):
        return predict_trajectory(steps).lower()




__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
