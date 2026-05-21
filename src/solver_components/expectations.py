"""Expected-response rules for TCG methods and host I/O."""

from __future__ import annotations

import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *
from .semantics import *


def _expected_start_session(state: State, event: Event) -> ExpectedResponse:
    if not _is_session_manager_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="StartSession must target the Session Manager", confidence="high")
    if state.session.open:
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Only one reconstructed Opal session is open", confidence="medium")
    if event.sp is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="StartSession has unknown or invalid SPID", confidence="high")
    if event.sp in state.deleted_sps:
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.sp} has been deleted and no longer accepts sessions",
            confidence="high",
        )
    if state.sp_frozen.get(event.sp, False):
        return ExpectedResponse({FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.sp} is frozen and cannot accept new sessions", confidence="high")
    spid_uid = _clean_uid(_raw_arg_value(event.required, event.optional, _method_raw_args(event), "SPID", "SP", "sp"))
    enterprise_locking_sp = spid_uid == "0000020500010001"
    if event.sp == "LockingSP" and not state.locking_sp_activated and not enterprise_locking_sp:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, reason="LockingSP is not activated in reconstructed state", confidence="medium")

    authority = event.authority or "Anybody"
    if authority == "Anybody":
        return ExpectedResponse({SUCCESS}, reason="Unauthenticated session is permitted", confidence="high")
    if authority in {"Admins", "Users", "Makers"}:
        return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="StartSession HostSigningAuthority must be an individual authority", confidence="high")
    if not _authority_allowed_in_sp(event.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{authority} is not an authority in {event.sp}", confidence="high")
    if not _authority_is_enabled(state, event.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} is not enabled", confidence="high")
    challenge = _credential_text(event.challenge)
    if not challenge:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Credential authority requires a host challenge", confidence="high")
    try_limit = state.pin_try_limits.get(authority, 0)
    if try_limit > 0 and state.pin_tries.get(authority, 0) >= try_limit:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} credential is locked out by TryLimit", confidence="high")

    known_pin = state.pins.get(authority)
    if known_pin is None:
        return ExpectedResponse({SUCCESS, NOT_AUTHORIZED}, reason=f"{authority} credential is unknown from history", confidence="low")
    if challenge != known_pin:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} challenge does not match tracked PIN", confidence="high")
    return ExpectedResponse({SUCCESS}, reason=f"{authority} challenge matches tracked PIN", confidence="high")


def _expected_start_trusted_session(state: State, event: Event) -> ExpectedResponse:
    if not _is_session_manager_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} must target the Session Manager", confidence="high")
    if not state.session.open:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires an existing session startup exchange", confidence="high")
    return ExpectedResponse({SUCCESS}, reason=f"{event.method} continues the existing session startup exchange", confidence="medium")


def _expected_authenticate(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Authenticate requires an open session", confidence="high")
    authority = (
        event.authority
        or _authority_from_value(_mapping_value(event.required, "Authority"))
        or _authority_from_value(_mapping_value(event.required, "HostSigningAuthority"))
    )
    if authority is None or authority == "Anybody":
        return ExpectedResponse({SUCCESS}, reason="No protected authority requested", confidence="medium")
    if authority in {"Admins", "Users", "Makers"}:
        return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Authenticate requires an individual authority", confidence="high")
    if not _authority_allowed_in_sp(state.session.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{authority} is not an authority in {state.session.sp}", confidence="high")
    if not _authority_is_enabled(state, state.session.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED, SUCCESS}, forbidden_return_bool=True, reason=f"{authority} is not enabled", confidence="high")
    try_limit = state.pin_try_limits.get(authority, 0)
    if try_limit > 0 and state.pin_tries.get(authority, 0) >= try_limit:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} credential is locked out by TryLimit", confidence="high")
    challenge = (
        event.challenge
        or _mapping_value(event.optional, "Challenge")
        or _mapping_value(event.required, "Challenge")
        or _mapping_value(event.required, "HostChallenge")
    )
    known_pin = state.pins.get(authority)
    if known_pin is None:
        return ExpectedResponse({SUCCESS, NOT_AUTHORIZED}, reason=f"{authority} credential is unknown from history", confidence="low")
    if _credential_text(challenge) != known_pin:
        return ExpectedResponse({NOT_AUTHORIZED, SUCCESS}, forbidden_return_bool=True, reason=f"{authority} authentication challenge does not match tracked PIN", confidence="high")
    return ExpectedResponse({SUCCESS}, forbidden_return_bool=False, reason=f"{authority} authentication challenge matches tracked PIN", confidence="high")


def _expected_get(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Get requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Get object does not belong to current SP", confidence="medium")

    symbol = event.invoking_symbol
    if symbol.startswith("_CertData_"):
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Certificate byte table Get cannot request column values in the Cellblock", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="TCGstorageAPI reads TPer certificate byte tables through AdminSP as Anybody", confidence="medium")
    if symbol == "C_PIN_MSID" and (not event.columns or PIN_COLUMN in event.columns):
        return ExpectedResponse({SUCCESS}, reason="C_PIN_MSID PIN is readable by Anybody in AdminSP", confidence="high")
    if symbol == "C_PIN_SID" and (not event.columns or PIN_COLUMN in event.columns):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="C_PIN_SID PIN is not readable", confidence="medium")
    if symbol == "C_PIN_SID":
        if not _has_any_authority(state, {"Admins", "SID"}):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="C_PIN_SID non-PIN columns require Admins or SID", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="Authorized C_PIN_SID non-PIN Get is allowed", confidence="medium")
    if symbol.startswith("C_PIN_") and (not event.columns or PIN_COLUMN in event.columns):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="C_PIN PIN columns are protected from Get", confidence="medium")
    if symbol.startswith("C_PIN_"):
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="C_PIN non-PIN columns require Admins", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="Authorized C_PIN non-PIN Get is allowed", confidence="medium")
    if symbol == "LockingInfo":
        return ExpectedResponse({SUCCESS}, reason="LockingInfo geometry columns may be retrieved by Anybody", confidence="high")
    if symbol.startswith("Locking_"):
        protected_columns = set(range(3, 20))
        range_id = _range_id_from_symbol(symbol)
        range_acl = range_id is not None and _ace_satisfied(state, _locking_ace_symbol(0xD000, range_id))
        range_master = _range_master_authorizes(state, range_id)
        if (not event.columns or event.columns & protected_columns) and not _has_authority(state, "Admins") and not range_acl and not range_master:
            return ExpectedResponse({NOT_AUTHORIZED}, reason="Locking range state columns require Admins", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="Authorized Locking range Get is allowed", confidence="high")
    if symbol == "MBRControl":
        return ExpectedResponse({SUCCESS}, reason="MBRControl Get is permitted by ACE_Anybody", confidence="high")
    if symbol == "MBR":
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Byte table Get cannot request column values in the Cellblock", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="MBR byte table Get is permitted by ACE_Anybody", confidence="high")
    if symbol.startswith("K_AES_") and event.method == "Get":
        columns = set(event.columns)
        if not columns:
            return ExpectedResponse(
                {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES Get without a Cellblock can include the protected Key column",
                confidence="medium",
            )
        if columns - {0, 1, 2, K_AES_KEY_COLUMN, K_AES_MODE_COLUMN}:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES Get requested columns outside the K_AES row definition",
                confidence="high",
            )
        if K_AES_KEY_COLUMN in columns:
            return ExpectedResponse(
                {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES Key is SecretProtect-protected from Get",
                confidence="high",
            )
        if K_AES_MODE_COLUMN in columns and _ace_expression_configured(state, "ACE_0003BFFF") and not _ace_satisfied(state, "ACE_0003BFFF"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="K_AES Mode Get is blocked by personalized ACE_K_AES_Mode", confidence="high")
        if K_AES_MODE_COLUMN not in columns:
            return ExpectedResponse({SUCCESS}, reason="K_AES metadata Get does not include the protected Key column", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="K_AES Mode Get is permitted by ACE_K_AES_Mode", confidence="medium")
    if symbol.startswith("DataStore"):
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Byte table Get cannot request column values in the Cellblock", confidence="high")
        if not _has_authority(state, "Admins") and not _datastore_master_authorizes(state) and not _user_acl_allows_datastore(state, write=False):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="DataStore Get requires Admins or a personalized read ACE", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="Authorized DataStore Get is allowed", confidence="medium")
    if symbol.startswith("AccessControl_"):
        if not event.columns or ACCESS_CONTROL_ACL_COLUMN in event.columns:
            return ExpectedResponse(
                {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="AccessControl ACL column is readable only through GetACL",
                confidence="high",
            )
        return ExpectedResponse({SUCCESS}, reason="AccessControl metadata columns may be retrieved directly", confidence="medium")
    if symbol.startswith("Authority_"):
        if event.columns and event.columns <= PUBLIC_COMMON_NAME_COLUMNS:
            return ExpectedResponse({SUCCESS}, reason=f"{symbol} UID/CommonName Get is permitted by ACE_Anybody_Get_CommonName", confidence="high")
        if not _has_authority(state, "Admins") and not _ace_satisfied(state, "ACE_00039000"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires Admins", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason=f"Authorized {symbol} Get is allowed", confidence="medium")
    if symbol.startswith("Port"):
        return ExpectedResponse({SUCCESS}, reason="Port Get is readable for TCGstorageAPI status checks", confidence="medium")
    if symbol.startswith("ACE_"):
        if event.columns and event.columns <= PUBLIC_COMMON_NAME_COLUMNS:
            return ExpectedResponse({SUCCESS}, reason=f"{symbol} UID/CommonName Get is permitted by ACE_Anybody_Get_CommonName", confidence="high")
        if not _has_authority(state, "Admins") and not _ace_satisfied(state, "ACE_00038000"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires Admins", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason=f"Authorized {symbol} Get is allowed", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason="Generic Get is permitted in an open session", confidence="medium")


def _expected_create_row(state: State, event: Event) -> ExpectedResponse:
    common = _table_method_common_failure(state, event, "CreateRow")
    if common is not None:
        return common
    if _created_table_for_event(state, event) is not None:
        if not event.values:
            return ExpectedResponse({INVALID_PARAMETER}, reason="CreateRow requires row values", confidence="high")
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateRow requires Admins authority", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="Authorized CreateRow is allowed on this created object table", confidence="medium")
    if event.invoking_symbol in {"MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateRow is not permitted on MethodID or AccessControl tables", confidence="high")
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="Opal row creation is only modeled for Locking range rows", confidence="medium")
    if not event.values:
        return ExpectedResponse({INVALID_PARAMETER}, reason="CreateRow requires row values", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateRow requires Admins authority", confidence="high")

    if event.invoking_symbol in {"LockingTable", "Table_Locking"}:
        if state.session.sp != "LockingSP":
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Locking rows belong to LockingSP", confidence="high")
        if _global_reencrypt_busy(state):
            return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Global Range re-encryption blocks Locking CreateRow", confidence="high")
        if not {3, 4}.issubset(event.values):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Locking CreateRow requires RangeStart and RangeLength", confidence="high")
        if _range_values_invalid_for_geometry(state, None, event.values, creating=True):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Locking CreateRow violates range geometry or alignment", confidence="high")
        start = _parse_int(event.values.get(3))
        length = _parse_int(event.values.get(4))
        if start is None or length is None:
            return ExpectedResponse({INVALID_PARAMETER}, reason="Locking CreateRow range values must be numeric", confidence="high")
        max_ranges = _parse_int(state.locking_info.get("MaxRanges"))
        if max_ranges is not None and len([range_id for range_id in state.ranges if range_id != 0]) >= max_ranges:
            return ExpectedResponse({INSUFFICIENT_ROWS, INSUFFICIENT_SPACE, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Locking CreateRow exceeds MaxRanges", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="Authorized Locking CreateRow is allowed", confidence="high")

    return ExpectedResponse({SUCCESS}, reason="Authorized CreateRow is allowed on this object table", confidence="medium")


def _expected_delete_row(state: State, event: Event) -> ExpectedResponse:
    common = _table_method_common_failure(state, event, "DeleteRow")
    if common is not None:
        return common
    if _created_table_for_event(state, event) is not None:
        if not _row_object_refs(event) and not _row_uids(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="DeleteRow requires row UIDs", confidence="high")
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteRow requires Admins authority", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="Authorized DeleteRow is allowed on this created object table", confidence="medium")
    if event.invoking_symbol in {"MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="DeleteRow is not permitted on MethodID or AccessControl tables", confidence="high")
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="Opal row deletion is only modeled for Locking range rows", confidence="medium")
    row_refs = _row_object_refs(event)
    if not row_refs and not _row_uids(event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="DeleteRow requires row UIDs", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteRow requires Admins authority", confidence="high")
    if event.invoking_symbol in {"LockingTable", "Table_Locking"}:
        if _global_reencrypt_busy(state):
            return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Global Range re-encryption blocks Locking DeleteRow", confidence="high")
        refs = row_refs or [(_object_by_uid(uid), uid) for uid in _row_uids(event)]
        for symbol, uid in refs:
            range_id = _range_id_from_symbol(symbol) if symbol else _range_id_from_delete_uid(uid)
            if range_id is None:
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Locking DeleteRow must reference Locking range rows", confidence="high")
            if range_id == 0:
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GlobalRange cannot be deleted", confidence="high")
            if range_id is not None and _range_reencrypt_active(_range(state, range_id)):
                return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="ACTIVE re-encryption blocks deleting this Locking object", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized DeleteRow is allowed on this object table", confidence="medium")


def _expected_delete(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Delete object does not belong to current SP", confidence="medium")
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None or range_id == 0:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL, NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="Delete is modeled for deletable non-global Locking range rows",
            confidence="medium",
        )
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete requires Admins authority", confidence="high")
    if _range_reencrypt_active(_range(state, range_id)):
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="ACTIVE re-encryption blocks deleting this Locking object", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized Delete removes the Locking range row", confidence="medium")


def _expected_delete_sp(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteSP requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteSP requires a read-write session", confidence="high")
    if state.session.sp is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="DeleteSP must be invoked within an SP session", confidence="high")
    if event.invoking_symbol not in {"", "ThisSP", state.session.sp}:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="DeleteSP is an SP method invoked on ThisSP/current SP",
            confidence="high",
        )
    if state.session.sp == "AdminSP":
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason="AdminSP deletion through DeleteSP is not modeled as an Opal owner operation",
            confidence="medium",
        )
    if state.session.sp in state.deleted_sps:
        return ExpectedResponse({FAIL, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="DeleteSP target SP is already deleted", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteSP requires normal Admins access control", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized DeleteSP schedules the current SP for deletion when the session closes", confidence="high")


def _expected_create_table(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateTable requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateTable requires a read-write session", confidence="high")
    if state.session.sp is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable must be invoked within an SP session", confidence="high")
    if event.invoking_symbol not in {"", "ThisSP", state.session.sp}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable is an SP method invoked on ThisSP/current SP", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateTable requires normal Admins access control", confidence="high")

    required_args = [
        _create_table_arg(event, 0, "NewTableName", "Name", "TableName"),
        _create_table_arg(event, 1, "Kind", "TableKind"),
        _create_table_arg(event, 2, "GetSetACL", "GetSetAcl", "ACL", "AccessControlList"),
        _create_table_arg(event, 3, "Columns"),
        _create_table_arg(event, 4, "MinSize", "MinimumSize"),
    ]
    if not all(found for found, _ in required_args):
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="CreateTable requires NewTableName, Kind, GetSetACL, Columns, and MinSize",
            confidence="high",
        )

    (_, name_value), (_, kind_value), (_, _acl_value), (_, columns_value), (_, min_size_value) = required_args
    name = _create_table_name_text(name_value)
    if not name:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable NewTableName must be non-empty", confidence="high")
    kind = _create_table_kind(kind_value)
    if kind is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable Kind must be Object or Byte", confidence="high")

    min_size = _parse_int(min_size_value)
    if min_size is None or min_size < 0:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable MinSize must be a non-negative integer", confidence="high")

    found_max, max_size_value = _create_table_arg(event, 5, "MaxSize", "MaximumSize")
    found_hint, hint_size_value = _create_table_arg(event, 6, "HintSize")
    if kind == "byte" and (found_max or found_hint):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Byte table CreateTable cannot include MaxSize or HintSize", confidence="high")
    if kind == "byte" and not _create_table_columns_empty(columns_value):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Byte table CreateTable requires an empty Columns list", confidence="high")

    if found_max:
        max_size = _parse_int(max_size_value)
        if max_size is None or max_size < min_size:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable MaxSize must be at least MinSize", confidence="high")
    if found_hint:
        hint_size = _parse_int(hint_size_value)
        if hint_size is None or hint_size < min_size:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable HintSize must be at least MinSize", confidence="medium")

    found_common, common_value = _create_table_arg(event, 7, "CommonName")
    common_name = _create_table_name_text(common_value) if found_common else ""
    key = (state.session.sp, name, common_name)
    if key in state.created_table_names:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable Name/CommonName combination already exists", confidence="high")

    return ExpectedResponse(
        {SUCCESS, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS},
        reason="Authorized CreateTable parameters satisfy Core table creation constraints",
        confidence="medium",
    )


def _expected_set(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Set requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Set requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Set object does not belong to current SP", confidence="medium")
    event, where_error = _set_effective_event(event)
    if where_error is not None:
        return where_error
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Set target row does not belong to current SP", confidence="high")
    required = _set_required_authorities(state, event)
    if not _has_any_authority(state, required) and not _master_authorizes_set(state, event) and not _ace_authorizes_set(state, event):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"Set requires one of {sorted(required)}", confidence="high")
    if _as_bool(_mapping_value(event.optional, "__RequireAllAuthAsValid")):
        for authority, credential in _authas_pairs(event.required, event.optional, _method_raw_args(event)):
            if authority in {None, "Anybody", "Admins", "Users"}:
                continue
            if not credential:
                return ExpectedResponse({NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="Wrapper-level Set requires each authAs credential to be present", confidence="high")
            known_pin = state.pins.get(authority)
            if known_pin is not None and _credential_text(credential) != known_pin:
                return ExpectedResponse({NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="Wrapper-level Set failed a secondary authAs credential check", confidence="high")
    if _set_values_omitted(event):
        return ExpectedResponse({SUCCESS}, reason="Set without Values succeeds with no effect", confidence="high")
    reencrypt_block = _reencrypt_blocks_set(state, event)
    if reencrypt_block is not None:
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason=reencrypt_block, confidence="high")
    if _invalid_set_values(state, event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="Set contains values disallowed by Opal table semantics", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason="Authorized Set is allowed", confidence="high")


def _expected_activate(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open or not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Activate requires an AdminSP read-write session", confidence="high")
    if state.session.sp != "AdminSP":
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Activate operates through AdminSP", confidence="high")
    if event.invoking_symbol != "LockingSP":
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason="Activate must target a manufactured SP object such as LockingSP", confidence="high")
    if not _has_authority(state, "SID"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Activate requires SID authority", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized LockingSP Activate is allowed", confidence="high")


def _expected_genkey(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GenKey object does not belong to current SP", confidence="high")
    found_exponent, _ = _named_method_arg_value(event, "PublicExponent", "publicExponent")
    found_pin_length, pin_length_value = _named_method_arg_value(event, "PinLength", "pinLength", "PINLength")
    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner:
        if owner == "MSID":
            return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="C_PIN_MSID cannot be regenerated with GenKey", confidence="medium")
        if found_exponent:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PublicExponent is valid only for C_RSA GenKey", confidence="high")
        pin_length = _parse_int(pin_length_value) if found_pin_length else 32
        if pin_length is None or pin_length < 0 or pin_length > 32:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="C_PIN GenKey PinLength must be 0..32", confidence="high")
        required = _set_required_authorities(state, Event(raw=event.raw, kind=event.kind, method="Set", invoking_symbol=event.invoking_symbol, invoking_uid=event.invoking_uid, values={PIN_COLUMN: ""}))
        if not _has_any_authority(state, required):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"C_PIN GenKey requires one of {sorted(required)}", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="Authorized C_PIN GenKey is allowed", confidence="high")

    if found_pin_length:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PinLength is valid only for C_PIN GenKey", confidence="high")
    if found_exponent:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PublicExponent is valid only for C_RSA GenKey", confidence="high")
    if state.session.sp != "LockingSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="K_AES GenKey key object belongs to LockingSP", confidence="high")
    if _range_id_from_key(event.invoking_symbol) is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="GenKey must target a K_AES range key or C_PIN credential", confidence="high")
    ace_symbol = _key_genkey_ace_symbol(event.invoking_symbol)
    if not _has_authority(state, "Admins") and not (ace_symbol and _ace_satisfied(state, ace_symbol)):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires Admins authority", confidence="high")
    range_id = _range_id_from_key(event.invoking_symbol)
    if range_id is not None and _range_reencrypt_busy(_range(state, range_id)):
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="GenKey on a range key is blocked while ReEncryptState is not IDLE", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized GenKey is allowed", confidence="high")


def _expected_get_package(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetPackage requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GetPackage object does not belong to current SP", confidence="high")
    if not _is_credential_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage must target a credential object", confidence="high")
    found_purpose, _ = _named_method_arg_value(event, "Purpose")
    if not found_purpose:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage requires a Purpose parameter", confidence="high")
    if _package_credential_arg_invalid(event, "WrappingKey", "WrappingKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage WrappingKey must reference a credential", confidence="high")
    if _package_credential_arg_invalid(event, "SigningKey", "SigningKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage SigningKey must reference a credential", confidence="high")
    required = _package_required_authorities(state, event)
    if not _has_any_authority(state, required):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"GetPackage requires one of {sorted(required)}", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized GetPackage retrieves credential material as a package", confidence="medium")


def _expected_set_package(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="SetPackage requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="SetPackage requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="SetPackage object does not belong to current SP", confidence="high")
    if not _is_credential_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage must target a credential object", confidence="high")
    found_value, value = _named_method_arg_value(event, "Value", "Package")
    if not found_value or value is None or value == "":
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage requires a Value package", confidence="high")
    if _package_credential_arg_invalid(event, "WrappingKey", "WrappingKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage WrappingKey must reference a credential", confidence="high")
    if _package_credential_arg_invalid(event, "SigningKey", "SigningKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage SigningKey must reference a credential", confidence="high")
    required = _package_required_authorities(state, event)
    if not _has_any_authority(state, required):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"SetPackage requires one of {sorted(required)}", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized SetPackage updates credential material from a package", confidence="medium")


def _expected_erase(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Erase requires an open Enterprise/Locking session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Erase requires a read-write session", confidence="high")
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None or range_id == 0:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Erase must target a non-global Band/Locking range", confidence="high")
    if not _has_authority(state, "EraseMaster"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Erase requires EraseMaster authority", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized Erase invalidates the target band media", confidence="medium")


def _expected_sign(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Sign requires an open AdminSP session", confidence="high")
    if state.session.sp != "AdminSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="TPerSign belongs to AdminSP", confidence="high")
    if event.invoking_symbol != "TPerSign":
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason="TCGstorageAPI Sign flow targets the TPerSign credential", confidence="medium")
    if not _sign_has_payload(event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="Sign requires host data or an input buffer", confidence="high")
    if _payload_too_long(event, 256):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="TCGstorageAPI TPerSign signs payloads up to 256 bytes", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason="TPerSign.Sign is callable by Anybody in an AdminSP session", confidence="medium")


def _expected_firmware_attestation(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="FirmwareAttestation requires an open AdminSP session", confidence="high")
    if state.session.sp != "AdminSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="TperAttestation belongs to AdminSP", confidence="high")
    if event.invoking_symbol != "TperAttestation":
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason="FirmwareAttestation must target the TperAttestation authority", confidence="medium")
    if not _firmware_attestation_has_nonce(event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="FirmwareAttestation requires an assessor nonce", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="TCGstorageAPI invokes FirmwareAttestation as Anybody on AdminSP", confidence="medium")


def _expected_random(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Random requires an open SP session", confidence="medium")
    if event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP", ""} and not event.invoking_symbol.startswith("UnknownSP_"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason="Random is an SP method", confidence="medium")
    count = _random_count(event)
    if count is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="Random requires a Count parameter", confidence="high")
    if count < 0 or count > 32:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Opal Random Count must be between 0 and 32 bytes", confidence="high")
    return ExpectedResponse({SUCCESS}, expected_return_length=count, reason="Random Count is within the Opal mandatory supported range", confidence="high")


def _expected_next(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Next requires an open session", confidence="medium")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Next table does not belong to current SP", confidence="medium")
    created = _created_table_for_event(state, event)
    if created is not None:
        table_sp, kind = created
        if state.session.sp is not None and table_sp != state.session.sp:
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Next dynamic table does not belong to current SP", confidence="high")
        if kind == "byte":
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next is defined only for Opal object tables", confidence="high")
    elif not _is_next_table_target(event.invoking_symbol, event.invoking_uid):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next is defined only for Opal object tables", confidence="high")
    if _next_count_invalid(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next Count must be an unsigned integer", confidence="high")
    if _next_where_invalid(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next Where must reference a row in the invoking object table", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason="Next is allowed on Opal object tables", confidence="medium")


def _expected_table_query(state: State, event: Event) -> ExpectedResponse:
    common = _table_query_common_failure(state, event, event.method)
    if common is not None:
        return common
    return ExpectedResponse({SUCCESS}, reason=f"{event.method} is allowed on Opal object tables", confidence="medium")


def _expected_get_free_space(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetFreeSpace requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GetFreeSpace SP target does not belong to current SP", confidence="medium")
    if event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP", ""} and not event.invoking_symbol.startswith("UnknownSP_"):
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="GetFreeSpace is an SP method invoked on ThisSP",
            confidence="high",
        )
    return ExpectedResponse({SUCCESS}, reason="GetFreeSpace is allowed on the current SP", confidence="high")


def _expected_revert(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="high")
    if event.method == "RevertSP" and event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP"}:
        return ExpectedResponse({INVALID_PARAMETER}, reason="RevertSP must be invoked on ThisSP/SP object", confidence="medium")
    if event.method == "Revert" and event.invoking_symbol not in {"AdminSP", "LockingSP", "ThisSP"}:
        return ExpectedResponse({INVALID_PARAMETER}, reason="Revert must target an SP object", confidence="medium")
    if event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP":
        required = {"PSID"}
    elif state.session.sp == "LockingSP":
        required = {"Admins"}
    else:
        required = {"SID", "PSID", "Admins"}
    if not _has_any_authority(state, required):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires one of {sorted(required)}", confidence="high")
    if event.method == "RevertSP" and state.session.sp == "LockingSP" and _keep_global_range_key(event):
        global_range = _range(state, 0)
        if _read_locked(global_range) and _write_locked(global_range):
            return ExpectedResponse({FAIL}, forbidden_statuses={SUCCESS}, reason="KeepGlobalRangeKey RevertSP fails when Global Range is read-locked and write-locked", confidence="high")
    return ExpectedResponse({SUCCESS}, reason=f"Authorized {event.method} is allowed", confidence="medium")


def _expected_get_acl(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetACL requires an open session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, reason="GetACL is invoked on the AccessControl table", confidence="medium")
    found_invoking, _ = _named_method_arg_value(event, "InvokingID", "InvokingId", "Object", "ObjectID", "Table", "TableUID")
    found_method, _ = _named_method_arg_value(event, "MethodID", "MethodId", "Method")
    if not found_invoking or not found_method:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="GetACL requires InvokingID and MethodID arguments",
            confidence="high",
        )
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED, FAIL}, reason="GetACL references an unknown InvokingID/MethodID association", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="GetACL is permitted by Opal GetACLACL preconfiguration for known associations", confidence="medium")


def _expected_acl_mutation(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires a read-write session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason=f"{event.method} must be invoked on the AccessControl table", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires Admins authority", confidence="high")
    found_invoking, _ = _named_method_arg_value(event, "InvokingID", "InvokingId", "Object", "ObjectID", "Table", "TableUID")
    found_method, _ = _named_method_arg_value(event, "MethodID", "MethodId", "Method")
    if not found_invoking or not found_method:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} requires InvokingID and MethodID arguments",
            confidence="high",
        )
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} references an unknown InvokingID/MethodID association",
            confidence="high",
        )
    if not _ace_method_refs(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires an ACE reference", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason=f"Authorized {event.method} updates an AccessControl ACL", confidence="medium")


def _expected_delete_method(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteMethod requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteMethod requires a read-write session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="DeleteMethod must be invoked on the AccessControl table", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteMethod requires Admins authority", confidence="high")
    found_invoking, _ = _named_method_arg_value(event, "InvokingID", "InvokingId", "Object", "ObjectID", "Table", "TableUID")
    found_method, _ = _named_method_arg_value(event, "MethodID", "MethodId", "Method")
    if not found_invoking or not found_method:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="DeleteMethod requires InvokingID and MethodID arguments",
            confidence="high",
        )
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason="DeleteMethod references an unknown InvokingID/MethodID association",
            confidence="high",
        )
    return ExpectedResponse({SUCCESS}, reason="Authorized DeleteMethod removes an AccessControl association", confidence="medium")


def expected_status(state: State, event: Event) -> ExpectedResponse:
    unsupported = _unsupported_method_response(event)
    if unsupported is not None:
        return unsupported
    if event.kind == "host_io":
        return _expected_host_io(state, event)
    if event.method == "Properties":
        if not _is_session_manager_target(event):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Properties must target the Session Manager", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="Properties is supported by the Session Manager", confidence="high")
    if event.method == "StartSession":
        return _expected_start_session(state, event)
    if event.method in {"StartTrustedSession", "StartTlsSession"}:
        return _expected_start_trusted_session(state, event)
    if not _method_supported_in_session(state, event):
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} is not supported in {state.session.sp}",
            confidence="high",
        )
    disabled = _disabled_sp_response(state, event)
    if disabled is not None:
        return disabled
    if _method_combo_deleted(state, event):
        return ExpectedResponse({NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="AccessControl association for this method was deleted", confidence="high")
    if event.method == "Authenticate":
        return _expected_authenticate(state, event)
    if event.method == "GetACL":
        return _expected_get_acl(state, event)
    if event.method in {"AddACE", "RemoveACE", "SetACL"}:
        return _expected_acl_mutation(state, event)
    if event.method == "DeleteMethod":
        return _expected_delete_method(state, event)
    if event.method == "Get":
        return _expected_get(state, event)
    if event.method == "Set":
        return _expected_set(state, event)
    if event.method == "CreateRow":
        return _expected_create_row(state, event)
    if event.method == "DeleteRow":
        return _expected_delete_row(state, event)
    if event.method == "Delete":
        return _expected_delete(state, event)
    if event.method == "DeleteSP":
        return _expected_delete_sp(state, event)
    if event.method == "CreateTable":
        return _expected_create_table(state, event)
    if event.method == "Activate":
        return _expected_activate(state, event)
    if event.method == "GenKey":
        return _expected_genkey(state, event)
    if event.method == "GetPackage":
        return _expected_get_package(state, event)
    if event.method == "SetPackage":
        return _expected_set_package(state, event)
    if event.method == "Erase":
        return _expected_erase(state, event)
    if event.method == "Sign":
        return _expected_sign(state, event)
    if event.method == "FirmwareAttestation":
        return _expected_firmware_attestation(state, event)
    if event.method in {"Revert", "RevertSP"}:
        return _expected_revert(state, event)
    if event.method in {"EndSession", "CloseSession", "SyncSession", "SyncTrustedSession", "SyncTlsSession"}:
        if not state.session.open:
            return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason=f"{event.method} is valid for closing the open session", confidence="high")
    if event.method == "Next":
        return _expected_next(state, event)
    if event.method == "GetFreeSpace":
        return _expected_get_free_space(state, event)
    if event.method == "GetFreeRows":
        return _expected_table_query(state, event)
    if event.method == "Random":
        return _expected_random(state, event)
    return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Method is outside the implemented Opal MethodID universe", confidence="medium")


def _expected_host_io(state: State, event: Event) -> ExpectedResponse:
    reset_type = _reset_event_type(event.method)
    if reset_type is not None:
        if reset_type == 3 and not state.programmatic_reset_enabled:
            return ExpectedResponse(
                {FAIL, INVALID_PARAMETER, NOT_AUTHORIZED},
                forbidden_statuses={SUCCESS, None, "PASS"},
                reason="TPER_RESET is disabled unless TPerInfo.ProgrammaticResetEnable is true",
                confidence="high",
            )
        return ExpectedResponse({SUCCESS, None, "PASS"}, reason="Reset events are valid host-side state transitions", confidence="medium")

    crossing_error_allowed = _range_crossing_error_allowed(state, event.lba)
    mbr_relation = _mbr_shadow_relation(state, event.lba)
    if event.method == "Write":
        if mbr_relation in {"within", "partial"}:
            return ExpectedResponse({FAIL, NOT_AUTHORIZED, INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, reason="MBR shadowing blocks host writes to the MBR address range", confidence="high")
        if _any_write_locked(state, event.lba):
            return ExpectedResponse({FAIL, NOT_AUTHORIZED, INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, reason="Write targets a write-locked range", confidence="high")
        if crossing_error_allowed:
            return ExpectedResponse({SUCCESS, None, "PASS", INVALID_PARAMETER, FAIL}, reason="Unlocked range-crossing writes may succeed or be rejected by Range Crossing Behavior", confidence="medium")
        return ExpectedResponse({SUCCESS, None, "PASS"}, reason="Write is allowed by current locking state", confidence="medium")

    if event.method == "Read":
        if mbr_relation == "partial":
            return ExpectedResponse({FAIL, NOT_AUTHORIZED, INVALID_PARAMETER, None}, forbidden_statuses={SUCCESS, "PASS"}, forbid_read_result_presence=True, reason="A host read spanning the MBR shadow boundary is a data-protection error", confidence="high")
        if mbr_relation == "within":
            remembered = _remembered_pattern_for_lba(state, event.lba)
            old_pattern = remembered[0] if remembered is not None else None
            return ExpectedResponse({SUCCESS, None, "PASS"}, forbidden_read_result=old_pattern, reason="MBR shadowing returns MBR table data instead of user media data", confidence="high")
        if _any_read_locked(state, event.lba):
            return ExpectedResponse({FAIL, NOT_AUTHORIZED, INVALID_PARAMETER, None}, forbidden_statuses={SUCCESS, "PASS"}, forbid_read_result_presence=True, reason="Read targets a read-locked range", confidence="high")
        if crossing_error_allowed:
            return ExpectedResponse({SUCCESS, None, "PASS", INVALID_PARAMETER, FAIL}, reason="Unlocked range-crossing reads may succeed or be rejected by Range Crossing Behavior", confidence="medium")
        remembered = _remembered_pattern_for_lba(state, event.lba)
        if remembered is None:
            return ExpectedResponse({SUCCESS, None, "PASS"}, reason="No prior write pattern is known for this LBA", confidence="low")
        old_pattern, range_id, generation = remembered
        current_generation = _range(state, range_id).media_generation
        if generation != current_generation:
            return ExpectedResponse({SUCCESS, None, "PASS"}, forbidden_read_result=old_pattern, reason="GenKey changed the media key after this pattern was written", confidence="high")
        return ExpectedResponse({SUCCESS, None, "PASS"}, expected_read_result=old_pattern, reason="Prior write pattern should still be readable", confidence="high")

    return ExpectedResponse({SUCCESS, None, "PASS", FAIL, NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Unknown host I/O fallback", confidence="low")


def _hex_payload_length(text: str) -> int | None:
    stripped = re.sub(r"[^0-9A-Fa-f]", "", text)
    if stripped and len(stripped) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", stripped):
        return len(stripped) // 2
    return None


def _return_payload_length(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, bytearray):
        return len(value)
    if isinstance(value, str):
        if re.sub(r"[^A-Za-z_]", "", value).upper() in {
            "SUCCESS",
            "PASS",
            "FAIL",
            "NOTAUTHORIZED",
            "INVALIDPARAMETER",
            "INSUFFICIENTSPACE",
            "INSUFFICIENTROWS",
        }:
            return None
        hex_length = _hex_payload_length(value)
        return hex_length if hex_length is not None else len(value.encode("utf-8"))
    if isinstance(value, dict):
        for key in ("Result", "result", "BufferOut", "Data", "bytes", "Bytes"):
            found, item = _dict_lookup(value, key)
            if found:
                length = _return_payload_length(item)
                if length is not None:
                    return length
        if len(value) == 1:
            return _return_payload_length(next(iter(value.values())))
        return None
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return _return_payload_length(value[0])
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return len(value)
        return None
    return None



__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
