"""Shared Opal authority, ACL, object, and table semantics."""

from __future__ import annotations

from dataclasses import replace
import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *


def _range(state: State, range_id: int) -> RangeState:
    if range_id not in state.ranges:
        state.ranges[range_id] = RangeState(range_id=range_id)
    return state.ranges[range_id]


def _has_authority(state: State, authority: str) -> bool:
    if authority == "Anybody":
        return state.session.open
    if authority == "Admins":
        if state.session.sp == "LockingSP":
            return any(auth.startswith("Admin") for auth in state.session.authenticated)
        return any(auth == "SID" or auth.startswith("Admin") for auth in state.session.authenticated)
    if authority == "Users":
        return any(auth.startswith("User") for auth in state.session.authenticated)
    if authority == "PSID":
        return "PSID" in state.session.authenticated
    return authority in state.session.authenticated


def _has_any_authority(state: State, authorities: set[str]) -> bool:
    return any(_has_authority(state, authority) for authority in authorities)


def _range_master_authorizes(state: State, range_id: int | None) -> bool:
    if range_id is None:
        return False
    if "EraseMaster" in state.session.authenticated:
        return True
    return f"BandMaster{range_id}" in state.session.authenticated


def _datastore_master_authorizes(state: State) -> bool:
    return "EraseMaster" in state.session.authenticated or any(_is_band_master(authority) for authority in state.session.authenticated)


def _is_user(authority: str | None) -> bool:
    return bool(authority and re.fullmatch(r"User\d+", authority))


def _is_band_master(authority: str | None) -> bool:
    return bool(authority and re.fullmatch(r"BandMaster\d+", authority))


def _user_enabled(state: State, authority: str | None) -> bool:
    if not _is_user(authority):
        return True
    return state.authority_enabled.get(authority, False)


def _authority_is_enabled(state: State, sp: str | None, authority: str | None) -> bool:
    if authority is None or authority == "Anybody":
        return True
    if authority in state.authority_enabled:
        return state.authority_enabled[authority]
    if authority.startswith("User"):
        return False
    match = re.fullmatch(r"Admin(\d+)", authority)
    if match:
        return sp == "LockingSP" and int(match.group(1)) == 1
    return True


def _authority_locked_out(state: State, authority: str | None) -> bool:
    if authority is None or authority in {"Anybody", "Admins", "Users", "Makers"}:
        return False
    try_limit = state.pin_try_limits.get(authority, 0)
    return try_limit > 0 and state.pin_tries.get(authority, 0) >= try_limit


def _authority_allowed_in_sp(sp: str | None, authority: str | None) -> bool:
    if authority is None or authority == "Anybody":
        return True
    if authority == "MSID":
        return False
    if sp == "AdminSP":
        if authority.startswith("User"):
            return False
        return True
    if sp == "LockingSP":
        return authority.startswith(("Admin", "User", "BandMaster")) or authority in {"Admins", "Users", "EraseMaster"}
    return True


def _authority_allowed_for_target_method(state: State, event: Event, authority: str | None) -> bool:
    if event.method == "Erase" and authority == "EraseMaster":
        return True
    if state.session.sp == "LockingSP" and (authority == "EraseMaster" or _is_band_master(authority)):
        if event.invoking_symbol.startswith(("Locking_", "DataStore")):
            return True
        if authority == "EraseMaster" and event.invoking_symbol.startswith("TLS_PSK_Key"):
            return True
    return _authority_allowed_in_sp(state.session.sp, authority)


def _expected_object_sp(event: Event, state: State | None = None) -> str | None:
    symbol = event.invoking_symbol
    if event.method == "Activate":
        return "AdminSP"
    if symbol in ADMIN_ONLY_TABLE_ROWS:
        return "AdminSP"
    if symbol in LOCKING_ONLY_TABLE_ROWS or symbol == "SecretProtectTable" or symbol.startswith("SecretProtect_"):
        return "LockingSP"
    if (
        symbol in {"TPerSign", "TperAttestation", "DataRemovalMechanism", "TPerInfo", "TemplateTable", "SPTable"}
        or symbol.startswith(("_CertData_", "Template_"))
    ):
        return "AdminSP"
    if symbol.startswith("Table_") or symbol in {"Table", "SPInfo", "SPTemplatesTable", "SPTemplates_Base", "SPTemplates_Admin", "MethodIDTable", "AccessControlTable", "ACETable"}:
        return state.session.sp if state is not None and state.session.sp else None
    if symbol in {"AdminSP", "LockingSP", "C_PIN_MSID", "C_PIN_SID"}:
        return "AdminSP"
    if symbol.startswith("UnknownSP_"):
        return "AdminSP"
    if symbol.startswith(("Locking_", "K_AES_", "MBRControl", "DataStore")) or symbol == "MBR":
        return "LockingSP"
    if symbol == "LockingInfo":
        return "LockingSP"
    if symbol in {"C_PIN_EraseMaster", "Authority_EraseMaster"} or symbol.startswith(("C_PIN_BandMaster", "Authority_BandMaster")):
        return "AdminSP"
    if symbol.startswith("C_PIN_Admin"):
        if event.invoking_uid.startswith("0000000B000002"):
            return "AdminSP"
        if event.invoking_uid.startswith("0000000B0001"):
            return "LockingSP"
        return state.session.sp if state is not None and state.session.sp else "LockingSP"
    if symbol.startswith("Authority_Admin"):
        if event.invoking_uid.startswith("00000009000002"):
            return "AdminSP"
        if event.invoking_uid.startswith("000000090001"):
            return "LockingSP"
        return state.session.sp if state is not None and state.session.sp else "LockingSP"
    if symbol.startswith(("C_PIN_User", "Authority_User")):
        return "LockingSP"
    if symbol.startswith("Port"):
        return "AdminSP"
    if symbol.startswith(("Authority_", "ACE_", "TLS_PSK_Key")):
        return state.session.sp if state is not None and state.session.sp else None
    return None


def _session_allows_object(state: State, event: Event) -> bool:
    expected_sp = _expected_object_sp(event, state)
    return expected_sp is None or state.session.sp is None or state.session.sp == expected_sp


def _implicit_session_sp(state: State, event: Event) -> str | None:
    if event.sp is not None:
        return event.sp
    expected = _expected_object_sp(event, state)
    if expected is not None:
        return expected
    if event.authority in {"SID", "Makers", "PSID", "Anybody"}:
        return "AdminSP"
    if event.authority:
        return "LockingSP"
    return None


def _implicit_session_for_event(state: State, event: Event, *, assume_authenticated: bool = False) -> Session:
    authenticated = {"Anybody"}
    if assume_authenticated and event.authority not in {None, "Anybody", "Admins", "Users", "Makers"}:
        authenticated.add(event.authority)
    return Session(open=True, sp=_implicit_session_sp(state, event), write=True, authenticated=authenticated)


def _method_supported_in_session(state: State, event: Event) -> bool:
    if event.method in {
        "Properties",
        "StartSession",
        "StartTrustedSession",
        "StartTlsSession",
        "EndSession",
        "CloseSession",
        "SyncSession",
        "SyncTrustedSession",
        "SyncTlsSession",
    }:
        return True
    if not state.session.open:
        return True
    allowed = SUPPORTED_METHODS_BY_SP.get(state.session.sp or "")
    return allowed is None or event.method in allowed


def _disabled_sp_response(state: State, event: Event) -> ExpectedResponse | None:
    sp = state.session.sp
    if not state.session.open or sp is None or state.sp_enabled.get(sp, True):
        return None
    if event.method in {"Authenticate", "DeleteSP", "EndSession", "CloseSession", "SyncSession", "SyncTrustedSession", "SyncTlsSession"}:
        return None
    if event.method == "Set" and event.invoking_symbol == "SPInfo" and set(event.values) == {6}:
        if _is_bool_literal(event.values[6]) and _as_bool(event.values[6]):
            return None
    return ExpectedResponse(
        {FAIL},
        forbidden_statuses={SUCCESS},
        reason="Issued-Disabled SP permits only Authenticate, control-session methods, and Set SPInfo.Enabled to re-enable",
        confidence="high",
    )


def _is_session_manager_target(event: Event) -> bool:
    return event.invoking_symbol in {"", "SessionManager"} or event.invoking_uid == "00000000000000FF"


def _unsupported_method_response(event: Event) -> ExpectedResponse | None:
    if event.method in UNSUPPORTED_OPAL_METHODS or event.method == "UNKNOWN":
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} is not present in Opal AdminSP/LockingSP MethodID tables",
            confidence="high",
        )
    return None


def _set_required_authorities(state: State, event: Event) -> set[str]:
    symbol = event.invoking_symbol
    owner = _pin_owner_by_object(symbol)
    if symbol == "C_PIN_SID":
        return {"SID"}
    if owner and owner.startswith("Admin"):
        if PIN_COLUMN in event.values and _ace_expression_configured(state, "ACE_0003A001"):
            return set()
        return {"Admins", owner, "SID"}
    if owner and owner.startswith("User"):
        ace_symbol = _pin_user_set_ace_symbol(owner)
        if ace_symbol and _ace_expression_configured(state, ace_symbol):
            return set()
        return {"Admins", owner}
    if owner and (owner == "EraseMaster" or owner.startswith("BandMaster")):
        return {"Admins", owner, "SID"}
    if symbol.startswith("Authority_BandMaster") and set(event.values) and set(event.values) <= {5}:
        return {"Admins", "SID", "EraseMaster"}
    if symbol.startswith("Authority_User"):
        return {"Admins"}
    if symbol.startswith("Authority_Admin"):
        return {"Admins", "SID"}
    if symbol in {"MBR", "DataStore"}:
        return {"Admins"}
    if symbol == "SPInfo":
        return {"Admins"}
    if symbol.startswith(("Locking_", "MBRControl", "ACE_", "DataStore", "Port")):
        return {"Admins"}
    if symbol.startswith("TLS_PSK_Key"):
        return {"Admins", "EraseMaster"} if state.session.sp == "LockingSP" else {"Admins", "SID"}
    if symbol == "DataRemovalMechanism":
        return {"Admins", "SID"}
    if symbol.startswith("K_AES_"):
        return {"Admins"}
    if symbol.startswith("Authority_"):
        return {"Admins", "SID"}
    return {"Admins", "SID"}


def _ace_locking_grant(symbol: str) -> tuple[str, int] | None:
    match = re.fullmatch(r"ACE_0003([A-F0-9]{4})", symbol)
    if not match:
        return None
    value = int(match.group(1), 16)
    if 0xE000 <= value <= 0xE7FF:
        return "read", value - 0xE000
    if 0xE800 <= value <= 0xEFFF:
        return "write", value - 0xE800
    return None


def _ace_datastore_grant(symbol: str) -> str | None:
    name_match = re.fullmatch(r"ACE_DataStore\d+_(Get|Set)_All", symbol)
    if name_match:
        return "read" if name_match.group(1) == "Get" else "write"
    match = re.fullmatch(r"ACE_0003FC([0-9A-F]{2})", symbol)
    if not match:
        return None
    if match.group(1) == "00":
        return "read"
    if match.group(1) in {"01", "02"}:
        return "write"
    return None


def _configured_datastore_ace_symbols(state: State, write: bool) -> list[str]:
    grant = "write" if write else "read"
    defaults = ["ACE_0003FC01" if write else "ACE_0003FC00"]
    for sp, symbol in state.ace_expressions:
        if sp == (state.session.sp or "") and _ace_datastore_grant(symbol) == grant and symbol not in defaults:
            defaults.append(symbol)
    return defaults


def _extract_authorities(node: Any) -> set[str]:
    authorities: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                walk(key)
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            uid = _clean_uid(value)
            authority = _authority_by_uid(uid)
            if uid == "0000000900030000":
                authorities.add("User1")
            if authority is None:
                authority = _authority_by_name(value)
            if authority is not None:
                authorities.add(authority)

    walk(node)
    return authorities


def _authority_by_name(value: Any) -> str | None:
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or ""))
    if not text:
        return None
    key = text.upper()
    fixed = {
        "ANYBODY": "Anybody",
        "ADMINS": "Admins",
        "USERS": "Users",
        "SID": "SID",
        "MSID": "MSID",
        "PSID": "PSID",
        "MAKERS": "Makers",
        "ERASEMASTER": "EraseMaster",
        "TPERSIGN": "TPerSign",
        "TPERATTESTATION": "TperAttestation",
    }
    match = re.fullmatch(r"BANDMASTER(\d+)", key)
    if match:
        return f"BandMaster{int(match.group(1))}"
    if key in fixed:
        return fixed[key]
    match = re.fullmatch(r"(ADMIN|USER)(\d+)", key)
    if match:
        return f"{match.group(1).title()}{int(match.group(2))}"
    return None


def _ace_tokens(node: Any) -> list[str]:
    tokens: list[str] = []

    def add_leaf(value: Any) -> None:
        authority = _authority_by_uid(_clean_uid(value)) or _authority_by_name(value)
        if authority is not None:
            tokens.append(authority)
            return
        text = _as_text(value or "").strip().upper()
        if re.fullmatch(r"AND|OR", text):
            tokens.append(text.lower())

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                walk(key)
                walk(val)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
        elif isinstance(value, set):
            for item in sorted(value, key=str):
                walk(item)
        else:
            add_leaf(value)

    walk(node)
    return tokens


def _ace_expression_from_value(value: Any) -> AceExpression:
    authorities = _extract_authorities(value)
    tokens = tuple(_ace_tokens(value))
    token_ops = {token for token in tokens if token in {"and", "or"}}
    text = repr(value).upper()
    if " OR " in text or "BOOLEAN_ACE - OR" in text or "BOOLEAN_ACE-OR" in text:
        operator = "or"
    elif " AND " in text or "BOOLEAN_ACE - AND" in text or "BOOLEAN_ACE-AND" in text:
        operator = "and"
    elif "and" in token_ops and "or" not in token_ops:
        operator = "and"
    else:
        operator = "or"
    return AceExpression(authorities=authorities, operator=operator, tokens=tokens)


def _evaluate_ace_expression(state: State, expression: AceExpression) -> bool:
    if not expression.authorities:
        return False

    stack: list[bool] = []
    saw_operator = False
    invalid_rpn = False
    for token in expression.tokens:
        if token == "and":
            saw_operator = True
            if len(stack) < 2:
                invalid_rpn = True
                break
            right = stack.pop()
            left = stack.pop()
            stack.append(left and right)
        elif token == "or":
            saw_operator = True
            if len(stack) < 2:
                invalid_rpn = True
                break
            right = stack.pop()
            left = stack.pop()
            stack.append(left or right)
        else:
            stack.append(_has_authority(state, token))
    if saw_operator and not invalid_rpn and len(stack) == 1:
        return stack[0]

    if expression.operator == "and":
        return all(_has_authority(state, authority) for authority in expression.authorities)
    return any(_has_authority(state, authority) for authority in expression.authorities)


def _ace_key(state: State, ace_symbol: str) -> tuple[str, str]:
    return state.session.sp or "", ace_symbol


def _ace_expression_configured(state: State, ace_symbol: str) -> bool:
    return _ace_key(state, ace_symbol) in state.ace_expressions


def _default_ace_expression(sp: str | None, ace_symbol: str) -> AceExpression | None:
    suffix = ace_symbol.removeprefix("ACE_")
    if ace_symbol == "ACE_00000001":
        return AceExpression({"Anybody"})
    if ace_symbol == "ACE_00000002":
        return AceExpression({"Admins"})

    if sp == "AdminSP":
        admin_sp_defaults = {
            "00030001": {"SID"},
            "00008C02": {"Admins", "SID"},
            "00008C03": {"SID"},
            "00008C04": {"Anybody"},
            "0003A001": {"Admins", "SID"},
            "00030003": {"SID"},
            "00030002": {"SID"},
            "00050001": {"Admins", "SID"},
        }
        if suffix in admin_sp_defaults:
            return AceExpression(set(admin_sp_defaults[suffix]))

    if sp == "LockingSP":
        if suffix == "0003BFFF":
            return AceExpression({"Anybody"})
        if suffix.startswith("0003A8"):
            user_index = int(suffix[-4:], 16) - 0xA800
            if user_index > 0:
                return AceExpression({"Admins", f"User{user_index}"})
        admin_prefixes = (
            "000380",
            "000390",
            "000440",
            "0003A0",
            "0003B0",
            "0003B8",
            "0003D0",
            "0003E0",
            "0003E8",
            "0003F0",
            "0003F8",
            "0003FC",
        )
        if suffix.startswith(admin_prefixes):
            return AceExpression({"Admins"})

    return None


def _ace_expression_for(state: State, ace_symbol: str) -> AceExpression | None:
    return state.ace_expressions.get(_ace_key(state, ace_symbol)) or _default_ace_expression(state.session.sp, ace_symbol)


def _ace_satisfied(state: State, ace_symbol: str) -> bool:
    expression = _ace_expression_for(state, ace_symbol)
    return bool(expression and _evaluate_ace_expression(state, expression))


def _pin_user_set_ace_symbol(owner: str) -> str | None:
    match = re.fullmatch(r"User(\d+)", owner)
    if not match:
        return None
    return f"ACE_0003{0xA800 + int(match.group(1)):04X}"


def _pin_user_from_set_ace_symbol(ace_symbol: str) -> str | None:
    match = re.fullmatch(r"ACE_0003([A-F0-9]{4})", ace_symbol)
    if not match:
        return None
    value = int(match.group(1), 16)
    if value <= 0xA800:
        return None
    if value < 0xA800 or value > 0xAFFF:
        return None
    return f"User{value - 0xA800}"


def _locking_ace_symbol(prefix: int, range_id: int) -> str:
    return f"ACE_0003{prefix + range_id:04X}"


def _key_genkey_ace_symbol(symbol: str) -> str | None:
    range_id = _range_id_from_key(symbol)
    if range_id is None:
        return None
    if symbol.startswith("K_AES_128_"):
        return _locking_ace_symbol(0xB000, range_id)
    if symbol.startswith("K_AES_256_"):
        return _locking_ace_symbol(0xB800, range_id)
    return None


def _ace_expression_users(state: State, ace_symbol: str) -> set[str]:
    expression = _ace_expression_for(state, ace_symbol)
    if expression is None:
        return set()
    return {authority for authority in expression.authorities if _is_user(authority)}


def _ace_authorizes_set(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    owner = _pin_owner_by_object(symbol)
    if owner and owner.startswith("Admin") and PIN_COLUMN in event.values and _ace_expression_configured(state, "ACE_0003A001"):
        return _ace_satisfied(state, "ACE_0003A001")
    if owner and owner.startswith("User") and PIN_COLUMN in event.values:
        ace_symbol = _pin_user_set_ace_symbol(owner)
        return bool(ace_symbol and _ace_satisfied(state, ace_symbol))

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        columns = set(event.values)
        admin_set_ace = _locking_ace_symbol(0xF000, range_id)
        if columns and columns <= set(range(3, 10)) and _ace_expression_configured(state, admin_set_ace) and _ace_satisfied(state, admin_set_ace):
            return True
        if columns and columns <= {7, 8}:
            checks: list[bool] = []
            for column, prefix, legacy in (
                (7, 0xE000, state.range_read_lock_users),
                (8, 0xE800, state.range_write_lock_users),
            ):
                if column not in columns:
                    continue
                ace_symbol = _locking_ace_symbol(prefix, range_id)
                if _ace_expression_configured(state, ace_symbol):
                    checks.append(_ace_satisfied(state, ace_symbol))
                else:
                    users = {auth for auth in state.session.authenticated if _is_user(auth)}
                    checks.append(bool(users & legacy.get(range_id, set())))
            return bool(checks) and all(checks)

    if symbol.startswith("DataStore"):
        configured = [ace_symbol for ace_symbol in _configured_datastore_ace_symbols(state, write=True) if _ace_expression_configured(state, ace_symbol)]
        if configured:
            return any(_ace_satisfied(state, ace_symbol) for ace_symbol in configured)
        return _user_acl_allows_datastore(state, write=True)

    if symbol.startswith("Authority_"):
        columns = set(event.values)
        if columns and columns <= {5} and _ace_expression_configured(state, "ACE_00039001"):
            return _ace_satisfied(state, "ACE_00039001")

    if symbol.startswith("ACE_"):
        columns = set(event.values)
        if ACE_BOOLEAN_EXPR_COLUMN in columns and _ace_expression_configured(state, "ACE_00038001"):
            return _ace_satisfied(state, "ACE_00038001")

    if symbol == "MBRControl":
        columns = set(event.values)
        if not columns or not columns <= {1, 2, 3}:
            return False
        checks: list[bool] = []
        if 1 in columns and _ace_expression_configured(state, "ACE_0003F800"):
            checks.append(_ace_satisfied(state, "ACE_0003F800"))
        if columns & {2, 3}:
            done_allowed = False
            if _ace_expression_configured(state, "ACE_0003F800"):
                done_allowed = done_allowed or _ace_satisfied(state, "ACE_0003F800")
            if _ace_expression_configured(state, "ACE_0003F801"):
                done_allowed = done_allowed or _ace_satisfied(state, "ACE_0003F801")
            checks.append(done_allowed)
        return bool(checks) and all(checks)

    return False


def _user_acl_allows_locking_set(state: State, event: Event) -> bool:
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None:
        return False
    columns = set(event.values)
    if not columns or not columns <= {7, 8}:
        return False
    users = {auth for auth in state.session.authenticated if _is_user(auth)}
    if not users:
        return False
    for user in users:
        if 7 in columns and user not in state.range_read_lock_users.get(range_id, set()):
            continue
        if 8 in columns and user not in state.range_write_lock_users.get(range_id, set()):
            continue
        return True
    return False


def _user_acl_allows_datastore(state: State, write: bool) -> bool:
    configured = [ace_symbol for ace_symbol in _configured_datastore_ace_symbols(state, write) if _ace_expression_configured(state, ace_symbol)]
    if configured:
        return any(_ace_satisfied(state, ace_symbol) for ace_symbol in configured)
    users = {auth for auth in state.session.authenticated if _is_user(auth)}
    if not users:
        return False
    allowed = state.datastore_write_users if write else state.datastore_read_users
    return bool(users & allowed)


def _range_values_invalid_for_geometry(state: State, range_id: int | None, values: dict[int, Any], creating: bool = False) -> bool:
    if range_id == 0 and any(col in values for col in (3, 4)):
        return True
    current = _range(state, range_id or 0)
    start = _parse_int(values.get(3)) if 3 in values else current.range_start
    length = _parse_int(values.get(4)) if 4 in values else current.range_length
    if start is None or length is None:
        return True
    if start < 0 or length < 0:
        return True

    alignment_required = _as_bool(state.locking_info.get("AlignmentRequired"))
    granularity = _parse_int(state.locking_info.get("AlignmentGranularity"))
    lowest = _parse_int(state.locking_info.get("LowestAlignedLBA")) or 0
    non_global = creating or bool(range_id)
    if non_global and alignment_required and granularity and granularity > 0:
        if 3 in values and start and (start - lowest) % granularity:
            return True
        if 4 in values and length:
            length_alignment = (length - lowest) % granularity if start == 0 else length % granularity
            if length_alignment:
                return True

    if non_global and (creating or 3 in values or 4 in values) and _range_values_overlap(state, range_id, start, length):
        return True
    return False


def _range_values_overlap(state: State, range_id: int | None, start: int, length: int) -> bool:
    if length == 0:
        return False
    end = start + length - 1
    for existing_id, existing in state.ranges.items():
        if existing_id == 0 or existing_id == range_id or existing.range_length == 0:
            continue
        existing_end = existing.range_start + existing.range_length - 1
        if start <= existing_end and existing.range_start <= end:
            return True
    return False


def _parse_data_removal_mechanism(value: Any) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    aliases = {
        "OVERWRITEDATAERASE": 0,
        "OVERWRITE": 0,
        "BLOCKERASE": 1,
        "BLOCK": 1,
        "CRYPTOGRAPHICERASE": 2,
        "CRYPTOERASE": 2,
        "CRYPTOGRAPHIC": 2,
        "CRYPTO": 2,
        "VENDORSPECIFICERASE": 5,
        "VENDORSPECIFIC": 5,
        "VENDOR": 5,
    }
    return aliases.get(key)


def _master_authorizes_set(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    if symbol.startswith("Locking_"):
        return _range_master_authorizes(state, _range_id_from_symbol(symbol))
    if symbol.startswith("DataStore"):
        return _datastore_master_authorizes(state)
    return False


def _range_reencrypt_busy(range_state: RangeState) -> bool:
    return range_state.reencrypt_state != 1


def _range_reencrypt_active(range_state: RangeState) -> bool:
    return range_state.reencrypt_state == 3


def _global_reencrypt_busy(state: State) -> bool:
    return _range_reencrypt_busy(_range(state, 0))


def _reencrypt_request_invalid(range_state: RangeState, request: int | None) -> bool:
    if request is None:
        return True
    current = range_state.reencrypt_state
    if request == 1:
        return current != 1
    if request == 2:
        return current not in {4, 5}
    if request in {3, 4}:
        return current != 5
    if request == 5:
        return current not in {2, 3}
    return True


def _reencrypt_blocks_set(state: State, event: Event) -> str | None:
    if not event.invoking_symbol.startswith("Locking_"):
        return None
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None:
        return None
    columns = set(event.values)
    if columns & {3, 4}:
        if _global_reencrypt_busy(state):
            return "Global Range re-encryption blocks Locking range geometry changes"
        if _range_reencrypt_busy(_range(state, range_id)):
            return "RangeStart/RangeLength cannot change while the range is re-encrypting"
    if 11 in columns and _range_reencrypt_busy(_range(state, range_id)):
        return "NextKey is writable only when ReEncryptState is IDLE"
    return None


def _range_id_from_delete_uid(uid: str) -> int | None:
    return _range_id_from_symbol(_object_by_uid(uid))


def _byte_table_ref_invalid(value: Any) -> bool:
    uid = _clean_uid(value)
    if uid in {"", "0000000000000000"}:
        return False
    symbol, uid_from_ref = _object_ref_from_value(value)
    return not (_is_byte_table_uid(uid_from_ref or uid) or _is_byte_table_symbol(symbol))


def _set_effective_event(event: Event) -> tuple[Event, ExpectedResponse | None]:
    where_found, where_value = _named_method_arg_value(event, "Where", "where")
    symbol = event.invoking_symbol
    if _is_byte_table_symbol(symbol):
        if _byte_table_where_invalid(event):
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Byte-table Set Where must use row addressing",
                confidence="high",
            )
        return event, None

    if _is_table_symbol(symbol):
        if not where_found:
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Table.Set on an object table requires a Where UID",
                confidence="high",
            )
        row_symbol, row_uid = _object_ref_from_value(where_value)
        if not row_symbol and not row_uid:
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Table.Set Where must identify an object-table row",
                confidence="high",
            )
        if _next_where_invalid(event):
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Table.Set Where must reference a row in the invoking object table",
                confidence="high",
            )
        if not row_symbol and row_uid:
            row_symbol = _object_by_uid(row_uid)
        return replace(event, invoking_symbol=row_symbol, invoking_uid=row_uid, invoking_name=row_symbol), None

    if where_found:
        return event, ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Object.Set must omit Where",
            confidence="high",
        )
    return event, None


def _set_values_omitted(event: Event) -> bool:
    if _is_byte_table_symbol(event.invoking_symbol):
        return False
    if event.values or _byte_table_has_payload(event):
        return False
    found, value = _named_method_arg_value(
        event,
        "Values",
        "values",
        "RowValues",
        "rowValues",
        "Bytes",
        "bytes",
        "Data",
        "data",
        "Buffer",
        "BufferIn",
        "Payload",
        "payload",
    )
    return not found or _empty_payload(value)


def _invalid_set_values(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    if symbol.startswith("_CertData_"):
        return True
    if _is_byte_table_symbol(symbol):
        return _byte_table_set_invalid(event)
    if _is_table_symbol(symbol):
        return True
    if symbol.startswith(("SPTemplates_", "Template_", "MethodID_", "AccessControl_", "SecretProtect_")):
        return True
    if symbol.startswith("K_AES_"):
        return True
    if symbol in {"LockingInfo", "MethodIDTable", "Table_MethodID"}:
        return True
    if symbol == "SPInfo":
        columns = set(event.values)
        if not columns or not columns <= {5, 6}:
            return True
        if 5 in event.values:
            timeout = _parse_int(event.values[5])
            if timeout is None or timeout < 0:
                return True
        if 6 in event.values and not _is_bool_literal(event.values[6]):
            return True
        return False
    if symbol in {"AdminSP", "LockingSP"}:
        columns = set(event.values)
        if not columns or not columns <= {7}:
            return True
        return not _is_bool_literal(event.values[7])
    if symbol == "DataRemovalMechanism":
        columns = set(event.values)
        if not columns or not columns <= {1}:
            return True
        mechanism = _parse_data_removal_mechanism(event.values.get(1))
        return mechanism not in DATA_REMOVAL_MECHANISM_VALUES
    if symbol == "TPerInfo":
        columns = set(event.values)
        if not columns or not columns <= {8}:
            return True
        return not _is_bool_literal(event.values[8])
    if symbol == "C_PIN_MSID":
        return True
    if symbol.startswith("C_PIN_"):
        columns = set(event.values)
        allowed = {
            PIN_COLUMN,
            CPIN_CHARSET_COLUMN,
            CPIN_TRY_LIMIT_COLUMN,
            CPIN_TRIES_COLUMN,
            CPIN_PERSISTENCE_COLUMN,
            MIN_PIN_COLUMN,
        }
        if not columns or not columns <= allowed:
            return True
        if CPIN_CHARSET_COLUMN in event.values and _byte_table_ref_invalid(event.values[CPIN_CHARSET_COLUMN]):
            return True
        if CPIN_TRY_LIMIT_COLUMN in event.values:
            try_limit = _parse_int(event.values[CPIN_TRY_LIMIT_COLUMN])
            if try_limit is None or try_limit < 0:
                return True
        if CPIN_TRIES_COLUMN in event.values and _parse_int(event.values[CPIN_TRIES_COLUMN]) != 0:
            return True
        if CPIN_PERSISTENCE_COLUMN in event.values and not _is_bool_literal(event.values[CPIN_PERSISTENCE_COLUMN]):
            return True
        if PIN_COLUMN in event.values and event.values[PIN_COLUMN] in {None, ""}:
            return True
        owner = _pin_owner_by_object(symbol)
        if MIN_PIN_COLUMN in event.values:
            min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
            if min_pin is None or min_pin < 0 or min_pin > 32:
                return True
        else:
            min_pin = state.pin_min_lengths.get(owner or "", 0)
        if PIN_COLUMN in event.values and owner and _credential_length(event.values[PIN_COLUMN]) < min_pin:
            return True
    if symbol.startswith("ACE_"):
        columns = set(event.values)
        if not columns or not columns <= {2, ACE_BOOLEAN_EXPR_COLUMN}:
            return True
        if ACE_BOOLEAN_EXPR_COLUMN in event.values:
            expression = _ace_expression_from_value(event.values[ACE_BOOLEAN_EXPR_COLUMN])
            pin_user = _pin_user_from_set_ace_symbol(symbol)
            if state.session.sp == "LockingSP" and pin_user:
                supported = ({"Admins"}, {"Admins", pin_user})
                return expression.operator != "or" or expression.authorities not in supported
    if symbol.startswith("Locking_"):
        range_id = _range_id_from_symbol(symbol)
        columns = set(event.values)
        if not columns or not columns <= ({2} | set(range(3, 20))):
            return True
        if 9 in event.values and _reset_list_invalid(event.values[9]):
            return True
        if 13 in event.values and _reencrypt_request_invalid(_range(state, range_id or 0), _parse_reencrypt_request(event.values[13])):
            return True
        if _range_values_invalid_for_geometry(state, range_id, event.values):
            return True
    if symbol.startswith("Authority_"):
        columns = set(event.values)
        if not columns or not columns <= {2, 5}:
            return True
        if 5 in event.values and not _is_bool_literal(event.values[5]):
            return True
    if symbol == "MBRControl":
        columns = set(event.values)
        if not columns or not columns <= set(MBR_COLUMNS):
            return True
        for column in (1, 2):
            if column in event.values and not _is_bool_literal(event.values[column]):
                return True
        if 3 in event.values and _reset_list_invalid(event.values[3]):
            return True
    if symbol.startswith("Port"):
        columns = set(event.values)
        if not columns or not columns <= set(PORT_COLUMNS):
            return True
        if 3 in event.values and not _is_bool_literal(event.values[3]):
            return True
        if 2 in event.values and _reset_list_invalid(event.values[2]):
            return True
    if symbol.startswith("TLS_PSK_Key"):
        columns = set(event.values)
        if not columns or not columns <= set(TLS_PSK_COLUMNS):
            return True
        if 3 in event.values and not _is_bool_literal(event.values[3]):
            return True
        if 5 in event.values and event.values[5] in {None, ""}:
            return True
    return False


def _create_table_arg(event: Event, index: int, *names: str) -> tuple[bool, Any]:
    found, value = _named_method_arg_value(event, *names)
    if found:
        return True, value
    raw_args = _method_raw_args(event)
    if not isinstance(raw_args, (list, tuple)) or any(_is_named_pair(item) for item in raw_args):
        return False, None
    if len(raw_args) <= index:
        return False, None
    return True, raw_args[index]


def _create_table_name_text(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("name", "Name", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                return _create_table_name_text(item)
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _create_table_name_text(value[0])
    return _as_text(value or "").strip()


def _create_table_kind(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("kind", "Kind", "name", "Name", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                kind = _create_table_kind(item)
                if kind is not None:
                    return kind
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _create_table_kind(value[0])
    parsed = _parse_int(value)
    if parsed == 1:
        return "object"
    if parsed == 2:
        return "byte"
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if text in {"OBJECT", "OBJECTTABLE", "OBJ"}:
        return "object"
    if text in {"BYTE", "BYTES", "BYTETABLE"}:
        return "byte"
    return None


def _create_table_columns_empty(value: Any) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    text = re.sub(r"\s+", "", _as_text(value or ""))
    return text in {"", "[]", "()", "{}"}


def _created_table_for_event(state: State, event: Event) -> tuple[str, str] | None:
    if not event.invoking_uid:
        return None
    return state.created_tables.get(event.invoking_uid)


def _is_credential_symbol(symbol: str) -> bool:
    return bool(
        _pin_owner_by_object(symbol)
        or _range_id_from_key(symbol) is not None
        or symbol in {"TPerSign", "TperAttestation"}
        or symbol.startswith("TLS_PSK_Key")
    )


def _credential_ref_invalid(value: Any) -> bool:
    symbol, uid = _object_ref_from_value(value)
    if not symbol and uid:
        symbol = _object_by_uid(uid)
    return not symbol or not _is_credential_symbol(symbol)


def _package_credential_arg_invalid(event: Event, *names: str) -> bool:
    found, value = _named_method_arg_value(event, *names)
    if not found:
        return False
    return _credential_ref_invalid(value)


def _package_required_authorities(state: State, event: Event) -> set[str]:
    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner == "SID":
        return {"Admins", "SID"}
    if owner and owner.startswith("Admin"):
        return {"Admins", owner, "SID"}
    if owner and owner.startswith("User"):
        return {"Admins", owner}
    if owner and (owner == "EraseMaster" or owner.startswith("BandMaster")):
        return {"Admins", owner, "SID"}
    if _range_id_from_key(event.invoking_symbol) is not None:
        return {"Admins"}
    if event.invoking_symbol.startswith("TLS_PSK_Key"):
        return {"Admins", "SID"} if state.session.sp == "AdminSP" else {"Admins", "EraseMaster"}
    return {"Admins"}


def _table_method_common_failure(state: State, event: Event, method: str) -> ExpectedResponse | None:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} table does not belong to current SP", confidence="medium")
    created = _created_table_for_event(state, event)
    if created is not None:
        table_sp, kind = created
        if state.session.sp is not None and table_sp != state.session.sp:
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} dynamic table does not belong to current SP", confidence="high")
        if kind == "byte":
            return ExpectedResponse({INVALID_PARAMETER}, reason=f"{method} is not available on byte tables", confidence="high")
        return None
    if not _is_table_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason=f"{method} is a table method", confidence="high")
    if event.invoking_symbol in {"MBR", "DataStore"} or event.invoking_symbol.startswith("DataStore"):
        return ExpectedResponse({INVALID_PARAMETER}, reason=f"{method} is not available on byte tables", confidence="high")
    return None


def _table_query_common_failure(state: State, event: Event, method: str) -> ExpectedResponse | None:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} table does not belong to current SP", confidence="medium")
    created = _created_table_for_event(state, event)
    if created is not None:
        table_sp, kind = created
        if state.session.sp is not None and table_sp != state.session.sp:
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} dynamic table does not belong to current SP", confidence="high")
        if kind == "byte":
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{method} is defined for Opal object tables", confidence="high")
        return None
    if not _is_table_symbol(event.invoking_symbol) or _is_byte_table_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{method} is defined for Opal object tables", confidence="high")
    return None


def _ace_method_refs(event: Event) -> list[str]:
    sources: list[Any] = [event.required, event.optional, _method_raw_args(event)]
    refs: list[str] = []

    def walk(value: Any) -> None:
        if not isinstance(value, (dict, list, tuple, set)):
            text = _as_text(value or "").strip()
            if re.fullmatch(r"ACE_[0-9A-Fa-f]{8}", text) or re.fullmatch(r"ACE_DataStore\d+_(Get|Set)_All", text, flags=re.IGNORECASE):
                symbol = _normalize_name(text)
                if symbol not in refs:
                    refs.append(symbol)
                return
        symbol, _ = _object_ref_from_value(value)
        if symbol.startswith("ACE_") and symbol not in refs:
            refs.append(symbol)
            return
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    for source in sources:
        walk(source)
    return refs


def _row_uids(event: Event) -> list[str]:
    rows: Any = None
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Rows")
        if found:
            rows = value
            break
        found, value = _dict_lookup(source, "Row")
        if found and event.method == "DeleteRow":
            rows = value
            break
    if rows is None:
        rows = _mapping_value(event.required, "UID")
        if rows is None:
            rows = _mapping_value(event.optional, "UID")
    if rows is None:
        return []

    out: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for val in value.values():
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            uid = _uid_ref(value)
            if uid:
                out.append(uid)

    walk(rows)
    return out


def _row_object_refs(event: Event) -> list[tuple[str, str]]:
    rows: Any = None
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Rows")
        if found:
            rows = value
            break
        found, value = _dict_lookup(source, "Row")
        if found:
            rows = value
            break
    if rows is None:
        return []

    values = list(rows) if isinstance(rows, (list, tuple, set)) else [rows]
    refs: list[tuple[str, str]] = []
    for value in values:
        symbol, uid = _object_ref_from_value(value)
        if symbol or uid:
            refs.append((symbol, uid))
    return refs


def _created_locking_range_id(state: State, event: Event) -> int:
    returned = _output_return_values(event.raw)
    candidates: list[tuple[str, str]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for val in value.values():
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            symbol, uid = _object_ref_from_value(value)
            if symbol or uid:
                candidates.append((symbol, uid))

    walk(returned)
    for symbol, uid in candidates:
        if not symbol and uid:
            symbol = _object_by_uid(uid)
        range_id = _range_id_from_symbol(symbol)
        if range_id is not None and range_id != 0:
            return range_id
    non_global = [range_id for range_id in state.ranges if range_id != 0]
    return (max(non_global) + 1) if non_global else 1


def _get_arg_uid(event: Event, *names: str) -> str:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return _uid_arg(value)
    return ""


def _access_control_combo_key(event: Event) -> tuple[str, str] | None:
    found_invoking, invoking_value = _named_method_arg_value(event, "InvokingID", "InvokingId", "Object", "ObjectID", "Table", "TableUID")
    found_method, method_value = _named_method_arg_value(event, "MethodID", "MethodId", "Method")
    if not found_invoking and not found_method:
        return None

    symbol, invoking_uid = _object_ref_from_value(invoking_value) if found_invoking else ("", "")
    method_name = _method_ref_name(method_value)
    if method_name is None:
        return None
    if not symbol and invoking_uid:
        symbol = _object_by_uid(invoking_uid)
    return (symbol or invoking_uid, method_name)


def _event_method_combo_key(event: Event) -> tuple[str, str]:
    return (event.invoking_symbol or event.invoking_uid, event.method)


def _method_combo_deleted(state: State, event: Event) -> bool:
    return _event_method_combo_key(event) in state.deleted_method_associations


def _combo_exists_for_get_acl(state: State, event: Event) -> bool | None:
    combo_key = _access_control_combo_key(event)
    found_invoking, invoking_value = _named_method_arg_value(event, "InvokingID", "InvokingId", "Object", "ObjectID", "Table", "TableUID")
    found_method, method_value = _named_method_arg_value(event, "MethodID", "MethodId", "Method")
    if not found_invoking and not found_method:
        return None

    symbol, invoking_uid = _object_ref_from_value(invoking_value) if found_invoking else ("", "")
    method_name = _method_ref_name(method_value)
    if method_name is None:
        return None
    if combo_key in state.deleted_method_associations:
        return False
    if method_name == "SPTemplatesObj":
        return state.session.sp == "LockingSP" and (symbol.startswith("SPTemplates_") or invoking_uid.startswith("00000003"))
    if method_name == "MethodIDObj":
        return state.session.sp == "LockingSP" and (_method_by_uid(invoking_uid) is not None or _method_ref_name(invoking_value) in set(METHOD_UIDS.values()))
    if not _known_opal_object_symbol(symbol, invoking_uid):
        return False
    if method_name == "Next":
        return _is_next_table_target(symbol, invoking_uid)
    if method_name == "Get":
        return not symbol.startswith("UnknownSP_")
    if method_name == "Set":
        if symbol.startswith("K_AES_") or symbol in {"LockingInfo", "MethodIDTable", "Table_MethodID"}:
            return False
        return not symbol.startswith("UnknownSP_")
    if method_name == "CreateRow":
        return _is_table_symbol(symbol) and symbol not in {"MBR", "DataStore", "MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}
    if method_name == "DeleteRow":
        return _is_table_symbol(symbol) and symbol not in {"MBR", "DataStore", "MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}
    if method_name == "GetFreeSpace":
        return symbol in {"ThisSP", "AdminSP", "LockingSP"} or symbol.startswith("UnknownSP_")
    if method_name == "CreateTable":
        return symbol in {"ThisSP", state.session.sp}
    if method_name == "DeleteSP":
        return symbol in {"ThisSP", state.session.sp}
    if method_name == "GetFreeRows":
        return _is_table_symbol(symbol) and not _is_byte_table_symbol(symbol)
    if method_name in {"AddACE", "RemoveACE", "SetACL"}:
        return symbol in {"AccessControlTable", "Table_AccessControl", "AccessControl"}
    if method_name == "GenKey":
        return _range_id_from_key(symbol) is not None
    if method_name in {"GetPackage", "SetPackage"}:
        return _is_credential_symbol(symbol)
    if method_name == "Erase":
        range_id = _range_id_from_symbol(symbol)
        return range_id is not None and range_id != 0
    if method_name == "Sign":
        return symbol == "TPerSign"
    if method_name == "FirmwareAttestation":
        return symbol == "TperAttestation"
    if method_name == "Activate":
        return symbol == "LockingSP" and state.session.sp == "AdminSP"
    if method_name == "Revert":
        return symbol in {"AdminSP", "ThisSP"} and state.session.sp == "AdminSP"
    if method_name == "RevertSP":
        if state.session.sp == "AdminSP":
            return symbol == "ThisSP"
        return symbol in {"ThisSP", "LockingSP"} and state.session.sp == "LockingSP"
    if method_name in {"Authenticate", "Random", "GetACL", "AddACE", "RemoveACE", "SetACL"}:
        return method_name in SUPPORTED_METHODS_BY_SP.get(state.session.sp or "", set())
    return False




def _matching_range(state: State, lba: tuple[int, int] | None) -> RangeState:
    if lba is None:
        return _range(state, 0)
    start, end = lba
    best: RangeState | None = None
    for range_state in state.ranges.values():
        if range_state.range_id == 0 or range_state.range_length <= 0:
            continue
        r_start = range_state.range_start
        r_end = r_start + range_state.range_length - 1
        if start >= r_start and end <= r_end:
            if best is None or range_state.range_length < best.range_length:
                best = range_state
    return best or _range(state, 0)


def _effective_ranges_for_lba(state: State, lba: tuple[int, int] | None) -> list[RangeState]:
    if lba is None:
        return [_range(state, 0)]
    start, end = lba
    overlaps: list[tuple[int, int, RangeState]] = []
    for range_state in state.ranges.values():
        if range_state.range_id == 0 or range_state.range_length <= 0:
            continue
        r_start = range_state.range_start
        r_end = r_start + range_state.range_length - 1
        if end < r_start or start > r_end:
            continue
        overlaps.append((max(start, r_start), min(end, r_end), range_state))

    if not overlaps:
        return [_range(state, 0)]

    overlaps.sort(key=lambda item: (item[0], item[1], item[2].range_id))
    ranges: list[RangeState] = []
    seen: set[int] = set()
    for _, _, range_state in overlaps:
        if range_state.range_id not in seen:
            ranges.append(range_state)
            seen.add(range_state.range_id)

    cursor = start
    uncovered = False
    for covered_start, covered_end, _ in overlaps:
        if cursor < covered_start:
            uncovered = True
            break
        cursor = max(cursor, covered_end + 1)
        if cursor > end:
            break
    if cursor <= end:
        uncovered = True
    if uncovered:
        global_range = _range(state, 0)
        if global_range.range_id not in seen:
            ranges.append(global_range)
    return ranges


def _range_crossing_error_allowed(state: State, lba: tuple[int, int] | None) -> bool:
    return len(_effective_ranges_for_lba(state, lba)) > 1


def _any_read_locked(state: State, lba: tuple[int, int] | None) -> bool:
    return any(_read_locked(range_state) for range_state in _effective_ranges_for_lba(state, lba))


def _any_write_locked(state: State, lba: tuple[int, int] | None) -> bool:
    return any(_write_locked(range_state) for range_state in _effective_ranges_for_lba(state, lba))


def _read_locked(range_state: RangeState) -> bool:
    return range_state.read_lock_enabled and range_state.read_locked


def _write_locked(range_state: RangeState) -> bool:
    return range_state.write_lock_enabled and range_state.write_locked


def _mbr_shadowing_active(state: State) -> bool:
    return _as_bool(state.mbr.get("Enabled")) and not _as_bool(state.mbr.get("Done"))


def _mbr_shadow_relation(state: State, lba: tuple[int, int] | None) -> str:
    if not _mbr_shadowing_active(state) or lba is None:
        return "none"
    start, end = lba
    start_in = 0 <= start < DEFAULT_MBR_SHADOW_LBA_COUNT
    end_in = 0 <= end < DEFAULT_MBR_SHADOW_LBA_COUNT
    if start_in and end_in:
        return "within"
    if start_in or end_in or start < DEFAULT_MBR_SHADOW_LBA_COUNT <= end:
        return "partial"
    return "outside"


def _remembered_pattern_for_lba(state: State, lba: tuple[int, int] | None) -> tuple[str, int, int] | None:
    if lba is None:
        return None
    exact = state.lba_patterns.get(lba)
    if exact is not None:
        return exact
    start, end = lba
    best: tuple[int, tuple[str, int, int]] | None = None
    for (written_start, written_end), remembered in state.lba_patterns.items():
        if written_start <= start and end <= written_end:
            span = written_end - written_start
            if best is None or span < best[0]:
                best = (span, remembered)
    return best[1] if best is not None else None

__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
