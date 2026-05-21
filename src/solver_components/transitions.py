"""State transitions applied from successful context records."""

from __future__ import annotations

from dataclasses import replace
import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *
from .semantics import *


def _auth_from_authenticate_event(event: Event) -> str | None:
    return (
        event.authority
        or _authority_from_value(_mapping_value(event.required, "Authority"))
        or _authority_from_value(_mapping_value(event.required, "HostSigningAuthority"))
    )


def _apply_start_session_success(state: State, event: Event) -> None:
    authenticated: set[str] = set()
    authority = event.authority or "Anybody"
    authenticated.add(authority)
    if event.challenge and authority != "Anybody":
        state.pins[authority] = _credential_text(event.challenge)
        state.pin_tries[authority] = 0
    if event.sp == "LockingSP":
        state.locking_sp_activated = True
    state.session = Session(
        open=True,
        sp=event.sp,
        write=event.write_session,
        authenticated=authenticated,
    )
    state.pending_deleted_sp = None


def _apply_get_success(state: State, event: Event) -> None:
    symbol = event.invoking_symbol
    returned = _flatten_return_values(_output_return_values(event.raw), symbol)
    owner = _pin_owner_by_object(symbol)

    if owner and MIN_PIN_COLUMN in returned:
        min_pin = _parse_int(returned[MIN_PIN_COLUMN])
        if min_pin is not None:
            state.pin_min_lengths[owner] = min_pin
    if owner and CPIN_TRY_LIMIT_COLUMN in returned:
        try_limit = _parse_int(returned[CPIN_TRY_LIMIT_COLUMN])
        if try_limit is not None:
            state.pin_try_limits[owner] = max(0, try_limit)
            if try_limit == 0:
                state.pin_tries[owner] = 0
    if owner and CPIN_TRIES_COLUMN in returned:
        tries = _parse_int(returned[CPIN_TRIES_COLUMN])
        if tries is not None:
            state.pin_tries[owner] = max(0, tries)
    if owner and CPIN_PERSISTENCE_COLUMN in returned:
        state.pin_persistence[owner] = _as_bool(returned[CPIN_PERSISTENCE_COLUMN])
    if symbol == "C_PIN_MSID" and PIN_COLUMN in returned:
        state.pins["MSID"] = _credential_text(returned[PIN_COLUMN])
        return

    if symbol in {"AdminSP", "LockingSP"}:
        if symbol == "LockingSP" and 6 in returned:
            lifecycle_value = returned[6]
            lifecycle = _parse_int(lifecycle_value)
            if lifecycle is not None:
                state.observed_sp_lifecycle["LockingSP"] = lifecycle
            active = _sp_lifecycle_active(lifecycle_value)
            if active is not None:
                state.locking_sp_activated = active
        if 7 in returned:
            state.sp_frozen[symbol] = _as_bool(returned[7])
        return

    if symbol == "LockingInfo":
        for column, value in returned.items():
            if column in LOCKING_INFO_COLUMNS:
                state.locking_info[LOCKING_INFO_COLUMNS[column]] = value
        return

    if symbol == "TPerInfo" and 8 in returned:
        state.programmatic_reset_enabled = _as_bool(returned[8])
        return

    if symbol == "SPInfo" and 6 in returned and state.session.sp is not None:
        state.sp_enabled[state.session.sp] = _as_bool(returned[6])
        return

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        range_state = _range(state, range_id)
        _update_range_from_columns(range_state, returned)
        return

    if symbol == "MBRControl":
        for column, value in returned.items():
            if column in MBR_COLUMNS:
                state.mbr[MBR_COLUMNS[column]] = value
        return

    authority = _authority_by_object(symbol)
    if authority and 5 in returned:
        state.authority_enabled[authority] = _enabled_bool(returned[5])


def _update_range_from_columns(range_state: RangeState, values: dict[int, Any]) -> None:
    for column, value in values.items():
        field_name = LOCKING_COLUMNS.get(column)
        if field_name is None:
            continue
        if field_name == "RangeStart":
            parsed = _parse_int(value)
            if parsed is not None:
                range_state.range_start = parsed
        elif field_name == "RangeLength":
            parsed = _parse_int(value)
            if parsed is not None:
                range_state.range_length = parsed
        elif field_name == "ReadLockEnabled":
            range_state.read_lock_enabled = _as_bool(value)
        elif field_name == "WriteLockEnabled":
            range_state.write_lock_enabled = _as_bool(value)
        elif field_name == "ReadLocked":
            range_state.read_locked = _as_bool(value)
        elif field_name == "WriteLocked":
            range_state.write_locked = _as_bool(value)
        elif field_name == "LockOnReset":
            range_state.lock_on_reset_types = _reset_types(value)
            range_state.lock_on_reset = bool(range_state.lock_on_reset_types)
        elif field_name == "ActiveKey":
            range_state.active_key = str(value)
        elif field_name == "NextKey":
            range_state.next_key = None if _clean_uid(value) in {"", "0000000000000000"} else str(value)
        elif field_name == "ReEncryptState":
            parsed = _parse_reencrypt_state(value)
            if parsed is not None:
                range_state.reencrypt_state = parsed
        elif field_name == "ReEncryptRequest":
            request = _parse_reencrypt_request(value)
            if request is not None:
                range_state.reencrypt_request = request
                _apply_reencrypt_request_success(range_state, request)
        elif field_name == "AdvKeyMode":
            range_state.adv_key_mode = _parse_int(value)
        elif field_name == "VerifyMode":
            range_state.verify_mode = _parse_int(value)
        elif field_name == "ContOnReset":
            range_state.cont_on_reset = value
        elif field_name == "LastReEncryptLBA":
            range_state.last_reencrypt_lba = _parse_int(value)
        elif field_name == "LastReEncStat":
            range_state.last_reenc_stat = value
        elif field_name == "GeneralStatus":
            range_state.general_status = value


def _apply_reencrypt_request_success(range_state: RangeState, request: int) -> None:
    if request == 1:
        range_state.reencrypt_state = 2
    elif request == 2:
        range_state.active_key = range_state.next_key
        range_state.next_key = None
        range_state.reencrypt_state = 1
    elif request == 3:
        range_state.reencrypt_state = 1
    elif request == 4:
        range_state.reencrypt_state = 2
    elif request == 5:
        range_state.reencrypt_state = 5


def _apply_set_success(state: State, event: Event) -> None:
    event, where_error = _set_effective_event(event)
    if where_error is not None:
        return

    symbol = event.invoking_symbol
    if symbol.startswith("ACE_") and ACE_BOOLEAN_EXPR_COLUMN in event.values:
        expression = _ace_expression_from_value(event.values[ACE_BOOLEAN_EXPR_COLUMN])
        state.ace_expressions[_ace_key(state, symbol)] = expression

        grant = _ace_locking_grant(symbol)
        if grant is not None:
            kind, range_id = grant
            target = state.range_read_lock_users if kind == "read" else state.range_write_lock_users
            target[range_id] = _ace_expression_users(state, symbol)
            return

        datastore_grant = _ace_datastore_grant(symbol)
        if datastore_grant is not None:
            target = state.datastore_read_users if datastore_grant == "read" else state.datastore_write_users
            target.clear()
            target.update(_ace_expression_users(state, symbol))
            return

        return

    grant = _ace_locking_grant(symbol)
    if grant is not None:
        kind, range_id = grant
        users = {auth for auth in _extract_authorities(event.values.get(ACE_BOOLEAN_EXPR_COLUMN, event.raw)) if _is_user(auth)}
        target = state.range_read_lock_users if kind == "read" else state.range_write_lock_users
        target.setdefault(range_id, set()).update(users)
        return

    datastore_grant = _ace_datastore_grant(symbol)
    if datastore_grant is not None:
        users = {auth for auth in _extract_authorities(event.values.get(ACE_BOOLEAN_EXPR_COLUMN, event.raw)) if _is_user(auth)}
        target = state.datastore_read_users if datastore_grant == "read" else state.datastore_write_users
        target.update(users)
        return

    owner = _pin_owner_by_object(symbol)
    if owner and PIN_COLUMN in event.values:
        state.pins[owner] = _credential_text(event.values[PIN_COLUMN])
        state.pin_tries[owner] = 0
        if MIN_PIN_COLUMN in event.values:
            min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
            if min_pin is not None:
                state.pin_min_lengths[owner] = min_pin
    if owner and CPIN_TRY_LIMIT_COLUMN in event.values:
        try_limit = _parse_int(event.values[CPIN_TRY_LIMIT_COLUMN])
        if try_limit is not None:
            state.pin_try_limits[owner] = max(0, try_limit)
            if try_limit == 0:
                state.pin_tries[owner] = 0
    if owner and CPIN_TRIES_COLUMN in event.values:
        tries = _parse_int(event.values[CPIN_TRIES_COLUMN])
        if tries is not None:
            state.pin_tries[owner] = max(0, tries)
    if owner and CPIN_PERSISTENCE_COLUMN in event.values:
        state.pin_persistence[owner] = _as_bool(event.values[CPIN_PERSISTENCE_COLUMN])
    if owner and PIN_COLUMN in event.values:
        return
    if owner and MIN_PIN_COLUMN in event.values:
        min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
        if min_pin is not None:
            state.pin_min_lengths[owner] = min_pin
        return

    authority = _authority_by_object(symbol)
    if authority and 5 in event.values:
        state.authority_enabled[authority] = _as_bool(event.values[5])
        return

    if symbol in {"AdminSP", "LockingSP"} and 7 in event.values:
        state.sp_frozen[symbol] = _as_bool(event.values[7])
        return

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        _update_range_from_columns(_range(state, range_id), event.values)
        return

    if symbol == "MBRControl":
        for column, value in event.values.items():
            if column in MBR_COLUMNS:
                state.mbr[MBR_COLUMNS[column]] = value
        return

    if symbol == "TPerInfo" and 8 in event.values:
        state.programmatic_reset_enabled = _as_bool(event.values[8])
        return

    if symbol == "SPInfo" and 6 in event.values and state.session.sp is not None:
        state.sp_enabled[state.session.sp] = _as_bool(event.values[6])
        return


def _apply_create_row_success(state: State, event: Event) -> None:
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return
    range_id = _created_locking_range_id(state, event)
    range_state = _range(state, range_id)
    _update_range_from_columns(range_state, event.values)


def _remove_range_state(state: State, range_id: int) -> None:
    state.ranges.pop(range_id, None)
    state.range_read_lock_users.pop(range_id, None)
    state.range_write_lock_users.pop(range_id, None)
    state.lba_patterns = {
        lba: remembered
        for lba, remembered in state.lba_patterns.items()
        if remembered[1] != range_id
    }


def _apply_delete_row_success(state: State, event: Event) -> None:
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return
    refs = _row_object_refs(event) or [(_object_by_uid(uid), uid) for uid in _row_uids(event)]
    for symbol, uid in refs:
        range_id = _range_id_from_symbol(symbol) if symbol else _range_id_from_symbol(_object_by_uid(uid))
        if range_id is None or range_id == 0:
            continue
        _remove_range_state(state, range_id)


def _apply_delete_success(state: State, event: Event) -> None:
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is not None and range_id != 0:
        _remove_range_state(state, range_id)


def _apply_delete_method_success(state: State, event: Event) -> None:
    combo_key = _access_control_combo_key(event)
    if combo_key is not None:
        state.deleted_method_associations.add(combo_key)


def _create_table_return_uid(event: Event) -> str:
    returned = _output_return_values(event.raw)

    def walk_uid_key(value: Any) -> str:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
                if key_text in {"UID", "TABLEUID"}:
                    uid = _uid_ref(item)
                    if uid:
                        return uid
                nested = walk_uid_key(item)
                if nested:
                    return nested
        if isinstance(value, (list, tuple, set)):
            for item in value:
                nested = walk_uid_key(item)
                if nested:
                    return nested
        return ""

    uid = walk_uid_key(returned)
    if uid:
        return uid
    if isinstance(returned, (list, tuple)) and returned:
        first = returned[0]
        if not isinstance(first, dict):
            return _uid_ref(first)
    return ""


def _apply_create_table_success(state: State, event: Event) -> None:
    if state.session.sp is None:
        return
    found_name, name_value = _create_table_arg(event, 0, "NewTableName", "Name", "TableName")
    found_common, common_value = _create_table_arg(event, 7, "CommonName")
    found_kind, kind_value = _create_table_arg(event, 1, "Kind", "TableKind")
    if found_name:
        state.created_table_names.add(
            (
                state.session.sp,
                _create_table_name_text(name_value),
                _create_table_name_text(common_value) if found_common else "",
            )
        )
    kind = _create_table_kind(kind_value) if found_kind else None
    uid = _create_table_return_uid(event)
    if uid and kind is not None:
        state.created_tables[uid] = (state.session.sp, kind)


def _apply_erase_success(state: State, event: Event) -> None:
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None or range_id == 0:
        return
    _range(state, range_id).media_generation += 1
    state.pins.pop(f"BandMaster{range_id}", None)
    state.authority_enabled.pop(f"BandMaster{range_id}", None)


def _invalidate_lba_patterns(state: State, keep_global: bool = False) -> None:
    state.lba_patterns = {
        lba: (pattern, range_id, generation if keep_global and range_id == 0 else -1)
        for lba, (pattern, range_id, generation) in state.lba_patterns.items()
    }


def _reset_locking_sp(state: State, keep_global_key: bool = False) -> None:
    global_generation = _range(state, 0).media_generation
    state.locking_sp_activated = False
    state.sp_enabled.pop("LockingSP", None)
    state.sp_frozen.pop("LockingSP", None)
    state.authority_enabled = {k: v for k, v in state.authority_enabled.items() if not k.startswith(("User", "Admin"))}
    state.pins = {k: v for k, v in state.pins.items() if not k.startswith(("User", "Admin"))}
    state.pin_min_lengths = {k: v for k, v in state.pin_min_lengths.items() if not k.startswith(("User", "Admin"))}
    state.pin_try_limits = {k: v for k, v in state.pin_try_limits.items() if not k.startswith(("User", "Admin"))}
    state.pin_tries = {k: v for k, v in state.pin_tries.items() if not k.startswith(("User", "Admin"))}
    state.pin_persistence = {k: v for k, v in state.pin_persistence.items() if not k.startswith(("User", "Admin"))}
    state.ranges = {}
    state.range_read_lock_users.clear()
    state.range_write_lock_users.clear()
    state.datastore_read_users.clear()
    state.datastore_write_users.clear()
    state.ace_expressions.clear()
    state.deleted_method_associations.clear()
    state.created_table_names = {key for key in state.created_table_names if key[0] != "LockingSP"}
    state.created_tables = {uid: info for uid, info in state.created_tables.items() if info[0] != "LockingSP"}
    if keep_global_key:
        _range(state, 0).media_generation = global_generation
    else:
        _range(state, 0).media_generation = global_generation + 1
    _invalidate_lba_patterns(state, keep_global=keep_global_key)


def _complete_delete_sp(state: State, sp: str | None) -> None:
    if sp is None or sp == "AdminSP":
        return
    if sp == "LockingSP":
        _reset_locking_sp(state)
    state.deleted_sps.add(sp)
    state.sp_enabled.pop(sp, None)
    state.sp_frozen.pop(sp, None)


def _reset_factory_state(state: State) -> None:
    msid_pin = state.pins.get("MSID")
    global_generation = _range(state, 0).media_generation
    state.pins.clear()
    state.pin_min_lengths.clear()
    state.pin_try_limits.clear()
    state.pin_tries.clear()
    state.pin_persistence.clear()
    if msid_pin is not None:
        state.pins["MSID"] = msid_pin
        state.pins["SID"] = msid_pin
    state.authority_enabled.clear()
    state.locking_sp_activated = False
    state.observed_sp_lifecycle.clear()
    state.sp_enabled.clear()
    state.sp_frozen.clear()
    state.deleted_sps.clear()
    state.pending_deleted_sp = None
    state.created_table_names.clear()
    state.created_tables.clear()
    state.programmatic_reset_enabled = False
    state.locking_info.clear()
    state.ranges = {}
    state.range_read_lock_users.clear()
    state.range_write_lock_users.clear()
    state.datastore_read_users.clear()
    state.datastore_write_users.clear()
    state.ace_expressions.clear()
    state.deleted_method_associations.clear()
    state.mbr.clear()
    _range(state, 0).media_generation = global_generation + 1
    _invalidate_lba_patterns(state)


def _apply_reset_event(state: State, reset_type: int) -> None:
    state.session = Session()
    state.pending_deleted_sp = None
    if reset_type == PROTOCOL_STACK_RESET:
        return
    if reset_type == 0:
        for authority, persistent in list(state.pin_persistence.items()):
            if not persistent:
                state.pin_tries[authority] = 0
    for range_state in state.ranges.values():
        if reset_type in range_state.lock_on_reset_types:
            if range_state.read_lock_enabled:
                range_state.read_locked = True
            if range_state.write_lock_enabled:
                range_state.write_locked = True
    if reset_type in _reset_types(state.mbr.get("DoneOnReset")):
        state.mbr["Done"] = 0


def apply_transition(state: State, event: Event) -> None:
    if event.kind == "host_io" and event.method == "msid" and event.is_success:
        msid = _output_return_values(event.raw)
        if msid is not None and msid is not False:
            credential = _credential_text(msid)
            if credential:
                state.pins["MSID"] = credential
                state.pins.setdefault("SID", credential)
        return

    reset_type = _reset_event_type(event.method)
    if event.kind == "host_io" and event.is_success and reset_type is not None:
        if reset_type == 3 and not state.programmatic_reset_enabled:
            return
        _apply_reset_event(state, reset_type)
        return

    if event.implicit_session and not state.session.open and event.kind == "tcg_method":
        saved_session = state.session
        state.session = _implicit_session_for_event(state, event, assume_authenticated=event.is_success)
        try:
            apply_transition(state, replace(event, implicit_session=False))
        finally:
            state.session = saved_session
        return

    if event.method in {"EndSession", "CloseSession"} and event.is_success:
        if state.pending_deleted_sp == state.session.sp:
            _complete_delete_sp(state, state.pending_deleted_sp)
        state.pending_deleted_sp = None
        state.session = Session()
        return

    if event.method == "StartSession" and event.is_success:
        _apply_start_session_success(state, event)
        return

    if event.method in {"StartTrustedSession", "StartTlsSession"} and event.is_success:
        return

    if not event.is_success:
        if event.status == NOT_AUTHORIZED:
            authority = event.authority if event.method == "StartSession" else _auth_from_authenticate_event(event)
            if authority and authority not in {"Anybody", "Admins", "Users"}:
                try_limit = state.pin_try_limits.get(authority, 0)
                if try_limit > 0:
                    state.pin_tries[authority] = min(try_limit, state.pin_tries.get(authority, 0) + 1)
        return

    if event.method == "Authenticate":
        authority = _auth_from_authenticate_event(event)
        authenticated = _return_bool(event.raw)
        if authenticated is False:
            if authority and authority not in {"Anybody", "Admins", "Users"}:
                try_limit = state.pin_try_limits.get(authority, 0)
                if try_limit > 0:
                    state.pin_tries[authority] = min(try_limit, state.pin_tries.get(authority, 0) + 1)
            return
        if authority:
            state.session.authenticated.add(authority)
            state.pin_tries[authority] = 0
            challenge = (
                event.challenge
                or _mapping_value(event.optional, "Challenge")
                or _mapping_value(event.required, "Challenge")
                or _mapping_value(event.required, "HostChallenge")
            )
            if challenge and authority != "Anybody":
                state.pins[authority] = _credential_text(challenge)
        return

    if event.method == "Get":
        _apply_get_success(state, event)
        return

    if event.method == "Set":
        state.session.write = True
        _apply_set_success(state, event)
        return

    if event.method == "CreateTable":
        state.session.write = True
        _apply_create_table_success(state, event)
        return

    if event.method == "CreateRow":
        state.session.write = True
        _apply_create_row_success(state, event)
        return

    if event.method == "DeleteRow":
        state.session.write = True
        _apply_delete_row_success(state, event)
        return

    if event.method == "Delete":
        state.session.write = True
        _apply_delete_success(state, event)
        return

    if event.method == "DeleteSP":
        state.session.write = True
        state.pending_deleted_sp = state.session.sp
        return

    if event.method == "DeleteMethod":
        state.session.write = True
        _apply_delete_method_success(state, event)
        return

    if event.method == "SetPackage":
        state.session.write = True
        owner = _pin_owner_by_object(event.invoking_symbol)
        if owner:
            state.pins.pop(owner, None)
            state.pin_tries[owner] = 0
            return
        range_id = _range_id_from_key(event.invoking_symbol)
        if range_id is not None:
            _range(state, range_id).media_generation += 1
        return

    if event.method == "Activate" and event.invoking_symbol == "LockingSP":
        state.session.write = True
        state.locking_sp_activated = True
        if "SID" in state.pins:
            state.pins["Admin1"] = state.pins["SID"]
        elif "MSID" in state.pins and "Admin1" not in state.pins:
            state.pins["Admin1"] = state.pins["MSID"]
        return

    if event.method == "GenKey":
        owner = _pin_owner_by_object(event.invoking_symbol)
        if owner:
            state.pins.pop(owner, None)
            state.pin_tries[owner] = 0
            return
        range_id = _range_id_from_key(event.invoking_symbol)
        if range_id is not None:
            _range(state, range_id).media_generation += 1
        return

    if event.method == "Erase":
        state.session.write = True
        _apply_erase_success(state, event)
        return

    if event.method in {"Revert", "RevertSP"}:
        state.session.write = True
        if (
            (event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP")
            or (event.method == "Revert" and state.session.sp == "AdminSP" and event.invoking_symbol in {"AdminSP", "ThisSP"})
        ):
            _reset_factory_state(state)
        elif state.session.sp == "LockingSP" or event.invoking_symbol == "LockingSP":
            keep = _keep_global_range_key(event)
            _reset_locking_sp(state, keep_global_key=keep)
        else:
            sid_pin = state.pins.get("SID")
            msid_pin = state.pins.get("MSID")
            state.pins.clear()
            state.pin_min_lengths.clear()
            state.pin_try_limits.clear()
            state.pin_tries.clear()
            state.pin_persistence.clear()
            if msid_pin is not None:
                state.pins["MSID"] = msid_pin
            if sid_pin is not None:
                state.pins["SID"] = sid_pin
        state.session = Session()
        return

    if event.kind == "host_io" and event.method == "Write" and event.lba is not None and event.pattern is not None:
        range_state = _matching_range(state, event.lba)
        if _mbr_shadow_relation(state, event.lba) not in {"within", "partial"} and not _write_locked(range_state):
            state.lba_patterns[event.lba] = (event.pattern, range_state.range_id, range_state.media_generation)




__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
