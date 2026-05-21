import re
from dataclasses import dataclass, field
from typing import Any


SUCCESS = "SUCCESS"


FIXED_AUTH_BY_UID = {
    "0000000900000001": "Anybody",
    "0000000900000002": "Admins",
    "0000000900000006": "SID",
    "0000000900030000": "Users",
}

FIXED_SP_BY_UID = {
    "0000020500000001": "AdminSP",
    "0000020500000002": "LockingSP",
    # TCGstorageAPI traces may use this LockingSP object-form alias.
    "0000020500010001": "LockingSP",
}

FIXED_OBJECT_BY_UID = {
    "0000000B00008402": "C_PIN_MSID",
    "0000000B00000001": "C_PIN_SID",
    "0000020500000001": "AdminSP",
    "0000020500000002": "LockingSP",
    "0000080100000000": "LockingInfo",
    "0000080100000001": "LockingInfo",
    "0000080200000001": "Locking_GlobalRange",
    "0000080300000001": "MBRControl",
    "0000080500000001": "K_AES_128_GlobalRange_Key",
    "0000080600000001": "K_AES_256_GlobalRange_Key",
}

# Copied from Seagate TCGstorageAPI/TCGstorageAPI/tcgSupport.py semantics:
# tokens_table maps high-level operation fields to TCG table columns.
LOCKING_COLUMNS = {
    3: "RangeStart",
    4: "RangeLength",
    5: "ReadLockEnabled",
    6: "WriteLockEnabled",
    7: "ReadLocked",
    8: "WriteLocked",
    9: "LockOnReset",
    10: "ActiveKey",
}

MBR_COLUMNS = {
    1: "Enabled",
    2: "Done",
}


@dataclass
class Event:
    raw: dict[str, Any]
    method: str
    invoking_name: str = ""
    invoking_uid: str = ""
    invoking_symbol: str = ""
    status: str | None = None
    required: dict[str, Any] = field(default_factory=dict)
    optional: dict[str, Any] = field(default_factory=dict)
    values: dict[int, Any] = field(default_factory=dict)
    sp: str | None = None
    authority: str | None = None
    challenge: str | None = None
    write_session: bool = False
    lba: tuple[int, int] | None = None
    pattern: str | None = None
    read_result: str | None = None

    @property
    def is_success(self) -> bool:
        if self.method in {"Read", "Write"}:
            return self.status in {None, SUCCESS, "PASS"}
        return self.status == SUCCESS


@dataclass
class Session:
    open: bool = False
    sp: str | None = None
    write: bool = False
    authenticated: set[str] = field(default_factory=set)


@dataclass
class State:
    session: Session = field(default_factory=Session)
    pins: dict[str, str] = field(default_factory=dict)
    authority_enabled: dict[str, bool] = field(default_factory=dict)
    locking_sp_activated: bool = False
    observed_sp_lifecycle: int | None = None
    locking: dict[str, Any] = field(default_factory=dict)
    mbr: dict[str, Any] = field(default_factory=dict)
    media_generation: int = 0
    lba_patterns: dict[tuple[int, int], tuple[str, int]] = field(default_factory=dict)


def _clean_uid(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper().zfill(16)


def _uid_suffix_index(uid: str, prefix: str) -> int | None:
    if not uid.startswith(prefix) or len(uid) <= len(prefix):
        return None
    suffix = uid[len(prefix):]
    if not re.fullmatch(r"[0-9A-F]+", suffix):
        return None
    value = int(suffix, 16)
    return value or None


def _authority_by_uid(uid: str) -> str | None:
    if not uid:
        return None
    if uid in FIXED_AUTH_BY_UID:
        return FIXED_AUTH_BY_UID[uid]

    admin_index = _uid_suffix_index(uid, "000000090001")
    if admin_index is not None:
        return f"Admin{admin_index}"

    admin_sp_index = _uid_suffix_index(uid, "00000009000002")
    if admin_sp_index is not None:
        return f"Admin{admin_sp_index}"

    user_index = _uid_suffix_index(uid, "000000090003")
    if user_index is not None:
        return f"User{user_index}"

    return None


def _sp_by_uid(uid: str) -> str | None:
    return FIXED_SP_BY_UID.get(uid)


def _object_by_uid(uid: str, fallback_name: str = "") -> str:
    if not uid:
        return fallback_name
    if uid in FIXED_OBJECT_BY_UID:
        return FIXED_OBJECT_BY_UID[uid]

    authority = _authority_by_uid(uid)
    if authority is not None:
        return f"Authority_{authority}"

    admin_pin_index = _uid_suffix_index(uid, "0000000B0001")
    if admin_pin_index is not None:
        return f"C_PIN_Admin{admin_pin_index}"

    admin_sp_pin_index = _uid_suffix_index(uid, "0000000B000002")
    if admin_sp_pin_index is not None:
        return f"C_PIN_Admin{admin_sp_pin_index}"

    user_pin_index = _uid_suffix_index(uid, "0000000B0003")
    if user_pin_index is not None:
        return f"C_PIN_User{user_pin_index}"

    locking_range_index = _uid_suffix_index(uid, "000008020003")
    if locking_range_index is not None:
        return f"Locking_Range{locking_range_index}"

    key_128_index = _uid_suffix_index(uid, "000008050003")
    if key_128_index is not None:
        return f"K_AES_128_Range{key_128_index}_Key"

    key_256_index = _uid_suffix_index(uid, "000008060003")
    if key_256_index is not None:
        return f"K_AES_256_Range{key_256_index}_Key"

    return fallback_name


def _pin_owner_by_object(symbol: str) -> str | None:
    if symbol == "C_PIN_SID":
        return "SID"
    match = re.fullmatch(r"C_PIN_(Admin|User)(\d+)", symbol)
    if match:
        return f"{match.group(1)}{int(match.group(2))}"
    return None


def _normalize_status(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    key = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    aliases = {
        "SUCCESS": SUCCESS,
        "PASS": "PASS",
        "FAIL": "FAIL",
        "NOTAUTHORIZED": "NOT_AUTHORIZED",
        "INVALIDPARAMETER": "INVALID_PARAMETER",
    }
    return aliases.get(key, key)


def _method_args(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    args = ((raw.get("input") or {}).get("method") or {}).get("args")
    if isinstance(args, dict):
        return dict(args.get("required") or {}), dict(args.get("optional") or {})
    return {}, {}


def _values(optional: dict[str, Any]) -> dict[int, Any]:
    values = optional.get("Values") or []
    if isinstance(values, dict):
        values = [values]
    decoded: dict[int, Any] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            try:
                decoded[int(str(key), 16)] = value
            except ValueError:
                try:
                    decoded[int(str(key))] = value
                except ValueError:
                    pass
    return decoded


def _flatten_return_values(value: Any) -> dict[int, Any]:
    out: dict[int, Any] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                try:
                    out[int(str(key), 16)] = val
                except ValueError:
                    try:
                        out[int(str(key))] = val
                    except ValueError:
                        pass
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return out


def _parse_lba(text: Any) -> tuple[int, int] | None:
    if text is None:
        return None
    nums = [int(x) for x in re.findall(r"\d+", str(text))]
    if not nums:
        return None
    if len(nums) == 1:
        return nums[0], nums[0]
    return nums[0], nums[1]


def _extract_pattern(text: Any) -> str | None:
    if text is None:
        return None
    value = str(text).strip()
    match = re.search(r"Pattern\s+([0-9A-Fa-f]+)", value)
    if match:
        return match.group(1).upper()
    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        return value.upper()
    return None


def parse_event(raw: dict[str, Any]) -> Event:
    inp = raw.get("input") or {}
    out = raw.get("output") or {}
    method_info = inp.get("method") or {}

    if "command" in inp:
        method = str(inp.get("command"))
        args = inp.get("args") or {}
        output_args = out.get("args") or {}
        result = out.get("result") or output_args.get("result")
        return Event(
            raw=raw,
            method=method,
            status=_normalize_status(out.get("status_codes") or out.get("result")),
            lba=_parse_lba(args.get("LBA")),
            pattern=_extract_pattern(args.get("pattern")),
            read_result=_extract_pattern(result),
        )

    required, optional = _method_args(raw)
    invoking = inp.get("invoking_id") or {}
    invoking_uid = _clean_uid(invoking.get("uid"))
    invoking_name = invoking.get("name") or ""
    invoking_symbol = _object_by_uid(invoking_uid, invoking_name)
    spid = _clean_uid(required.get("SPID"))
    auth_uid = _clean_uid(optional.get("HostSigningAuthority"))

    return Event(
        raw=raw,
        method=method_info.get("name") or "UNKNOWN",
        invoking_name=invoking_name,
        invoking_uid=invoking_uid,
        invoking_symbol=invoking_symbol,
        status=_normalize_status(out.get("status_codes") or inp.get("status_codes")),
        required=required,
        optional=optional,
        values=_values(optional),
        sp=_sp_by_uid(spid),
        authority=_authority_by_uid(auth_uid),
        challenge=optional.get("HostChallenge"),
        write_session=bool(required.get("Write")),
    )


def _has_admin_authority(state: State) -> bool:
    return any(auth == "SID" or auth.startswith("Admin") for auth in state.session.authenticated)


def _expected_start_session(state: State, event: Event) -> str:
    if event.sp == "LockingSP" and not state.locking_sp_activated:
        return "NOT_AUTHORIZED"
    if event.authority is None or event.authority == "Anybody":
        return SUCCESS
    known_pin = state.pins.get(event.authority)
    if known_pin is not None and event.challenge != known_pin:
        return "NOT_AUTHORIZED"
    return SUCCESS


def _expected_get(state: State, event: Event) -> str:
    if not state.session.open:
        return "NOT_AUTHORIZED"
    # The traces use TCGstorageAPI's Get flow for MSID, Locking, MBRControl,
    # LockingInfo, and SP lifecycle columns. These are readable in the active
    # session once the expected SP/authentication context has been established.
    return SUCCESS


def _expected_set(state: State, event: Event) -> str:
    if not state.session.open or not state.session.write:
        return "NOT_AUTHORIZED"
    if event.invoking_symbol.startswith("C_PIN_"):
        if event.invoking_symbol == "C_PIN_SID":
            return SUCCESS if "SID" in state.session.authenticated else "NOT_AUTHORIZED"
        return SUCCESS if _has_admin_authority(state) else "NOT_AUTHORIZED"
    if event.invoking_symbol.startswith(("Authority_", "Locking_", "MBRControl")):
        return SUCCESS if _has_admin_authority(state) else "NOT_AUTHORIZED"
    return SUCCESS if _has_admin_authority(state) else "NOT_AUTHORIZED"


def _expected_activate(state: State, event: Event) -> str:
    if not state.session.open or not state.session.write or "SID" not in state.session.authenticated:
        return "NOT_AUTHORIZED"
    # Opal Activate is a lifecycle transition, not an idempotent operation.
    # Public traces expose column 6 of the SP object immediately before Activate;
    # value 8 marks a state where returning SUCCESS to Activate is non-compliant.
    if state.observed_sp_lifecycle == 8:
        return "INVALID_PARAMETER"
    return SUCCESS


def expected_status(state: State, event: Event) -> str | None:
    if event.method == "Properties":
        return SUCCESS
    if event.method == "StartSession":
        return _expected_start_session(state, event)
    if event.method == "Get":
        return _expected_get(state, event)
    if event.method == "Set":
        return _expected_set(state, event)
    if event.method == "Activate":
        return _expected_activate(state, event)
    if event.method == "GenKey":
        return SUCCESS if state.session.open and _has_admin_authority(state) else "NOT_AUTHORIZED"
    if event.method in {"EndSession", "CloseSession", "SyncSession"}:
        return SUCCESS
    return None


def _actual_read_is_valid(state: State, event: Event) -> bool:
    if event.method != "Read" or event.lba is None:
        return True
    remembered = state.lba_patterns.get(event.lba)
    if remembered is None:
        return True
    old_pattern, generation = remembered
    if generation != state.media_generation:
        return event.read_result != old_pattern
    return event.read_result == old_pattern


def judge_target(state: State, event: Event) -> str:
    if event.method == "Read":
        return "pass" if _actual_read_is_valid(state, event) else "fail"
    if event.method == "Write":
        return "pass"

    expected = expected_status(state, event)
    if expected is None:
        return "pass" if event.status in {SUCCESS, None, "PASS"} else "fail"
    return "pass" if event.status == expected else "fail"


def apply_transition(state: State, event: Event) -> None:
    if event.method in {"EndSession", "CloseSession"} and event.is_success:
        state.session = Session()
        return

    if event.method == "StartSession" and event.is_success:
        authenticated = set()
        if event.authority:
            authenticated.add(event.authority)
            if event.challenge and event.authority != "Anybody":
                state.pins.setdefault(event.authority, event.challenge)
        else:
            authenticated.add("Anybody")
        state.session = Session(
            open=True,
            sp=event.sp,
            write=event.write_session,
            authenticated=authenticated,
        )
        return

    if not event.is_success:
        return

    if event.method == "Get":
        returned = _flatten_return_values((event.raw.get("output") or {}).get("return_values"))
        if event.invoking_symbol == "C_PIN_MSID" and 3 in returned:
            state.pins.setdefault("MSID", str(returned[3]))
        elif event.invoking_symbol == "LockingSP" and 6 in returned:
            try:
                state.observed_sp_lifecycle = int(returned[6])
            except (TypeError, ValueError):
                pass
        elif event.invoking_symbol.startswith("Locking_"):
            for column, value in returned.items():
                if column in LOCKING_COLUMNS:
                    state.locking[LOCKING_COLUMNS[column]] = value
        elif event.invoking_symbol == "MBRControl":
            for column, value in returned.items():
                if column in MBR_COLUMNS:
                    state.mbr[MBR_COLUMNS[column]] = value
        return

    if event.method == "Set":
        if event.invoking_symbol.startswith("C_PIN_") and 3 in event.values:
            owner = _pin_owner_by_object(event.invoking_symbol)
            if owner:
                state.pins[owner] = str(event.values[3])
        elif event.invoking_symbol.startswith("Authority_") and 5 in event.values:
            state.authority_enabled[event.invoking_symbol.removeprefix("Authority_")] = bool(event.values[5])
        elif event.invoking_symbol.startswith("Locking_"):
            for column, value in event.values.items():
                if column in LOCKING_COLUMNS:
                    state.locking[LOCKING_COLUMNS[column]] = value
        elif event.invoking_symbol == "MBRControl":
            for column, value in event.values.items():
                if column in MBR_COLUMNS:
                    state.mbr[MBR_COLUMNS[column]] = value
        return

    if event.method == "Activate":
        state.locking_sp_activated = True
        if "SID" in state.pins:
            state.pins["Admin1"] = state.pins["SID"]
        return

    if event.method == "GenKey":
        state.media_generation += 1
        return

    if event.method == "Write" and event.lba is not None and event.pattern is not None:
        state.lba_patterns[event.lba] = (event.pattern, state.media_generation)


def predict_trajectory(trajectory: list[dict[str, Any]]) -> str:
    if not trajectory:
        return "FAIL"
    state = State()
    for raw in trajectory[:-1]:
        apply_transition(state, parse_event(raw))
    return judge_target(state, parse_event(trajectory[-1])).upper()


class Solver:
    def predict(self, dataset):
        return {item["id"]: self.predict_one(item["steps"]) for item in dataset}

    def predict_one(self, steps):
        return predict_trajectory(steps).lower()
