import re
from dataclasses import dataclass, field
from typing import Any


SUCCESS = "SUCCESS"
NOT_AUTHORIZED = "NOT_AUTHORIZED"
INVALID_PARAMETER = "INVALID_PARAMETER"
INSUFFICIENT_SPACE = "INSUFFICIENT_SPACE"
INSUFFICIENT_ROWS = "INSUFFICIENT_ROWS"
FAIL = "FAIL"


# Offline copies of the Seagate TCGstorageAPI Opal UID/column semantics used by
# tcgapi.py, tcgSupport.py, and pysedSupport.py.  The live transport layer is
# intentionally not imported; evaluation only has recorded command/response logs.
METHOD_UIDS = {
    "0000000600000002": "CreateTable",
    "0000000600000003": "Delete",
    "0000000600000004": "CreateRow",
    "0000000600000005": "DeleteRow",
    "0000000600000006": "Get",
    "0000000600000007": "Set",
    "0000000600000008": "Next",
    "0000000600000009": "GetFreeSpace",
    "000000060000000A": "GetFreeRows",
    "000000060000000B": "DeleteMethod",
    "000000060000000C": "Authenticate",
    "000000060000000D": "GetACL",
    "000000060000000E": "AddACE",
    "000000060000000F": "RemoveACE",
    "0000000600000010": "GenKey",
    "0000000600000011": "RevertSP",
    "0000000600000016": "Get",          # Opalv2 override in pysedSupport.py
    "0000000600000017": "Set",          # Opalv2 override in pysedSupport.py
    "000000060000001C": "Authenticate", # Opalv2 override in pysedSupport.py
    "0000000600000202": "Revert",
    "0000000600000203": "Activate",
    "0000000600000601": "Random",
    "000000060000060F": "Sign",
    "0000000600000803": "Erase",
    "00000006FFFF000B": "FirmwareAttestation",
}

FIXED_AUTH_BY_UID = {
    "0000000900000001": "Anybody",
    "0000000900000002": "Admins",
    "0000000900000003": "Makers",
    "0000000900000006": "SID",
    "0000000900000007": "TPerSign",
    "0000000900008401": "EraseMaster",
    "0000000900010001": "Admin1",
    "000000090001FF01": "PSID",
    "000000090001FF05": "TperAttestation",
    "0000000900030000": "Users",
}

FIXED_SP_BY_UID = {
    "0000020500000001": "AdminSP",
    "0000020500000002": "LockingSP",
    "0000020500010001": "LockingSP",
}

FIXED_OBJECT_BY_UID = {
    "0000000000000001": "ThisSP",
    "00000000000000FF": "SessionManager",
    "0000000100000001": "Table",
    "0000000100000002": "Table_SPInfo",
    "0000000100000003": "Table_SPTemplates",
    "0000000100000006": "Table_MethodID",
    "0000000100000007": "Table_AccessControl",
    "0000000100000008": "Table_ACE",
    "0000000100000009": "Table_Authority",
    "000000010000000B": "Table_C_PIN",
    "000000010000001D": "Table_SecretProtect",
    "0000000100000205": "Table_SP",
    "0000000100000801": "Table_LockingInfo",
    "0000000100000802": "Table_Locking",
    "0000000100000803": "Table_MBRControl",
    "0000000100000804": "Table_MBR",
    "0000000100000805": "Table_K_AES_128",
    "0000000100000806": "Table_K_AES_256",
    "0000000100001001": "Table_DataStore",
    "0000000100001101": "Table_DataRemovalMechanism",
    "0000020500000001": "AdminSP",
    "0000020500000002": "LockingSP",
    "0000020500010001": "LockingSP",
    "0000000B00008402": "C_PIN_MSID",
    "0000000B00000001": "C_PIN_SID",
    "0000000B00008401": "C_PIN_EraseMaster",
    "0000000200000001": "SPInfo",
    "0000000300000001": "SPTemplates_Base",
    "0000000300000002": "SPTemplates_Admin",
    "0000000600000000": "MethodIDTable",
    "0000000700000000": "AccessControlTable",
    "0000000800000000": "ACETable",
    "0000000900000000": "AuthorityTable",
    "0000000900000007": "TPerSign",
    "000000090001FF05": "TperAttestation",
    "0000000B00000000": "C_PINTable",
    "0000001D00000000": "SecretProtectTable",
    "0000110100000001": "DataRemovalMechanism",
    "0001000400000000": "_CertData_TPerSign",
    "0001001F00000000": "_CertData_TPerAttestation",
    "0000080100000000": "LockingInfo",
    "0000080100000001": "LockingInfo",
    "0000080200000000": "LockingTable",
    "0000080200000001": "Locking_GlobalRange",
    "0000080300000001": "MBRControl",
    "0000080400000000": "MBR",
    "0000080500000000": "K_AES_128Table",
    "0000080500000001": "K_AES_128_GlobalRange_Key",
    "0000080600000000": "K_AES_256Table",
    "0000080600000001": "K_AES_256_GlobalRange_Key",
    "0000100100000000": "DataStore",
    "0000800100000000": "DataStore",
}

SUPPORTED_METHODS_BY_SP = {
    "AdminSP": {"Next", "GetACL", "Get", "Set", "CreateRow", "DeleteRow", "Authenticate", "Revert", "RevertSP", "Activate", "Random", "Sign", "FirmwareAttestation"},
    "LockingSP": {"Next", "GetACL", "GenKey", "RevertSP", "Get", "Set", "CreateRow", "DeleteRow", "Authenticate", "Random"},
}

UNSUPPORTED_OPAL_METHODS = {
    "CreateTable",
    "DeleteSP",
    "Delete",
    "GetFreeSpace",
    "GetFreeRows",
    "DeleteMethod",
    "AddACE",
    "RemoveACE",
    "SetACL",
    "Erase",
}

# tcgSupport.tokens_table / locking_table / c_tls_psk_table.
PIN_COLUMN = 3
MIN_PIN_COLUMN = 0xFFFF0001
AUTHORITY_COLUMNS = {5: "Enabled"}
LOCKING_COLUMNS = {
    3: "RangeStart",
    4: "RangeLength",
    5: "ReadLockEnabled",
    6: "WriteLockEnabled",
    7: "ReadLocked",
    8: "WriteLocked",
    9: "LockOnReset",
    10: "ActiveKey",
    11: "NextKey",
    12: "ReEncryptState",
    13: "ReEncryptRequest",
    14: "AdvKeyMode",
    15: "VerifyMode",
    16: "ContOnReset",
    17: "LastReEncryptLBA",
    18: "LastReEncStat",
    19: "GeneralStatus",
}
MBR_COLUMNS = {
    1: "Enabled",
    2: "Done",
    3: "DoneOnReset",
}
DEFAULT_MBR_SHADOW_LBA_COUNT = 0x08000000 // 512
LOCKING_INFO_COLUMNS = {
    4: "MaxRanges",
    7: "AlignmentRequired",
    8: "LogicalBlockSize",
    9: "AlignmentGranularity",
    10: "LowestAlignedLBA",
}
PORT_COLUMNS = {
    2: "LockOnReset",
    3: "PortLocked",
}
TLS_PSK_COLUMNS = {
    3: "Enabled",
    4: "PSK",
    5: "CipherSuite",
}
ACE_BOOLEAN_EXPR_COLUMN = 3
ACE_COLUMNS_COLUMN = 4


def _clean_uid(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "0000000000000001" if value else "0000000000000000"
    if isinstance(value, int):
        return f"{value & ((1 << 64) - 1):016X}"
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            decoded = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            decoded = ""
        if decoded and re.fullmatch(r"(?:0x)?[0-9A-Fa-f\s:_-]+", decoded):
            cleaned = re.sub(r"[^0-9A-Fa-f]", "", decoded).upper()
            if cleaned:
                return cleaned.zfill(16)[-16:]
        return raw.hex().upper().zfill(16)[-16:]
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()
    if not cleaned:
        return ""
    return cleaned.zfill(16)[-16:]


def _as_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return str(value)
    return str(value)


def _credential_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("plainText", "PlainText", "plaintext", "PIN", "pin", "HostChallenge", "Challenge", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                return _credential_text(item)
        if len(value) == 1:
            return _credential_text(next(iter(value.values())))
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _credential_text(value[0])
    return _as_text(value)


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
    if admin_index is not None and uid != "000000090001FF01":
        return f"Admin{admin_index}"

    admin_sp_index = _uid_suffix_index(uid, "00000009000002")
    if admin_sp_index is not None:
        return f"Admin{admin_sp_index}"

    user_index = _uid_suffix_index(uid, "000000090003")
    if user_index is not None:
        return f"User{user_index}"

    band_master_index = _uid_suffix_index(uid, "00000009000080")
    if band_master_index is not None:
        return f"BandMaster{band_master_index}"

    return None


def _sp_by_uid(uid: str) -> str | None:
    return FIXED_SP_BY_UID.get(uid)


def _sp_by_name(value: Any) -> str | None:
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if text in {"ADMINSP", "ADMIN"}:
        return "AdminSP"
    if text in {"LOCKINGSP", "LOCKING"}:
        return "LockingSP"
    return None


def _sp_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("uid", "UID", "spid", "SPID"):
            sp = _sp_by_uid(_clean_uid(_mapping_value(value, key)))
            if sp is not None:
                return sp
        for key in ("name", "Name"):
            sp = _sp_by_name(_mapping_value(value, key))
            if sp is not None:
                return sp
        for item in value.values():
            sp = _sp_from_value(item)
            if sp is not None:
                return sp
        return None
    if isinstance(value, (list, tuple, set)):
        for item in value:
            sp = _sp_from_value(item)
            if sp is not None:
                return sp
        return None
    return _sp_by_uid(_clean_uid(value)) or _sp_by_name(value)


def _authority_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("uid", "UID", "authority", "Authority", "HostSigningAuthority"):
            authority = _authority_by_uid(_clean_uid(_mapping_value(value, key)))
            if authority is not None:
                return authority
        for key in ("name", "Name"):
            authority = _authority_by_name(_mapping_value(value, key))
            if authority is not None:
                return authority
        for item in value.values():
            authority = _authority_from_value(item)
            if authority is not None:
                return authority
        return None
    if isinstance(value, (list, tuple, set)):
        for item in value:
            authority = _authority_from_value(item)
            if authority is not None:
                return authority
        return None
    return _authority_by_uid(_clean_uid(value)) or _authority_by_name(value)


def _method_by_uid(uid: str) -> str | None:
    return METHOD_UIDS.get(uid)


def _object_by_uid(uid: str, fallback_name: str = "") -> str:
    if not uid:
        return _normalize_name(fallback_name)
    if uid in FIXED_OBJECT_BY_UID:
        return FIXED_OBJECT_BY_UID[uid]
    normalized = _normalize_name(fallback_name)

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

    band_master_pin_index = _uid_suffix_index(uid, "0000000B000080")
    if band_master_pin_index is not None:
        return f"C_PIN_BandMaster{band_master_pin_index}"

    locking_range_index = _uid_suffix_index(uid, "000008020003")
    if locking_range_index is not None:
        return f"Locking_Range{locking_range_index}"

    key_128_index = _uid_suffix_index(uid, "000008050003")
    if key_128_index is not None:
        return f"K_AES_128_Range{key_128_index}_Key"

    key_256_index = _uid_suffix_index(uid, "000008060003")
    if key_256_index is not None:
        return f"K_AES_256_Range{key_256_index}_Key"

    data_store_index = _uid_suffix_index(uid, "000010010000")
    if data_store_index is not None:
        return f"DataStore{data_store_index}"

    data_store_index = _uid_suffix_index(uid, "000080010000")
    if data_store_index is not None:
        return f"DataStore{data_store_index}"

    tls_psk_index = _uid_suffix_index(uid, "0000001E000000")
    if tls_psk_index is not None:
        return f"TLS_PSK_Key{tls_psk_index - 1}"

    port_index = _uid_suffix_index(uid, "000100020001")
    if port_index is not None:
        return f"Port{port_index}"

    ace_index = _uid_suffix_index(uid, "0000000800")
    if ace_index is not None:
        if normalized.startswith("ACE_DataStore"):
            return normalized
        return f"ACE_{uid[-8:]}"

    if normalized == "SP":
        return f"UnknownSP_{uid}"
    return normalized


def _normalize_name(name: Any) -> str:
    text = _as_text(name or "").strip()
    if not text:
        return ""
    compact = text.replace(" ", "")
    match = re.fullmatch(r"Band(\d+)", compact, flags=re.IGNORECASE)
    if match:
        range_id = int(match.group(1))
        return "Locking_GlobalRange" if range_id == 0 else f"Locking_Range{range_id}"
    match = re.fullmatch(r"ACE_Locking_Range(\d+)_Set_RdLocked", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_0003{0xE000 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACE_Locking_Range(\d+)_Set_WrLocked", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_0003{0xE800 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACE_DataStore(\d+)_(Get|Set)_All", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_DataStore{int(match.group(1))}_{match.group(2).title()}_All"
    match = re.fullmatch(r"K_AES_(128|256)_Range(\d+)_Key(?:_UID)?", compact, flags=re.IGNORECASE)
    if match:
        return f"K_AES_{match.group(1)}_Range{int(match.group(2))}_Key"
    match = re.fullmatch(r"K_AES_(128|256)_GlobalRange_Key(?:_UID)?", compact, flags=re.IGNORECASE)
    if match:
        return f"K_AES_{match.group(1)}_GlobalRange_Key"
    match = re.fullmatch(r"Port(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"Port{int(match.group(1))}"
    key = compact.upper()
    if key == "MSID":
        return "C_PIN_MSID"
    if key == "SID":
        return "C_PIN_SID"
    if key == "ERASEMASTER":
        return "C_PIN_EraseMaster"
    if key == "TPERSIGN":
        return "TPerSign"
    if key == "TPERATTESTATION":
        return "TperAttestation"
    if key == "_CERTDATA_TPERSIGN":
        return "_CertData_TPerSign"
    if key == "_CERTDATA_TPERATTESTATION":
        return "_CertData_TPerAttestation"
    match = re.fullmatch(r"BandMaster(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"C_PIN_BandMaster{int(match.group(1))}"
    match = re.fullmatch(r"Admin(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"C_PIN_Admin{int(match.group(1))}"
    match = re.fullmatch(r"User(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"Authority_User{int(match.group(1))}"
    aliases = {
        "Session Manager UID": "SessionManager",
        "SessionManagerUID": "SessionManager",
        "Locking": "LockingTable",
        "C_PIN": "C_PINTable",
        "Authority": "AuthorityTable",
        "ACE": "ACETable",
        "AccessControl": "AccessControlTable",
        "MethodID": "MethodIDTable",
        "K_AES_256": "K_AES_256Table",
        "K_AES_128": "K_AES_128Table",
    }
    return aliases.get(text, compact)


def _pin_owner_by_object(symbol: str) -> str | None:
    if symbol == "C_PIN_SID":
        return "SID"
    if symbol == "C_PIN_MSID":
        return "MSID"
    if symbol == "C_PIN_EraseMaster":
        return "EraseMaster"
    match = re.fullmatch(r"C_PIN_BandMaster(\d+)", symbol)
    if match:
        return f"BandMaster{int(match.group(1))}"
    match = re.fullmatch(r"C_PIN_(Admin|User)(\d+)", symbol)
    if match:
        return f"{match.group(1)}{int(match.group(2))}"
    return None


def _authority_from_cpin_name(name: Any) -> str | None:
    text = _as_text(name or "").strip()
    match = re.fullmatch(r"C_PIN_(Admin|User|BandMaster)(\d+)", text, flags=re.IGNORECASE)
    if match:
        family = match.group(1).title()
        if family == "Bandmaster":
            family = "BandMaster"
        return f"{family}{int(match.group(2))}"
    if re.fullmatch(r"C_PIN_EraseMaster", text, flags=re.IGNORECASE):
        return "EraseMaster"
    return None


def _authority_by_object(symbol: str) -> str | None:
    if symbol.startswith("Authority_"):
        return symbol.removeprefix("Authority_")
    return None


def _range_id_from_symbol(symbol: str) -> int | None:
    if symbol == "Locking_GlobalRange":
        return 0
    match = re.fullmatch(r"Locking_Range(\d+)", symbol)
    if match:
        return int(match.group(1))
    return None


def _range_id_from_key(symbol: str) -> int | None:
    if re.fullmatch(r"K_AES_(128|256)_GlobalRange_Key", symbol):
        return 0
    match = re.fullmatch(r"K_AES_(128|256)_Range(\d+)_Key", symbol)
    if match:
        return int(match.group(2))
    return None


def _is_table_symbol(symbol: str) -> bool:
    return symbol in {
        "Table",
        "MethodIDTable",
        "AccessControlTable",
        "ACETable",
        "AuthorityTable",
        "C_PINTable",
        "SecretProtectTable",
        "LockingTable",
        "K_AES_128Table",
        "K_AES_256Table",
        "MBR",
        "DataStore",
    } or symbol.startswith("Table_") or symbol.endswith("Table")


def _is_next_table_target(symbol: str, uid: str) -> bool:
    if _is_byte_table_symbol(symbol) or _is_byte_table_uid(uid):
        return False
    if _is_table_symbol(symbol):
        return True
    return bool(uid and uid.endswith("00000000"))


def _method_ref_name(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("uid", "UID", "method", "Method", "MethodID", "MethodId"):
            method = _method_ref_name(_mapping_value(value, key))
            if method is not None:
                return method
        for key in ("name", "Name"):
            method = _method_ref_name(_mapping_value(value, key))
            if method is not None:
                return method
        return None
    if isinstance(value, (list, tuple, set)) and len(value) == 1:
        return _method_ref_name(next(iter(value)))
    uid = _clean_uid(value)
    if uid:
        method = _method_by_uid(uid)
        if method is not None:
            return method
    text = _as_text(value or "").strip()
    if not text:
        return None
    return re.sub(r"[^A-Za-z0-9_]", "", text)


def _normalize_status(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) <= 8 and any(byte < 0x20 or byte > 0x7E for byte in raw):
            return _normalize_status(int.from_bytes(raw, "big"))
    if isinstance(value, int) and not isinstance(value, bool):
        numeric = {
            0x00: SUCCESS,
            0x01: NOT_AUTHORIZED,
            0x03: FAIL,
            0x04: FAIL,
            0x05: FAIL,
            0x06: FAIL,
            0x07: FAIL,
            0x08: INVALID_PARAMETER,
            0x09: INSUFFICIENT_SPACE,
            0x0A: INSUFFICIENT_ROWS,
            0x0C: INVALID_PARAMETER,
            0x0D: NOT_AUTHORIZED,
            0x0F: FAIL,
            0x10: FAIL,
            0x11: FAIL,
            0x12: NOT_AUTHORIZED,
            0x3F: FAIL,
            0x40: FAIL,
            0x41: FAIL,
            0x42: FAIL,
        }
        return numeric.get(value, FAIL)
    text = _as_text(value).strip()
    if not text:
        return None
    key = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    if re.fullmatch(r"0X[0-9A-F]+", key):
        return _normalize_status(int(key[2:], 16))
    aliases = {
        "SUCCESS": SUCCESS,
        "0": SUCCESS,
        "PASS": "PASS",
        "FAIL": FAIL,
        "NOTAUTHORIZED": NOT_AUTHORIZED,
        "1": NOT_AUTHORIZED,
        "INVALIDPARAMETER": INVALID_PARAMETER,
        "12": INVALID_PARAMETER,
        "0C": INVALID_PARAMETER,
        "13": NOT_AUTHORIZED,
        "0D": NOT_AUTHORIZED,
        "INVALIDCOMMAND": INVALID_PARAMETER,
        "INVALIDCOMMANDPARAMETER": INVALID_PARAMETER,
        "OTHERINVALIDCOMMANDPARAMETER": INVALID_PARAMETER,
        "INSUFFICIENTSPACE": INSUFFICIENT_SPACE,
        "9": INSUFFICIENT_SPACE,
        "INSUFFICIENTROWS": INSUFFICIENT_ROWS,
        "10": INSUFFICIENT_ROWS,
        "0A": INSUFFICIENT_ROWS,
        "SPBUSY": FAIL,
        "BUSY": FAIL,
        "SPFAILED": FAIL,
        "FAILED": FAIL,
        "SPDISABLED": FAIL,
        "DISABLED": FAIL,
        "SPFROZEN": FAIL,
        "FROZEN": FAIL,
        "NOSESSIONSAVAILABLE": FAIL,
        "UNIQUENESSCONFLICT": INVALID_PARAMETER,
        "TPERMALFUNCTION": FAIL,
        "TRANSACTIONFAILURE": FAIL,
        "RESPONSEOVERFLOW": FAIL,
        "AUTHORITYLOCKEDOUT": NOT_AUTHORIZED,
        "TIMEOUT": FAIL,
        "UNEXPECTEDRESULTS": FAIL,
        "TLSALERT": FAIL,
    }
    return aliases.get(key, key)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, bytes):
        return any(value)
    text = _as_text(value).strip().lower()
    return text in {"1", "true", "t", "yes", "y", "enabled", "on"}


def _enabled_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    text = _as_text(value).strip().lower()
    return text in {"1", "true", "t", "yes", "y", "enabled", "on"}


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    text = _as_text(value).strip()
    if not text:
        return None
    try:
        if re.fullmatch(r"0x[0-9A-Fa-f]+", text):
            return int(text, 16)
        if re.fullmatch(r"[0-9A-Fa-f]{2,}", text) and re.search(r"[A-Fa-f]", text):
            return int(text, 16)
        if re.fullmatch(r"0+[0-9A-Fa-f]+", text) and len(text) > 1:
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _parse_reencrypt_state(value: Any) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    return {
        "IDLE": 1,
        "PENDING": 2,
        "ACTIVE": 3,
        "COMPLETED": 4,
        "COMPLETE": 4,
        "PAUSED": 5,
        "PAUSE": 5,
    }.get(text)


def _parse_reencrypt_request(value: Any) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    return {
        "START": 1,
        "STARTREQ": 1,
        "ADVKEY": 2,
        "ADVKEYREQ": 2,
        "RETIDLE": 3,
        "RETIDLEREQ": 3,
        "CONT": 4,
        "CONTREQ": 4,
        "PAUSE": 5,
        "PAUSEREQ": 5,
    }.get(text)


def _reset_types(value: Any) -> set[int]:
    if value is None or value is False or value == "" or value == [] or value == ():
        return set()
    if value is True:
        return {0}
    if isinstance(value, int):
        return {value}
    if isinstance(value, bytes):
        return {int.from_bytes(value, "big")}
    if isinstance(value, (list, tuple, set)):
        out: set[int] = set()
        for item in value:
            out.update(_reset_types(item))
        return out
    raw_text = _as_text(value or "")
    text = re.sub(r"[^A-Za-z0-9]+", "", raw_text).upper()
    named = {
        "POWERCYCLE": 0,
        "POWER": 0,
        "HARDWARERESET": 1,
        "HWRESET": 1,
        "PROGRAMMATIC": 3,
        "TPERRESET": 3,
        "PROTOCOLSTACKRESET": 3,
        "STACKRESET": 3,
    }
    if text in named:
        return {named[text]}
    out: set[int] = set()
    if "POWERCYCLE" in text or text == "POWER":
        out.add(0)
    if "HARDWARERESET" in text or "HWRESET" in text:
        out.add(1)
    if "PROGRAMMATIC" in text or "TPERRESET" in text or "STACKRESET" in text:
        out.add(3)
    for number in re.findall(r"\d+", raw_text):
        out.add(int(number))
    if out:
        return out
    parsed = _parse_int(value)
    return {parsed} if parsed is not None else set()


def _reset_event_type(method: str) -> int | None:
    text = re.sub(r"[^A-Za-z0-9]+", "", _as_text(method or "")).upper()
    if text in {"POWERCYCLE", "POWERRESET", "COLDRESET"}:
        return 0
    if text in {"HARDWARERESET", "HWRESET"}:
        return 1
    if text in {"TPERRESET", "TCGRESET", "PROGRAMMATICRESET", "PROTOCOLSTACKRESET", "STACKRESET"}:
        return 3
    if text == "RESET":
        return 0
    return None


def _sp_lifecycle_active(value: Any) -> bool | None:
    parsed = _parse_int(value)
    if parsed is not None:
        if parsed == 8:
            return False
        if parsed >= 9:
            return True
        return None
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if not text:
        return None
    if "INACTIVE" in text or text in {"MANUFACTUREDINACTIVE", "MFGINACTIVE"}:
        return False
    if text in {"MANUFACTURED", "ACTIVE", "ISSUED"} or "ISSUED" in text:
        return True
    return None


def _dict_lookup(mapping: Any, *names: Any) -> tuple[bool, Any]:
    if not isinstance(mapping, dict):
        return False, None
    wanted = {_as_text(name).strip().lower() for name in names}
    for key, value in mapping.items():
        if _as_text(key).strip().lower() in wanted:
            return True, value
    return False, None


def _mapping_value(mapping: Any, *names: Any, default: Any = None) -> Any:
    found, value = _dict_lookup(mapping, *names)
    return value if found else default


def _mapping_section(mapping: Any, *names: Any) -> dict[str, Any]:
    value = _mapping_value(mapping, *names)
    return value if isinstance(value, dict) else {}


def _input_section(raw: dict[str, Any]) -> dict[str, Any]:
    return _mapping_section(raw, "input", "Input")


def _output_section(raw: dict[str, Any]) -> dict[str, Any]:
    return _mapping_section(raw, "output", "Output")


def _method_info_from_input(inp: dict[str, Any]) -> Any:
    return _mapping_value(inp, "method", "Method")


def _method_args_node(raw: dict[str, Any]) -> Any:
    inp = _input_section(raw)
    method_info = _method_info_from_input(inp)
    if not isinstance(method_info, dict):
        return _mapping_value(inp, "args", "Args", "arguments", "Arguments")
    args = _mapping_value(method_info, "args", "Args", "arguments", "Arguments")
    if args is not None:
        return args
    return _mapping_value(inp, "args", "Args", "arguments", "Arguments")


def _method_args(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Any]:
    args = _method_args_node(raw)
    if isinstance(args, dict):
        _, required = _dict_lookup(args, "required", "Required")
        _, optional = _dict_lookup(args, "optional", "Optional")
        return (
            dict(required) if isinstance(required, dict) else {},
            dict(optional) if isinstance(optional, dict) else {},
            args,
        )
    return {}, {}, args


def _walk_column_values(node: Any) -> dict[int, Any]:
    out: dict[int, Any] = {}

    def parse_column_key(key: Any) -> int | None:
        text = _as_text(key).strip()
        if not text:
            return None
        try:
            if re.fullmatch(r"0x[0-9A-Fa-f]+", text):
                return int(text, 16)
            if re.fullmatch(r"\d+", text):
                return int(text, 10)
            if re.fullmatch(r"[0-9A-Fa-f]+", text):
                return int(text, 16)
        except ValueError:
            return None
        return None

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                column = parse_column_key(key)
                if column is not None:
                    out[column] = val
                walk(val)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, tuple):
            for item in value:
                walk(item)

    walk(node)
    return out


def _column_from_name(name: Any, symbol: str = "", siblings: set[str] | None = None) -> int | None:
    key = re.sub(r"[^A-Za-z0-9_]", "", _as_text(name or "")).upper()
    if not key:
        return None
    if key in {"PIN"}:
        return PIN_COLUMN
    if key in {"_MINPINLENGTH", "MINPINLENGTH"}:
        return MIN_PIN_COLUMN
    locking_names = {
        "RANGESTART": 3,
        "RANGELENGTH": 4,
        "READLOCKENABLED": 5,
        "WRITELOCKENABLED": 6,
        "READLOCKED": 7,
        "WRITELOCKED": 8,
        "LOCKONRESET": 9,
        "ACTIVEKEY": 10,
        "NEXTKEY": 11,
        "REENCRYPTSTATE": 12,
        "REENCRYPTREQUEST": 13,
        "ADVKEYMODE": 14,
        "VERIFYMODE": 15,
        "CONTONRESET": 16,
        "LASTREENCRYPTLBA": 17,
        "LASTREENCSTAT": 18,
        "GENERALSTATUS": 19,
    }
    if key in locking_names:
        return locking_names[key]
    if key == "ENABLED":
        sibling_keys = siblings or set()
        if symbol == "MBRControl":
            return 1
        if symbol.startswith("TLS_PSK_Key") or "CIPHERSUITE" in sibling_keys or "PSK" in sibling_keys:
            return 3
        return 5
    if key == "DONE" and symbol == "MBRControl":
        return 2
    if key == "DONEONRESET" and symbol == "MBRControl":
        return 3
    if key == "PORTLOCKED":
        return 3
    if key == "PSK":
        return 4
    if key == "CIPHERSUITE":
        return 5
    locking_info_names = {
        "MAXRANGES": 4,
        "ALIGNMENTREQUIRED": 7,
        "LOGICALBLOCKSIZE": 8,
        "ALIGNMENTGRANULARITY": 9,
        "LOWESTALIGNEDLBA": 10,
    }
    if key in {"LIFECYCLE", "LIFECYCLESTATE", "LIFECYCLESTATEVALUE"}:
        return 6
    return locking_info_names.get(key)


def _walk_named_column_values(node: Any, symbol: str = "") -> dict[int, Any]:
    out: dict[int, Any] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            sibling_keys = {re.sub(r"[^A-Za-z0-9_]", "", _as_text(key or "")).upper() for key in value}
            for key, val in value.items():
                column = _column_from_name(key, symbol, sibling_keys)
                if column is not None:
                    out[column] = val
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    walk(node)
    return out


def _values(optional: dict[str, Any], raw_args: Any, symbol: str = "") -> dict[int, Any]:
    found, values_node = _dict_lookup(optional, "Values")
    if found:
        values = _walk_column_values(values_node)
        values.update(_walk_named_column_values(values_node, symbol))
        return values
    found, row_node = _dict_lookup(optional, "Row")
    if found:
        values = _walk_column_values(row_node)
        values.update(_walk_named_column_values(row_node, symbol))
        return values

    named = _walk_named_column_values(optional, symbol)
    if named:
        return named

    # TCGstorageAPI noNamed calls sometimes appear as positional arguments rather
    # than optional.Values.  Only keep plausible column/value pairs.
    row = None
    if isinstance(raw_args, dict):
        required = _mapping_section(raw_args, "required", "Required")
        optional_args = _mapping_section(raw_args, "optional", "Optional")
        row = _mapping_value(optional_args, "Row")
        if row is None:
            row = _mapping_value(required, "Row")
    source = row if row is not None else raw_args
    if isinstance(source, (list, tuple, dict)):
        decoded = _walk_column_values(source)
        decoded.update(_walk_named_column_values(source, symbol))
        return {k: v for k, v in decoded.items() if k in set(range(0, 64)) | {MIN_PIN_COLUMN}}
    return {}


def _is_byte_table_symbol(symbol: str) -> bool:
    return symbol == "MBR" or symbol.startswith("DataStore") or symbol.startswith("_CertData_")


def _is_byte_table_uid(uid: str) -> bool:
    if uid in {"0000080400000000", "0000100100000000", "0000800100000000", "0001000400000000", "0001001F00000000"}:
        return True
    return uid.startswith(("000010010000", "000080010000"))


def _has_explicit_row_values(event: Any) -> bool:
    values = _mapping_value(event.optional, "Values")
    return values is not None and bool(_walk_column_values(values))


def _contains_payload_bytes(value: Any) -> bool:
    if isinstance(value, (bytes, bytearray)):
        return len(value) > 0
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, dict):
        found, payload = _dict_lookup(value, "Bytes", "bytes", "Data", "data", "Buffer", "BufferIn", "Payload", "payload")
        if found and _contains_payload_bytes(payload):
            return True
        return any(_contains_payload_bytes(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                if key_text in {"bytes", "data", "buffer", "bufferin", "payload", "1"} and _contains_payload_bytes(item[1]):
                    return True
                continue
            if _contains_payload_bytes(item):
                return True
    return False


def _byte_table_has_payload(event: Any) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Bytes", "bytes", "Data", "data", "Buffer", "BufferIn", "Payload", "payload")
        if found and _contains_payload_bytes(value):
            return True
    return _contains_payload_bytes(_method_raw_args(event))


def _byte_table_pair_invalid(key: Any, value: Any, method: str) -> bool:
    key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
    if key_text in {"bytes", "data", "buffer", "bufferin", "payload"}:
        return False
    if method == "Set" and _parse_int(key) == 1 and isinstance(value, (bytes, bytearray, str)):
        return False
    if key_text in {"startrow", "endrow", "row", "where", "start", "end"}:
        return False
    if key_text in {"startcolumn", "endcolumn", "column", "columns", "startcol", "endcol", "col"}:
        return True
    parsed = _parse_int(key)
    return parsed is not None and parsed not in {0, 1, 2}


def _byte_table_raw_args_invalid(event: Any) -> bool:
    raw_args = _method_raw_args(event)
    if raw_args is None or isinstance(raw_args, dict):
        return False

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, val in value.items():
                if _byte_table_pair_invalid(key, val, event.method):
                    return True
                if walk(val):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                key, val = value
                if _byte_table_pair_invalid(key, val, event.method):
                    return True
                return False if isinstance(val, (bytes, bytearray, str)) else walk(val)
            return any(walk(item) for item in value)
        return False

    return walk(raw_args)


def _byte_table_where_invalid(event: Any) -> bool:
    if event.columns:
        return True
    where = _mapping_value(event.required, "Where")
    if where is None:
        where = _mapping_value(event.optional, "Where")
    if where is None:
        return False
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(where)).lower()
    if "startcolumn" in text or "endcolumn" in text or "column" in text or "table" in text:
        return True
    return bool(_walk_column_values(where)) and "row" not in text and "startrow" not in text


def _byte_table_get_invalid(event: Any) -> bool:
    return _byte_table_where_invalid(event) or _byte_table_raw_args_invalid(event)


def _byte_table_set_invalid(event: Any) -> bool:
    return _has_explicit_row_values(event) or _byte_table_where_invalid(event) or _byte_table_raw_args_invalid(event) or not _byte_table_has_payload(event)


def _method_raw_args(event: Any) -> Any:
    return _method_args_node(event.raw)


def _bare_authority_symbol(name: Any, method: str, values: dict[int, Any], columns: set[int]) -> str | None:
    authority = _authority_by_name(name) or _authority_from_cpin_name(name)
    if authority is None or authority in {"Anybody", "Admins", "SID", "MSID", "PSID", "TPerSign", "TperAttestation"}:
        return None
    if method == "Set" and values and set(values) <= {5}:
        return f"Authority_{authority}"
    if method == "Get" and (not columns or columns & {5}):
        return f"Authority_{authority}"
    return None


def _empty_payload(value: Any) -> bool:
    return value is None or value == "" or value == b"" or value == () or value == [] or value == {}


def _has_method_payload(event: Any, *names: str) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found and not _empty_payload(value):
            return True
    raw_args = _method_raw_args(event)
    if raw_args is None:
        return False
    if isinstance(raw_args, dict):
        for key, value in raw_args.items():
            if key in {"required", "optional"}:
                continue
            if not _empty_payload(value):
                return True
        return False
    return not _empty_payload(raw_args)


def _is_named_pair(value: Any, names: set[str] | None = None) -> bool:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return False
    if names is None:
        return isinstance(value[0], str) or isinstance(value[0], int)
    return _as_text(value[0]).strip().lower() in names


def _sequence_named_arg_value(raw_args: Any, *names: str) -> tuple[bool, Any]:
    if not isinstance(raw_args, (list, tuple)):
        return False, None
    wanted = {_as_text(name).lower() for name in names}

    def walk(sequence: Any) -> tuple[bool, Any]:
        if not isinstance(sequence, (list, tuple)):
            return False, None
        for item in sequence:
            if isinstance(item, dict):
                for key, value in item.items():
                    if _as_text(key).lower() in wanted:
                        return True, value
                    found, nested = walk(value)
                    if found:
                        return True, nested
            elif isinstance(item, (list, tuple)) and len(item) == 2 and _as_text(item[0]).lower() in wanted:
                return True, item[1]
            else:
                found, nested = walk(item)
                if found:
                    return True, nested
        return False, None

    return walk(raw_args)


def _raw_first_positional_arg(raw_args: Any, named_keys: set[str] | None = None) -> Any:
    if raw_args is None or isinstance(raw_args, dict):
        return None
    if isinstance(raw_args, (list, tuple)):
        if not raw_args:
            return None
        if _is_named_pair(raw_args, named_keys):
            return None
        first = raw_args[0]
        if _is_named_pair(first, named_keys):
            return None
        return first
    return raw_args


def _firmware_attestation_has_nonce(event: Any) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "AssessorNonce", "Nonce", "Data", "Input")
        if found and not _empty_payload(value):
            return True
    raw_args = _method_raw_args(event)
    first = _raw_first_positional_arg(raw_args, {"0", "1", "rtrid", "assessorid", "subname"})
    return not _empty_payload(first)


def _sign_has_payload(event: Any) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Data", "Input", "Buffer")
        if found and not _empty_payload(value):
            return True
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, "Data", "Input", "Buffer")
        if found and not _empty_payload(value):
            return True
        return False
    found, value = _sequence_named_arg_value(raw_args, "Data", "Input", "Buffer")
    if found:
        return not _empty_payload(value)
    first = _raw_first_positional_arg(raw_args)
    return not _empty_payload(first)


def _input_payload_length(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, dict):
        found, payload = _dict_lookup(value, "Data", "Input", "Buffer", "BufferIn", "Bytes", "Payload", "AssessorNonce", "Nonce")
        if found:
            length = _input_payload_length(payload)
            if length is not None:
                return length
        lengths = [_input_payload_length(item) for item in value.values()]
        lengths = [length for length in lengths if length is not None]
        return max(lengths) if lengths else None
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return _input_payload_length(value[0])
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return len(value)
        lengths: list[int] = []
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                if key in {"data", "input", "buffer", "bufferin", "bytes", "payload", "assessornonce", "nonce", "0"}:
                    length = _input_payload_length(item[1])
                    if length is not None:
                        lengths.append(length)
                continue
            length = _input_payload_length(item)
            if length is not None:
                lengths.append(length)
        return max(lengths) if lengths else None
    return None


def _payload_too_long(event: Any, limit: int) -> bool:
    candidates = []
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Data", "Input", "AssessorNonce", "Nonce")
        if found:
            candidates.append(value)
    raw_args = _method_raw_args(event)
    if not isinstance(raw_args, dict):
        candidates.append(raw_args)
    for value in candidates:
        length = _input_payload_length(value)
        if length is not None and length > limit:
            return True
    return False


def _method_arg_value(event: Any, *names: str) -> Any:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return value
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, *names)
        if found:
            return value
    found, value = _sequence_named_arg_value(raw_args, *names)
    if found:
        return value
    return raw_args


def _named_method_arg_value(event: Any, *names: str) -> tuple[bool, Any]:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return True, value
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, *names)
        if found:
            return True, value
    found, value = _sequence_named_arg_value(raw_args, *names)
    if found:
        return True, value
    return False, None


def _raw_arg_value(required: dict[str, Any], optional: dict[str, Any], raw_args: Any, *names: str) -> Any:
    for source in (required, optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return value
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, *names)
        if found:
            return value
    found, value = _sequence_named_arg_value(raw_args, *names)
    if found:
        return value
    return None


def _start_session_positional(raw_args: Any) -> tuple[Any, Any]:
    if not isinstance(raw_args, (list, tuple)) or _is_named_pair(raw_args):
        return None, None
    if raw_args and _is_named_pair(raw_args[0]):
        return None, None
    if len(raw_args) >= 3:
        return raw_args[1], raw_args[2]
    if len(raw_args) >= 2 and _sp_from_value(raw_args[0]) is not None:
        return raw_args[0], raw_args[1]
    return None, None


def _authenticate_authority_arg(raw_args: Any) -> Any:
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, "Authority", "HostSigningAuthority", "AuthAs", "authAs")
        if found:
            return value
    if not isinstance(raw_args, (list, tuple)):
        return None

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            found, item = _dict_lookup(value, "Authority", "HostSigningAuthority", "AuthAs", "authAs")
            if found:
                return item
            for item in value.values():
                found = walk(item)
                if found is not None:
                    return found
            return None
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and _as_text(value[0]).lower() in {"0", "challenge", "hostchallenge"}:
                return None
            for item in value:
                if _authority_from_value(item) is not None:
                    return item
                found = walk(item)
                if found is not None:
                    return found
        else:
            if _authority_from_value(value) is not None:
                return value
        return None

    return walk(raw_args)


def _random_count(event: Any) -> int | None:
    value = _method_arg_value(event, "Count", "count")
    if isinstance(value, (list, tuple)) and value:
        value = value[0]
    return _parse_int(value)


def _next_count_invalid(event: Any) -> bool:
    found, value = _named_method_arg_value(event, "Count", "count")
    if not found:
        return False
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            return True
        value = value[0]
    parsed = _parse_int(value)
    return parsed is None or parsed < 0


def _uid_arg(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("uid", "UID", "row", "Row", "object", "Object"):
            uid = _clean_uid(_mapping_value(value, key))
            if uid:
                return uid
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _uid_arg(value[0])
    return _clean_uid(value)


def _uid_ref(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, bytes, bytearray)):
        return _clean_uid(value)
    text = _as_text(value).strip()
    if not text or not re.fullmatch(r"(?:0x)?[0-9A-Fa-f\s:_-]+", text):
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text).upper()
    return cleaned.zfill(16)[-16:] if cleaned else ""


def _object_ref_from_value(value: Any) -> tuple[str, str]:
    if isinstance(value, dict):
        name = ""
        for key in ("name", "Name", "symbol", "Symbol"):
            found, name_value = _dict_lookup(value, key)
            if found:
                name = _as_text(name_value)
                break
        for key in ("uid", "UID", "row", "Row", "object", "Object", "objectID", "ObjectID", "Table", "TableUID"):
            found, raw_uid = _dict_lookup(value, key)
            if found:
                uid = _uid_ref(raw_uid)
                if uid:
                    return _object_by_uid(uid, name), uid
                symbol, nested_uid = _object_ref_from_value(raw_uid)
                if symbol or nested_uid:
                    return symbol, nested_uid
        if name:
            return _normalize_name(name), ""
        for item in value.values():
            symbol, uid = _object_ref_from_value(item)
            if symbol or uid:
                return symbol, uid
        return "", ""
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return _object_ref_from_value(value[0])
        for item in value:
            symbol, uid = _object_ref_from_value(item)
            if symbol or uid:
                return symbol, uid
        return "", ""
    if isinstance(value, set):
        for item in sorted(value, key=str):
            symbol, uid = _object_ref_from_value(item)
            if symbol or uid:
                return symbol, uid
        return "", ""
    uid = _uid_ref(value)
    if uid:
        return _object_by_uid(uid), uid
    symbol = _normalize_name(value)
    return symbol, ""


def _known_opal_object_symbol(symbol: str, uid: str = "") -> bool:
    if not symbol:
        return False
    if uid and not symbol.startswith("UnknownSP_"):
        return True
    if symbol in set(FIXED_OBJECT_BY_UID.values()) | {
        "Table",
        "SPInfo",
        "MethodIDTable",
        "AccessControlTable",
        "ACETable",
        "AuthorityTable",
        "C_PINTable",
        "SecretProtectTable",
        "LockingTable",
        "MBR",
        "DataStore",
        "DataRemovalMechanism",
        "MBRControl",
        "LockingInfo",
    }:
        return True
    if _is_table_symbol(symbol) or _is_byte_table_symbol(symbol):
        return True
    return bool(
        re.fullmatch(r"(C_PIN|Authority)_(SID|MSID|PSID|Admins|Makers|EraseMaster|BandMaster\d+|Admin\d+|User\d+)", symbol)
        or re.fullmatch(r"Locking_(GlobalRange|Range\d+)", symbol)
        or re.fullmatch(r"K_AES_(128|256)_(GlobalRange|Range\d+)_Key", symbol)
        or re.fullmatch(r"TLS_PSK_Key\d+", symbol)
        or re.fullmatch(r"Port\d+", symbol)
        or re.fullmatch(r"ACE_[0-9A-F]{8}", symbol)
        or re.fullmatch(r"ACE_DataStore\d+_(Get|Set)_All", symbol)
        or symbol.startswith("SPTemplates_")
    )


def _table_family(symbol: str) -> str:
    aliases = {
        "MethodIDTable": "MethodID",
        "AccessControlTable": "AccessControl",
        "ACETable": "ACE",
        "AuthorityTable": "Authority",
        "C_PINTable": "C_PIN",
        "SecretProtectTable": "SecretProtect",
        "LockingTable": "Locking",
        "K_AES_128Table": "K_AES_128",
        "K_AES_256Table": "K_AES_256",
    }
    if symbol in aliases:
        return aliases[symbol]
    if symbol.startswith("Table_"):
        return symbol.removeprefix("Table_")
    if symbol.endswith("Table"):
        return symbol.removesuffix("Table")
    return symbol


def _next_where_invalid(event: Any) -> bool:
    found, value = _named_method_arg_value(event, "Where", "where")
    if not found:
        return False
    row_symbol, uid = _object_ref_from_value(value)
    if not uid and not row_symbol:
        return True
    if _is_byte_table_uid(uid) or _is_byte_table_symbol(row_symbol):
        return True

    family = _table_family(event.invoking_symbol)
    if family == "Table":
        return not row_symbol.startswith("Table_")
    if family == "MethodID":
        return _method_by_uid(uid) is None and _method_ref_name(value) not in set(METHOD_UIDS.values())
    if family == "C_PIN":
        return not row_symbol.startswith("C_PIN_")
    if family == "Locking":
        return not row_symbol.startswith("Locking_")
    if family == "K_AES_128":
        return not row_symbol.startswith("K_AES_128_")
    if family == "K_AES_256":
        return not row_symbol.startswith("K_AES_256_")
    if family == "Authority":
        authority = _authority_from_value(value)
        if authority is not None:
            row_symbol = f"Authority_{authority}"
        return not row_symbol.startswith("Authority_")
    if family == "ACE":
        return not row_symbol.startswith("ACE_")
    if row_symbol.startswith("UnknownSP_") or _is_byte_table_symbol(row_symbol):
        return True
    return False


def _keep_global_range_key(event: Any) -> bool:
    found, value = _named_method_arg_value(event, "KeepGlobalRangeKey", "KeepGlobalRange", "060000", "0x060000", "393216")
    if found:
        return _as_bool(value)

    raw_args = _method_raw_args(event)
    if isinstance(raw_args, (list, tuple)):
        for item in raw_args:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            key, value = item
            if _parse_int(key) == 0x060000 or re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower() == "keepglobalrangekey":
                return _as_bool(value)
    return False


def _flatten_return_values(value: Any, symbol: str = "") -> dict[int, Any]:
    returned = _walk_column_values(value)
    returned.update(_walk_named_column_values(value, symbol))
    return returned


def _cellblock_columns(required: dict[str, Any]) -> set[int]:
    columns: set[int] = set()
    cellblock = _mapping_value(required, "Cellblock", "CellBlock")
    if isinstance(cellblock, dict):
        cellblock = [cellblock]
    if not isinstance(cellblock, list):
        return columns

    start: int | None = None
    end: int | None = None
    for item in cellblock:
        if not isinstance(item, dict):
            continue
        found, start_value = _dict_lookup(item, "startColumn", "StartColumn", "start_column", "startCol", "StartCol")
        if found:
            start = _parse_int(start_value)
        found, end_value = _dict_lookup(item, "endColumn", "EndColumn", "end_column", "endCol", "EndCol")
        if found:
            end = _parse_int(end_value)
    if start is not None and end is not None:
        columns.update(range(min(start, end), max(start, end) + 1))
    elif start is not None:
        columns.add(start)
    elif end is not None:
        columns.add(end)
    return columns


def _parse_lba(text: Any) -> tuple[int, int] | None:
    if text is None:
        return None
    nums = [int(x) for x in re.findall(r"\d+", _as_text(text))]
    if not nums:
        return None
    if len(nums) == 1:
        return nums[0], nums[0]
    return min(nums[0], nums[1]), max(nums[0], nums[1])


def _extract_pattern(text: Any) -> str | None:
    if text is None:
        return None
    value = _as_text(text).strip()
    match = re.search(r"Pattern\s+([0-9A-Fa-f]+)", value)
    if match:
        return match.group(1).upper()
    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        return value.upper()
    return None


def _host_status(output: dict[str, Any]) -> str | None:
    status_value = _mapping_value(output, "status_codes", "statusCodes", "StatusCodes", "status", "Status")
    status = _normalize_status(status_value)
    if status is not None:
        return status
    output_args = _mapping_section(output, "args", "Args")
    result = _mapping_value(output_args, "result", "Result")
    if result is None:
        result = _mapping_value(output, "result", "Result")
    normalized = _normalize_status(result)
    if normalized in {FAIL, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS}:
        return normalized
    return None


def _output_status_value(output: dict[str, Any], inp: dict[str, Any] | None = None) -> Any:
    value = _mapping_value(output, "status_codes", "statusCodes", "StatusCodes", "status", "Status")
    if value is not None:
        return value
    if inp is not None:
        value = _mapping_value(inp, "status_codes", "statusCodes", "StatusCodes", "status", "Status")
        if value is not None:
            return value
    output_args = _mapping_section(output, "args", "Args")
    for source in (output_args, output):
        candidate = _mapping_value(source, "result", "Result")
        normalized = _normalize_status(candidate)
        if normalized in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}:
            return normalized
    return None


def _output_return_values(raw: dict[str, Any]) -> Any:
    output = _output_section(raw)
    names = (
        "return_values",
        "ReturnValues",
        "returnValues",
        "returned_values",
        "returnedValues",
        "returnedNamedValues",
        "ReturnedNamedValues",
        "rvs",
        "RVs",
        "rv",
        "RV",
        "kwrvs",
        "kwrv",
        "results",
        "Results",
    )
    found, value = _dict_lookup(output, *names)
    if found:
        return value
    output_args = _mapping_section(output, "args", "Args")
    found, value = _dict_lookup(output_args, *names)
    if found:
        return value
    return _mapping_value(output_args, "result", "Result", default=_mapping_value(output, "result", "Result"))


@dataclass
class Event:
    raw: dict[str, Any]
    kind: str
    method: str
    invoking_name: str = ""
    invoking_uid: str = ""
    invoking_symbol: str = ""
    status: str | None = None
    required: dict[str, Any] = field(default_factory=dict)
    optional: dict[str, Any] = field(default_factory=dict)
    values: dict[int, Any] = field(default_factory=dict)
    columns: set[int] = field(default_factory=set)
    sp: str | None = None
    authority: str | None = None
    challenge: str | None = None
    write_session: bool = False
    lba: tuple[int, int] | None = None
    pattern: str | None = None
    read_result: str | None = None

    @property
    def is_success(self) -> bool:
        if self.kind == "host_io":
            return self.status in {None, SUCCESS, "PASS"}
        return self.status == SUCCESS


@dataclass
class ExpectedResponse:
    allowed_statuses: set[str | None] = field(default_factory=set)
    forbidden_statuses: set[str | None] = field(default_factory=set)
    expected_read_result: str | None = None
    forbidden_read_result: str | None = None
    expected_return_length: int | None = None
    forbid_read_result_presence: bool = False
    reason: str = ""
    confidence: str = "medium"


@dataclass
class Session:
    open: bool = False
    sp: str | None = None
    write: bool = False
    authenticated: set[str] = field(default_factory=set)


@dataclass
class RangeState:
    range_id: int
    range_start: int = 0
    range_length: int = 0
    read_lock_enabled: bool = False
    write_lock_enabled: bool = False
    read_locked: bool = False
    write_locked: bool = False
    lock_on_reset: bool = False
    active_key: str | None = None
    next_key: str | None = None
    reencrypt_state: int = 1
    reencrypt_request: int | None = None
    adv_key_mode: int | None = None
    verify_mode: int | None = None
    cont_on_reset: Any = None
    last_reencrypt_lba: int | None = None
    last_reenc_stat: Any = None
    general_status: Any = None
    media_generation: int = 0
    lock_on_reset_types: set[int] = field(default_factory=set)


@dataclass
class AceExpression:
    authorities: set[str] = field(default_factory=set)
    operator: str = "or"
    tokens: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class State:
    session: Session = field(default_factory=Session)
    pins: dict[str, str] = field(default_factory=dict)
    authority_enabled: dict[str, bool] = field(default_factory=dict)
    locking_sp_activated: bool = False
    observed_sp_lifecycle: dict[str, int] = field(default_factory=dict)
    locking_info: dict[str, Any] = field(default_factory=dict)
    ranges: dict[int, RangeState] = field(default_factory=dict)
    range_read_lock_users: dict[int, set[str]] = field(default_factory=dict)
    range_write_lock_users: dict[int, set[str]] = field(default_factory=dict)
    datastore_read_users: set[str] = field(default_factory=set)
    datastore_write_users: set[str] = field(default_factory=set)
    ace_expressions: dict[tuple[str, str], AceExpression] = field(default_factory=dict)
    mbr: dict[str, Any] = field(default_factory=dict)
    lba_patterns: dict[tuple[int, int], tuple[str, int, int]] = field(default_factory=dict)


def parse_event(raw: dict[str, Any]) -> Event:
    inp = _input_section(raw)
    out = _output_section(raw)

    found_command, command = _dict_lookup(inp, "command", "Command")
    if found_command:
        method = _as_text(command or "UNKNOWN")
        args = _mapping_section(inp, "args", "Args")
        output_args = _mapping_section(out, "args", "Args")
        result = _mapping_value(out, "result", "Result")
        if result is None:
            result = _mapping_value(output_args, "result", "Result")
        return Event(
            raw=raw,
            kind="host_io",
            method=method,
            status=_host_status(out),
            lba=_parse_lba(_mapping_value(args, "LBA", "lba", "Lba")),
            pattern=_extract_pattern(_mapping_value(args, "pattern", "Pattern")),
            read_result=_extract_pattern(result),
        )

    method_info = _method_info_from_input(inp) or {}
    required, optional, raw_args = _method_args(raw)
    invoking = _mapping_value(inp, "invoking_id", "InvokingID", "invokingId", "invoking", "Invoking") or {}
    if isinstance(invoking, dict):
        invoking_uid = _clean_uid(_mapping_value(invoking, "uid", "UID"))
        invoking_name_source = _mapping_value(invoking, "name", "Name")
    else:
        invoking_uid = _clean_uid(invoking)
        invoking_name_source = invoking
    invoking_name = _normalize_name(invoking_name_source or "")
    invoking_symbol = _object_by_uid(invoking_uid, invoking_name)
    if isinstance(method_info, dict):
        method_uid = _clean_uid(_mapping_value(method_info, "uid", "UID"))
        method_name = _mapping_value(method_info, "name", "Name")
    else:
        method_uid = _clean_uid(method_info)
        method_name = method_info
    method_from_uid = _method_by_uid(method_uid)
    method_text = "" if method_name is None else _as_text(method_name).strip()
    if method_from_uid is not None and (not method_text or _uid_ref(method_name)):
        method = method_from_uid
    else:
        method = method_text or method_from_uid or "UNKNOWN"
    values = _values(optional, raw_args, invoking_symbol)
    columns = _cellblock_columns(required)
    if not invoking_uid:
        authority_symbol = _bare_authority_symbol(invoking_name_source, method, values, columns)
        if authority_symbol is not None:
            invoking_symbol = authority_symbol
    spid_value = _raw_arg_value(required, optional, raw_args, "SPID", "SP", "sp")
    positional_spid, positional_write = _start_session_positional(raw_args) if method == "StartSession" else (None, None)
    if spid_value is None:
        spid_value = positional_spid
    auth_value = _raw_arg_value(required, optional, raw_args, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    if auth_value is None and method == "Authenticate":
        auth_value = _authenticate_authority_arg(raw_args)
    challenge = _raw_arg_value(required, optional, raw_args, "HostChallenge", "Challenge", 0, "0")
    write_value = _raw_arg_value(required, optional, raw_args, "Write", "write")
    if write_value is None:
        write_value = positional_write

    return Event(
        raw=raw,
        kind="tcg_method",
        method=method,
        invoking_name=invoking_name,
        invoking_uid=invoking_uid,
        invoking_symbol=invoking_symbol,
        status=_normalize_status(_output_status_value(out, inp)),
        required=required,
        optional=optional,
        values=values,
        columns=columns,
        sp=_sp_from_value(spid_value),
        authority=_authority_from_value(auth_value),
        challenge=challenge,
        write_session=_as_bool(write_value),
    )


def _range(state: State, range_id: int) -> RangeState:
    if range_id not in state.ranges:
        state.ranges[range_id] = RangeState(range_id=range_id)
    return state.ranges[range_id]


def _has_authority(state: State, authority: str) -> bool:
    if authority == "Anybody":
        return state.session.open
    if authority == "Admins":
        return any(auth == "SID" or auth.startswith("Admin") for auth in state.session.authenticated)
    if authority == "Users":
        return any(auth.startswith("User") for auth in state.session.authenticated)
    if authority == "PSID":
        return "PSID" in state.session.authenticated
    return authority in state.session.authenticated


def _has_any_authority(state: State, authorities: set[str]) -> bool:
    return any(_has_authority(state, authority) for authority in authorities)


def _is_user(authority: str | None) -> bool:
    return bool(authority and re.fullmatch(r"User\d+", authority))


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


def _expected_object_sp(event: Event, state: State | None = None) -> str | None:
    symbol = event.invoking_symbol
    if event.method == "Activate":
        return "AdminSP"
    if symbol in {"TPerSign", "TperAttestation", "DataRemovalMechanism"} or symbol.startswith("_CertData_"):
        return "AdminSP"
    if symbol.startswith("Table_") or symbol in {"Table", "SPInfo", "SPTemplates_Base", "SPTemplates_Admin", "MethodIDTable", "AccessControlTable", "ACETable"}:
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


def _method_supported_in_session(state: State, event: Event) -> bool:
    if event.method in {"Properties", "StartSession", "EndSession", "CloseSession", "SyncSession"}:
        return True
    if not state.session.open:
        return True
    allowed = SUPPORTED_METHODS_BY_SP.get(state.session.sp or "")
    return allowed is None or event.method in allowed


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


def _expected_start_session(state: State, event: Event) -> ExpectedResponse:
    if not _is_session_manager_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="StartSession must target the Session Manager", confidence="high")
    if event.sp is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="StartSession has unknown or invalid SPID", confidence="high")
    if event.sp == "LockingSP" and not state.locking_sp_activated:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, reason="LockingSP is not activated in reconstructed state", confidence="medium")

    authority = event.authority or "Anybody"
    if authority == "Anybody":
        return ExpectedResponse({SUCCESS}, reason="Unauthenticated session is permitted", confidence="high")
    if not _authority_is_enabled(state, event.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} is not enabled", confidence="high")
    challenge = _credential_text(event.challenge)
    if not challenge:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Credential authority requires a host challenge", confidence="high")

    known_pin = state.pins.get(authority)
    if known_pin is None:
        return ExpectedResponse({SUCCESS, NOT_AUTHORIZED}, reason=f"{authority} credential is unknown from history", confidence="low")
    if challenge != known_pin:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} challenge does not match tracked PIN", confidence="high")
    return ExpectedResponse({SUCCESS}, reason=f"{authority} challenge matches tracked PIN", confidence="high")


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
    if not _authority_is_enabled(state, state.session.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} is not enabled", confidence="high")
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
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} authentication challenge does not match tracked PIN", confidence="high")
    return ExpectedResponse({SUCCESS}, reason=f"{authority} authentication challenge matches tracked PIN", confidence="high")


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
        if (not event.columns or event.columns & protected_columns) and not _has_authority(state, "Admins") and not range_acl:
            return ExpectedResponse({NOT_AUTHORIZED}, reason="Locking range state columns require Admins", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="Authorized Locking range Get is allowed", confidence="high")
    if symbol == "MBRControl":
        return ExpectedResponse({SUCCESS}, reason="MBRControl Get is permitted by ACE_Anybody", confidence="high")
    if symbol == "MBR":
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Byte table Get cannot request column values in the Cellblock", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="MBR byte table Get is permitted by ACE_Anybody", confidence="high")
    if symbol.startswith("K_AES_") and event.method == "Get":
        if _ace_expression_configured(state, "ACE_0003BFFF") and not _ace_satisfied(state, "ACE_0003BFFF"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="K_AES Mode Get is blocked by personalized ACE_K_AES_Mode", confidence="high")
        return ExpectedResponse({SUCCESS}, reason="K_AES Mode Get is permitted by ACE_K_AES_Mode", confidence="medium")
    if symbol.startswith("DataStore"):
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Byte table Get cannot request column values in the Cellblock", confidence="high")
        if not _has_authority(state, "Admins") and not _user_acl_allows_datastore(state, write=False):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="DataStore Get requires Admins or a personalized read ACE", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="Authorized DataStore Get is allowed", confidence="medium")
    if symbol.startswith("Authority_"):
        if not _has_authority(state, "Admins") and not _ace_satisfied(state, "ACE_00039000"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires Admins", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason=f"Authorized {symbol} Get is allowed", confidence="medium")
    if symbol.startswith("Port"):
        if not _has_any_authority(state, {"Admins", "SID"}):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="Port Get requires SID/Admin authority in the TCGstorageAPI flow", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="Authorized Port Get is allowed", confidence="medium")
    if symbol.startswith("ACE_"):
        if not _has_authority(state, "Admins") and not _ace_satisfied(state, "ACE_00038000"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires Admins", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason=f"Authorized {symbol} Get is allowed", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason="Generic Get is permitted in an open session", confidence="medium")


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
    if symbol.startswith("Authority_User"):
        return {"Admins"}
    if symbol.startswith("Authority_Admin"):
        return {"Admins", "SID"}
    if symbol in {"MBR", "DataStore"}:
        return {"Admins"}
    if symbol.startswith(("Locking_", "MBRControl", "ACE_", "DataStore", "Port")):
        return {"Admins"}
    if symbol.startswith("TLS_PSK_Key"):
        return {"Admins", "SID"}
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
    if match.group(1) == "01":
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
            if length % granularity:
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


def _invalid_set_values(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    if symbol.startswith("_CertData_"):
        return True
    if _is_byte_table_symbol(symbol):
        return _byte_table_set_invalid(event)
    if _is_table_symbol(symbol):
        return True
    if symbol.startswith("K_AES_"):
        return True
    if symbol in {"LockingInfo", "MethodIDTable", "Table_MethodID"}:
        return True
    if symbol == "DataRemovalMechanism":
        columns = set(event.values)
        return not columns or not columns <= {1}
    if symbol == "C_PIN_MSID":
        return True
    if symbol.startswith("C_PIN_"):
        columns = set(event.values)
        if not columns or not columns <= {PIN_COLUMN, MIN_PIN_COLUMN}:
            return True
        if PIN_COLUMN in event.values and event.values[PIN_COLUMN] in {None, ""}:
            return True
        if MIN_PIN_COLUMN in event.values:
            min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
            return min_pin is None or min_pin < 0 or min_pin > 32
    if symbol.startswith("ACE_") and ACE_BOOLEAN_EXPR_COLUMN in event.values:
        expression = _ace_expression_from_value(event.values[ACE_BOOLEAN_EXPR_COLUMN])
        pin_user = _pin_user_from_set_ace_symbol(symbol)
        if state.session.sp == "LockingSP" and pin_user:
            supported = ({"Admins"}, {"Admins", pin_user})
            return expression.operator != "or" or expression.authorities not in supported
    if symbol.startswith("Locking_"):
        range_id = _range_id_from_symbol(symbol)
        if 13 in event.values and _reencrypt_request_invalid(_range(state, range_id or 0), _parse_reencrypt_request(event.values[13])):
            return True
        if _range_values_invalid_for_geometry(state, range_id, event.values):
            return True
    if symbol.startswith("Authority_") and 5 in event.values:
        return event.values[5] not in {0, 1, False, True, "0", "1", "False", "True", "false", "true"}
    if symbol == "MBRControl":
        for column in (1, 2, 3):
            if column in event.values and event.values[column] not in {0, 1, False, True, "0", "1", "False", "True", "false", "true"}:
                return True
    if symbol.startswith("Port"):
        columns = set(event.values)
        if not columns or not columns <= set(PORT_COLUMNS):
            return True
        if 3 in event.values and event.values[3] not in {0, 1, False, True, "0", "1", "False", "True", "false", "true"}:
            return True
    if symbol.startswith("TLS_PSK_Key"):
        columns = set(event.values)
        if not columns or not columns <= set(TLS_PSK_COLUMNS):
            return True
        if 3 in event.values and event.values[3] not in {0, 1, False, True, "0", "1", "False", "True", "false", "true"}:
            return True
        if 5 in event.values and event.values[5] in {None, ""}:
            return True
    return False


def _table_method_common_failure(state: State, event: Event, method: str) -> ExpectedResponse | None:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} table does not belong to current SP", confidence="medium")
    if not _is_table_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason=f"{method} is a table method", confidence="high")
    if event.invoking_symbol in {"MBR", "DataStore"} or event.invoking_symbol.startswith("DataStore"):
        return ExpectedResponse({INVALID_PARAMETER}, reason=f"{method} is not available on byte tables", confidence="high")
    return None


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


def _expected_create_row(state: State, event: Event) -> ExpectedResponse:
    common = _table_method_common_failure(state, event, "CreateRow")
    if common is not None:
        return common
    if event.invoking_symbol in {"MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateRow is not permitted on MethodID or AccessControl tables", confidence="high")
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
    if event.invoking_symbol in {"MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="DeleteRow is not permitted on MethodID or AccessControl tables", confidence="high")
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


def _expected_set(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Set requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Set requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Set object does not belong to current SP", confidence="medium")
    reencrypt_block = _reencrypt_blocks_set(state, event)
    if reencrypt_block is not None:
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason=reencrypt_block, confidence="high")
    if _invalid_set_values(state, event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="Set contains values disallowed by Opal table semantics", confidence="medium")
    required = _set_required_authorities(state, event)
    if not _has_any_authority(state, required) and not _ace_authorizes_set(state, event):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"Set requires one of {sorted(required)}", confidence="high")
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
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires an open LockingSP session", confidence="high")
    if state.session.sp != "LockingSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GenKey key object belongs to LockingSP", confidence="high")
    if _range_id_from_key(event.invoking_symbol) is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="GenKey must target a K_AES range key", confidence="high")
    ace_symbol = _key_genkey_ace_symbol(event.invoking_symbol)
    if not _has_authority(state, "Admins") and not (ace_symbol and _ace_satisfied(state, ace_symbol)):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires Admins authority", confidence="high")
    range_id = _range_id_from_key(event.invoking_symbol)
    if range_id is not None and _range_reencrypt_busy(_range(state, range_id)):
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="GenKey on a range key is blocked while ReEncryptState is not IDLE", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized GenKey is allowed", confidence="high")


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
    if not _is_next_table_target(event.invoking_symbol, event.invoking_uid):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next is defined only for Opal object tables", confidence="high")
    if _next_count_invalid(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next Count must be an unsigned integer", confidence="high")
    if _next_where_invalid(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next Where must reference a row in the invoking object table", confidence="medium")
    return ExpectedResponse({SUCCESS}, reason="Next is allowed on Opal object tables", confidence="medium")


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


def _get_arg_uid(event: Event, *names: str) -> str:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return _uid_arg(value)
    return ""


def _combo_exists_for_get_acl(state: State, event: Event) -> bool | None:
    found_invoking, invoking_value = _named_method_arg_value(event, "InvokingID", "InvokingId", "Object", "ObjectID", "Table", "TableUID")
    found_method, method_value = _named_method_arg_value(event, "MethodID", "MethodId", "Method")
    if not found_invoking and not found_method:
        return None

    symbol, invoking_uid = _object_ref_from_value(invoking_value) if found_invoking else ("", "")
    method_name = _method_ref_name(method_value)
    if method_name is None:
        return None
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
    if method_name == "GenKey":
        return _range_id_from_key(symbol) is not None
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
    if method_name in {"Authenticate", "Random", "GetACL"}:
        return method_name in SUPPORTED_METHODS_BY_SP.get(state.session.sp or "", set())
    return False


def _expected_get_acl(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetACL requires an open session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, reason="GetACL is invoked on the AccessControl table", confidence="medium")
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED, FAIL}, reason="GetACL references an unknown InvokingID/MethodID association", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="GetACL is permitted by Opal GetACLACL preconfiguration for known associations", confidence="medium")


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
    if not _method_supported_in_session(state, event):
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} is not supported in {state.session.sp}",
            confidence="high",
        )
    if event.method == "Authenticate":
        return _expected_authenticate(state, event)
    if event.method == "GetACL":
        return _expected_get_acl(state, event)
    if event.method == "Get":
        return _expected_get(state, event)
    if event.method == "Set":
        return _expected_set(state, event)
    if event.method == "CreateRow":
        return _expected_create_row(state, event)
    if event.method == "DeleteRow":
        return _expected_delete_row(state, event)
    if event.method == "Activate":
        return _expected_activate(state, event)
    if event.method == "GenKey":
        return _expected_genkey(state, event)
    if event.method == "Sign":
        return _expected_sign(state, event)
    if event.method == "FirmwareAttestation":
        return _expected_firmware_attestation(state, event)
    if event.method in {"Revert", "RevertSP"}:
        return _expected_revert(state, event)
    if event.method in {"EndSession", "CloseSession"}:
        if not state.session.open:
            return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason=f"{event.method} is valid for closing the open session", confidence="high")
    if event.method == "SyncSession":
        if not state.session.open:
            return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, reason="SyncSession requires an open session", confidence="medium")
        return ExpectedResponse({SUCCESS}, reason="SyncSession is valid in an open session", confidence="medium")
    if event.method == "Next":
        return _expected_next(state, event)
    if event.method == "Random":
        return _expected_random(state, event)
    return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Method is outside the implemented Opal MethodID universe", confidence="medium")


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


def _expected_host_io(state: State, event: Event) -> ExpectedResponse:
    if _reset_event_type(event.method) is not None:
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
        if actual == SUCCESS and expected.expected_return_length is not None:
            actual_length = _return_payload_length(_output_return_values(target.raw))
            if actual_length is not None and actual_length != expected.expected_return_length:
                return "FAIL"
        return "PASS"
    return "FAIL"


def judge_target(state: State, event: Event) -> str:
    return compare_expected_actual(expected_status(state, event), event)


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
    if event.sp == "LockingSP":
        state.locking_sp_activated = True
    state.session = Session(
        open=True,
        sp=event.sp,
        write=event.write_session,
        authenticated=authenticated,
    )


def _apply_get_success(state: State, event: Event) -> None:
    symbol = event.invoking_symbol
    returned = _flatten_return_values(_output_return_values(event.raw), symbol)

    if symbol == "C_PIN_MSID" and PIN_COLUMN in returned:
        state.pins["MSID"] = _credential_text(returned[PIN_COLUMN])
        return

    if symbol == "LockingSP" and 6 in returned:
        lifecycle_value = returned[6]
        lifecycle = _parse_int(lifecycle_value)
        if lifecycle is not None:
            state.observed_sp_lifecycle["LockingSP"] = lifecycle
        active = _sp_lifecycle_active(lifecycle_value)
        if active is not None:
            state.locking_sp_activated = active
        return

    if symbol == "LockingInfo":
        for column, value in returned.items():
            if column in LOCKING_INFO_COLUMNS:
                state.locking_info[LOCKING_INFO_COLUMNS[column]] = value
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
        return

    authority = _authority_by_object(symbol)
    if authority and 5 in event.values:
        state.authority_enabled[authority] = _as_bool(event.values[5])
        return

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        _update_range_from_columns(_range(state, range_id), event.values)
        return

    if symbol == "MBRControl":
        for column, value in event.values.items():
            if column in MBR_COLUMNS:
                state.mbr[MBR_COLUMNS[column]] = value


def _apply_create_row_success(state: State, event: Event) -> None:
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return
    range_id = _created_locking_range_id(state, event)
    range_state = _range(state, range_id)
    _update_range_from_columns(range_state, event.values)


def _apply_delete_row_success(state: State, event: Event) -> None:
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return
    refs = _row_object_refs(event) or [(_object_by_uid(uid), uid) for uid in _row_uids(event)]
    for symbol, uid in refs:
        range_id = _range_id_from_symbol(symbol) if symbol else _range_id_from_symbol(_object_by_uid(uid))
        if range_id is None or range_id == 0:
            continue
        state.ranges.pop(range_id, None)
        state.range_read_lock_users.pop(range_id, None)
        state.range_write_lock_users.pop(range_id, None)
        state.lba_patterns = {
            lba: remembered
            for lba, remembered in state.lba_patterns.items()
            if remembered[1] != range_id
        }


def _invalidate_lba_patterns(state: State, keep_global: bool = False) -> None:
    state.lba_patterns = {
        lba: (pattern, range_id, generation if keep_global and range_id == 0 else -1)
        for lba, (pattern, range_id, generation) in state.lba_patterns.items()
    }


def _reset_locking_sp(state: State, keep_global_key: bool = False) -> None:
    global_generation = _range(state, 0).media_generation
    state.locking_sp_activated = False
    state.authority_enabled = {k: v for k, v in state.authority_enabled.items() if not k.startswith(("User", "Admin"))}
    state.pins = {k: v for k, v in state.pins.items() if not k.startswith(("User", "Admin"))}
    state.ranges = {}
    state.range_read_lock_users.clear()
    state.range_write_lock_users.clear()
    state.datastore_read_users.clear()
    state.datastore_write_users.clear()
    state.ace_expressions.clear()
    if keep_global_key:
        _range(state, 0).media_generation = global_generation
    else:
        _range(state, 0).media_generation = global_generation + 1
    _invalidate_lba_patterns(state, keep_global=keep_global_key)


def _reset_factory_state(state: State) -> None:
    msid_pin = state.pins.get("MSID")
    global_generation = _range(state, 0).media_generation
    state.pins.clear()
    if msid_pin is not None:
        state.pins["MSID"] = msid_pin
        state.pins["SID"] = msid_pin
    state.authority_enabled.clear()
    state.locking_sp_activated = False
    state.observed_sp_lifecycle.clear()
    state.locking_info.clear()
    state.ranges = {}
    state.range_read_lock_users.clear()
    state.range_write_lock_users.clear()
    state.datastore_read_users.clear()
    state.datastore_write_users.clear()
    state.ace_expressions.clear()
    state.mbr.clear()
    _range(state, 0).media_generation = global_generation + 1
    _invalidate_lba_patterns(state)


def _apply_reset_event(state: State, reset_type: int) -> None:
    state.session = Session()
    for range_state in state.ranges.values():
        if reset_type in range_state.lock_on_reset_types:
            if range_state.read_lock_enabled:
                range_state.read_locked = True
            if range_state.write_lock_enabled:
                range_state.write_locked = True
    if reset_type in _reset_types(state.mbr.get("DoneOnReset")):
        state.mbr["Done"] = 0


def apply_transition(state: State, event: Event) -> None:
    reset_type = _reset_event_type(event.method)
    if event.kind == "host_io" and event.is_success and reset_type is not None:
        _apply_reset_event(state, reset_type)
        return

    if event.method in {"EndSession", "CloseSession"} and event.is_success:
        state.session = Session()
        return

    if event.method == "StartSession" and event.is_success:
        _apply_start_session_success(state, event)
        return

    if not event.is_success:
        return

    if event.method == "Authenticate":
        authority = _auth_from_authenticate_event(event)
        if authority:
            state.session.authenticated.add(authority)
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
        _apply_set_success(state, event)
        return

    if event.method == "CreateRow":
        _apply_create_row_success(state, event)
        return

    if event.method == "DeleteRow":
        _apply_delete_row_success(state, event)
        return

    if event.method == "Activate" and event.invoking_symbol == "LockingSP":
        state.locking_sp_activated = True
        if "SID" in state.pins:
            state.pins["Admin1"] = state.pins["SID"]
        elif "MSID" in state.pins and "Admin1" not in state.pins:
            state.pins["Admin1"] = state.pins["MSID"]
        return

    if event.method == "GenKey":
        range_id = _range_id_from_key(event.invoking_symbol)
        if range_id is not None:
            _range(state, range_id).media_generation += 1
        return

    if event.method in {"Revert", "RevertSP"}:
        if event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP":
            _reset_factory_state(state)
        elif state.session.sp == "LockingSP" or event.invoking_symbol == "LockingSP":
            keep = _keep_global_range_key(event)
            _reset_locking_sp(state, keep_global_key=keep)
        else:
            sid_pin = state.pins.get("SID")
            msid_pin = state.pins.get("MSID")
            state.pins.clear()
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
