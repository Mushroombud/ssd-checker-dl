"""Parsing, normalization, and TCGstorageAPI log decoding helpers."""

from __future__ import annotations

import re
from typing import Any

from .constants import *
from .models import *


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


def _credential_length(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, dict):
        for key in ("plainText", "PlainText", "plaintext", "PIN", "pin", "HostChallenge", "Challenge", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                return _credential_length(item)
        if len(value) == 1:
            return _credential_length(next(iter(value.values())))
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _credential_length(value[0])
    return len(_credential_text(value).encode("utf-8"))


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

    method = _method_by_uid(uid)
    if method is not None:
        return f"MethodID_{method}"

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

    sp_templates_index = _uid_suffix_index(uid, "000000030000")
    if sp_templates_index is not None:
        return f"SPTemplates_{sp_templates_index}"

    secret_protect_index = _uid_suffix_index(uid, "0000001D000000")
    if secret_protect_index is not None:
        return f"SecretProtect_{secret_protect_index}"

    template_index = _uid_suffix_index(uid, "000002040000")
    if template_index is not None:
        return f"Template_{template_index}"

    tls_psk_index = _uid_suffix_index(uid, "0000001E000000")
    if tls_psk_index is not None:
        return f"TLS_PSK_Key{tls_psk_index - 1}"

    port_index = _uid_suffix_index(uid, "000100020001")
    if port_index is not None:
        return f"Port{port_index}"

    access_control_index = _uid_suffix_index(uid, "0000000700")
    if access_control_index is not None:
        return f"AccessControl_{uid[-8:]}"

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
        "SPTemplates": "SPTemplatesTable",
        "Template": "TemplateTable",
        "SP": "SPTable",
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
        "SPTemplatesTable",
        "TemplateTable",
        "SPTable",
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
        "SUCCESSCODE": SUCCESS,
        "0": SUCCESS,
        "PASS": "PASS",
        "FAIL": FAIL,
        "NOTAUTHORIZED": NOT_AUTHORIZED,
        "1": NOT_AUTHORIZED,
        "OBSOLETE": FAIL,
        "OBSOLETECODE": FAIL,
        "2": FAIL,
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
    for prefix in ("STATUSCODE", "PYSEDSTATUSCODE", "TCGSTATUSCODE"):
        if key.startswith(prefix):
            stripped = key.removeprefix(prefix)
            if stripped in aliases:
                return aliases[stripped]
    for alias, normalized in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        if alias and alias != "0" and alias in key:
            return normalized
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


def _is_bool_literal(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return value in {0, 1}
    text = _as_text(value).strip().lower()
    return text in {"0", "1", "true", "false"}


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


def _reset_list_invalid(value: Any) -> bool:
    reset_types = _reset_types(value)
    if not reset_types:
        return False
    return 0 not in reset_types or not reset_types <= {0, 1, 3}


def _reset_event_type(method: str) -> int | None:
    text = re.sub(r"[^A-Za-z0-9]+", "", _as_text(method or "")).upper()
    if text in {"POWERCYCLE", "POWERRESET", "COLDRESET"}:
        return 0
    if text in {"HARDWARERESET", "HWRESET"}:
        return 1
    if text in {"PROTOCOLSTACKRESET", "STACKRESET", "TCGRESET"}:
        return PROTOCOL_STACK_RESET
    if text in {"TPERRESET", "PROGRAMMATICRESET"}:
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
    if symbol == "SPInfo":
        spinfo_names = {
            "SPSESSIONTIMEOUT": 5,
            "ENABLED": 6,
        }
        if key in spinfo_names:
            return spinfo_names[key]
    if symbol in {"AdminSP", "LockingSP"} and key == "FROZEN":
        return 7
    common_object_names = {
        "UID": 0,
        "NAME": 1,
        "COMMONNAME": 2,
    }
    if key in common_object_names:
        return common_object_names[key]
    if symbol.startswith("ACE_"):
        ace_names = {
            "BOOLEANEXPR": ACE_BOOLEAN_EXPR_COLUMN,
            "BOOLEANEXPRESSION": ACE_BOOLEAN_EXPR_COLUMN,
            "COLUMNS": ACE_COLUMNS_COLUMN,
        }
        if key in ace_names:
            return ace_names[key]
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
    if key == "ACTIVEDATAREMOVALMECHANISM" and symbol == "DataRemovalMechanism":
        return 1
    if key == "PROGRAMMATICRESETENABLE" and symbol == "TPerInfo":
        return 8
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


def _authas_credential_arg(required: dict[str, Any], optional: dict[str, Any], raw_args: Any) -> Any:
    def from_value(value: Any) -> Any:
        if isinstance(value, dict):
            found, item = _dict_lookup(value, "AuthAs", "authAs")
            if found:
                return from_value(item)
            found, item = _dict_lookup(
                value,
                "Credential",
                "credential",
                "Cred",
                "cred",
                "PIN",
                "pin",
                "HostChallenge",
                "Challenge",
                "plainText",
                "PlainText",
            )
            if found:
                return item
            authority = _authority_from_value(_mapping_value(value, "Authority", "HostSigningAuthority", "auth", "Auth"))
            if authority is not None:
                found, item = _dict_lookup(value, "Value", "value")
                if found:
                    return item
            for item in value.values():
                found = from_value(item)
                if found is not None:
                    return found
            return None
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower() in {"authas", "hostsigningauthority"}:
                return from_value(value[1])
            if len(value) >= 2 and _authority_from_value(value[0]) is not None:
                return value[1]
            if len(value) >= 2 and _unspecified_authority(value[0]):
                return value[1]
            for item in value:
                found = from_value(item)
                if found is not None:
                    return found
        return None

    for source in (required, optional):
        found, value = _dict_lookup(source, "AuthAs", "authAs")
        if found:
            credential = from_value(value)
            if credential is not None:
                return credential
    if isinstance(raw_args, dict):
        credential = from_value(raw_args)
        if credential is not None:
            return credential
    return from_value(raw_args)


def _unspecified_authority(value: Any) -> bool:
    if value is None:
        return True
    text = _as_text(value).strip().lower()
    return text in {"", "none", "null"}


def _authas_pairs(required: dict[str, Any], optional: dict[str, Any], raw_args: Any) -> list[tuple[str | None, Any]]:
    sources: list[Any] = []
    for source in (required, optional):
        found, value = _dict_lookup(source, "AuthAs", "authAs")
        if found:
            sources.append(value)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, "AuthAs", "authAs")
        if found:
            sources.append(value)
    found, value = _sequence_named_arg_value(raw_args, "AuthAs", "authAs")
    if found:
        sources.append(value)

    pairs: list[tuple[str | None, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            found, nested = _dict_lookup(value, "AuthAs", "authAs")
            if found:
                walk(nested)
                return
            found_authority, raw_authority = _dict_lookup(value, "Authority", "HostSigningAuthority", "auth", "Auth")
            authority = _authority_from_value(raw_authority) if found_authority else None
            credential = _authas_credential_arg({}, {"authAs": value}, None)
            if authority is not None and credential is not None:
                pairs.append((authority, credential))
                return
            if found_authority and _unspecified_authority(raw_authority) and credential is not None:
                pairs.append((None, credential))
                return
            for item in value.values():
                walk(item)
            return
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower() in {"authas", "hostsigningauthority"}:
                walk(value[1])
                return
            if len(value) >= 2 and not isinstance(value[0], (dict, list, tuple, set)):
                authority = _authority_from_value(value[0])
                if authority is not None:
                    pairs.append((authority, value[1]))
                    return
                if _unspecified_authority(value[0]):
                    pairs.append((None, value[1]))
                    return
            for item in value:
                walk(item)

    for source in sources:
        walk(source)
    return pairs


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
        "Table_TPerInfo",
        "Table_Template",
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
        "TPerSign",
        "TperAttestation",
        "TPerInfo",
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
        or symbol.startswith("AccessControl_")
        or symbol.startswith("MethodID_")
        or symbol.startswith("SecretProtect_")
        or symbol.startswith("SPTemplates_")
        or symbol.startswith("Template_")
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
        "SPTemplatesTable": "SPTemplates",
        "TemplateTable": "Template",
        "SPTable": "SP",
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
    if family == "AccessControl":
        return not (row_symbol.startswith("AccessControl_") or (uid.startswith("00000007") and uid != "0000000700000000"))
    if family == "SecretProtect":
        return not row_symbol.startswith("SecretProtect_")
    if family == "SPTemplates":
        return not row_symbol.startswith("SPTemplates_")
    if family == "Template":
        return not row_symbol.startswith("Template_")
    if family == "SP":
        return not (row_symbol in {"AdminSP", "LockingSP"} or row_symbol.startswith("UnknownSP_") or uid.startswith("00000205"))
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


def _cellblock_columns(required: dict[str, Any], raw_args: Any = None, method: str = "") -> set[int]:
    columns: set[int] = set()

    def add_bounds(start: int | None, end: int | None) -> None:
        if start is not None and end is not None:
            columns.update(range(min(start, end), max(start, end) + 1))
        elif start is not None:
            columns.add(start)
        elif end is not None:
            columns.add(end)

    def bounds_from_mapping(item: dict[str, Any]) -> tuple[int | None, int | None]:
        start: int | None = None
        end: int | None = None
        found, start_value = _dict_lookup(item, "startColumn", "StartColumn", "start_column", "startCol", "StartCol")
        if found:
            start = _parse_int(start_value)
        found, end_value = _dict_lookup(item, "endColumn", "EndColumn", "end_column", "endCol", "EndCol")
        if found:
            end = _parse_int(end_value)
        return start, end

    def add_from_cellblock(cellblock: Any) -> None:
        if isinstance(cellblock, dict):
            cellblock = [cellblock]
        if not isinstance(cellblock, list):
            return
        start: int | None = None
        end: int | None = None
        for item in cellblock:
            if not isinstance(item, dict):
                continue
            item_start, item_end = bounds_from_mapping(item)
            start = item_start if item_start is not None else start
            end = item_end if item_end is not None else end
        add_bounds(start, end)

    add_from_cellblock(_mapping_value(required, "Cellblock", "CellBlock"))
    add_bounds(*bounds_from_mapping(required))

    if raw_args is not None:
        if isinstance(raw_args, dict):
            add_from_cellblock(_mapping_value(raw_args, "Cellblock", "CellBlock"))
            add_bounds(*bounds_from_mapping(raw_args))
        found_start, raw_start = _sequence_named_arg_value(raw_args, "startColumn", "StartColumn", "start_column", "startCol", "StartCol")
        found_end, raw_end = _sequence_named_arg_value(raw_args, "endColumn", "EndColumn", "end_column", "endCol", "EndCol")
        if found_start or found_end:
            add_bounds(_parse_int(raw_start) if found_start else None, _parse_int(raw_end) if found_end else None)
        if method == "Get" and not isinstance(raw_args, dict):
            start: int | None = None
            end: int | None = None

            def walk_no_named(value: Any) -> None:
                nonlocal start, end
                if isinstance(value, dict):
                    for key, val in value.items():
                        parsed = _parse_int(key)
                        if parsed == 3:
                            start = _parse_int(val)
                        elif parsed == 4:
                            end = _parse_int(val)
                        else:
                            walk_no_named(val)
                    return
                if isinstance(value, (list, tuple)):
                    if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                        parsed = _parse_int(value[0])
                        if parsed == 3:
                            start = _parse_int(value[1])
                            return
                        if parsed == 4:
                            end = _parse_int(value[1])
                            return
                    for item in value:
                        walk_no_named(item)

            walk_no_named(raw_args)
            add_bounds(start, end)

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
    columns = _cellblock_columns(required, raw_args, method)
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
    if challenge is None:
        challenge = _authas_credential_arg(required, optional, raw_args)
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



__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
