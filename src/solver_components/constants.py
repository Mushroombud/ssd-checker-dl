"""Protocol constants and offline Opal UID tables for the solver."""

SUCCESS = "SUCCESS"


NOT_AUTHORIZED = "NOT_AUTHORIZED"


INVALID_PARAMETER = "INVALID_PARAMETER"


INSUFFICIENT_SPACE = "INSUFFICIENT_SPACE"


INSUFFICIENT_ROWS = "INSUFFICIENT_ROWS"


FAIL = "FAIL"


PROTOCOL_STACK_RESET = -1


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
    "0000000100000000": "Table",
    "0000000100000001": "Table",
    "0000000100000002": "Table_SPInfo",
    "0000000100000003": "Table_SPTemplates",
    "0000000100000006": "Table_MethodID",
    "0000000100000007": "Table_AccessControl",
    "0000000100000008": "Table_ACE",
    "0000000100000009": "Table_Authority",
    "000000010000000B": "Table_C_PIN",
    "000000010000001D": "Table_SecretProtect",
    "0000000100000201": "Table_TPerInfo",
    "0000000100000204": "Table_Template",
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
    "0000000300000000": "SPTemplatesTable",
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
    "0000020100030001": "TPerInfo",
    "0000020400000000": "TemplateTable",
    "0000020500000000": "SPTable",
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
    "AdminSP": {"Next", "GetACL", "AddACE", "RemoveACE", "SetACL", "Get", "Set", "CreateRow", "DeleteRow", "GetFreeSpace", "GetFreeRows", "Authenticate", "Revert", "RevertSP", "Activate", "Random", "Sign", "FirmwareAttestation", "Erase"},
    "LockingSP": {"Next", "GetACL", "AddACE", "RemoveACE", "SetACL", "GenKey", "RevertSP", "Get", "Set", "CreateRow", "DeleteRow", "GetFreeSpace", "GetFreeRows", "Authenticate", "Random", "Erase"},
}


UNSUPPORTED_OPAL_METHODS = {
    "CreateTable",
    "DeleteSP",
    "Delete",
    "DeleteMethod",
}


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


ACCESS_CONTROL_ACL_COLUMN = 4
PUBLIC_COMMON_NAME_COLUMNS = {0, 2}


ADMIN_ONLY_TABLE_ROWS = {
    "Table_TPerInfo",
    "Table_Template",
    "Table_SP",
    "Table_DataRemovalMechanism",
}


LOCKING_ONLY_TABLE_ROWS = {
    "Table_SecretProtect",
    "Table_LockingInfo",
    "Table_Locking",
    "Table_MBRControl",
    "Table_MBR",
    "Table_K_AES_128",
    "Table_K_AES_256",
    "Table_DataStore",
}


DATA_REMOVAL_MECHANISM_VALUES = {
    0: "Overwrite Data Erase",
    1: "Block Erase",
    2: "Cryptographic Erase",
    5: "Vendor Specific Erase",
}


ACE_BOOLEAN_EXPR_COLUMN = 3


ACE_COLUMNS_COLUMN = 4


K_AES_KEY_COLUMN = 3


K_AES_MODE_COLUMN = 4



__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
