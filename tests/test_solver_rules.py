import unittest

from src.solver import predict_trajectory


SID = "0000000900000006"
ADMIN1 = "0000000900010001"
ADMIN_SP = "0000020500000001"
LOCKING_SP = "0000020500000002"
SID_INT = int(SID, 16)
ADMIN1_INT = int(ADMIN1, 16)
ADMIN_SP_INT = int(ADMIN_SP, 16)
LOCKING_SP_INT = int(LOCKING_SP, 16)


def method_record(method, uid="", name="", status="SUCCESS", required=None, optional=None, return_values=None):
    return {
        "input": {
            "method": {
                "name": method,
                "args": {
                    "required": required or {},
                    "optional": optional or {},
                },
            },
            "invoking_id": {"uid": uid, "name": name},
        },
        "output": {
            "status_codes": status,
            "return_values": [] if return_values is None else return_values,
        },
    }


def raw_method_record(method, uid="", name="", status="SUCCESS", args=None, return_values=None):
    return {
        "input": {
            "method": {
                "name": method,
                "args": args,
            },
            "invoking_id": {"uid": uid, "name": name},
        },
        "output": {
            "status_codes": status,
            "return_values": [] if return_values is None else return_values,
        },
    }


def start_session(spid, authority=None, challenge=None, status="SUCCESS"):
    optional = {}
    if authority:
        optional["HostSigningAuthority"] = authority
    if challenge:
        optional["HostChallenge"] = challenge
    return method_record(
        "StartSession",
        "00000000000000FF",
        "Session Manager UID",
        status,
        {"SPID": spid, "Write": 1},
        optional,
        {"required": {"HostSessionID": "00000001", "SPSessionID": "00000001"}, "optional": {}},
    )


def end_session():
    return method_record("EndSession")


def host_write(pattern="8E", lba="80 ~ 87"):
    return {
        "input": {"command": "Write", "args": {"LBA": lba, "pattern": pattern}},
        "output": {"command": "Write"},
    }


def host_read(result, lba="80 ~ 87"):
    return {
        "input": {"command": "Read", "args": {"LBA": lba}},
        "output": {"command": "Read", "args": {"result": result}},
    }


def host_write_status(status, pattern="AA", lba="80 ~ 87"):
    return {
        "input": {"command": "Write", "args": {"LBA": lba, "pattern": pattern}},
        "output": {"command": "Write", "status": status},
    }


def host_read_status(status, lba="80 ~ 87"):
    return {
        "input": {"command": "Read", "args": {"LBA": lba}},
        "output": {"command": "Read", "status": status},
    }


def host_reset(command="PowerCycle"):
    return {
        "input": {"command": command, "args": {}},
        "output": {"command": command, "result": "pass"},
    }


def owned_admin_context():
    return [
        start_session(ADMIN_SP),
        method_record("Get", "0000000B00008402", "C_PIN", return_values=[[{"3": "MSID"}]]),
        end_session(),
        start_session(ADMIN_SP, SID, "old"),
        method_record("Set", "0000000B00000001", "C_PIN", optional={"Values": [{"3": "new"}]}),
        end_session(),
    ]


def activated_locking_context():
    return owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        method_record("Activate", "0000020500000002", "SP"),
        end_session(),
    ]


class SolverRuleTests(unittest.TestCase):
    def test_credential_update_success_controls_later_auth(self):
        trajectory = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_named_sp_and_authority_are_accepted_in_start_session(self):
        trajectory = owned_admin_context() + [start_session("AdminSP", "SID", "new")]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_rejects_non_session_manager_target_success(self):
        record = start_session(ADMIN_SP)
        record["input"]["invoking_id"] = {"uid": "0000020500000001", "name": "AdminSP"}
        self.assertEqual(predict_trajectory([record]), "FAIL")

    def test_properties_rejects_non_session_manager_target_success(self):
        trajectory = [method_record("Properties", "0000020500000001", "AdminSP", "SUCCESS")]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_method_uid_string_without_name_is_mapped(self):
        record = method_record("unused", "0000000B00008402", "C_PIN", "SUCCESS", return_values=[[{"3": "MSID"}]])
        record["input"]["method"] = "0000000600000006"
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tcg_output_result_is_used_as_status_when_status_field_missing(self):
        record = method_record("Get", "0000000B00008402", "C_PIN", "SUCCESS", return_values=[[{"3": "MSID"}]])
        record["output"].pop("status_codes")
        record["output"]["args"] = {"result": "SUCCESS"}
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_method_uid_int_without_name_is_mapped(self):
        record = method_record("unused", "0000000B00008402", "C_PIN", "SUCCESS", return_values=[[{"3": "MSID"}]])
        record["input"]["method"] = int("0000000600000006", 16)
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_input_level_args_are_parsed_when_method_is_string(self):
        record = start_session(ADMIN_SP, SID, "new")
        args = record["input"]["method"]["args"]
        record["input"]["method"] = "StartSession"
        record["input"]["args"] = args
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_end_session_target_is_valid_when_session_open(self):
        trajectory = [start_session(ADMIN_SP), end_session()]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_end_session_without_open_session_rejects_success(self):
        trajectory = [end_session()]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_start_session_accepts_generic_challenge_field(self):
        record = start_session("AdminSP", "SID", None)
        record["input"]["method"]["args"]["optional"]["Challenge"] = "new"
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_required_authority_field(self):
        record = start_session(ADMIN_SP, None, "new")
        record["input"]["method"]["args"]["required"]["HostSigningAuthority"] = SID
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_named_sequence_args(self):
        record = raw_method_record(
            "StartSession",
            "00000000000000FF",
            "Session Manager UID",
            args=[("SPID", ADMIN_SP), ("Write", 1), ("HostSigningAuthority", SID), ("HostChallenge", "new")],
        )
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_bytes_required_optional_keys(self):
        record = raw_method_record(
            "StartSession",
            "00000000000000FF",
            "Session Manager UID",
            args={
                b"required": {b"SPID": ADMIN_SP, b"Write": 1},
                b"optional": {b"HostSigningAuthority": SID, b"HostChallenge": "new"},
            },
        )
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_bytes_challenge_matching_tracked_pin(self):
        trajectory = owned_admin_context() + [start_session(ADMIN_SP, SID, b"new")]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_authas_tuple_credential(self):
        record = start_session(ADMIN_SP, None, None)
        record["input"]["method"]["args"]["optional"]["authAs"] = ("SID", "new")
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_named_sequence_authas_tuple(self):
        record = raw_method_record(
            "StartSession",
            "00000000000000FF",
            "Session Manager UID",
            args=[("SPID", ADMIN_SP), ("Write", 1), ("authAs", ("SID", "new"))],
        )
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_accepts_tcgstorageapi_positional_args(self):
        record = raw_method_record(
            "StartSession",
            "00000000000000FF",
            "Session Manager UID",
            args=[100, ADMIN_SP_INT, 1],
        )
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_start_session_positional_write_flag_controls_later_set(self):
        record = raw_method_record(
            "StartSession",
            "00000000000000FF",
            "Session Manager UID",
            args=[100, ADMIN_SP_INT, 0],
        )
        trajectory = [record, method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "new"}]})]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_authenticate_accepts_plaintext_challenge_object(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Authenticate", "0000020500000001", "SP", "SUCCESS", required={"Authority": "SID", "Challenge": {"plainText": "new"}}),
            method_record("Set", "0000000B00000001", "C_PIN", optional={"Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authenticate_accepts_authas_tuple_credential(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Authenticate", "0000020500000001", "SP", "SUCCESS", optional={"authAs": ("SID", "new")}),
            method_record("Set", "0000000B00000001", "C_PIN", optional={"Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_method_level_authas_authorizes_target_set(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"authAs": ("SID", "new"), "Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_method_level_authas_none_infers_cpin_sid_default(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"authAs": (None, "new"), "Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_method_level_authas_rejects_target_set_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"authAs": ("SID", "wrong"), "Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_wrong_method_level_authas_none_rejects_target_set_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"authAs": (None, "wrong"), "Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_method_level_authas_authorizes_target_genkey(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("GenKey", "0000080600030001", "K_AES_256", "SUCCESS", optional={"authAs": ("Admin1", "new")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authas_none_uses_matching_admin_for_genkey(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("GenKey", "0000080600030001", "K_AES_256", "SUCCESS", optional={"authAs": (None, "new")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_authas_none_rejects_genkey_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("GenKey", "0000080600030001", "K_AES_256", "SUCCESS", optional={"authAs": (None, "wrong")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_authas_none_uses_matching_admin_for_user_cpin_set(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Set", "0000000B00030001", "C_PIN", "SUCCESS", optional={"authAs": (None, "new"), "Values": [{"3": "userpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_authas_none_rejects_user_cpin_set_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Set", "0000000B00030001", "C_PIN", "SUCCESS", optional={"authAs": (None, "wrong"), "Values": [{"3": "userpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_locking_sp_start_session_rejects_sid_authority_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, SID, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_locking_sp_authenticate_rejects_sid_authority_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Authenticate", "0000000000000001", "ThisSP", "SUCCESS", optional={"authAs": ("SID", "new")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_authas_none_uses_matching_sid_for_activate(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Activate", "0000020500000002", "SP", "SUCCESS", optional={"authAs": (None, "new")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_authas_none_rejects_activate_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Activate", "0000020500000002", "SP", "SUCCESS", optional={"authAs": (None, "wrong")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_cpin_sid_full_row_get_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000000B00000001", "C_PIN", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_cpin_admin_full_row_get_rejects_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000000B00010001", "C_PIN", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_outer_bytes_schema_and_return_alias_update_lifecycle(self):
        lifecycle_get = {
            b"input": {
                b"method": {
                    b"name": b"Get",
                    b"args": {
                        b"required": {b"Cellblock": [{b"startColumn": 6, b"endColumn": 6}]},
                        b"optional": {},
                    },
                },
                b"invoking_id": {b"uid": b"0000020500000002", b"name": b"SP"},
            },
            b"output": {
                b"StatusCodes": b"SUCCESS",
                b"args": {b"returnValues": {b"LifeCycle": "Manufactured"}},
            },
        }
        trajectory = [start_session(ADMIN_SP), lifecycle_get, end_session(), start_session(LOCKING_SP)]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bytes_cellblock_columns_protect_c_pin_pin_get(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "Get",
                "0000000B00000001",
                "C_PIN",
                "SUCCESS",
                required={b"Cellblock": [{b"startColumn": 3, b"endColumn": 3}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_set_accepts_bytes_values_key_for_pin_update(self):
        trajectory = [
            start_session(ADMIN_SP),
            method_record("Get", "0000000B00008402", "C_PIN", return_values=[[{"3": "MSID"}]]),
            end_session(),
            start_session(ADMIN_SP, SID, "old"),
            method_record("Set", "0000000B00000001", "C_PIN", optional={b"Values": [{b"PIN": "new"}]}),
            end_session(),
            start_session(ADMIN_SP, SID, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_raw_opal_authenticate_adds_authority(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            raw_method_record(
                "Authenticate",
                "0000000000000001",
                "ThisSP",
                args=(ADMIN1_INT, [(0, "new")]),
            ),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"7": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_structured_sp_and_authority_are_accepted(self):
        record = start_session({"uid": ADMIN_SP, "name": "AdminSP"}, {"uid": SID, "name": "SID"}, "new")
        trajectory = owned_admin_context() + [record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bytes_named_msid_pin_return_updates_sid_pin(self):
        trajectory = [
            start_session(ADMIN_SP),
            method_record("Get", "0000000B00008402", "C_PIN", return_values={b"PIN": "MSID"}),
            end_session(),
            start_session(ADMIN_SP, SID, "MSID"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_numeric_uid_sp_and_authority_are_accepted(self):
        trajectory = owned_admin_context() + [start_session(ADMIN_SP_INT, SID_INT, "new")]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_ascii_bytes_uid_is_treated_as_hex_uid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", b"0000000B00008401", "C_PIN", "SUCCESS", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP, b"0000000900008401", "erasepin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_numeric_invoking_uid_updates_pin_state(self):
        trajectory = owned_admin_context()[:-2] + [
            start_session(ADMIN_SP, SID, "old"),
            method_record("Set", int("0000000B00000001", 16), "C_PIN", optional={"Values": [{3: "new"}]}),
            end_session(),
            start_session(ADMIN_SP, SID, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_named_pin_argument_updates_pin_state(self):
        trajectory = owned_admin_context()[:-2] + [
            start_session(ADMIN_SP, SID, "old"),
            method_record("Set", "0000000B00000001", "C_PIN", optional={"PIN": "new"}),
            end_session(),
            start_session(ADMIN_SP, SID, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_numeric_tcg_status_code_is_normalized(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", 1, optional={"Values": [{"3": "new"}]})
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_raw_status_byte_is_normalized(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", b"\x01", optional={"Values": [{"3": "new"}]})
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tcgstorageapi_numeric_13_status_is_auth_failure(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", 13, optional={"Values": [{"3": "new"}]})
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authority_locked_out_status_is_auth_failure(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", "AuthorityLockedOut", optional={"Values": [{"3": "new"}]})
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_hex_status_text_is_normalized(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", "0x12", optional={"Values": [{"3": "new"}]})
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tcg_status_field_is_used_when_status_codes_absent(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", optional={"Values": [{"3": "new"}]})
        record["output"]["status"] = "NotAuthorized"
        del record["output"]["status_codes"]
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_statuscode_enum_string_is_normalized(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", "StatusCode.NotAuthorized", optional={"Values": [{"3": "new"}]})
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_statuscode_repr_string_is_normalized(self):
        record = method_record("Set", "0000000B00000001", "C_PIN", "<StatusCode.InvalidParameter: 12>", optional={"Values": [{"4": "UTF-8"}]})
        trajectory = [start_session(ADMIN_SP, SID, "new"), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_obsolete_status_is_treated_as_failure_status(self):
        record = method_record("CreateTable", "0000000000000001", "ThisSP", "StatusCode.Obsolete")
        trajectory = [start_session(ADMIN_SP), record]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_failed_credential_update_does_not_change_pin(self):
        trajectory = owned_admin_context()[:-2] + [
            method_record("Set", "0000000B00000001", "C_PIN", "NOT_AUTHORIZED", optional={"Values": [{"3": "new"}]}),
            end_session(),
            start_session(ADMIN_SP, SID, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_erase_master_pin_uid_updates_later_auth(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN", "SUCCESS", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP, "0000000900008401", "erasepin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_initial_erase_master_pin_can_be_changed_with_observed_msid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", "SUCCESS", optional={"authAs": (None, "MSID"), "Values": [{"3": "erasepin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_initial_erase_master_default_pin_rejects_success_when_msid_known(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", "SUCCESS", optional={"authAs": (None, "wrong"), "Values": [{"3": "erasepin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_initial_bandmaster_pin_can_be_changed_with_observed_msid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00008001", "C_PIN_BandMaster1", "SUCCESS", optional={"authAs": (None, "MSID"), "Values": [{"3": "bandpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_initial_bandmaster_default_pin_rejects_success_when_msid_known(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Set", "0000000B00008001", "C_PIN_BandMaster1", "SUCCESS", optional={"authAs": (None, "wrong"), "Values": [{"3": "bandpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_bare_sid_object_name_updates_pin_state(self):
        trajectory = owned_admin_context()[:-2] + [
            start_session(ADMIN_SP, SID, "old"),
            method_record("Set", "", "SID", optional={"Values": [{"3": "new"}]}),
            end_session(),
            start_session(ADMIN_SP, SID, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_cpin_prefixed_erase_master_name_can_set_enabled_column(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "", "C_PIN_EraseMaster", optional={"Values": [{"5": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_cpin_user_object_name_updates_pin_state(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "", "C_PIN_User1", optional={"Values": [{"3": "userpin"}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bare_user_object_name_enables_authority(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "", "User1", optional={"Values": [{"5": 1}]}),
            method_record("Set", "", "C_PIN_User1", optional={"Values": [{"3": "userpin"}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_cpin_prefixed_user_name_enables_authority_when_setting_enabled(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "", "C_PIN_User1", optional={"Values": [{"5": 1}]}),
            method_record("Set", "", "C_PIN_User1", optional={"Values": [{"3": "userpin"}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_named_authority_get_updates_enabled_state(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "", "User1", return_values={"Enabled": 1}),
            method_record("Set", "", "C_PIN_User1", optional={"PIN": "userpin"}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authority_get_enabled_value_two_is_not_enabled(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "", "User1", return_values={"Enabled": 2}),
            method_record("Set", "", "C_PIN_User1", optional={"PIN": "userpin"}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_band_master_pin_uid_updates_later_auth(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "bandpin"}]}),
            end_session(),
            start_session(ADMIN_SP, "0000000900008001", "bandpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_band_master_pin_set_from_lockingsp_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "bandpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_cpin_msid_set_success_is_invalid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008402", "C_PIN", "SUCCESS", optional={"Values": [{"3": "newmsid"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_cpin_set_rejects_non_pin_column_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"4": "UTF-8"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_set_on_object_table_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000000", "C_PIN", "SUCCESS", optional={"Values": [{"3": "new"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_min_pin_length_set_is_allowed_for_cpin(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"0xFFFF0001": 4}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_min_pin_length_over_cpin_max_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"0xFFFF0001": 33}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_min_pin_length_rejects_short_later_pin_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", optional={"Values": [{"0xFFFF0001": 4}]}),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "abc"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_min_pin_length_allows_long_enough_later_pin_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", optional={"Values": [{"0xFFFF0001": 4}]}),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "abcd"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_min_pin_length_in_same_set_rejects_short_pin_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"0xFFFF0001": 5}, {"3": "abcd"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_min_pin_length_return_value_updates_state(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000000B00000001", "C_PIN", "SUCCESS", required={"Cellblock": [{"startColumn": "0xFFFF0001"}]}, return_values={"_MinPINLength": 4}),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "abc"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_failed_min_pin_length_set_does_not_update_state(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000001", "C_PIN", "NOT_AUTHORIZED", optional={"Values": [{"0xFFFF0001": 4}]}),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "abc"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_min_pin_length_is_per_cpin_owner(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000B00010001", "C_PIN", optional={"Values": [{"0xFFFF0001": 5}]}),
            method_record("Set", "0000000B00030001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "abc"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_admin_sp_admin_pin_uid_is_recognized(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000201", "C_PIN", "SUCCESS", optional={"Values": [{"3": "adminpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_locking_user_pin_uid_from_admin_sp_is_invalid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00030001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "userpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_admin_sp_admin_pin_uid_from_locking_sp_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000B00000201", "C_PIN", "SUCCESS", optional={"Values": [{"3": "adminpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_unauthenticated_protected_set_success_is_invalid(self):
        trajectory = [
            start_session(LOCKING_SP),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"8": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_unauthenticated_protected_set_not_authorized_is_valid(self):
        trajectory = [
            start_session(LOCKING_SP),
            method_record("Set", "0000080200030001", "Locking", "NOT_AUTHORIZED", optional={"Values": [{"8": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_unauthenticated_locking_get_not_authorized_is_valid(self):
        trajectory = [
            start_session(LOCKING_SP),
            method_record(
                "Get",
                "0000080200030001",
                "Locking",
                "NOT_AUTHORIZED",
                required={"Cellblock": [{"startColumn": 3}, {"endColumn": 8}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_named_authority_authenticate_updates_session(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Authenticate", "0000020500000001", "SP", "SUCCESS", required={"Authority": "SID", "Challenge": "new"}),
            method_record("Set", "0000000B00000001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "newer"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_sign_allows_anybody_in_adminsp(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", required={"Data": "payload"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_sign_accepts_name_only_case_variant(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Sign", "", "TperSign", "SUCCESS", required={"Data": "payload"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_sign_accepts_nonamed_payload(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", args=("payload",)),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_sign_accepts_bytes_invoking_name(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Sign", "", b"TPerSign", "SUCCESS", required={"Data": "payload"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_sign_accepts_bytes_data_key(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", required={b"Data": "payload"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_sign_rejects_missing_payload_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_sign_rejects_only_unrelated_named_pair_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", args=(("Algorithm", "RSA"),)),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_sign_rejects_lockingsp_session_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", required={"Data": "payload"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_sign_rejects_oversized_payload_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", required={"Data": "A" * 257}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_sign_rejects_oversized_nonamed_tuple_payload_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Sign", "0000000900000007", "TPerSign", "SUCCESS", args=("A" * 257,)),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_firmware_attestation_allows_anybody_in_adminsp(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("FirmwareAttestation", "000000090001FF05", "TperAttestation", "SUCCESS", required={"AssessorNonce": "23helloseagate"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_firmware_attestation_accepts_nonamed_nonce_with_optional_pairs(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record(
                "FirmwareAttestation",
                "000000090001FF05",
                "TperAttestation",
                "SUCCESS",
                args=("nonce", (0, "subject"), (1, "assessor")),
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_firmware_attestation_rejects_missing_nonce_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("FirmwareAttestation", "000000090001FF05", "TperAttestation", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_firmware_attestation_rejects_only_optional_pairs_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record(
                "FirmwareAttestation",
                "000000090001FF05",
                "TperAttestation",
                "SUCCESS",
                args=((0, "subject"), (1, "assessor")),
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_certificate_byte_table_get_is_allowed(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0001000400000000", "_CertData_TPerSign", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_certificate_byte_table_get_accepts_row_range_args(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Get", "0001001F00000000", "_CertData_TPerAttestation", "SUCCESS", args=[(1, 0), (2, 0x5FF)]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_certificate_byte_table_get_rejects_columns(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0001000400000000", "_CertData_TPerSign", "SUCCESS", required={"Cellblock": [{"startColumn": 1}, {"endColumn": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_certificate_byte_table_get_rejects_column_raw_args(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Get", "0001000400000000", "_CertData_TPerSign", "SUCCESS", args=[(3, 0)]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_certificate_byte_table_set_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0001000400000000", "_CertData_TPerSign", "SUCCESS", optional={"Bytes": "AA"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_random_count_within_opal_limit_is_allowed(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Random", "0000000000000001", "ThisSP", "SUCCESS", args=16, return_values=[bytes(range(16))]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_random_count_over_opal_limit_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Random", "0000000000000001", "ThisSP", "SUCCESS", args=33, return_values=[bytes(range(33))]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_random_success_with_wrong_result_length_is_invalid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Random", "0000000000000001", "ThisSP", "SUCCESS", args=4, return_values=[b"abc"]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_random_missing_count_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Random", "0000000000000001", "ThisSP", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_random_accepts_named_pair_count_args(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Random", "0000000000000001", "ThisSP", "SUCCESS", args=[("Count", 4)], return_values=[b"abcd"]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_accepts_count_on_object_table(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000000B00000000", "C_PIN", "SUCCESS", optional={"Count": 2}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_rejects_byte_table_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Next", "0000100100000000", "DataStore", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_rejects_negative_count_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000000B00000000", "C_PIN", "SUCCESS", optional={"Count": -1}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_rejects_negative_named_pair_count_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            raw_method_record("Next", "0000000B00000000", "C_PIN", "SUCCESS", args=[("Count", -1)]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_rejects_wrong_table_where_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000000B00000000", "C_PIN", "SUCCESS", optional={"Where": "0000080200000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_accepts_name_only_where_on_cpin_table(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000000B00000000", "C_PIN", "SUCCESS", optional={"Where": "SID"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_accepts_name_only_where_on_locking_table(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Next", "0000080200000000", "Locking", "SUCCESS", optional={"Where": "Band1"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_accepts_name_only_where_on_authority_table(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Next", "0000000900000000", "Authority", "SUCCESS", optional={"Where": "User1"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_accepts_name_only_cpin_table(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "", "C_PIN", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_rejects_wrong_template_where_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000020400000000", "Template", "SUCCESS", optional={"Where": "0000000300000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_accepts_template_where(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000020400000000", "Template", "SUCCESS", optional={"Where": "0000020400000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_rejects_wrong_sp_where_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000020500000000", "SP", "SUCCESS", optional={"Where": "0000020400000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_accepts_sp_where(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000020500000000", "SP", "SUCCESS", optional={"Where": "0000020500000002"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_rejects_wrong_access_control_where_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000000700000000", "AccessControl", "SUCCESS", optional={"Where": "0000000800000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_accepts_access_control_where(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Next", "0000000700000000", "AccessControl", "SUCCESS", optional={"Where": "0000000700000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_rejects_wrong_secretprotect_where_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Next", "0000001D00000000", "SecretProtect", "SUCCESS", optional={"Where": "0000000800038001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_next_accepts_secretprotect_where(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Next", "0000001D00000000", "SecretProtect", "SUCCESS", optional={"Where": "0000001D0000001D"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_next_rejects_secretprotect_table_in_admin_sp_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Next", "0000001D00000000", "SecretProtect", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_get_free_space_accepts_opal_object_table(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("GetFreeSpace", "0000000B00000000", "C_PIN", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_get_free_space_rejects_sp_object_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("GetFreeSpace", "0000000000000001", "ThisSP", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_get_free_rows_accepts_opal_object_table(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("GetFreeRows", "0000000B00000000", "C_PIN", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_get_free_rows_rejects_byte_table_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("GetFreeRows", "0000100100000000", "DataStore", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_genkey_invalidates_old_plaintext_pattern(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}]}),
            method_record("GenKey", "0000080600030001", "K_AES_256"),
            end_session(),
            host_write("8E"),
            host_read("Pattern 8E"),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("GenKey", "0000080600030001", "K_AES_256"),
            end_session(),
            host_read("8E"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_genkey_accepts_tcgstorageapi_key_name_without_uid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("GenKey", "", "K_AES_256_Range1_Key_UID", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_read_subrange_matches_prior_written_pattern(self):
        trajectory = activated_locking_context() + [
            host_write("8E", lba="80 ~ 87"),
            host_read("Pattern 8E", lba="82 ~ 83"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_write_locked_range_rejects_successful_host_write(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"6": 1}, {"8": 1}]}),
            end_session(),
            host_write("AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_named_locking_set_fields_update_range_state(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "Set",
                "0000080200030001",
                "Locking",
                optional={"RangeStart": 80, "RangeLength": 8, "WriteLockEnabled": 1, "WriteLocked": 1},
            ),
            end_session(),
            host_write_status("SUCCESS", lba="80 ~ 87"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_locking_set_accepts_supported_lock_on_reset_list(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"9": [0, 3]}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_locking_set_rejects_programmatic_only_lock_on_reset_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"9": [3]}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_read_locked_range_rejects_returned_plaintext(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"5": 1}, {"7": 1}]}),
            end_session(),
            host_read("Pattern AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_write_crossing_into_locked_range_rejects_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 10}, {"4": 10}, {"6": 1}, {"8": 1}]}),
            end_session(),
            host_write("AA", lba="5 ~ 12"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_read_crossing_into_locked_range_rejects_plaintext(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 10}, {"4": 10}, {"5": 1}, {"7": 1}]}),
            end_session(),
            host_read("Pattern AA", lba="5 ~ 12"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_unlocked_range_crossing_write_may_return_invalid_parameter(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 10}, {"4": 10}]}),
            end_session(),
            host_write_status("INVALID_PARAMETER", lba="5 ~ 12"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_unlocked_range_crossing_read_may_return_invalid_parameter(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 10}, {"4": 10}]}),
            end_session(),
            host_read_status("INVALID_PARAMETER", lba="5 ~ 12"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_power_cycle_applies_lock_on_reset(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"6": 1}, {"8": 0}, {"9": [0]}]}),
            end_session(),
            host_reset("PowerCycle"),
            host_write("AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_string_lock_on_reset_value_is_parsed(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"6": 1}, {"8": 0}, {"9": "[0]"}]}),
            end_session(),
            host_reset("PowerCycle"),
            host_write("AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_programmatic_reset_does_not_apply_power_only_lock_on_reset(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"6": 1}, {"8": 0}, {"9": [0]}]}),
            end_session(),
            host_reset("TCGReset"),
            host_write("AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tcg_reset_is_protocol_stack_reset_not_tper_reset(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"6": 1}, {"8": 0}, {"9": [0, 3]}]}),
            end_session(),
            host_reset("TCGReset"),
            host_write("AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tper_reset_requires_programmatic_reset_enable(self):
        trajectory = activated_locking_context() + [
            host_reset("TPerReset"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tper_reset_applies_programmatic_lock_when_enabled(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020100030001", "TPerInfo", optional={"ProgrammaticResetEnable": True}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 0}, {"4": "00020000"}, {"6": 1}, {"8": 0}, {"9": [0, 3]}]}),
            end_session(),
            host_reset("TPerReset"),
            host_write("AA"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_admin_revert_restores_programmatic_reset_disabled(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020100030001", "TPerInfo", optional={"ProgrammaticResetEnable": True}),
            method_record("Revert", "0000020500000001", "SP", "SUCCESS"),
            host_reset("TPerReset"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_activate_on_unknown_sp_object_rejects_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Activate", "0000010500000004", "SP", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_get_lockingsp_lifecycle_active_enables_later_session(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0000020500000002", "SP", return_values={"LifeCycle": "Manufactured"}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_get_lockingsp_object_from_lockingsp_session_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000020500000002", "SP", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_get_lockingsp_lifecycle_inactive_blocks_later_session_success(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0000020500000002", "SP", return_values={"LifeCycle": "Manufactured-Inactive"}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_get_lockingsp_numeric_lifecycle_active_enables_later_session(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0000020500000002", "SP", return_values={6: 9}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_get_lockingsp_numeric_lifecycle_inactive_blocks_later_session_success(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0000020500000002", "SP", return_values={6: 8}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_adminsp_thissp_revertsp_requires_psid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("RevertSP", "0000000000000001", "ThisSP", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_adminsp_psid_revertsp_success_is_valid(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, "PSID", "psid"),
            method_record("RevertSP", "0000000000000001", "ThisSP", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_psid_revertsp_resets_locking_sp_activation(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP, "PSID", "psid"),
            method_record("RevertSP", "0000000000000001", "ThisSP"),
            start_session(LOCKING_SP, ADMIN1, "new"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_keep_global_range_key_revertsp_fails_when_global_range_locked(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200000001", "Locking", optional={"Values": [{"5": 1}, {"6": 1}, {"7": 1}, {"8": 1}]}),
            method_record("RevertSP", "0000000000000001", "ThisSP", "SUCCESS", optional={"KeepGlobalRangeKey": True}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_keep_global_range_key_revertsp_preserves_global_user_data(self):
        trajectory = activated_locking_context() + [
            host_write("AA", lba="200 ~ 207"),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("RevertSP", "0000000000000001", "ThisSP", optional={"KeepGlobalRangeKey": True}),
            host_read("Pattern AA", lba="200 ~ 207"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_revertsp_without_keep_global_range_key_invalidates_global_user_data(self):
        trajectory = activated_locking_context() + [
            host_write("AA", lba="200 ~ 207"),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("RevertSP", "0000000000000001", "ThisSP"),
            host_read("Pattern AA", lba="200 ~ 207"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_enterprise_bandmaster_can_start_locking_session_after_pin_set(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", optional={"Values": [{"3": "bandpin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, "BandMaster1", "bandpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_erasemaster_can_enable_enterprise_bandmaster_authority(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP),
            method_record(
                "Set",
                "",
                "C_PIN_BandMaster1",
                "SUCCESS",
                optional={"authAs": ("EraseMaster", "erasepin"), "Values": [{"5": 1}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_erasemaster_cannot_enable_bandmaster_authority(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP),
            method_record(
                "Set",
                "",
                "C_PIN_BandMaster1",
                "SUCCESS",
                optional={"authAs": ("EraseMaster", "wrong"), "Values": [{"5": 1}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_bandmaster_authorizes_matching_range_set(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", optional={"Values": [{"3": "bandpin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, "BandMaster1", "bandpin"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"3": 8}, {"4": 64}, {"5": 1}, {"6": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bandmaster_does_not_authorize_other_range_set(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", optional={"Values": [{"3": "bandpin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, "BandMaster1", "bandpin"),
            method_record("Set", "0000080200030002", "Locking", "SUCCESS", optional={"Values": [{"3": 8}, {"4": 64}, {"5": 1}, {"6": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_erasemaster_authorizes_locking_range_set(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, "EraseMaster", "erasepin"),
            method_record("Set", "0000080200030002", "Locking", "SUCCESS", optional={"Values": [{"3": 8}, {"4": 64}, {"5": 1}, {"6": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_erase_requires_erase_master(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Erase", "", "Band1", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_erase_not_authorized_with_admin_is_valid_failure(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Erase", "", "Band1", "NOT_AUTHORIZED"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_erase_master_authorizes_band_erase(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP, "EraseMaster", "erasepin"),
            method_record("Erase", "", "Band1", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authas_none_uses_erase_master_for_band_erase(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP),
            method_record("Erase", "", "Band1", "SUCCESS", optional={"authAs": (None, "erasepin")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_authas_none_rejects_band_erase_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            end_session(),
            start_session(ADMIN_SP),
            method_record("Erase", "", "Band1", "SUCCESS", optional={"authAs": (None, "wrong")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_erase_invalidates_band_user_data(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"3": 80}, {"4": 8}]}),
            end_session(),
            host_write("AA", lba="80 ~ 87"),
            start_session(ADMIN_SP),
            method_record("Erase", "", "Band1", "SUCCESS", optional={"authAs": (None, "erasepin")}),
            end_session(),
            host_read("Pattern AA", lba="80 ~ 87"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_disabled_locking_admin2_cannot_start_session(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, "0000000900010002", "admin2"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_enabled_locking_admin2_can_start_session_after_pin_set(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900010002", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00010002", "C_PIN", optional={"Values": [{"3": "admin2"}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900010002", "admin2"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bare_admin_authority_name_enables_admin2(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "", "Admin2", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00010002", "C_PIN", optional={"Values": [{"3": "admin2"}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900010002", "admin2"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_disabled_adminsp_admin1_cannot_start_session_after_pin_set(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00000201", "C_PIN", optional={"Values": [{"3": "adminpin"}]}),
            end_session(),
            start_session(ADMIN_SP, "0000000900000201", "adminpin"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_ace_grant_allows_user_to_set_range_read_lock(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003E001", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"7": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_ace_grant_accepts_tcgstorageapi_binary_authority_uid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            raw_method_record(
                "Set",
                "000000080003E001",
                "ACE",
                args=(1, [(3, [("\x00\x00\x0C\x05", bytes.fromhex("0000000900030001"))])]),
            ),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"7": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_ace_grant_accepts_integer_authority_uid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", int("0000000900030001", 16), "Authority", optional={"Values": [{5: 1}]}),
            method_record("Set", int("0000000B00030001", 16), "C_PIN", optional={"Values": [{3: "userpin"}]}),
            raw_method_record(
                "Set",
                int("000000080003E001", 16),
                "ACE",
                args=(1, [(3, [("\x00\x00\x0C\x05", int("0000000900030001", 16))])]),
            ),
            end_session(),
            start_session(LOCKING_SP_INT, int("0000000900030001", 16), "userpin"),
            method_record("Set", int("0000080200030001", 16), "Locking", "SUCCESS", optional={"Values": [{7: 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tcgstorageapi_band_name_maps_to_locking_range(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "Set",
                "",
                "Band1",
                optional={"Values": [{"3": 80}, {"4": 8}, {"5": 1}, {"6": 1}, {"8": 1}]},
            ),
            end_session(),
            host_write_status("SUCCESS", lba="80 ~ 87"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tcgstorageapi_ace_name_grants_range_access(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "", "ACE_Locking_Range1_Set_RdLocked", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "", "Band1", "SUCCESS", optional={"Values": [{"7": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_ace_revoke_removes_user_range_lock_permission(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003E001", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            method_record("Set", "000000080003E001", "ACE", optional={"Values": [{"3": ["0000000900000002"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"7": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_c_pin_user_ace_admins_only_blocks_user_pin_change(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003A801", "ACE", optional={"Values": [{"3": ["0000000900000002"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000000B00030001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "newuserpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_c_pin_user_ace_admins_or_user_allows_user_pin_change(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003A801", "ACE", optional={"Values": [{"3": ["0000000900000002"]}]}),
            method_record("Set", "000000080003A801", "ACE", optional={"Values": [{"3": ["Admins", "OR", "User1"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000000B00030001", "C_PIN", "SUCCESS", optional={"Values": [{"3": "newuserpin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_datastore_write_ace_allows_user_write(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003FC01", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000100100000000", "DataStore", "SUCCESS", optional={"Bytes": "AA"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bandmaster_authorizes_datastore_write(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", optional={"Values": [{"3": "bandpin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, "BandMaster1", "bandpin"),
            method_record("Set", "0000100100000000", "DataStore", "SUCCESS", optional={"Bytes": "AA"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_bandmaster_authorizes_datastore_get(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008001", "C_PIN", optional={"Values": [{"3": "bandpin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP, "BandMaster1", "bandpin"),
            method_record("Get", "0000100100000000", "DataStore", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authas_none_uses_matching_user_for_datastore_write_ace(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003FC01", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP),
            method_record("Set", "0000100100000000", "DataStore", "SUCCESS", optional={"authAs": (None, "userpin"), "Bytes": "AA"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_authas_none_rejects_datastore_write_ace_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003FC01", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP),
            method_record("Set", "0000100100000000", "DataStore", "SUCCESS", optional={"authAs": (None, "wrong"), "Bytes": "AA"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_authas_none_uses_matching_user_for_datastore_read_ace(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003FC00", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP),
            method_record("Get", "0000100100000000", "DataStore", "SUCCESS", optional={"authAs": (None, "userpin")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_wrong_authas_none_rejects_datastore_read_ace_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003FC00", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP),
            method_record("Get", "0000100100000000", "DataStore", "SUCCESS", optional={"authAs": (None, "wrong")}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_datastore_set_accepts_tcgstorageapi_nonamed_byte_payload(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record(
                "Set",
                "0000100100000000",
                "DataStore",
                "SUCCESS",
                args=([(1, 0), (2, 64)], (1, b"payload")),
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_datastore_get_accepts_tcgstorageapi_row_range_args(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record("Get", "0000100100000000", "DataStore", "SUCCESS", args=[(1, 0), (2, 64)]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_datastore_get_rejects_column_raw_args(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record("Get", "0000100100000000", "DataStore", "SUCCESS", args=[(3, 0)]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_datastore_set_rejects_column_raw_payload_pair_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record("Set", "0000100100000000", "DataStore", "SUCCESS", args=[(3, b"payload")]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_datastore_set_without_payload_rejects_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record("Set", "0000100100000000", "DataStore", "SUCCESS", args=[("startRow", 0)]),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_datastore_set_with_column_cellblock_rejects_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "Set",
                "0000100100000000",
                "DataStore",
                "SUCCESS",
                required={"Cellblock": [{"startColumn": 1}, {"endColumn": 1}]},
                optional={"Bytes": "AA"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_datastore_write_ace_accepts_tcgstorageapi_table_name(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "000000080003FC02", "ACE_DataStore1_Set_All", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "0000100100000000", "DataStore", "SUCCESS", optional={"Bytes": "AA"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_datastore_row_values_are_invalid_for_byte_table_set(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000100100000000", "DataStore", "SUCCESS", optional={"Values": [{"1": "AA"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_datastore_get_with_column_cellblock_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "Get",
                "0000100100000000",
                "DataStore",
                "SUCCESS",
                required={"Cellblock": [{"startColumn": 1}, {"endColumn": 1}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_ace_meta_acl_allows_user_to_personalize_ace(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", optional={"Values": [{"5": 1}]}),
            method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"3": "userpin"}]}),
            method_record("Set", "0000000800038001", "ACE", optional={"Values": [{"3": ["0000000900030001"]}]}),
            end_session(),
            start_session(LOCKING_SP, "0000000900030001", "userpin"),
            method_record("Set", "000000080003E001", "ACE", "SUCCESS", optional={"Values": [{"3": ["0000000900030001"]}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_k_aes_mode_ace_can_block_anybody_get(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "000000080003BFFF", "ACE", optional={"Values": [{"3": ["0000000900000002"]}]}),
            end_session(),
            start_session(LOCKING_SP),
            method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                required={"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_k_aes_mode_get_uses_column_four(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                required={"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_k_aes_mode_get_accepts_raw_named_cellblock_columns(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            raw_method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                args=[("startColumn", 4), ("endColumn", 4)],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_k_aes_mode_get_accepts_tcgstorageapi_nonamed_cellblock_columns(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            raw_method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                args=[(3, 4), (4, 4)],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_k_aes_raw_named_key_column_get_success_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                args=[("startColumn", 3), ("endColumn", 3)],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_k_aes_nonamed_key_column_get_success_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                args=[(3, 3), (4, 3)],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_k_aes_key_column_get_success_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                required={"Cellblock": [{"startColumn": 3}, {"endColumn": 3}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_k_aes_get_without_cellblock_success_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Get", "0000080600030001", "K_AES_256", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_k_aes_unknown_column_get_success_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record(
                "Get",
                "0000080600030001",
                "K_AES_256",
                "SUCCESS",
                required={"Cellblock": [{"startColumn": 5}, {"endColumn": 5}]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_k_aes_set_success_is_invalid_because_opal_has_no_set_acl(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080600030001", "K_AES_256", "SUCCESS", optional={"Values": [{"4": "x"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_mbrcontrol_get_is_available_to_anybody(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Get", "0000080300000001", "MBRControl", "SUCCESS", required={"Cellblock": [{"startColumn": 1}, {"endColumn": 2}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_mbr_shadowing_blocks_host_writes(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", optional={"Values": [{"1": 1}, {"2": 0}]}),
            end_session(),
            host_write("AA", lba="0"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_mbr_shadowing_read_does_not_return_prior_user_data(self):
        trajectory = activated_locking_context() + [
            host_write("AA", lba="0"),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", optional={"Values": [{"1": 1}, {"2": 0}]}),
            end_session(),
            host_read("Pattern AA", lba="0"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_mbr_done_disables_shadowing_for_user_data_reads(self):
        trajectory = activated_locking_context() + [
            host_write("AA", lba="0"),
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", optional={"Values": [{"1": 1}, {"2": 1}]}),
            end_session(),
            host_read("Pattern AA", lba="0"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_power_cycle_applies_mbr_done_on_reset(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", optional={"Values": [{"1": 1}, {"2": 1}, {"3": [0]}]}),
            end_session(),
            host_reset("PowerCycle"),
            host_write("AA", lba="0"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_programmatic_reset_does_not_apply_power_only_done_on_reset(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", optional={"Values": [{"1": 1}, {"2": 1}, {"3": [0]}]}),
            end_session(),
            host_reset("TCGReset"),
            host_write("AA", lba="0"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_mbrcontrol_set_accepts_supported_done_on_reset_list(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", "SUCCESS", optional={"Values": [{"1": 1}, {"2": 1}, {"3": [0, 3]}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_mbrcontrol_set_rejects_programmatic_only_done_on_reset_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", "SUCCESS", optional={"Values": [{"1": 1}, {"2": 1}, {"3": [3]}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_port_set_is_admin_sp_operation(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0001000200010002", "Port", "SUCCESS", optional={"Values": [{"2": [0]}, {"3": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_port_set_accepts_name_only_port_row(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "", "Port2", "SUCCESS", optional={"Values": [{"3": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_port_get_allows_anybody_status_check(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0001000200010002", "Port", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0001000200010002", "Port", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_port_set_from_locking_sp_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0001000200010002", "Port", "SUCCESS", optional={"Values": [{"3": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_port_set_rejects_invalid_locked_value(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0001000200010002", "Port", "SUCCESS", optional={"Values": [{"3": "locked"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_port_set_rejects_unsupported_lock_on_reset_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0001000200010002", "Port", "SUCCESS", optional={"Values": [{"2": [2]}, {"3": 1}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tls_psk_set_rejects_invalid_enabled_value(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000001E00000001", "TLS_PSK_Key", "SUCCESS", optional={"Values": [{"3": "enabled"}, {"5": "0x1301"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tls_psk_set_accepts_named_tcgstorageapi_fields(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"Enabled": False, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tls_psk_set_accepts_bytes_named_fields(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={b"Enabled": False, b"PSK": b"secret", b"CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tls_psk_set_in_locking_sp_accepts_admin1_authas(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"authAs": ("Admin1", "new"), "Enabled": False, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tls_psk_set_in_locking_sp_selects_matching_authas_list_entry(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"authAs": [("SID", "new"), ("Admin1", "new")], "Enabled": False, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tls_psk_set_in_locking_sp_accepts_erasemaster_authas(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"authAs": [("SID", "new"), ("EraseMaster", "erasepin")], "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tls_psk_set_in_locking_sp_rejects_wrong_erasemaster_authas(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000B00008401", "C_PIN_EraseMaster", optional={"Values": [{"3": "erasepin"}]}),
            method_record("Activate", "0000020500000002", "SP"),
            end_session(),
            start_session(LOCKING_SP),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"authAs": [("SID", "new"), ("EraseMaster", "wrong")], "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tls_psk_set_in_locking_sp_rejects_wrong_matching_authas_entry(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"authAs": [("SID", "new"), ("Admin1", "wrong")], "Enabled": False, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tls_psk_set_in_locking_sp_rejects_sid_only_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record(
                "Set",
                "",
                "TLS_PSK_Key0",
                "SUCCESS",
                optional={"authAs": ("SID", "new"), "Enabled": False, "PSK": b"secret", "CipherSuite": "0x1301"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tls_psk_get_accepts_bytes_named_return_keys(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "Get",
                b"\x00\x00\x00\x1e\x00\x00\x00\x01",
                b"TLS_PSK_Key0",
                "SUCCESS",
                return_values={b"Enabled": 1, b"CipherSuite": "0x1301", b"UID": b"\x00\x00\x00\x1e\x00\x00\x00\x01"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_data_removal_mechanism_get_is_admin_sp_operation(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("Get", "0000110100000001", "DataRemovalMechanism", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_data_removal_mechanism_set_allows_active_mechanism_column(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000110100000001", "DataRemovalMechanism", "SUCCESS", optional={"Values": [{"1": 2}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_data_removal_mechanism_set_accepts_named_mechanism(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000110100000001", "DataRemovalMechanism", "SUCCESS", optional={"ActiveDataRemovalMechanism": "Cryptographic Erase"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_data_removal_mechanism_set_rejects_reserved_mechanism_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000110100000001", "DataRemovalMechanism", "SUCCESS", optional={"Values": [{"1": 4}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_data_removal_mechanism_set_rejects_out_of_range_mechanism_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000110100000001", "DataRemovalMechanism", "SUCCESS", optional={"Values": [{"1": 8}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_data_removal_mechanism_set_rejects_uid_column_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000110100000001", "DataRemovalMechanism", "SUCCESS", optional={"Values": [{"0": "0000110100000001"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_data_removal_mechanism_set_from_locking_sp_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000110100000001", "DataRemovalMechanism", "SUCCESS", optional={"Values": [{"1": 2}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tperinfo_set_accepts_programmatic_reset_enable(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020100030001", "TPerInfo", "SUCCESS", optional={"ProgrammaticResetEnable": True}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tperinfo_set_accepts_uppercase_boolean_literal(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020100030001", "TPerInfo", "SUCCESS", optional={"ProgrammaticResetEnable": "FALSE"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_tperinfo_set_rejects_invalid_programmatic_reset_enable_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020100030001", "TPerInfo", "SUCCESS", optional={"ProgrammaticResetEnable": "enabled"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_tperinfo_set_from_locking_sp_is_invalid(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000020100030001", "TPerInfo", "SUCCESS", optional={"ProgrammaticResetEnable": True}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_spinfo_set_accepts_session_timeout(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000200000001", "SPInfo", "SUCCESS", optional={"SPSessionTimeout": 30000}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_spinfo_set_rejects_readonly_column_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000200000001", "SPInfo", "SUCCESS", optional={"Values": [{"2": "renamed"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_spinfo_set_rejects_invalid_enabled_literal_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000200000001", "SPInfo", "SUCCESS", optional={"Enabled": "enabled"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_disabled_sp_blocks_non_reenable_methods(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000200000001", "SPInfo", "SUCCESS", optional={"Enabled": False}),
            method_record("Get", "0000000200000001", "SPInfo", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_disabled_sp_allows_session_start_and_reenable(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000200000001", "SPInfo", "SUCCESS", optional={"Enabled": False}),
            end_session(),
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000200000001", "SPInfo", "SUCCESS", optional={"Enabled": True}),
            method_record("Get", "0000000200000001", "SPInfo", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_admin_sp_accepts_admin_only_table_row_get(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000000100000204", "Table", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_locking_sp_rejects_admin_only_table_row_get_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000000100000204", "Table", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_locking_sp_accepts_locking_only_table_row_get(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "000000010000001D", "Table", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_admin_sp_rejects_locking_only_table_row_get_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "000000010000001D", "Table", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_sptemplates_row_set_rejects_readonly_version_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000300000001", "SPTemplates", "SUCCESS", optional={"Values": [{"3": "00000002"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_template_row_set_rejects_readonly_maxinstances_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020400000001", "Template", "SUCCESS", optional={"Values": [{"4": 2}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_methodid_row_set_rejects_readonly_name_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000600000008", "MethodID", "SUCCESS", optional={"Values": [{"1": "Next2"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_access_control_row_set_rejects_direct_acl_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000700000001", "AccessControl", "SUCCESS", optional={"Values": [{"4": ["ACE_00038000"]}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_access_control_row_get_rejects_direct_acl_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000000700000001", "AccessControl", "SUCCESS", required={"Cellblock": [{"startColumn": 4, "endColumn": 4}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_access_control_row_get_rejects_all_columns_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000000700000001", "AccessControl", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_access_control_row_get_accepts_non_acl_column(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000000700000001", "AccessControl", "SUCCESS", required={"Cellblock": [{"startColumn": 3, "endColumn": 3}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_secretprotect_row_set_rejects_readonly_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000001D0000001D", "SecretProtect", "SUCCESS", optional={"Values": [{"3": "VU"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_ace_row_set_rejects_readonly_name_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000000800038001", "ACE", "SUCCESS", optional={"Values": [{"1": "renamed"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_ace_row_set_rejects_columns_write_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000800038001", "ACE", "SUCCESS", optional={"Columns": "All"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_authority_get_common_name_allows_anybody(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Get", "0000000900030001", "Authority", "SUCCESS", required={"Cellblock": [{"startColumn": 2, "endColumn": 2}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authority_get_enabled_requires_admin_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Get", "0000000900030001", "Authority", "SUCCESS", required={"Cellblock": [{"startColumn": 5, "endColumn": 5}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_ace_get_common_name_allows_anybody(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Get", "0000000800038001", "ACE", "SUCCESS", required={"Cellblock": [{"startColumn": 2, "endColumn": 2}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_ace_get_boolean_expr_requires_admin_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP),
            method_record("Get", "0000000800038001", "ACE", "SUCCESS", required={"Cellblock": [{"startColumn": 3, "endColumn": 3}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_authority_set_accepts_common_name(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", "SUCCESS", optional={"CommonName": "UserAlias"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_authority_set_rejects_readonly_name_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000000900030001", "Authority", "SUCCESS", optional={"Name": "renamed"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_locking_set_rejects_readonly_name_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Name": "BandX"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_mbrcontrol_set_rejects_uid_column_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080300000001", "MBRControl", "SUCCESS", optional={"UID": "0000080300000001"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_sp_frozen_blocks_later_start_session(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020500000002", "SP", "SUCCESS", optional={"Frozen": True}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_sp_frozen_can_be_cleared_before_start_session(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020500000002", "SP", "SUCCESS", optional={"Frozen": True}),
            method_record("Set", "0000020500000002", "SP", "SUCCESS", optional={"Frozen": False}),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_sp_get_frozen_state_blocks_start_session(self):
        trajectory = activated_locking_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Get", "0000020500000002", "SP", "SUCCESS", return_values=[[{"7": True}]]),
            end_session(),
            start_session(LOCKING_SP, ADMIN1, "new", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_sp_set_rejects_direct_lifecycle_write_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("Set", "0000020500000002", "SP", "SUCCESS", optional={"Values": [{"6": "Manufactured"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_alignment_lowest_lba_applies_to_start_not_length(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080100000000", "LockingInfo", return_values={"AlignmentRequired": 1, "AlignmentGranularity": 8, "LowestAlignedLBA": 4}),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"3": 4}, {"4": 8}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_alignment_rejects_unaligned_length_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080100000000", "LockingInfo", return_values={"AlignmentRequired": 1, "AlignmentGranularity": 8, "LowestAlignedLBA": 4}),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"3": 4}, {"4": 12}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_invalid_method_association_rejects_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000080600030001", "MethodID": "0000000600000017"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_create_row_success_is_invalid_for_opal_methodid_tables(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("CreateRow", "0000080200000000", "Locking", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_create_row_rejects_non_locking_table_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("CreateRow", "0000000B00000000", "C_PIN", "SUCCESS", optional={"Row": [{"3": "pin"}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_delete_row_rejects_non_locking_table_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("DeleteRow", "0000000900000000", "Authority", "SUCCESS", required={"Rows": ["0000000900000003"]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_create_row_success_creates_locking_range_state(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                optional={"Row": [{"3": 0}, {"4": 100}, {"5": 1}, {"6": 1}]},
                return_values=["0000080200030001"],
            ),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                optional={"Row": [{"3": 50}, {"4": 10}]},
                return_values=["0000080200030002"],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_create_row_accepts_name_only_locking_table(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "CreateRow",
                "",
                "Locking",
                "SUCCESS",
                optional={"Values": [{"3": 96}, {"4": 8}]},
                return_values=["0000080200030001"],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_create_row_uses_name_only_returned_range_id(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                optional={"Row": [{"3": 0}, {"4": 100}]},
                return_values=["Band3"],
            ),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                optional={"Row": [{"3": 50}, {"4": 10}]},
                return_values=["Band4"],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_create_row_allows_non_overlapping_locking_range(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                optional={"Row": [{"3": 0}, {"4": 100}]},
                return_values=["0000080200030001"],
            ),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                optional={"Row": [{"3": 100}, {"4": 50}]},
                return_values=["0000080200030002"],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_delete_row_rejects_global_range_delete_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "DeleteRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                required={"Rows": ["0000080200000001"]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_delete_row_rejects_name_only_global_range_delete_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "DeleteRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                required={"Rows": ["Band0"]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_delete_row_rejects_unknown_locking_row_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "DeleteRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                required={"Rows": ["NotALockingRange"]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_active_reencrypt_blocks_range_geometry_set_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": 3}]]),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"3": 10}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_active_reencrypt_blocks_range_genkey_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "ACTIVE"}]]),
            method_record("GenKey", "0000080600030001", "K_AES_256", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_invalid_reencrypt_request_success_is_rejected(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", "SUCCESS", optional={"Values": [{"13": 4}]}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_start_reencrypt_request_blocks_later_genkey(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"13": "START_req"}]}),
            method_record("GenKey", "0000080600030001", "K_AES_256", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_advkey_from_completed_returns_range_to_idle(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"11": "0000080600030001"}, {"12": 4}]]),
            method_record("Set", "0000080200030001", "Locking", optional={"Values": [{"13": "ADVKEY_req"}]}),
            method_record("GenKey", "0000080600030001", "K_AES_256", "SUCCESS"),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_global_reencrypt_blocks_locking_create_row_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080200000001", "Locking", return_values=[[{"12": 2}]]),
            method_record(
                "CreateRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                optional={"Row": [{"3": 100}, {"4": 50}]},
                return_values=["0000080200030001"],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_active_reencrypt_blocks_locking_delete_row_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": 3}]]),
            method_record(
                "DeleteRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                required={"Rows": ["0000080200030001"]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_active_reencrypt_blocks_name_only_locking_delete_row_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": 3}]]),
            method_record(
                "DeleteRow",
                "0000080200000000",
                "Locking",
                "SUCCESS",
                required={"Rows": ["Band1"]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_accepts_locking_create_row_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000080200000000", "MethodID": "0000000600000004"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_rejects_missing_methodid_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000080200000000"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_rejects_missing_invokingid_success(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"MethodID": "0000000600000004"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_addace_requires_admin_authority(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record("AddACE", "0000000700000000", "AccessControl", "SUCCESS", optional={"ACE": "ACE_00038000"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_addace_not_authorized_response_is_valid_without_admin(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "AddACE",
                "0000000700000000",
                "AccessControl",
                "NOT_AUTHORIZED",
                required={"InvokingID": "AccessControl", "MethodID": "GetACL"},
                optional={"ACE": "ACE_00038000"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_addace_accepts_admin_with_ace_reference(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "AddACE",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "AccessControl", "MethodID": "GetACL"},
                optional={"ACE": "ACE_00038000"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_removeace_accepts_raw_ace_reference(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            raw_method_record(
                "RemoveACE",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                args=[("InvokingID", "AccessControl"), ("MethodID", "GetACL"), ("ACE", "ACE_00038000")],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_setacl_accepts_admin_with_ace_reference(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "SetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "AccessControl", "MethodID": "GetACL"},
                optional={"ACL": ["ACE_00038000"]},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_setacl_rejects_missing_ace_reference_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("SetACL", "0000000700000000", "AccessControl", "SUCCESS", required={"InvokingID": "AccessControl", "MethodID": "GetACL"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_addace_rejects_missing_ace_reference_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("AddACE", "0000000700000000", "AccessControl", "SUCCESS", required={"InvokingID": "AccessControl", "MethodID": "GetACL"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_addace_rejects_missing_invokingid_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("AddACE", "0000000700000000", "AccessControl", "SUCCESS", required={"MethodID": "GetACL"}, optional={"ACE": "ACE_00038000"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_removeace_rejects_unknown_acl_association_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record(
                "RemoveACE",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000100100000000", "MethodID": "Next"},
                optional={"ACE": "ACE_00038000"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_addace_rejects_non_access_control_target_success(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            method_record("AddACE", "0000000B00000000", "C_PIN", "SUCCESS", optional={"ACE": "ACE_00038000"}),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_accepts_band_erase_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "Band1", "MethodID": "Erase"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_access_control_addace_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "AccessControl", "MethodID": "AddACE"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_access_control_setacl_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "AccessControl", "MethodID": "SetACL"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_table_get_free_rows_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "C_PIN", "MethodID": "GetFreeRows"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_rejects_byte_table_get_free_space_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "DataStore", "MethodID": "GetFreeSpace"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_rejects_global_range_erase_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "Band0", "MethodID": "Erase"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_accepts_tper_sign_association_by_name(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "TPerSign", "MethodID": "Sign"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_firmware_attestation_association_by_name(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "TperAttestation", "MethodID": "FirmwareAttestation"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_locking_sptemplates_object_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000000300000001", "MethodID": "SPTemplatesObj"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_locking_methodid_object_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000000600000008", "MethodID": "MethodIDObj"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_rejects_byte_table_create_row_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000100100000000", "MethodID": "0000000600000004"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_rejects_byte_table_next_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000100100000000", "MethodID": "0000000600000008"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_accepts_name_only_locking_set_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": {"name": "Band1"}, "MethodID": "Set"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_raw_name_only_create_row_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            raw_method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                args=[("InvokingID", "Locking"), ("MethodID", "CreateRow")],
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_rejects_name_only_key_set_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "K_AES_256_Range1_Key", "MethodID": "Set"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")

    def test_getacl_accepts_admin_table_table_next_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000000100000000", "MethodID": "Next"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_admin_tperinfo_set_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000020100030001", "MethodID": "Set"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_admin_template_table_next_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000020400000000", "MethodID": "Next"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_admin_template_row_get_association(self):
        trajectory = owned_admin_context() + [
            start_session(ADMIN_SP),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000020400000001", "MethodID": "Get"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_locking_sptemplates_table_next_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000000300000000", "MethodID": "Next"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_accepts_locking_sptemplates_row_object_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "0000000300000002", "MethodID": "SPTemplatesObj"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "PASS")

    def test_getacl_rejects_unknown_symbol_association(self):
        trajectory = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "GetACL",
                "0000000700000000",
                "AccessControl",
                "SUCCESS",
                required={"InvokingID": "DefinitelyNotAnOpalObject", "MethodID": "Get"},
            ),
        ]
        self.assertEqual(predict_trajectory(trajectory), "FAIL")


if __name__ == "__main__":
    unittest.main()
