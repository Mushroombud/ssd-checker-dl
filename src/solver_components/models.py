"""Canonical event and reconstructed verifier state models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import *


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
    implicit_session: bool = False

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
    expected_return_bool: bool | None = None
    forbidden_return_bool: bool | None = None
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
    pin_min_lengths: dict[str, int] = field(default_factory=dict)
    pin_try_limits: dict[str, int] = field(default_factory=dict)
    pin_tries: dict[str, int] = field(default_factory=dict)
    pin_persistence: dict[str, bool] = field(default_factory=dict)
    authority_enabled: dict[str, bool] = field(default_factory=dict)
    locking_sp_activated: bool = False
    observed_sp_lifecycle: dict[str, int] = field(default_factory=dict)
    sp_enabled: dict[str, bool] = field(default_factory=dict)
    sp_frozen: dict[str, bool] = field(default_factory=dict)
    deleted_sps: set[str] = field(default_factory=set)
    pending_deleted_sp: str | None = None
    created_table_names: set[tuple[str, str, str]] = field(default_factory=set)
    created_tables: dict[str, tuple[str, str]] = field(default_factory=dict)
    programmatic_reset_enabled: bool = False
    locking_info: dict[str, Any] = field(default_factory=dict)
    ranges: dict[int, RangeState] = field(default_factory=dict)
    range_read_lock_users: dict[int, set[str]] = field(default_factory=dict)
    range_write_lock_users: dict[int, set[str]] = field(default_factory=dict)
    datastore_read_users: set[str] = field(default_factory=set)
    datastore_write_users: set[str] = field(default_factory=set)
    ace_expressions: dict[tuple[str, str], AceExpression] = field(default_factory=dict)
    deleted_method_associations: set[tuple[str, str]] = field(default_factory=set)
    mbr: dict[str, Any] = field(default_factory=dict)
    lba_patterns: dict[tuple[int, int], tuple[str, int, int]] = field(default_factory=dict)
    wwn: Any = None


__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
