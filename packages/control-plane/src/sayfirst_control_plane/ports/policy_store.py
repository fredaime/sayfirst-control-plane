# SPDX-License-Identifier: Apache-2.0
"""The policy authority port and its three-valued access answers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from ..domain.policy import Policy, Principal


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    policy_version: str
    loaded_at: datetime
    byte_length: int
    #: The exact bytes the authority read and hashed, so the archive can keep
    #: them under `policy_version` before a decision is taken on them (A1).
    #: `None` is an adapter that supplied no bytes; nothing is archived for it
    #: and no decision is committed on it (article 3, fail-closed).
    content: bytes | None = None


@dataclass(frozen=True)
class PolicyUnavailable:
    reason: Literal[
        "absent",
        "unreadable",
        "too_large",
        "malformed",
        "format_unsupported",
        "invalid",
    ]
    message: str


class ProtectionState(StrEnum):
    PROTECTED = "protected"
    EXPOSED = "exposed"
    UNKNOWN = "unknown"


class AccessState(StrEnum):
    WRITABLE = "writable"
    NOT_WRITABLE = "not_writable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProtectionVerdict:
    kind: ProtectionState
    component: Path | None = None
    reason: str | None = None


@dataclass(frozen=True)
class AccessVerdict:
    kind: AccessState
    component: Path | None = None
    reason: str | None = None


@dataclass(frozen=True)
class ProtectionExpectation:
    allowed_owner_uids: frozenset[int]
    allowed_write_gids: frozenset[int]

    @classmethod
    def per_user(cls, daemon_uid: int) -> ProtectionExpectation:
        return cls(frozenset({0, daemon_uid}), frozenset())

    @classmethod
    def system(cls, administrator_gid: int) -> ProtectionExpectation:
        return cls(frozenset({0}), frozenset({0, administrator_gid}))


class PolicyStore(Protocol):
    VERSION = 1
    max_lifetime_seconds: int

    def load(self) -> LoadedPolicy | PolicyUnavailable: ...

    def protection_at_start(self, expectation: ProtectionExpectation) -> ProtectionVerdict: ...

    def write_access_of(self, principal: Principal) -> AccessVerdict: ...
