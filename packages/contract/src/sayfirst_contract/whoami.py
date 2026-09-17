# SPDX-License-Identifier: Apache-2.0
"""The identity vocabulary: who a peer is, what the kernel said, and for whom it acts.

The kinds of principal are an open registry (article 6): a value outside the
documented four is read and recorded as given, never folded into a known one
and never rejected. There is no enumeration of them anywhere.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal

from .problems import classes_by_code, problem_class
from .values import Unknown, read_enum

WELL_KNOWN_KINDS: Final[tuple[str, ...]] = ("user", "service", "workload", "process")
"""The documented kinds. The registry is open; this is not an enumeration."""

ESTABLISHED_BY_PEER_CREDENTIAL: Final[str] = "peer_credential"
DECLARED: Final[str] = "declared"
MAX_DELEGATION_DEPTH: Final[int] = 4
MAX_KIND_BYTES: Final[int] = 64
MAX_NAME_BYTES: Final[int] = 256
MAX_VIA_BYTES: Final[int] = 64
DOCUMENTED_VIA: Final[tuple[str, ...]] = ("privilege_tool", "scheduler", "build_runner")


class GroupsStatus(StrEnum):
    """How completely the directory answered. Three values, article 2."""

    RESOLVED = "resolved"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ConnectionStatus(StrEnum):
    """What the daemon knows about a connection. Three values, article 2."""

    ESTABLISHED = "established"
    UNKNOWN = "unknown"
    REFUSED = "refused"


class Mode(StrEnum):
    """The two deployment modes article 6 names."""

    PER_USER = "per_user"
    SYSTEM = "system"


def _rendered(value: object) -> object:
    """The value as it travels: a member's own string, or a retained unknown."""
    if isinstance(value, Unknown):
        return value.raw
    if isinstance(value, StrEnum):
        return value.value
    return value


def _codes_of_class(wanted: str) -> frozenset[str]:
    return frozenset(name for name, klass in classes_by_code().items() if klass == wanted)


# The two sets below are read off the registry at import, which is why
# `problems` is imported at the top like any other module: there is no cycle to
# break — `problems` imports `artifacts` and `values` and never this file — and
# a deferred import would not defer the read anyway, because these run at module
# scope. What it costs is that a registry missing a class is a failure at import
# rather than at first use, which is the right moment for a rule every client of
# this package depends on.
REFUSAL_CODES: Final[frozenset[str]] = _codes_of_class("refused")
"""Every code the registry classes as a refusal: the question was received and rejected."""

COULD_NOT_ASK_CODES: Final[frozenset[str]] = _codes_of_class("could_not_ask")
"""No answer about the effect exists, so the effect that has not started does not start."""


def classify(code: str) -> Literal["refused", "could_not_ask"]:
    """Article 1: a refusal and an absent answer are distinct results.

    The class is the registry's (`problems.problem_class`), so this reader and
    the binding client cannot disagree about one code. A code this generation
    does not know is never read as a refusal.

    It answers about a CODE, so it answers the column and nothing else. A
    caller holding a problem VALUE asks `problems.problem_class_of`, which
    also knows whether a control plane answered at all.
    """
    return problem_class(code)


@dataclass(frozen=True)
class Peer:
    """What the kernel said. The pid is diagnostic and decides nothing."""

    uid: int
    gid: int
    pid: int | None
    captured_at: str

    def to_document(self) -> dict[str, object]:
        return {"uid": self.uid, "gid": self.gid, "pid": self.pid, "captured_at": self.captured_at}

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Peer:
        pid = document["pid"]
        return cls(
            uid=int(document["uid"]),  # type: ignore[arg-type]
            gid=int(document["gid"]),  # type: ignore[arg-type]
            pid=int(pid) if isinstance(pid, int) and not isinstance(pid, bool) else None,
            captured_at=str(document["captured_at"]),
        )


@dataclass(frozen=True)
class Principal:
    """The identity a decision is evaluated against. It carries no process id."""

    kind: str
    uid: int
    gid: int
    name: str | None
    groups: tuple[str, ...] | None
    groups_status: GroupsStatus | Unknown | str
    unnamed_group_ids: tuple[int, ...]
    established_by: str
    established_at: str
    extra: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.groups_status, GroupsStatus | Unknown):
            object.__setattr__(self, "groups_status", read_enum(GroupsStatus, self.groups_status))

    @property
    def groups_are_unknown(self) -> bool:
        """Whether this membership may be read as resolved. A fourth value may not."""
        return self.groups_status is not GroupsStatus.RESOLVED and (
            self.groups_status is not GroupsStatus.PARTIAL
        )

    @property
    def reference(self) -> str:
        """The opaque actor string write-side ports record."""
        return f"{self.kind}:{self.uid}"

    def to_document(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "uid": self.uid,
            "gid": self.gid,
            "name": self.name,
            "groups": None if self.groups is None else list(self.groups),
            "groups_status": _rendered(self.groups_status),
            "unnamed_group_ids": list(self.unnamed_group_ids),
            "established_by": self.established_by,
            "established_at": self.established_at,
            "reference": self.reference,
            **self.extra,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Principal:
        defined = {
            "kind",
            "uid",
            "gid",
            "name",
            "groups",
            "groups_status",
            "unnamed_group_ids",
            "established_by",
            "established_at",
            "reference",
        }
        groups = document["groups"]
        name = document["name"]
        return cls(
            kind=str(document["kind"]),
            uid=int(document["uid"]),  # type: ignore[arg-type]
            gid=int(document["gid"]),  # type: ignore[arg-type]
            name=name if isinstance(name, str) else None,
            groups=tuple(str(item) for item in groups) if isinstance(groups, list) else None,
            groups_status=read_enum(GroupsStatus, document["groups_status"]),
            unnamed_group_ids=tuple(
                int(item)
                for item in document.get("unnamed_group_ids", ())  # type: ignore[union-attr]
            ),
            established_by=str(document["established_by"]),
            established_at=str(document["established_at"]),
            extra={key: value for key, value in document.items() if key not in defined},
        )


class DelegationOutOfBounds(ValueError):
    """A declaration outside the bounds the contract names."""


@dataclass(frozen=True)
class DelegatedIdentity:
    kind: str
    name: str | None
    uid: int | None
    via: str

    def to_document(self) -> dict[str, object]:
        return {"kind": self.kind, "name": self.name, "uid": self.uid, "via": self.via}


@dataclass(frozen=True)
class Delegation:
    """A declaration by the peer that it acts for someone else.

    An observation (article 3): recorded verbatim, never verified, never
    decisional. It sits beside the principal and never inside it.
    """

    status: str
    chain: tuple[DelegatedIdentity, ...]

    @classmethod
    def declared(cls, chain: Iterable[Mapping[str, object]]) -> Delegation:
        return cls(DECLARED, tuple(_read_link(item) for item in chain))

    def to_document(self) -> dict[str, object]:
        return {"status": self.status, "chain": [link.to_document() for link in self.chain]}

    @classmethod
    def from_request_member(cls, value: object) -> Delegation | None:
        """Read the optional request member; absence is "nothing declared"."""
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise DelegationOutOfBounds("delegation must be an object")
        unknown = set(value) - {"status", "chain"}
        if unknown:
            raise DelegationOutOfBounds(f"delegation names {sorted(unknown)[0]!r}")
        chain = value.get("chain")
        if not isinstance(chain, Sequence) or isinstance(chain, str | bytes):
            raise DelegationOutOfBounds("delegation chain must be a list")
        if not 1 <= len(chain) <= MAX_DELEGATION_DEPTH:
            raise DelegationOutOfBounds(
                f"delegation chain holds {len(chain)} entries, bounds are 1 to "
                f"{MAX_DELEGATION_DEPTH}"
            )
        return cls(DECLARED, tuple(_read_link(item) for item in chain))


def _bounded(value: str, limit: int, member: str) -> str:
    if len(value.encode()) > limit:
        raise DelegationOutOfBounds(f"delegation {member} is longer than {limit} bytes")
    return value


def _read_link(item: object) -> DelegatedIdentity:
    if not isinstance(item, Mapping):
        raise DelegationOutOfBounds("a delegation entry must be an object")
    unknown = set(item) - {"kind", "name", "uid", "via"}
    if unknown:
        raise DelegationOutOfBounds(f"a delegation entry names {sorted(unknown)[0]!r}")
    kind = item.get("kind")
    via = item.get("via")
    name = item.get("name")
    uid = item.get("uid")
    if not isinstance(kind, str) or not kind:
        raise DelegationOutOfBounds("a delegation entry needs a kind")
    if not isinstance(via, str) or not via:
        raise DelegationOutOfBounds("a delegation entry needs a via")
    if name is not None and not isinstance(name, str):
        raise DelegationOutOfBounds("a delegation name must be a string or null")
    if uid is not None and (not isinstance(uid, int) or isinstance(uid, bool) or uid < 0):
        raise DelegationOutOfBounds("a delegation uid must be a whole number or null")
    return DelegatedIdentity(
        kind=_bounded(kind, MAX_KIND_BYTES, "kind"),
        name=None if name is None else _bounded(name, MAX_NAME_BYTES, "name"),
        uid=uid,
        via=_bounded(via, MAX_VIA_BYTES, "via"),
    )


@dataclass(frozen=True)
class WhoAmI:
    """The principal as the daemon saw it when it accepted, looked up no further."""

    contract_generation: int
    connection_id: str
    socket_path: str
    mode: Mode | Unknown | str
    peer: Peer
    principal: Principal | None
    status: ConnectionStatus | Unknown | str
    refresh_due_at: str | None
    group_lifetime_seconds: int
    delegation: Delegation | None
    extra: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.mode, Mode | Unknown):
            object.__setattr__(self, "mode", read_enum(Mode, self.mode))
        if not isinstance(self.status, ConnectionStatus | Unknown):
            object.__setattr__(self, "status", read_enum(ConnectionStatus, self.status))

    @property
    def is_established(self) -> bool:
        """Whether a principal may be read from this. A fourth state may not."""
        return self.status is ConnectionStatus.ESTABLISHED

    def to_document(self) -> dict[str, object]:
        return {
            "contract_generation": self.contract_generation,
            "connection_id": self.connection_id,
            "socket_path": self.socket_path,
            "mode": _rendered(self.mode),
            "peer": self.peer.to_document(),
            "principal": None if self.principal is None else self.principal.to_document(),
            "status": _rendered(self.status),
            "refresh_due_at": self.refresh_due_at,
            "group_lifetime_seconds": self.group_lifetime_seconds,
            "delegation": None if self.delegation is None else self.delegation.to_document(),
            **self.extra,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> WhoAmI:
        defined = {
            "contract_generation",
            "connection_id",
            "socket_path",
            "mode",
            "peer",
            "principal",
            "status",
            "refresh_due_at",
            "group_lifetime_seconds",
            "delegation",
        }
        peer = document["peer"]
        principal = document["principal"]
        delegation = document["delegation"]
        refresh_due_at = document["refresh_due_at"]
        if not isinstance(peer, Mapping):
            raise ValueError("peer must be an object")
        return cls(
            contract_generation=int(document["contract_generation"]),  # type: ignore[arg-type]
            connection_id=str(document["connection_id"]),
            socket_path=str(document["socket_path"]),
            mode=read_enum(Mode, document["mode"]),
            peer=Peer.from_document(peer),
            principal=Principal.from_document(principal)
            if isinstance(principal, Mapping)
            else None,
            status=read_enum(ConnectionStatus, document["status"]),
            refresh_due_at=str(refresh_due_at) if isinstance(refresh_due_at, str) else None,
            group_lifetime_seconds=int(document["group_lifetime_seconds"]),  # type: ignore[arg-type]
            delegation=Delegation.declared(delegation["chain"])  # type: ignore[index]
            if isinstance(delegation, Mapping)
            else None,
            extra={key: value for key, value in document.items() if key not in defined},
        )
