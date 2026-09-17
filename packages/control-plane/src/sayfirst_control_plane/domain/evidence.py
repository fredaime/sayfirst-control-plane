# SPDX-License-Identifier: Apache-2.0
"""The records a connection causes, shaped here and stored by another block.

Article 11: the principal is part of the identity of every effect. A refused
connection's record carries the raw credential and no principal, because none
was established. A declared delegation sits beside the principal and never
inside it, and its absence is rendered `null`, never omitted (article 2).

This block **emits** these records; block 2.4 owns the store that keeps them
and the port that reaches it. `RecordCollector` below is therefore a plain
collaborator of this package, not a port: it carries no version, it is not a
protocol a configuration could name a provider for, and article 4 forbids
publishing a port whose only implementation is a stub. Block 2.4 replaces it
with its store.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from sayfirst_contract.whoami import Delegation, Principal

from .connection import ConnectionIdentity

CONNECTION_OPENED: Final[str] = "connection_opened"
PRINCIPAL_CHANGED: Final[str] = "principal_changed"
CONNECTION_CLOSED: Final[str] = "connection_closed"
LOCAL_SCOPE: Final[str] = "local"


@dataclass(frozen=True)
class Record:
    """One record, on one scope's chain."""

    kind: str
    scope: str
    members: Mapping[str, object]


@dataclass
class RecordCollector:
    """The records this block emitted, in order, for the block that stores them.

    Not a port and not a provider: block 2.4 owns the evidence store, its
    port and its conformance suite, and this hands its records over until the
    two blocks meet.
    """

    records: list[Record] = field(default_factory=list)

    def append(self, record: Record) -> None:
        self.records.append(record)

    def kinds(self, scope: str | None = None) -> list[str]:
        return [record.kind for record in self.records if scope is None or record.scope == scope]


def connection_opened(identity: ConnectionIdentity, scope: str) -> Record:
    """The first record a connection causes on a scope's chain."""
    return Record(
        CONNECTION_OPENED,
        scope,
        {
            "connection_id": identity.connection_id,
            "accepted_at": identity.accepted_at,
            "socket_path": identity.socket_path,
            "mode": identity.mode,
            "peer": identity.peer_document(),
            "status": identity.status,
            "principal": None if identity.principal is None else identity.principal.to_document(),
            "refusal": identity.refusal,
        },
    )


def principal_changed(
    connection_id: str, at: str, before: Principal | None, after: Principal | None, scope: str
) -> Record:
    """What the directory now says, beside what it said before."""
    return Record(
        PRINCIPAL_CHANGED,
        scope,
        {
            "connection_id": connection_id,
            "at": at,
            "before": None if before is None else before.to_document(),
            "after": None if after is None else after.to_document(),
        },
    )


def connection_closed(connection_id: str, at: str, scope: str) -> Record:
    return Record(CONNECTION_CLOSED, scope, {"connection_id": connection_id, "at": at})


def actor_members(principal: Principal | None, delegation: Delegation | None) -> dict[str, object]:
    """The two members every decision record carries about who acted.

    The delegation never changes who the principal is; it is recorded beside
    it, and its absence is a present `null` rather than a missing member.
    """
    return {
        "principal": None if principal is None else principal.to_document(),
        "delegation": None if delegation is None else delegation.to_document(),
    }


def principal_for_evaluation(
    principal: Principal | None, delegation: Delegation | None
) -> Principal | None:
    """Who a policy is evaluated against: the peer, whatever the peer declared.

    Nothing the peer declares changes who it is (rule D1).
    """
    del delegation
    return principal
