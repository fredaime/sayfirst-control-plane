# SPDX-License-Identifier: Apache-2.0
"""Connection-bound grant and policy-change signal values."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .decisions import DecisionAsk


class GrantSignalKind(StrEnum):
    HEARTBEAT = "heartbeat"
    GRANT_ENDED = "grant_ended"


class GrantEndReason(StrEnum):
    POLICY_VERSION_CHANGED = "policy_version_changed"
    EXPIRED = "expired"
    DAEMON_STOPPING = "daemon_stopping"


@dataclass(frozen=True)
class GrantConditions:
    scope: str
    capability: str
    principal_reference: str
    arguments_digest: str | None


@dataclass(frozen=True)
class Grant:
    grant_id: str
    decision_ref: str
    policy_version: str
    issued_at: str
    lifetime_seconds: int
    expires_at: str
    heartbeat_seconds: int
    conditions: GrantConditions

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Grant:
        """Read a served grant, refusing one that omits a condition it pins."""
        conditions = document["conditions"]
        if not isinstance(conditions, Mapping):
            raise ValueError("a grant publishes its conditions as an object")
        return cls(
            str(document["grant_id"]),
            str(document["decision_ref"]),
            str(document["policy_version"]),
            str(document["issued_at"]),
            int(document["lifetime_seconds"]),  # type: ignore[call-overload]
            str(document["expires_at"]),
            int(document["heartbeat_seconds"]),  # type: ignore[call-overload]
            GrantConditions(
                str(conditions["scope"]),
                str(conditions["capability"]),
                str(conditions["principal_reference"]),
                None
                if conditions["arguments_digest"] is None
                else str(conditions["arguments_digest"]),
            ),
        )

    def to_document(self) -> Mapping[str, object]:
        return {
            "grant_id": self.grant_id,
            "decision_ref": self.decision_ref,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "lifetime_seconds": self.lifetime_seconds,
            "expires_at": self.expires_at,
            "heartbeat_seconds": self.heartbeat_seconds,
            "conditions": {
                "scope": self.conditions.scope,
                "capability": self.conditions.capability,
                "principal_reference": self.conditions.principal_reference,
                "arguments_digest": self.conditions.arguments_digest,
            },
        }


@dataclass(frozen=True)
class GrantSignal:
    kind: GrantSignalKind
    grant_id: str
    policy_version: str
    at: str
    reason: GrantEndReason | None
    contract_generation: int

    def to_document(self) -> Mapping[str, object]:
        return {
            "contract_generation": self.contract_generation,
            "kind": self.kind.value,
            "grant_id": self.grant_id,
            "policy_version": self.policy_version,
            "at": self.at,
            **({"reason": self.reason.value} if self.reason is not None else {}),
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> GrantSignal:
        """Read a served signal, refusing one this generation cannot interpret.

        The pair was asymmetric until a holder needed it: this value could be
        written and not read, which is the shape a contract takes when only one
        side of it was ever built. The daemon serialises these; nothing consumed
        them, because nothing kept the connection they arrive on.

        An unreadable `kind` or `reason` raises rather than being dropped or
        guessed at. A signal whose kind this generation does not know may be the
        one that ends the grant, so treating it as noise would be the permissive
        reading of an unknown input, which article 3 forbids.
        """
        try:
            kind = GrantSignalKind(str(document["kind"]))
        except ValueError as exc:
            raise ValueError(f"unknown grant signal kind {document['kind']!r}") from exc
        raw_reason = document.get("reason")
        if raw_reason is None:
            reason = None
        else:
            try:
                reason = GrantEndReason(str(raw_reason))
            except ValueError as exc:
                raise ValueError(f"unknown grant end reason {raw_reason!r}") from exc
        return cls(
            kind=kind,
            grant_id=str(document["grant_id"]),
            policy_version=str(document["policy_version"]),
            at=str(document["at"]),
            reason=reason,
            contract_generation=int(document["contract_generation"]),  # type: ignore[call-overload]
        )


class GrantUse(StrEnum):
    """What a held grant answers about the next thing its holder is about to do."""

    HIT = "hit"
    CONNECTION_LOST = "connection_lost"
    EXPIRED = "expired"
    ARGUMENTS_CHANGED = "arguments_changed"
    CONDITIONS_DIFFER = "conditions_differ"


def grant_use(
    grant: Grant,
    ask: DecisionAsk,
    principal_reference: str,
    *,
    now: datetime,
    connection_live: bool,
) -> GrantUse:
    """Answer whether a held grant covers this ask, or name why it does not.

    The point of a grant is that its holder acts again without asking
    (article 10), so the rule deciding that has to be published, or a
    third-party boundary and this control plane disagree about what a grant
    still covers (article 13). The order is the constitutional one: the grant
    is bound to the connection carrying its signals, then to its lifetime,
    then to every closed condition it pins — a pinned arguments digest is
    never satisfied by an ask carrying a different one, or none (article 3).

    A holder that has read a `grant_ended` signal holds no grant any more and
    asks; this rule is what it applies while it still holds one.
    """
    if not connection_live:
        return GrantUse.CONNECTION_LOST
    if now >= _instant(grant.expires_at):
        return GrantUse.EXPIRED
    conditions = grant.conditions
    if (
        conditions.scope != ask.scope
        or conditions.capability != ask.capability
        or conditions.principal_reference != principal_reference
    ):
        return GrantUse.CONDITIONS_DIFFER
    if conditions.arguments_digest != ask.arguments_digest:
        return GrantUse.ARGUMENTS_CHANGED
    return GrantUse.HIT


def _instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("a published instant carries its offset")
    return parsed
