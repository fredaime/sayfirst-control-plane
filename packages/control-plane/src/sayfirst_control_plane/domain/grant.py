# SPDX-License-Identifier: Apache-2.0
"""The connection-bound cached decision and its render-on-read state."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import uuid4

from sayfirst_contract.decisions import Decision, Outcome

from .policy import DecisionQuestion


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
    issued_at: datetime
    lifetime_seconds: int
    expires_at: datetime
    heartbeat_seconds: int
    conditions: GrantConditions

    def __post_init__(self) -> None:
        if not 1 <= self.lifetime_seconds <= 86400:
            raise ValueError("grant lifetime must be between 1 and 86400 seconds")
        if not 1 <= self.heartbeat_seconds <= 60:
            raise ValueError("grant heartbeat must be between 1 and 60 seconds")
        if self.expires_at != self.issued_at + timedelta(seconds=self.lifetime_seconds):
            raise ValueError("grant expiry must equal issued_at plus its lifetime")


class GrantState(StrEnum):
    LIVE = "live"
    EXPIRED = "expired"
    SILENT = "silent"
    POLICY_VERSION_CHANGED = "policy_version_changed"
    CONNECTION_LOST = "connection_lost"


def mint_grant(
    decision: Decision,
    now: datetime,
    *,
    lifetime_seconds: int,
    policy_version: str,
    heartbeat_seconds: int,
) -> Grant:
    """Mint exactly the question represented by an allow decision."""
    if decision.outcome is not Outcome.ALLOW:
        raise ValueError("only allow decisions can be cached")
    if decision.policy_version != policy_version:
        raise ValueError("grant policy version must equal its decision's version")
    principal = decision.extra.get("principal")
    principal_name = principal.get("name") if isinstance(principal, Mapping) else None
    if "arguments_digest" not in decision.extra:
        raise ValueError("decision lacks its pinned grant conditions")
    arguments_digest = decision.extra["arguments_digest"]
    if not isinstance(principal_name, str) or not isinstance(arguments_digest, str | None):
        raise ValueError("decision lacks its pinned grant conditions")
    return Grant(
        grant_id=str(uuid4()),
        decision_ref=decision.decision_ref,
        policy_version=policy_version,
        issued_at=now,
        lifetime_seconds=lifetime_seconds,
        expires_at=now + timedelta(seconds=lifetime_seconds),
        heartbeat_seconds=heartbeat_seconds,
        conditions=GrantConditions(
            decision.scope,
            decision.capability,
            f"user:{principal_name}",
            arguments_digest,
        ),
    )


def grant_state(
    grant: Grant,
    now: datetime,
    *,
    current_policy_version: str,
    connection_live: bool,
    last_heard_at: datetime,
) -> GrantState:
    """Render state in the constitutional precedence order."""
    if not connection_live:
        return GrantState.CONNECTION_LOST
    if now >= grant.expires_at:
        return GrantState.EXPIRED
    if now - last_heard_at >= timedelta(seconds=grant.lifetime_seconds):
        return GrantState.SILENT
    if current_policy_version != grant.policy_version:
        return GrantState.POLICY_VERSION_CHANGED
    return GrantState.LIVE


def grant_matches(grant: Grant, question: DecisionQuestion) -> bool:
    """Require exact equality on every closed condition."""
    return grant.conditions == GrantConditions(
        question.ask.scope,
        question.ask.capability,
        question.principal.reference,
        question.ask.arguments_digest,
    )
