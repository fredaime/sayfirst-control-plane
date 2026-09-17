# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_control_plane.domain.grant import (
    GrantState,
    grant_matches,
    grant_state,
    mint_grant,
)
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal

NOW = datetime(2026, 9, 4, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64


def _decision() -> Decision:
    return Decision(
        decision_ref="decision-1",
        scope="local",
        capability="mail.send",
        outcome=Outcome.ALLOW,
        reason=Reason.POLICY_ALLOWS,
        policy_version="sha256:" + "a" * 64,
        approval_ref=None,
        decided_at=NOW.isoformat(),
        correlation=None,
        contract_generation=1,
        extra={
            "principal": {"kind": "process", "uid": 1001, "name": "build"},
            "arguments_digest": DIGEST,
        },
    )


def _grant(*, lifetime: int = 30):  # type: ignore[no-untyped-def]
    return mint_grant(
        _decision(),
        NOW,
        lifetime_seconds=lifetime,
        policy_version="sha256:" + "a" * 64,
        heartbeat_seconds=5,
    )


def _question(*, digest: str = DIGEST) -> DecisionQuestion:
    return DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=digest),
        Principal("process", 1001, "build", (2001,), ("ci",)),
    )


def test_mint_grant_preserves_the_lifetime_selected_by_the_service() -> None:
    """Article 10: minting preserves the service's already-bounded lifetime."""
    grant = _grant(lifetime=120)
    assert grant.lifetime_seconds == 120
    assert grant.expires_at == NOW + timedelta(seconds=120)


def test_a_grant_covers_exactly_the_decision_it_caches() -> None:
    """Articles 1 and 10: all conditions come from the recorded question."""
    grant = _grant()
    assert grant.conditions.scope == "local"
    assert grant.conditions.capability == "mail.send"
    assert grant.conditions.principal_reference == "user:build"
    assert grant.conditions.arguments_digest == DIGEST
    assert grant.policy_version == _decision().policy_version


def test_a_grant_expires_at_its_lifetime() -> None:
    """Article 10: the expiry instant itself is not live."""
    grant = _grant()
    state = grant_state(
        grant,
        grant.expires_at,
        current_policy_version=grant.policy_version,
        connection_live=True,
        last_heard_at=NOW,
    )
    assert state is GrantState.EXPIRED


def test_a_grant_is_void_when_the_policy_version_changes() -> None:
    """Article 10: a grant never crosses its authority version."""
    grant = _grant()
    state = grant_state(
        grant,
        NOW,
        current_policy_version="sha256:" + "b" * 64,
        connection_live=True,
        last_heard_at=NOW,
    )
    assert state is GrantState.POLICY_VERSION_CHANGED


def test_a_grant_is_void_when_the_connection_is_lost() -> None:
    """Article 10: connection loss dominates the grant state."""
    grant = _grant()
    state = grant_state(
        grant,
        NOW,
        current_policy_version=grant.policy_version,
        connection_live=False,
        last_heard_at=NOW,
    )
    assert state is GrantState.CONNECTION_LOST


def test_a_grant_is_void_after_silence_longer_than_its_lifetime() -> None:
    """Article 10: silence for the whole lifetime voids a live connection."""
    grant = _grant()
    state = grant_state(
        grant,
        NOW + timedelta(seconds=29),
        current_policy_version=grant.policy_version,
        connection_live=True,
        last_heard_at=NOW - timedelta(seconds=1),
    )
    assert state is GrantState.SILENT


def test_a_change_to_the_pinned_arguments_digest_voids_the_grant() -> None:
    """Article 3: grant hits include exact equality of the boundary digest."""
    grant = _grant()
    assert grant_matches(grant, _question())
    assert not grant_matches(grant, _question(digest="sha256:" + "2" * 64))
