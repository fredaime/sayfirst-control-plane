# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.ports.decision_store import DecisionAlreadyExists, ScopeRequired


def _decision(*, scope: str = "local", outcome: Outcome = Outcome.DENY) -> Decision:
    return Decision(
        decision_ref="decision-1",
        scope=scope,
        capability="mail.send",
        outcome=outcome,
        reason=Reason.POLICY_ABSENT,
        policy_version="sha256:" + "a" * 64,
        approval_ref=None,
        decided_at="2026-09-04T00:00:00+00:00",
        correlation=None,
        contract_generation=1,
        extra={},
    )


def test_an_appended_decision_is_never_updated() -> None:
    """Article 3: later caller mutation cannot rewrite an authority record."""
    store = MemoryDecisionStore()
    decision = _decision()
    store.append(decision)
    decision.extra["planted"] = "mutation"  # type: ignore[index]
    assert store.get("local", "decision-1") == _decision()


def test_a_duplicate_decision_id_is_refused_never_upserted() -> None:
    """Article 3: an authority identity is append-only within its scope."""
    store = MemoryDecisionStore()
    store.append(_decision())
    with pytest.raises(DecisionAlreadyExists):
        store.append(_decision(outcome=Outcome.ALLOW))
    assert store.get("local", "decision-1") == _decision()


def test_a_read_without_a_scope_is_refused() -> None:
    """Article 5: the local default never applies to reads."""
    with pytest.raises(ScopeRequired):
        MemoryDecisionStore().get("", "decision-1")


def test_absence_answers_the_same_across_scopes() -> None:
    """Article 5: an id in another scope is indistinguishable from no id."""
    store = MemoryDecisionStore()
    store.append(_decision(scope="one"))
    assert store.get("two", "decision-1") is None
    assert store.get("two", "never-existed") is None
