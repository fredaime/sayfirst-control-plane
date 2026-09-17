# SPDX-License-Identifier: Apache-2.0
"""Reusable contract suite for an append-only scoped decision authority.

Article 3: a decision is an authority record, appended once and never updated;
article 5: every read names its scope, and the local default never applies to
a read. Block 2.7 adds what a durable store owes on top: an append answers the
position it committed the record at, in a store it names, and the store says
where it keeps its records so the grade can inspect them (article 7).
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_control_plane.ports.decision_store import (
    DecisionAlreadyExists,
    DecisionPosition,
    DecisionStore,
    ScopeRequired,
)


def _decision(reference: str, *, scope: str = "local", outcome: Outcome = Outcome.DENY) -> Decision:
    return Decision(
        decision_ref=reference,
        scope=scope,
        capability="mail.send",
        outcome=outcome,
        reason=Reason.POLICY_ABSENT,
        policy_version="sha256:" + "a" * 64,
        approval_ref=None,
        decided_at="2026-09-04T00:00:00Z",
        correlation=None,
        contract_generation=1,
        extra={
            "principal": {"kind": "process", "uid": 1000, "name": "build"},
            "arguments_digest": None,
            "rule_id": None,
            "grant_id": None,
        },
    )


def assert_decision_store_contract(
    store: DecisionStore,
    first: Decision,
    replacement: Decision,
) -> None:
    """Prove append-only identity, copy isolation, and explicit scoped reads."""
    assert store.VERSION == 1
    expected = deepcopy(first)
    store.append(first)
    if isinstance(first.extra, dict):
        first.extra["planted"] = "caller mutation"
    assert store.get(expected.scope, expected.decision_ref) == expected
    try:
        store.append(replacement)
    except DecisionAlreadyExists:
        pass
    else:
        raise AssertionError("a duplicate decision was accepted")
    assert store.get(expected.scope, expected.decision_ref) == expected
    try:
        store.get("", expected.decision_ref)
    except ScopeRequired:
        pass
    else:
        raise AssertionError("an unscoped read was accepted")
    assert store.get(f"{expected.scope}-other", expected.decision_ref) is None
    assert store.get(f"{expected.scope}-other", "never-existed") is None


class DecisionStoreContract:
    """Subclass, implement `make_store`, and every case below runs against the adapter."""

    def make_store(self, tmp_path: Path) -> DecisionStore:
        raise NotImplementedError

    def test_a_decision_appended_is_read_back_as_appended(self, tmp_path: Path) -> None:
        """Article 3: the record read is the record appended, whole, not rebuilt."""
        store = self.make_store(tmp_path)
        given = _decision("decision-1", outcome=Outcome.ALLOW)
        expected = deepcopy(given)
        store.append(given)
        given.extra["planted"] = "caller mutation"  # type: ignore[index]
        read = store.get("local", "decision-1")
        assert read == expected
        assert read is not given

    def test_a_duplicate_decision_reference_is_refused_never_upserted(self, tmp_path: Path) -> None:
        """Article 3: an authority identity is append-only within its scope."""
        store = self.make_store(tmp_path)
        store.append(_decision("decision-1"))
        try:
            store.append(_decision("decision-1", outcome=Outcome.ALLOW))
        except DecisionAlreadyExists:
            pass
        else:
            raise AssertionError("a duplicate decision reference was accepted")
        read = store.get("local", "decision-1")
        assert read is not None and read.outcome is Outcome.DENY

    def test_a_read_without_a_scope_is_refused(self, tmp_path: Path) -> None:
        """Article 5: the local default never applies to a read."""
        store = self.make_store(tmp_path)
        store.append(_decision("decision-1"))
        try:
            store.get("", "decision-1")
        except ScopeRequired:
            pass
        else:
            raise AssertionError("an unscoped read was accepted")

    def test_another_scopes_decision_is_never_read_here(self, tmp_path: Path) -> None:
        """Article 5: an id in another scope is indistinguishable from no id."""
        store = self.make_store(tmp_path)
        store.append(_decision("decision-1", scope="one"))
        assert store.get("two", "decision-1") is None
        assert store.get("two", "never-existed") is None
        read = store.get("one", "decision-1")
        assert read is not None and read.scope == "one"

    def test_an_append_answers_its_committed_position_in_a_named_store(
        self, tmp_path: Path
    ) -> None:
        """C2: the position is fixed when the append completes, and never recycled."""
        store = self.make_store(tmp_path)
        first = store.append(_decision("decision-1"))
        second = store.append(_decision("decision-2"))
        other = store.append(_decision("decision-3", scope="other"))
        assert isinstance(first, DecisionPosition) and isinstance(second, DecisionPosition)
        assert first.store_id and first.store_id == second.store_id
        assert (first.position, second.position) == (1, 2)
        assert other.position == 1 and other.store_id != first.store_id

    def test_the_store_says_where_it_keeps_its_records(self, tmp_path: Path) -> None:
        """Article 7: a grade inspects what it can name."""
        location = self.make_store(tmp_path).location()
        assert location.kind
        assert location.retention
