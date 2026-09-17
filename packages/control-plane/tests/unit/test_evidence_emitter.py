# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Event
from time import sleep

from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.evidence_emitter import (
    EffectDecision,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal
from sayfirst_control_plane.domain.integrity_grade import CallerAccess
from sayfirst_control_plane.plugins.interfaces import Redaction


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)

    def now(self) -> datetime:
        value = self.value
        self.value += timedelta(seconds=1)
        return value


def record(clock: Clock, decision: str) -> EvidenceRecord:
    now = clock.now()
    return EvidenceRecord(
        scope="local",
        kind="effect",
        recorded_at=now,
        connection_id="connection-1",
        principal=Principal("user", "example"),
        body={
            "capability": "example.effect",
            "decision_id": decision,
            "outcome": "allow",
            "decided_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy_version": "policy-1",
        },
    )


class StallingStore(InMemoryEvidenceStore):
    def __init__(self) -> None:
        super().__init__()
        self.started = Event()
        self.release = Event()

    def append(self, item: EvidenceRecord):  # type: ignore[no-untyped-def]
        self.started.set()
        self.release.wait(timeout=2)
        return super().append(item)


def test_emit_returns_before_the_store_has_appended() -> None:
    clock = Clock()
    store = StallingStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=2)
    emitter.emit(record(clock, "decision-1"))
    assert store.started.wait(timeout=1)
    assert store.latest_sequence("local") is None
    store.release.set()
    assert emitter.flush("local", timeout=2)
    emitter.close()


def test_emit_never_raises_when_the_queue_is_full() -> None:
    clock = Clock()
    store = StallingStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    assert emitter.emit(record(clock, "in-flight")) is True
    assert store.started.wait(timeout=1)
    assert emitter.emit(record(clock, "queued")) is True
    assert emitter.emit(record(clock, "dropped")) is False
    store.release.set()
    assert emitter.flush("local", timeout=2)
    emitter.close()


def test_flush_appends_a_pending_gap_with_no_record_following() -> None:
    clock = Clock()
    store = StallingStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    emitter.emit(record(clock, "in-flight"))
    assert store.started.wait(timeout=1)
    emitter.emit(record(clock, "queued"))
    emitter.emit(record(clock, "dropped"))
    store.release.set()
    assert emitter.flush("local", timeout=2)
    emitter.close()
    entries = store.read_range("local", from_sequence=1)
    assert entries[-1].kind == "gap"
    assert entries[-1].body["count"] == 1


def test_a_dropped_record_becomes_a_declared_gap_where_the_loss_happened() -> None:
    """Article 10: backpressure is visible in the chain."""
    clock = Clock()
    store = StallingStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    emitter.emit(record(clock, "accepted-in-flight"))
    assert store.started.wait(timeout=1)
    emitter.emit(record(clock, "accepted-before-drop"))
    emitter.emit(record(clock, "dropped"))
    store.release.set()
    assert emitter.flush("local", timeout=2)
    emitter.emit(record(clock, "accepted-after-drop"))
    assert emitter.flush("local", timeout=2)
    emitter.close()

    entries = store.read_range("local", from_sequence=1)
    assert [entry.kind for entry in entries] == ["effect", "effect", "grade", "gap", "effect"]
    gap = next(entry for entry in entries if entry.kind == "gap")
    assert gap.body["reason"] == "dropped"
    assert gap.body["count"] == 1
    assert gap.body["kinds"] == {"effect": 1}


def test_a_grade_and_effect_pair_is_dropped_whole_and_counted_twice() -> None:
    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    accepted = emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", clock.now(), "policy-1"),
    )
    assert accepted is False
    assert emitter.flush("local", timeout=2)
    emitter.close()
    gap = next(entry for entry in store.read_range("local", from_sequence=1) if entry.kind == "gap")
    assert gap.body["count"] == 2
    assert gap.body["kinds"] == {"effect": 1, "grade": 1}


def test_a_connections_first_record_in_a_scope_is_preceded_by_its_grade() -> None:
    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=clock)
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    assert [entry.kind for entry in store.read_range("local", from_sequence=1)] == [
        "grade",
        "effect",
    ]


def test_the_daemons_own_gap_record_is_graded_too() -> None:
    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    entries = store.read_range("local", from_sequence=1)
    gap_index = next(index for index, entry in enumerate(entries) if entry.kind == "gap")
    assert entries[gap_index - 1].kind == "grade"
    assert entries[gap_index - 1].connection_id == "daemon"


class RefusingStore(InMemoryEvidenceStore):
    """A store that refuses every append and counts the attempts."""

    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0
        self.refusing = True

    def append(self, item: EvidenceRecord):  # type: ignore[no-untyped-def]
        self.attempts += 1
        if self.refusing:
            raise OSError("synthetic append failure")
        return super().append(item)


def _stalled_emitter(store: RefusingStore, clock: Clock) -> EvidenceEmitter:
    """An emitter holding a pending gap its store will not accept."""
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    emitter.emit(record(clock, "refused"))
    assert emitter.flush("local", timeout=0.5) is False
    return emitter


def test_a_pending_gap_a_failing_store_refuses_does_not_spin_the_drain_thread() -> None:
    """Article 10: emission is bounded — a refusing authority costs a retry, not a core."""
    clock = Clock()
    store = RefusingStore()
    emitter = _stalled_emitter(store, clock)
    try:
        settled = store.attempts
        sleep(1.0)
        assert store.attempts - settled <= 20, store.attempts - settled
    finally:
        emitter.close(timeout=1)


def test_a_flush_that_timed_out_leaves_no_standing_request() -> None:
    """Article 2: a request that was not satisfied is discarded, not left asserting itself."""
    clock = Clock()
    store = RefusingStore()
    emitter = _stalled_emitter(store, clock)
    try:
        assert emitter.pending_flush_requests == ()
    finally:
        emitter.close(timeout=1)


def test_close_terminates_the_worker_even_when_the_store_refuses() -> None:
    """Article 2: shutting down on a broken authority ends, and says it did not flush."""
    clock = Clock()
    store = RefusingStore()
    emitter = _stalled_emitter(store, clock)
    assert emitter.close(timeout=2) is False
    assert emitter.worker_is_alive is False


def test_emit_does_not_report_success_while_the_store_is_refusing() -> None:
    """Article 2: `True` means the pipeline is recording, never merely that it accepted."""
    clock = Clock()
    store = RefusingStore()
    emitter = _stalled_emitter(store, clock)
    try:
        assert emitter.emit(record(clock, "after-refusal")) is False
    finally:
        emitter.close(timeout=1)


def test_a_refusing_store_is_declared_in_the_emission_status() -> None:
    """Article 10: a pipeline that is not delivering says so, with the records it holds."""
    clock = Clock()
    store = RefusingStore()
    emitter = _stalled_emitter(store, clock)
    try:
        emission = emitter.emission_status
        assert emission["delivering"] is False
        assert emission["undelivered_records"] >= 1
        assert emission["scopes_undelivered"] == ["local"]
    finally:
        emitter.close(timeout=1)


def test_a_store_that_recovers_writes_the_gap_it_refused() -> None:
    """Article 10: the records the store lost leave a declared gap once it accepts one."""
    clock = Clock()
    store = RefusingStore()
    emitter = _stalled_emitter(store, clock)
    try:
        store.refusing = False
        assert emitter.flush("local", timeout=2) is True
        assert emitter.emission_status["delivering"] is True
        entries = store.read_range("local", from_sequence=1)
        assert [item.kind for item in entries][-1] == "gap"
        assert entries[-1].body["reason"] == "dropped"
    finally:
        emitter.close(timeout=2)


# -- block 2.7: the effect copies the decision's facts and names its epoch --


def _decided(clock: Clock) -> EffectDecision:
    from sayfirst_control_plane.ports.decision_store import DecisionPosition

    return EffectDecision(
        "decision-1",
        "allow",
        clock.now(),
        "sha256:" + "a" * 64,
        reason="policy_allows",
        rule_id="rule-0",
        arguments_digest="sha256:" + "1" * 64,
        correlation="corr-1",
        principal_references=("group:ops", "user:alice"),
        evaluation_recipe="sayfirst/policy-evaluation/v1",
        position=DecisionPosition("store-1", 7),
    )


def test_the_effect_copies_the_decision_facts_and_marks_who_chose_the_correlation() -> None:
    """M1, M4: reason, rule, digest, correlation and its source, references, recipe, position."""
    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=clock, recording_epoch="epoch-1")
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "alice"),
        capability="example.effect",
        decision=_decided(clock),
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    entries = store.read_range("local", from_sequence=1)
    effect = next(item for item in entries if item.kind == "effect")
    assert effect.body["reason"] == "policy_allows"
    assert effect.body["rule_id"] == "rule-0"
    assert effect.body["arguments_digest"] == "sha256:" + "1" * 64
    assert effect.body["correlation"] == "corr-1"
    assert effect.body["correlation_source"] == "boundary_supplied"
    assert effect.body["principal_references"] == ["group:ops", "user:alice"]
    assert effect.body["evaluation_recipe"] == "sayfirst/policy-evaluation/v1"
    assert effect.body["decision_position"] == {"store_id": "store-1", "position": 7}
    assert effect.body["recording_epoch"] == "epoch-1"
    grade = next(item for item in entries if item.kind == "grade")
    assert grade.body["recording_epoch"] == "epoch-1"
    assert "capture" not in effect.body


def test_an_absent_correlation_is_null_and_marked_absent_never_synthesised() -> None:
    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=clock)
    from dataclasses import replace

    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "alice"),
        capability="example.effect",
        decision=replace(_decided(clock), correlation=None, arguments_digest=None, rule_id=None),
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    effect = next(
        item for item in store.read_range("local", from_sequence=1) if item.kind == "effect"
    )
    assert effect.body["correlation"] is None
    assert effect.body["correlation_source"] == "absent"
    assert effect.body["arguments_digest"] is None
    assert effect.body["rule_id"] is None


def test_capture_redaction_does_not_change_copied_decision_identity() -> None:
    """G15: what a redactor does to captured bytes never reaches the copied facts."""
    from sayfirst_control_plane.application.evidence_emitter import CapturePolicy, CaptureRule

    class Rewriting:
        interface_version = 1
        name = "rewriting"

        def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction:
            return Redaction(b"[redacted]", "applied", self.name)

    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(
        store,
        clock=clock,
        privacy_redactor=Rewriting(),  # type: ignore[arg-type]
        capture_policy=CapturePolicy([CaptureRule("example.effect", 64)]),
    )
    decided = _decided(clock)
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "alice"),
        capability="example.effect",
        decision=decided,
        payload=b"the payload",
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    effect = next(
        item for item in store.read_range("local", from_sequence=1) if item.kind == "effect"
    )
    assert effect.body["capture"]["content"] == "[redacted]"
    assert effect.body["correlation"] == "corr-1"
    assert effect.body["correlation_source"] == "boundary_supplied"
    assert effect.body["principal_references"] == ["group:ops", "user:alice"]
    assert effect.body["decision_id"] == decided.decision_id
