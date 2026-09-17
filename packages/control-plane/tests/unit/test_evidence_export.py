# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application import evidence_reads
from sayfirst_control_plane.application.evidence_emitter import EvidenceEmitter
from sayfirst_control_plane.application.evidence_reads import (
    EvidenceReads,
    EvidenceStoreUnavailable,
)
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal, canonical_json
from sayfirst_control_plane.domain.evidence_export import manifest_hash


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)

    def now(self) -> datetime:
        result = self.value
        self.value += timedelta(seconds=1)
        return result


def record(clock: Clock, identifier: str) -> EvidenceRecord:
    now = clock.now()
    return EvidenceRecord(
        "local",
        "effect",
        now,
        "connection-1",
        Principal("user", "example"),
        {
            "capability": "example.effect",
            "decision_id": identifier,
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


def test_the_export_carries_the_gap_marker_recorded_under_backpressure() -> None:
    """Article 10: a bounded pipeline exports its loss as evidence."""
    clock = Clock()
    store = StallingStore()
    emitter = EvidenceEmitter(store, clock=clock, queue_capacity=1)
    emitter.emit(record(clock, "one"))
    assert store.started.wait(timeout=1)
    emitter.emit(record(clock, "two"))
    emitter.emit(record(clock, "lost"))
    store.release.set()
    assert emitter.flush("local", timeout=2)

    bundle = EvidenceReads(store, emitter=emitter).export(scope="local", from_sequence=1)
    emitter.close()
    gaps = [item for item in bundle["entries"] if item["kind"] == "gap"]
    assert len(gaps) == 1
    assert gaps[0]["body"]["reason"] == "dropped"
    assert bundle["verification"]["condition"] == "intact"
    assert bundle["verification"]["declared_gaps"] == [
        {"sequence": gaps[0]["sequence"], "reason": "dropped", "count": 1}
    ]

    entries = store.read_range("local", from_sequence=1)
    without_gap = [item.entry_hash for item in entries if item.kind != "gap"]
    changed = manifest_hash(
        scope="local",
        from_sequence=1,
        to_sequence=entries[-1].sequence,
        contract_version="1",
        verdict=bundle["verification"],
        entry_hashes=without_gap,
    )
    assert changed != bundle["manifest_hash"]


def test_the_bundle_is_deterministic() -> None:
    clock = Clock()
    store = InMemoryEvidenceStore()
    store.append(record(clock, "one"))
    reads = EvidenceReads(store)
    assert reads.export(scope="local", from_sequence=1) == reads.export(
        scope="local", from_sequence=1
    )


def test_the_manifest_hashes_entry_hashes_not_entries() -> None:
    """Article 10: `manifest_hash` accepts stored digests, never entry content."""
    parameters = inspect.signature(manifest_hash).parameters
    assert "entry_hashes" in parameters
    assert "entries" not in parameters


def test_a_bundle_over_a_range_beginning_after_the_asked_start_carries_gap_at() -> None:
    class MissingHeadStore(InMemoryEvidenceStore):
        def read_range(self, scope: str, *, from_sequence: int, to_sequence=None):  # type: ignore[no-untyped-def]
            entries = super().read_range(
                scope,
                from_sequence=from_sequence,
                to_sequence=to_sequence,
            )
            return entries[1:] if from_sequence == 1 else entries

    clock = Clock()
    store = MissingHeadStore()
    store.append(record(clock, "one"))
    store.append(record(clock, "two"))
    bundle = EvidenceReads(store).export(scope="local", from_sequence=1)
    assert bundle["verification"]["condition"] == "gap_at"
    assert bundle["verification"]["sequence"] == 1


def test_an_export_over_the_byte_bound_serves_the_largest_prefix_that_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A6: over the byte bound, the largest contiguous prefix that fits, then the rest."""
    clock = Clock()
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=clock)
    for index in range(6):
        emitter.emit(record(clock, f"decision-{index}"))
    assert emitter.flush("local", timeout=2)
    reads = EvidenceReads(store, emitter=emitter)
    whole = reads.export(scope="local", from_sequence=1)
    assert whole["next_from"] is None
    total = len(whole["entries"])
    bound = len(canonical_json(whole)) - 1

    monkeypatch.setattr(evidence_reads, "EXPORT_BYTE_BOUND", bound)
    bounded = reads.export(scope="local", from_sequence=1)
    assert len(canonical_json(bounded)) <= bound
    served = [item["sequence"] for item in bounded["entries"]]
    assert served == list(range(1, len(served) + 1))
    assert 0 < len(served) < total
    assert bounded["next_from"] == served[-1] + 1
    rest = reads.export(scope="local", from_sequence=bounded["next_from"])
    assert [item["sequence"] for item in rest["entries"]] == list(range(served[-1] + 1, total + 1))

    # One entry alone over the bound is refused, never served cut short.
    monkeypatch.setattr(evidence_reads, "EXPORT_BYTE_BOUND", 1)
    with pytest.raises(EvidenceStoreUnavailable):
        reads.export(scope="local", from_sequence=1)
    emitter.close()
