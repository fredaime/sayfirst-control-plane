# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters.file import evidence_store as file_store
from sayfirst_control_plane.adapters.file.evidence_store import FileEvidenceStore
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.domain.evidence_chain import (
    EvidenceRecord,
    Principal,
    canonical_json,
    chained,
    entry_to_document,
    verify,
)
from sayfirst_control_plane.testing import EvidenceStoreContract


def record(scope: str = "local") -> EvidenceRecord:
    return EvidenceRecord(
        scope=scope,
        kind="grade",
        recorded_at=datetime(2026, 9, 4, tzinfo=UTC),
        connection_id="connection-1",
        principal=Principal("user", "example"),
        body={
            "grade": "unverified",
            "basis": "access_not_established",
            "evaluated_at": "2026-09-04T00:00:00Z",
            "paths_inspected": 0,
        },
    )


@pytest.fixture(params=("memory", "file"))
def store(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        return InMemoryEvidenceStore()
    return FileEvidenceStore(tmp_path / "evidence")


class TestMemoryEvidenceStore(EvidenceStoreContract):
    def make_store(self, tmp_path: Path) -> InMemoryEvidenceStore:
        return InMemoryEvidenceStore()


class TestFileEvidenceStore(EvidenceStoreContract):
    def make_store(self, tmp_path: Path) -> FileEvidenceStore:
        return FileEvidenceStore(tmp_path / "contract-file")


def test_sequences_are_consecutive_per_scope(store) -> None:  # type: ignore[no-untyped-def]
    local = [store.append(record()) for _ in range(3)]
    other = store.append(record("other"))
    assert [entry.sequence for entry in local] == [1, 2, 3]
    assert other.sequence == 1
    assert verify(local, scope="local", from_sequence=1, grades_before={}).up_to == 3


def test_a_reader_must_name_its_scope(store) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="scope"):
        store.read_range("", from_sequence=1)


@pytest.mark.parametrize("scope", ("../outside", "a" * 129))
def test_a_scope_outside_the_contract_is_refused_by_every_operation(store, scope) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="contract"):
        store.append(record(scope))
    with pytest.raises(ValueError, match="contract"):
        store.read_range(scope, from_sequence=1)
    with pytest.raises(ValueError, match="contract"):
        store.latest_sequence(scope)


def test_another_scopes_entries_are_never_read_here(store) -> None:  # type: ignore[no-untyped-def]
    store.append(record())
    store.append(record("other"))
    assert [entry.scope for entry in store.read_range("local", from_sequence=1)] == ["local"]


def test_the_store_has_no_mutating_verb_beyond_append(store) -> None:  # type: ignore[no-untyped-def]
    forbidden = (
        "update",
        "delete",
        "remove",
        "replace",
        "redact",
        "purge",
        "truncate",
        "rewrite",
        "edit",
        "drop",
    )
    assert not [
        name
        for name in dir(store)
        if name != "append" and any(word in name.lower() for word in forbidden)
    ]


def test_two_concurrent_appends_are_consecutive_with_no_duplicate(tmp_path: Path) -> None:
    store = FileEvidenceStore(tmp_path / "concurrent")
    with ThreadPoolExecutor(max_workers=8) as pool:
        entries = tuple(pool.map(lambda _: store.append(record()), range(50)))
    assert sorted(item.sequence for item in entries) == list(range(1, 51))
    assert len({item.entry_hash for item in entries}) == 50


def test_a_read_uses_the_last_complete_file_entry(tmp_path: Path) -> None:
    store = FileEvidenceStore(tmp_path / "partial")
    first = store.append(record())
    with store.location().scope_path("local").open("ab") as stream:  # type: ignore[union-attr]
        stream.write(b'{"incomplete":')
    assert store.latest_sequence("local") == first.sequence
    assert store.read_range("local", from_sequence=1) == (first,)


def test_the_largest_entry_is_readable_and_one_byte_more_is_never_written(tmp_path: Path) -> None:
    """Article 10: an refused entry cannot kill the append-only scope chain."""
    store = FileEvidenceStore(tmp_path / "bounded")
    baseline = record("legal")
    baseline_size = len(canonical_json(entry_to_document(chained(baseline, None)))) + 1
    evaluated_at = str(baseline.body["evaluated_at"])
    filler = "x" * (file_store._ENTRY_BOUND - baseline_size + len(evaluated_at))
    largest = EvidenceRecord(
        **{
            **baseline.__dict__,
            "body": {**baseline.body, "evaluated_at": filler},
        }
    )
    assert (
        len(canonical_json(entry_to_document(chained(largest, None)))) + 1
        == file_store._ENTRY_BOUND
    )
    assert file_store._TAIL_BOUND > file_store._ENTRY_BOUND

    first = store.append(largest)
    target = store.location().scope_path("legal")
    assert target is not None
    before_refusal = target.read_bytes()
    next_baseline = record("legal")
    next_size = len(canonical_json(entry_to_document(chained(next_baseline, first)))) + 1
    next_evaluated_at = str(next_baseline.body["evaluated_at"])
    oversized_filler = "x" * (file_store._ENTRY_BOUND + 1 - next_size + len(next_evaluated_at))
    oversized = EvidenceRecord(
        **{
            **next_baseline.__dict__,
            "body": {**next_baseline.body, "evaluated_at": oversized_filler},
        }
    )
    assert (
        len(canonical_json(entry_to_document(chained(oversized, first)))) + 1
        == file_store._ENTRY_BOUND + 1
    )
    with pytest.raises(ValueError, match="entry.*bound"):
        store.append(oversized)
    assert target.read_bytes() == before_refusal

    second = store.append(next_baseline)
    assert store.latest_sequence("legal") == 2
    assert store.read_range("legal", from_sequence=1) == (first, second)


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def test_an_append_after_a_torn_last_line_records_and_declares_the_loss(tmp_path: Path) -> None:
    """Article 10: a crash mid-append leaves a declared gap, never a dead scope."""
    store = FileEvidenceStore(tmp_path / "torn", clock=FixedClock())
    store.append(record())
    store.append(record())
    with store.location().scope_path("local").open("ab") as stream:  # type: ignore[union-attr]
        stream.write(b'{"incomplete":')

    fourth = store.append(record())

    assert fourth.sequence == 4
    entries = store.read_range("local", from_sequence=1)
    assert [item.kind for item in entries] == ["grade", "grade", "gap", "grade"]
    assert entries[2].body["reason"] == "torn"
    assert entries[2].body["count"] == 1
    verdict = verify(entries, scope="local", from_sequence=1, to_sequence=4, grades_before={})
    assert verdict.condition.value == "intact"
    assert [gap.sequence for gap in verdict.declared_gaps] == [3]


def test_an_append_after_a_tampered_last_line_keeps_recording(tmp_path: Path) -> None:
    """Article 10: one damaged line is a break the verifier reports, not a stopped recorder."""
    store = FileEvidenceStore(tmp_path / "tampered", clock=FixedClock())
    store.append(record())
    second = store.append(record())
    target = store.location().scope_path("local")
    assert target is not None
    lines = target.read_bytes().splitlines()
    document = json.loads(lines[-1])
    document["entry_hash"] = "0" * 64
    target.write_bytes(b"\n".join((*lines[:-1], canonical_json(document))) + b"\n")

    third = store.append(record())

    assert third.sequence == 3
    assert third.previous_hash == "0" * 64
    entries = store.read_range("local", from_sequence=1)
    verdict = verify(entries, scope="local", from_sequence=1, to_sequence=3, grades_before={})
    assert verdict.condition.value == "broken_at"
    assert verdict.sequence == second.sequence


def test_the_torn_recovery_never_removes_a_complete_entry(tmp_path: Path) -> None:
    """Article 3: only the bytes that never became an entry are dropped."""
    store = FileEvidenceStore(tmp_path / "keeps", clock=FixedClock())
    first = store.append(record())
    second = store.append(record())
    with store.location().scope_path("local").open("ab") as stream:  # type: ignore[union-attr]
        stream.write(b'{"incomplete":')
    store.append(record())
    entries = store.read_range("local", from_sequence=1)
    assert entries[0] == first
    assert entries[1] == second
