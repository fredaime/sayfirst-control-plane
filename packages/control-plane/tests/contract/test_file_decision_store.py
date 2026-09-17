# SPDX-License-Identifier: Apache-2.0
"""Articles 1, 3, 5, 7 and 10: the durable decision authority, one file per scope."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_control_plane.adapters.file.decision_store import (
    FileDecisionStore,
    RootHeldByAnotherWriter,
)
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.ports.decision_store import (
    DecisionAlreadyExists,
    DecisionStoreUnavailable,
)
from sayfirst_testing.decision_store_contract import DecisionStoreContract


def _decision(
    reference: str, *, scope: str = "local", outcome: Outcome = Outcome.ALLOW
) -> Decision:
    return Decision(
        decision_ref=reference,
        scope=scope,
        capability="mail.send",
        outcome=outcome,
        reason=Reason.POLICY_ALLOWS if outcome is Outcome.ALLOW else Reason.POLICY_ABSENT,
        policy_version="sha256:" + "a" * 64,
        approval_ref=None,
        decided_at="2026-09-04T00:00:00Z",
        correlation="corr-1",
        contract_generation=1,
        extra={
            "principal": {"kind": "process", "uid": 1000, "name": "build"},
            "arguments_digest": None,
            "rule_id": "rule-0" if outcome is Outcome.ALLOW else None,
            "grant_id": None,
            "principal_references": ["user:build"],
            "evaluation_recipe": "sayfirst/policy-evaluation/v1",
            "correlation_source": "boundary_supplied",
        },
    )


class TestMemoryDecisionStore(DecisionStoreContract):
    def make_store(self, tmp_path: Path) -> MemoryDecisionStore:
        return MemoryDecisionStore()


class TestFileDecisionStore(DecisionStoreContract):
    def make_store(self, tmp_path: Path) -> FileDecisionStore:
        return FileDecisionStore(tmp_path / "evidence")


def _file(root: Path, scope: str = "local") -> Path:
    return root / "decisions" / f"{scope}.jsonl"


def test_the_envelope_is_the_storage_format_and_the_wire_decision_is_inside_it(
    tmp_path: Path,
) -> None:
    """R3: the storage envelope owns positions; the decision inside is the published record."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    position = store.append(_decision("decision-1"))
    lines = _file(root).read_text(encoding="utf-8").splitlines()
    header, envelope = (json.loads(line) for line in lines)
    assert header == {
        "storage_version": 1,
        "header": {"scope": "local", "store_id": position.store_id},
    }
    assert envelope["storage_version"] == 1
    assert (envelope["scope"], envelope["store_id"], envelope["position"]) == (
        "local",
        position.store_id,
        1,
    )
    assert envelope["recording_epoch"]
    assert envelope["decision"] == _decision("decision-1").to_document()
    assert stat.S_IMODE(_file(root).stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "decisions").stat().st_mode) == 0o700


def test_duplicate_and_mutation_attempts_cannot_rewrite_a_committed_record(
    tmp_path: Path,
) -> None:
    """G3: the bytes of a committed record do not move, whatever a caller does afterwards."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    given = _decision("decision-1")
    store.append(given)
    before = _file(root).read_bytes()
    given.extra["rule_id"] = "planted"  # type: ignore[index]
    with pytest.raises(DecisionAlreadyExists):
        store.append(_decision("decision-1", outcome=Outcome.DENY))
    assert _file(root).read_bytes() == before
    assert not any(name in ("update", "delete", "remove", "replace") for name in dir(store))
    read = store.get("local", "decision-1")
    assert read is not None and read.extra["rule_id"] == "rule-0"


def test_torn_tail_recovery_preserves_complete_records_and_rebuilds_index(
    tmp_path: Path,
) -> None:
    """R4, G4: a torn final suffix is quarantined and counted; every complete record stays."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    positions = [store.append(_decision(f"decision-{index}")) for index in range(3)]
    torn = b'{"storage_version": 1, "scope": "local", "posi'
    with _file(root).open("ab") as stream:
        stream.write(torn)
    reopened = FileDecisionStore(root)
    assert reopened.recover("local") == len(torn)
    for index in range(3):
        read = reopened.get("local", f"decision-{index}")
        assert read is not None and read.decision_ref == f"decision-{index}"
    fourth = reopened.append(_decision("decision-3"))
    assert fourth.position == 4
    assert fourth.store_id == positions[0].store_id
    assert _file(root).read_bytes().endswith(b"\n")


def test_a_malformed_complete_line_makes_the_scope_unavailable_not_absent(tmp_path: Path) -> None:
    """R4: storage corruption is never discarded and never read as a missing decision."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    store.append(_decision("decision-1"))
    with _file(root).open("ab") as stream:
        stream.write(b"this is not an envelope\n")
    reopened = FileDecisionStore(root)
    with pytest.raises(DecisionStoreUnavailable):
        reopened.get("local", "decision-1")
    with pytest.raises(DecisionStoreUnavailable):
        reopened.get("local", "never-existed")
    with pytest.raises(DecisionStoreUnavailable):
        reopened.append(_decision("decision-2"))
    # Another scope is untouched by this one's damage (S8: healthy scopes serve).
    assert reopened.append(_decision("decision-1", scope="other")).position == 1


def test_conflicting_duplicate_identities_make_the_scope_unavailable(tmp_path: Path) -> None:
    """R4: the store never chooses between two records of one id."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    store.append(_decision("decision-1"))
    line = _file(root).read_text(encoding="utf-8").splitlines()[-1]
    with _file(root).open("a", encoding="utf-8") as stream:
        stream.write(line.replace('"position": 1', '"position": 2') + "\n")
    with pytest.raises(DecisionStoreUnavailable):
        FileDecisionStore(root).get("local", "decision-1")


def test_positions_and_the_store_id_are_stable_across_reopening(tmp_path: Path) -> None:
    """S1: the index is a rebuildable projection of the file, which is the authority."""
    root = tmp_path / "evidence"
    first = FileDecisionStore(root)
    a = first.append(_decision("decision-a"))
    b = first.append(_decision("decision-b"))
    first.close()
    second = FileDecisionStore(root)
    c = second.append(_decision("decision-c"))
    assert (a.position, b.position, c.position) == (1, 2, 3)
    assert a.store_id == c.store_id
    assert second.get("local", "decision-a") == _decision("decision-a")
    assert second.position_of("local", "decision-b") == b


def test_a_second_writer_on_the_same_root_is_refused(tmp_path: Path) -> None:
    """One writer process per root: a second would allocate the positions of the first."""
    root = tmp_path / "evidence"
    first = FileDecisionStore(root, exclusive=True)
    first.append(_decision("decision-1"))
    with pytest.raises(RootHeldByAnotherWriter):
        FileDecisionStore(root, exclusive=True).append(_decision("decision-2"))
    first.close()
    assert FileDecisionStore(root, exclusive=True).append(_decision("decision-2")).position == 2


def test_scan_yields_every_envelope_in_position_order(tmp_path: Path) -> None:
    """The reconciliation walk reads the authority as stored, never through the index."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    for index in range(3):
        store.append(_decision(f"decision-{index}"))
    envelopes = list(store.scan("local"))
    assert [item.position for item in envelopes] == [1, 2, 3]
    assert [item.decision.decision_ref for item in envelopes] == [f"decision-{i}" for i in range(3)]
    assert list(store.scan("never")) == []
    assert store.scopes_present() == frozenset({"local"})


def test_the_location_names_the_decisions_directory(tmp_path: Path) -> None:
    location = FileDecisionStore(tmp_path / "evidence").location()
    assert location.kind == "file"
    assert location.root == tmp_path / "evidence" / "decisions"
    assert location.scope_path("local") == tmp_path / "evidence" / "decisions" / "local.jsonl"
    assert "indefinite" in location.retention


def test_the_directory_is_created_only_when_first_written(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    assert store.get("local", "decision-1") is None
    assert not (root / "decisions").exists() or os.listdir(root / "decisions") == []


def test_a_torn_tail_that_happens_to_parse_is_never_walked_as_a_record(tmp_path: Path) -> None:
    """R4: a suffix without its newline is torn whether or not its bytes parse.

    A crash between the last byte of an envelope and its newline leaves a
    suffix that is valid JSON on its own. The index never counts it, and the
    reconciliation walk must agree with the index: an envelope nobody was
    answered a position for is not a committed decision, before recovery as
    after it.
    """
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    store.append(_decision("decision-0"))
    store.append(_decision("decision-1"))
    path = _file(root)
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    torn = raw.rsplit(b"\n", 2)[-2]
    assert json.loads(torn)["decision"]["decision_ref"] == "decision-1"
    path.write_bytes(raw[:-1])

    reopened = FileDecisionStore(root)
    assert reopened.get("local", "decision-1") is None
    assert [item.decision.decision_ref for item in reopened.scan("local")] == ["decision-0"]
    assert reopened.recover("local") == len(torn)
    assert [item.decision.decision_ref for item in reopened.scan("local")] == ["decision-0"]
    assert reopened.append(_decision("decision-2")).position == 2


def test_a_torn_tail_that_does_not_parse_is_skipped_by_the_walk_not_raised(tmp_path: Path) -> None:
    """R4: the walk reads complete lines; a torn suffix is neither a record nor an error."""
    root = tmp_path / "evidence"
    store = FileDecisionStore(root)
    store.append(_decision("decision-0"))
    with _file(root).open("ab") as stream:
        stream.write(b'{"storage_version": 1, "scope": "local", "posi')
    reopened = FileDecisionStore(root)
    assert [item.decision.decision_ref for item in reopened.scan("local")] == ["decision-0"]
