# SPDX-License-Identifier: Apache-2.0
"""Articles 2, 3, 7 and 10: recovery declares what an unclean stop may have lost, by identity.

The asynchronous emitter keeps the evidence authority off the hot path (article
10), so a crash can lose an effect whose decision was committed. Recovery
compares the durable decision positions of the epoch with the effect positions
that survived and declares each missing one in an `unflushed` gap, exact and
bounded; it writes an `unclean_stop` marker over the epoch's chain span so a
verifier lowers every connection in it and reports the coverage unknown; and
it converges: a second recovery over the same journal appends nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_control_plane.adapters.file.decision_store import FileDecisionStore
from sayfirst_control_plane.adapters.file.recovery_journal import FileRecoveryJournal
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application import recovery as recovery_module
from sayfirst_control_plane.application.recovery import RecoveryWriter
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal

AT = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)


def _decision(reference: str) -> Decision:
    return Decision(
        reference,
        "local",
        "example.effect",
        Outcome.ALLOW,
        Reason.POLICY_ALLOWS,
        "sha256:" + "a" * 64,
        None,
        "2026-09-05T10:00:00Z",
        None,
        1,
        {
            "principal": {"kind": "user", "uid": 1000, "name": "alice"},
            "arguments_digest": None,
            "rule_id": "rule-0",
            "grant_id": None,
            "principal_references": ["user:alice"],
            "evaluation_recipe": "sayfirst/policy-evaluation/v1",
            "correlation_source": "absent",
        },
    )


def _effect(store: InMemoryEvidenceStore, decision: Decision, position, epoch: str) -> None:  # type: ignore[no-untyped-def]
    store.append(
        EvidenceRecord(
            "local",
            "effect",
            AT,
            "connection-1",
            Principal("user", "alice"),
            {
                "capability": decision.capability,
                "decision_id": decision.decision_ref,
                "outcome": "allow",
                "decided_at": decision.decided_at,
                "policy_version": decision.policy_version,
                "reason": "policy_allows",
                "rule_id": decision.extra["rule_id"],
                "arguments_digest": None,
                "correlation": None,
                "correlation_source": "absent",
                "principal_references": ["user:alice"],
                "evaluation_recipe": "sayfirst/policy-evaluation/v1",
                "decision_position": {"store_id": position.store_id, "position": position.position},
                "recording_epoch": epoch,
            },
        )
    )


def _daemon_grade(epoch: str):  # type: ignore[no-untyped-def]
    """One grade record per scope per life, the way the emitter answers the writer."""
    graded: set[str] = set()

    def grade(scope: str) -> EvidenceRecord | None:
        if scope in graded:
            return None
        graded.add(scope)
        return EvidenceRecord(
            scope,
            "grade",
            AT,
            "daemon",
            Principal("service", "daemon"),
            {
                "grade": "unverified",
                "basis": "access_not_established",
                "evaluated_at": "2026-09-05T10:00:00Z",
                "paths_inspected": 0,
                "recording_epoch": epoch,
            },
        )

    return grade


def _life(tmp_path: Path, epoch: str):  # type: ignore[no-untyped-def]
    chain = InMemoryEvidenceStore()
    decisions = FileDecisionStore(tmp_path / "evidence", recording_epoch=epoch)
    journal = FileRecoveryJournal(tmp_path / "evidence")
    writer = RecoveryWriter(
        chain,
        decisions,
        journal,
        recording_epoch=epoch,
        clock=lambda: AT,
        daemon_grade=_daemon_grade(epoch),
    )
    return chain, decisions, journal, writer


def test_a_clean_stop_closes_the_epoch_with_a_marker_over_its_span(tmp_path: Path) -> None:
    """C3: after the queues drain, the marker names the span and the journal names the marker."""
    chain, decisions, journal, writer = _life(tmp_path, "epoch-1")
    writer.open_epoch("local")
    position = decisions.append(_decision("decision-1"))
    _effect(chain, _decision("decision-1"), position, "epoch-1")
    assert writer.close_clean("local") is True
    entries = chain.read_range("local", from_sequence=1)
    marker = entries[-1]
    assert marker.kind == "recovery"
    assert marker.body["event"] == "clean_stop"
    assert marker.body["epoch_id"] == "epoch-1"
    # The span closes over the daemon's own grade too, so no asynchronous
    # entry of the epoch is left outside a clean span.
    assert (marker.body["from_sequence"], marker.body["through_sequence"]) == (1, 2)
    assert marker.body["recording_epoch"] == "recovery:epoch-1"
    assert marker.connection_id == "daemon"
    assert journal.open_epochs("local") == ()
    # The daemon's own grade precedes its marker, or its grade would be unverified.
    assert [item.kind for item in entries] == ["effect", "grade", "recovery"]


def test_an_open_epoch_at_the_next_start_is_declared_unclean_and_its_lost_decisions_named(
    tmp_path: Path,
) -> None:
    """C3, C4: unknown coverage over the span; the missing decision by identity and position."""
    chain, decisions, journal, writer = _life(tmp_path, "epoch-1")
    writer.open_epoch("local")
    kept = decisions.append(_decision("decision-kept"))
    _effect(chain, _decision("decision-kept"), kept, "epoch-1")
    lost = decisions.append(_decision("decision-lost"))
    # No clean stop: the process died with the second effect in the queue.
    decisions.close()

    second = RecoveryWriter(
        chain,
        FileDecisionStore(tmp_path / "evidence", recording_epoch="epoch-2"),
        FileRecoveryJournal(tmp_path / "evidence"),
        recording_epoch="epoch-2",
        clock=lambda: AT,
        daemon_grade=_daemon_grade("epoch-2"),
    )
    report = second.reconcile_at_start("local")
    entries = chain.read_range("local", from_sequence=1)
    kinds = [item.kind for item in entries]
    assert kinds == ["effect", "grade", "recovery", "gap"]
    unclean = entries[2].body
    assert unclean["event"] == "unclean_stop"
    assert unclean["epoch_id"] == "epoch-1"
    assert (unclean["from_sequence"], unclean["through_sequence"]) == (1, 1)
    assert unclean["lost_event_count"] is None and unclean["coverage"] == "unknown"
    gap = entries[3].body
    assert gap["reason"] == "unflushed"
    assert gap["accounting"] == "decision"
    assert gap["decision_ids"] == ["decision-lost"]
    assert gap["decision_positions"] == [{"store_id": lost.store_id, "position": lost.position}]
    assert gap["kinds"] == {"effect": 1} and gap["count"] == 1
    # The producer epoch, not the recovering one (C4).
    assert gap["recording_epoch"] == "epoch-1"
    assert journal.open_epochs("local") == ()
    assert report.unflushed_declared == 1
    assert report.effects_without_decision == 0
    assert report.unknown_event_coverage is True
    assert report.state == "agrees"


def test_recovery_is_idempotent_across_another_crash(tmp_path: Path) -> None:
    """G40: markers already written are reused, never appended again."""
    chain, decisions, journal, writer = _life(tmp_path, "epoch-1")
    writer.open_epoch("local")
    decisions.append(_decision("decision-lost"))
    decisions.close()
    second = RecoveryWriter(
        chain,
        FileDecisionStore(tmp_path / "evidence", recording_epoch="epoch-2"),
        FileRecoveryJournal(tmp_path / "evidence"),
        recording_epoch="epoch-2",
        clock=lambda: AT,
        daemon_grade=_daemon_grade("epoch-2"),
    )
    second.reconcile_at_start("local")
    count = len(chain.read_range("local", from_sequence=1))
    # A crash between the markers and the journal: the journal still says open.
    with (tmp_path / "evidence" / "recovery" / "local.jsonl").open("r+b") as stream:
        lines = stream.read().splitlines(keepends=True)
        stream.seek(0)
        stream.truncate()
        stream.writelines(lines[:-1])
    third = RecoveryWriter(
        chain,
        FileDecisionStore(tmp_path / "evidence", recording_epoch="epoch-3"),
        FileRecoveryJournal(tmp_path / "evidence"),
        recording_epoch="epoch-3",
        clock=lambda: AT,
        daemon_grade=_daemon_grade("epoch-3"),
    )
    assert [item.epoch_id for item in third.journal.open_epochs("local")] == ["epoch-1"]
    third.reconcile_at_start("local")
    assert len(chain.read_range("local", from_sequence=1)) == count
    assert third.journal.open_epochs("local") == ()
    # And a further start over a reconciled journal appends nothing at all.
    third.reconcile_at_start("local")
    assert len(chain.read_range("local", from_sequence=1)) == count


def test_more_lost_decisions_than_the_bound_are_split_across_markers_never_id_less(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """C4: a loss larger than the bound is several markers, each exact."""
    monkeypatch.setattr(recovery_module, "GAP_ID_BOUND", 2)
    chain, decisions, journal, writer = _life(tmp_path, "epoch-1")
    writer.open_epoch("local")
    for index in range(5):
        decisions.append(_decision(f"decision-{index}"))
    decisions.close()
    second = RecoveryWriter(
        chain,
        FileDecisionStore(tmp_path / "evidence", recording_epoch="epoch-2"),
        FileRecoveryJournal(tmp_path / "evidence"),
        recording_epoch="epoch-2",
        clock=lambda: AT,
        daemon_grade=_daemon_grade("epoch-2"),
    )
    second.reconcile_at_start("local")
    gaps = [item for item in chain.read_range("local", from_sequence=1) if item.kind == "gap"]
    named = [identifier for gap in gaps for identifier in gap.body["decision_ids"]]
    assert [len(gap.body["decision_ids"]) for gap in gaps] == [2, 2, 1]
    assert named == [f"decision-{index}" for index in range(5)]


def test_an_effect_without_authority_is_counted_and_a_contradiction_named(tmp_path: Path) -> None:
    """S8: compare contents, not just identities; report, never repair."""
    chain, decisions, journal, writer = _life(tmp_path, "epoch-1")
    writer.open_epoch("local")
    position = decisions.append(_decision("decision-1"))
    contradicted = _decision("decision-1")
    contradicted.extra["rule_id"] = "another-rule"  # type: ignore[index]
    _effect(chain, contradicted, position, "epoch-1")
    orphan = _decision("decision-orphan")
    _effect(chain, orphan, position.__class__(position.store_id, 99), "epoch-1")
    assert writer.close_clean("local") is True
    report = writer.reconcile_at_start("local")
    assert report.effects_without_decision == 1
    assert report.contradictory_decisions == 1
    assert report.state == "contradicts"
    assert report.unknown_event_coverage is False
    assert decisions.get("local", "decision-1") == _decision("decision-1")


def test_an_authority_that_cannot_be_read_is_not_run_never_disagrees(tmp_path: Path) -> None:
    """Article 2, S8: an unreadable decision store is no evidence that decisions are missing.

    A scope whose file the authority refuses to serve has effects the comparison
    cannot pair with anything; counting each as an effect without a decision
    rendered the absence of the authority as `disagrees`. The comparison did
    not run, and the report says so with null counts, never zeros.
    """
    chain, decisions, journal, writer = _life(tmp_path, "epoch-1")
    writer.open_epoch("local")
    position = decisions.append(_decision("decision-1"))
    _effect(chain, _decision("decision-1"), position, "epoch-1")
    assert writer.close_clean("local") is True
    decisions.close()
    # A malformed complete line: the scope is unavailable, not empty (R4).
    with (tmp_path / "evidence" / "decisions" / "local.jsonl").open("ab") as stream:
        stream.write(b"{this is not a record}\n")

    second = RecoveryWriter(
        chain,
        FileDecisionStore(tmp_path / "evidence", recording_epoch="epoch-2"),
        FileRecoveryJournal(tmp_path / "evidence"),
        recording_epoch="epoch-2",
        clock=lambda: AT,
        daemon_grade=_daemon_grade("epoch-2"),
    )
    report = second.reconcile_at_start("local")
    assert report.state == "not_run"
    document = report.to_document()
    assert document["state"] == "not_run"
    for member in (
        "checked_at",
        "through_sequence",
        "through_decision_position",
        "effects_without_decision",
        "contradictory_decisions",
        "unflushed_declared",
        "unknown_event_coverage",
        "policy_versions_absent",
        "policy_versions_damaged",
    ):
        assert document[member] is None, member
