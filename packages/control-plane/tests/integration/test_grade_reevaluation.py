# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sayfirst_control_plane.adapters.file.evidence_store import FileEvidenceStore
from sayfirst_control_plane.adapters.posix.path_access import PosixPathAccess
from sayfirst_control_plane.application.evidence_emitter import (
    EffectDecision,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.application.evidence_reads import EvidenceReads
from sayfirst_control_plane.domain.evidence_chain import Principal, verify
from sayfirst_control_plane.domain.integrity_grade import CallerAccess, Grade
from sayfirst_control_plane.ports.path_access import PathFacts


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value


class ControlledTreeAccess:
    def __init__(self, controlled: Path) -> None:
        self.controlled = controlled.absolute()
        self.posix = PosixPathAccess()

    def inspect(self, path: Path) -> PathFacts:
        absolute = path.absolute()
        if absolute == self.controlled or self.controlled in absolute.parents:
            return self.posix.inspect(absolute)
        return PathFacts(absolute, True, 0, 0, 0o755, False)


def test_a_permission_change_during_a_connection_lowers_the_grade_after_the_next_reevaluation(
    tmp_path: Path,
) -> None:
    """Article 7: the documented interval bounds detection of changed effective access."""
    controlled = tmp_path / "controlled"
    controlled.mkdir(mode=0o711)
    root = controlled / "store"
    store = FileEvidenceStore(root)
    os.chmod(root, 0o777)
    clock = Clock()
    emitter = EvidenceEmitter(
        store,
        clock=clock,
        path_access=ControlledTreeAccess(controlled),
        grade_reevaluation_seconds=30,
    )
    connection = EvidenceConnection("connection-1", CallerAccess(4242, frozenset({4242})))
    principal = Principal("user", "example")

    emitter.emit_effect(
        scope="local",
        connection=connection,
        principal=principal,
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    earlier = store.read_range("local", from_sequence=1)
    assert earlier[0].body["grade"] == "observability"

    os.chmod(root, 0o755)
    clock.value += timedelta(seconds=31)
    emitter.emit_effect(
        scope="local",
        connection=connection,
        principal=principal,
        capability="example.effect",
        decision=EffectDecision("decision-2", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()

    entries = store.read_range("local", from_sequence=1)
    grades = [entry.body for entry in entries if entry.kind == "grade"]
    assert [(item["grade"], item["basis"]) for item in grades] == [
        ("observability", "caller_can_write"),
        ("unverified", "caller_cannot_write"),
    ]
    assert (
        verify(earlier, scope="local", from_sequence=1, grades_before={}).grades[0].grade
        is Grade.observability
    )
    assert (
        verify(entries, scope="local", from_sequence=1, grades_before={}).grades[0].grade
        is Grade.unverified
    )


def test_a_permission_change_that_grants_write_raises_the_grade_to_observability(
    tmp_path: Path,
) -> None:
    controlled = tmp_path / "controlled-raise"
    controlled.mkdir(mode=0o711)
    root = controlled / "store"
    store = FileEvidenceStore(root)
    os.chmod(root, 0o755)
    clock = Clock()
    emitter = EvidenceEmitter(
        store,
        clock=clock,
        path_access=ControlledTreeAccess(controlled),
        grade_reevaluation_seconds=30,
    )
    connection = EvidenceConnection("connection-1", CallerAccess(4242, frozenset({4242})))
    principal = Principal("user", "example")
    emitter.emit_effect(
        scope="local",
        connection=connection,
        principal=principal,
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    os.chmod(root, 0o777)
    clock.value += timedelta(seconds=31)
    emitter.emit_effect(
        scope="local",
        connection=connection,
        principal=principal,
        capability="example.effect",
        decision=EffectDecision("decision-2", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    grades = [
        entry.body["grade"]
        for entry in store.read_range("local", from_sequence=1)
        if entry.kind == "grade"
    ]
    assert grades == ["unverified", "observability"]


def test_the_grade_is_reevaluated_before_a_verdict(tmp_path: Path) -> None:
    controlled = tmp_path / "controlled-verdict"
    controlled.mkdir(mode=0o711)
    root = controlled / "store"
    store = FileEvidenceStore(root)
    os.chmod(root, 0o777)
    clock = Clock()
    emitter = EvidenceEmitter(
        store,
        clock=clock,
        path_access=ControlledTreeAccess(controlled),
        grade_reevaluation_seconds=300,
    )
    connection = EvidenceConnection("connection-1", CallerAccess(4242, frozenset({4242})))
    principal = Principal("user", "example")
    emitter.emit_effect(
        scope="local",
        connection=connection,
        principal=principal,
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", clock.now(), "policy-1"),
    )
    assert emitter.flush("local", timeout=2)
    os.chmod(root, 0o755)
    bundle = EvidenceReads(store, emitter=emitter).export(
        scope="local",
        from_sequence=1,
        connection=connection,
        principal=principal,
    )
    emitter.close()
    assert bundle["entries"][-1]["kind"] == "grade"
    assert bundle["entries"][-1]["body"]["grade"] == "unverified"
