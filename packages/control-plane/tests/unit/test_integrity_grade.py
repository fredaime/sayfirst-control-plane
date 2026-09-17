# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sayfirst_control_plane.domain.integrity_grade import (
    CallerAccess,
    Grade,
    evaluate_grade,
)
from sayfirst_control_plane.ports.path_access import PathFacts

NOW = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)
CALLER = CallerAccess(1000, frozenset({1000}))


def fact(path: str, *, uid: int = 0, gid: int = 0, mode: int = 0o755, acl=False):  # type: ignore[no-untyped-def]
    return PathFacts(Path(path), True, uid, gid, mode, acl)


def test_a_caller_that_can_write_the_store_is_at_observability() -> None:
    result = evaluate_grade(
        CALLER,
        (fact("/"), fact("/store", mode=0o777), fact("/store/local.jsonl", mode=0o600)),
        at=NOW,
    )
    assert result.grade is Grade.observability
    assert result.basis == "caller_can_write"


def test_a_caller_that_cannot_write_is_unverified_with_its_basis() -> None:
    result = evaluate_grade(
        CALLER,
        (fact("/"), fact("/store"), fact("/store/local.jsonl", mode=0o600)),
        at=NOW,
    )
    assert result.grade is Grade.unverified
    assert result.basis == "caller_cannot_write"


def test_an_owner_counts_as_able_to_write_even_without_a_write_bit() -> None:
    result = evaluate_grade(CALLER, (fact("/", uid=1000, mode=0o500),), at=NOW)
    assert result.grade is Grade.observability


def test_an_unknown_acl_is_access_not_established() -> None:
    result = evaluate_grade(CALLER, (fact("/", acl=None),), at=NOW)
    assert result.grade is Grade.unverified
    assert result.basis == "access_not_established"


def test_a_present_acl_is_access_not_established() -> None:
    result = evaluate_grade(CALLER, (fact("/", acl=True),), at=NOW)
    assert result.grade is Grade.unverified
    assert result.basis == "access_not_established"


def test_a_sticky_directory_does_not_let_a_stranger_replace_anothers_file() -> None:
    result = evaluate_grade(
        CALLER,
        (
            fact("/"),
            fact("/sticky", mode=0o1777),
            fact("/sticky/local.jsonl", uid=2000, mode=0o600),
        ),
        at=NOW,
    )
    assert result.grade is Grade.unverified
    assert result.basis == "caller_cannot_write"


def test_evidence_grade_is_never_produced_in_this_version() -> None:
    cases = (
        (),
        (fact("/", mode=0o777),),
        (fact("/", mode=0o755),),
        (fact("/", acl=True),),
    )
    assert all(evaluate_grade(CALLER, case, at=NOW).grade is not Grade.evidence for case in cases)


def test_root_is_at_observability() -> None:
    result = evaluate_grade(CallerAccess(0, frozenset({0})), (), at=NOW)
    assert result.grade is Grade.observability
    assert result.basis == "caller_can_write"


def test_an_unreachable_writable_path_is_not_write_access() -> None:
    result = evaluate_grade(
        CALLER,
        (
            fact("/", mode=0o700),
            fact("/closed", mode=0o777),
        ),
        at=NOW,
    )
    assert result.grade is Grade.unverified
    assert result.basis == "caller_cannot_write"


def test_writable_decision_archive_or_recovery_paths_lower_the_grade(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """R6, G6: a caller who can write the archive can forge history, whatever the chain says."""

    from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
    from sayfirst_control_plane.application.evidence_emitter import (
        EvidenceConnection,
        EvidenceEmitter,
    )
    from sayfirst_control_plane.domain.evidence_chain import Principal
    from sayfirst_control_plane.ports.evidence_store import StoreLocation
    from sayfirst_control_plane.ports.path_access import PathFacts

    evidence_root = tmp_path / "evidence"
    archive_root = evidence_root / "policy"
    archive_root.mkdir(parents=True)
    version_file = archive_root / ("a" * 64 + ".toml")
    version_file.write_bytes(b"format = 1\n")
    (evidence_root / "local.jsonl").write_bytes(b"")

    class Access:
        """Everything is the daemon's and closed, except what the case opens."""

        def __init__(self, open_paths: set[Path]) -> None:
            self.open_paths = open_paths
            self.seen: list[Path] = []

        def inspect(self, path: Path) -> PathFacts:
            self.seen.append(path)
            closed = 0o755 if path.is_dir() else 0o600
            mode = 0o666 if path in self.open_paths else closed
            return PathFacts(path, path.exists(), 0, 0, mode, False)

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            return StoreLocation(kind="file", root=evidence_root, retention="test")

    def archive_location() -> StoreLocation:
        return StoreLocation(kind="file", root=archive_root, retention="test")

    caller = CallerAccess(1000, frozenset({1000}))
    connection = EvidenceConnection("connection-1", caller)
    principal = Principal("user", "example")

    closed = Access(set())
    emitter = EvidenceEmitter(Store(), path_access=closed, also_inspected=(archive_location,))
    try:
        evaluation = emitter.evaluation_for("local", connection, principal, force=True)
    finally:
        emitter.close()
    assert evaluation.grade is Grade.unverified
    assert evaluation.basis == "caller_cannot_write"
    assert version_file in closed.seen, "the archive's actual files were not inspected"

    opened = Access({version_file})
    emitter = EvidenceEmitter(Store(), path_access=opened, also_inspected=(archive_location,))
    try:
        evaluation = emitter.evaluation_for("local", connection, principal, force=True)
    finally:
        emitter.close()
    assert evaluation.grade is Grade.observability
    assert evaluation.basis == "caller_can_write"
