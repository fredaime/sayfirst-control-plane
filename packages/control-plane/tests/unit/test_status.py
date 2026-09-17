# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

from sayfirst_contract.transport.cli import render_status
from sayfirst_control_plane.adapters.file.evidence_store import FileEvidenceStore
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.evidence_emitter import EvidenceConnection, EvidenceEmitter
from sayfirst_control_plane.application.status import evidence_status
from sayfirst_control_plane.configuration import GRADE_REEVALUATION_HELP
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal
from sayfirst_control_plane.domain.integrity_grade import CallerAccess, Grade, GradeEvaluation
from sayfirst_control_plane.ports.evidence_store import StoreLocation


class Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 4, 10, 0, tzinfo=UTC)


def test_status_names_the_grade_and_active_privacy_provider() -> None:
    emitter = EvidenceEmitter(InMemoryEvidenceStore(), clock=Clock())
    document = evidence_status(
        emitter,
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
    )
    assert document["integrity_grade"] == {
        "grade": "unverified",
        "basis": "access_not_established",
        "evaluated_at": "2026-09-04T10:00:00Z",
        "store": "memory",
        "reevaluation_interval_seconds": 30,
    }
    assert document["privacy_provider"] == "none"
    rendered = render_status(document)
    assert "integrity grade: unverified (access not established)" in rendered
    assert "privacy provider: none (captured content is recorded as given)" in rendered
    emitter.close()


def test_status_names_unknown_without_claiming_a_default() -> None:
    rendered = render_status(
        {
            "integrity_grade": {
                "grade": "unverified",
                "basis": "access_not_established",
            },
            "privacy_provider": "unknown",
        }
    )
    assert "privacy provider: unknown (could not consult the composition)" in rendered


def test_status_renders_the_active_privacy_provider_by_name() -> None:
    rendered = render_status(
        {
            "integrity_grade": {
                "grade": "unverified",
                "basis": "access_not_established",
            },
            "privacy_provider": "example-provider",
        }
    )
    assert "privacy provider: example-provider" in rendered


def test_status_converts_evaluation_time_to_utc() -> None:
    class Emitter:
        grade_reevaluation_seconds = 30
        privacy_provider = "none"
        store_location = StoreLocation("memory", None, "process lifetime")
        emission_status: ClassVar[dict[str, object]] = {
            "delivering": True,
            "undelivered_records": 0,
            "scopes_undelivered": [],
        }

        def evaluation_for(self, scope, connection, principal, *, force=False):  # type: ignore[no-untyped-def]
            return GradeEvaluation(
                Grade.unverified,
                "access_not_established",
                datetime(2026, 9, 4, 10, 0, tzinfo=timezone(timedelta(hours=2))),
                0,
            )

    document = evidence_status(
        Emitter(),  # type: ignore[arg-type]
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
    )
    assert document["integrity_grade"]["evaluated_at"] == "2026-09-04T08:00:00Z"


def test_status_does_not_render_the_unproduced_evidence_grade() -> None:
    rendered = render_status(
        {
            "integrity_grade": {"grade": "evidence", "basis": "caller_cannot_write"},
            "privacy_provider": "none",
        }
    )
    assert "integrity grade: unverified" in rendered
    assert "integrity grade: evidence" not in rendered


def test_the_interval_is_documented_as_the_latency_of_detection() -> None:
    assert "latency of detection" in GRADE_REEVALUATION_HELP


def test_status_renders_unverified_when_access_cannot_be_established(tmp_path: Path) -> None:
    class UnavailablePathAccess:
        def inspect(self, path: Path):  # type: ignore[no-untyped-def]
            raise OSError("synthetic inspection failure")

    emitter = EvidenceEmitter(
        FileEvidenceStore(tmp_path / "store"),
        clock=Clock(),
        path_access=UnavailablePathAccess(),
    )
    document = evidence_status(
        emitter,
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
    )
    assert document["integrity_grade"]["grade"] == "unverified"
    assert document["integrity_grade"]["basis"] == "access_not_established"
    emitter.close()


def test_status_declares_a_pipeline_that_is_not_delivering() -> None:
    """Article 10: a store refusing appends is reported, never a silent clean status."""

    class RefusingStore(InMemoryEvidenceStore):
        def append(self, item):  # type: ignore[no-untyped-def]
            raise OSError("synthetic append failure")

    emitter = EvidenceEmitter(RefusingStore(), queue_capacity=1)
    try:
        emitter.emit(
            EvidenceRecord(
                "local",
                "effect",
                datetime(2026, 9, 4, tzinfo=UTC),
                "connection-1",
                Principal("user", "example"),
                {
                    "capability": "example.effect",
                    "decision_id": "decision-1",
                    "outcome": "allow",
                    "decided_at": "2026-09-04T00:00:00Z",
                    "policy_version": "policy-1",
                },
            )
        )
        assert emitter.flush("local", timeout=0.5) is False
        emission = evidence_status(
            emitter,
            scope="local",
            connection=EvidenceConnection("connection-1", CallerAccess(0, frozenset())),
            principal=Principal("user", "example"),
        )["evidence_emission"]
        assert isinstance(emission, dict)
        assert emission["delivering"] is False
        assert emission["undelivered_records"] >= 1
        assert emission["scopes_undelivered"] == ["local"]
    finally:
        emitter.close(timeout=1)


def test_status_renders_a_pipeline_that_is_not_delivering() -> None:
    """Article 2: a status that is not clean does not read as clean."""
    rendered = render_status(
        {
            "integrity_grade": {"grade": "observability", "basis": "caller_can_write"},
            "privacy_provider": "none",
            "evidence_emission": {
                "delivering": False,
                "undelivered_records": 3,
                "scopes_undelivered": ["local"],
            },
        }
    )
    assert "evidence emission: not delivering (3 records held, scopes: local)" in rendered


def test_status_renders_a_delivering_pipeline_without_a_claim_about_the_store() -> None:
    rendered = render_status(
        {
            "integrity_grade": {"grade": "observability", "basis": "caller_can_write"},
            "privacy_provider": "none",
            "evidence_emission": {
                "delivering": True,
                "undelivered_records": 0,
                "scopes_undelivered": [],
            },
        }
    )
    assert "evidence emission: delivering" in rendered
    for word in ("proof", "tamper", "complete", "intact"):
        assert word not in rendered


def test_status_without_an_emission_member_says_it_is_unknown() -> None:
    """Article 2: an absent member is never rendered as a healthy one."""
    rendered = render_status(
        {
            "integrity_grade": {"grade": "observability", "basis": "caller_can_write"},
            "privacy_provider": "none",
        }
    )
    assert "evidence emission: unknown (the daemon did not report it)" in rendered
