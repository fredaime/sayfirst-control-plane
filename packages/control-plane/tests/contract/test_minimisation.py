# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.evidence_emitter import (
    CapturePolicy,
    EffectDecision,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.domain.evidence_chain import (
    Principal,
    canonical_json,
    entry_to_document,
)
from sayfirst_control_plane.domain.integrity_grade import CallerAccess


class Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 4, 10, 0, tzinfo=UTC)


def test_the_default_configuration_emits_no_payload_member() -> None:
    """Article 11: an unconfigured recorder keeps only the effect's identity."""
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=Clock(), capture_policy=CapturePolicy())
    payload = b"secret-payload-" * 256
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset({1000}))),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", Clock().now(), "policy-1"),
        payload=payload,
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    effect = next(
        entry for entry in store.read_range("local", from_sequence=1) if entry.kind == "effect"
    )
    assert "capture" not in effect.body
    assert payload not in canonical_json(entry_to_document(effect))
