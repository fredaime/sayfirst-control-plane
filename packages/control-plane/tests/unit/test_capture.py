# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.evidence_emitter import (
    CAPTURE_HARD_CEILING,
    CapturePolicy,
    CaptureRule,
    EffectDecision,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.domain.evidence_chain import Principal
from sayfirst_control_plane.domain.integrity_grade import CallerAccess
from sayfirst_control_plane.plugins.interfaces import Redaction
from sayfirst_control_plane.plugins.privacy.none import NoRedaction


class Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 4, 10, 0, tzinfo=UTC)


def _captured(policy: CapturePolicy, payload: bytes, *, capability: str = "example.effect"):
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(
        store,
        clock=Clock(),
        capture_policy=policy,
        privacy_redactor=NoRedaction(),
    )
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability=capability,
        decision=EffectDecision("decision-1", "allow", Clock().now(), "policy-1"),
        payload=payload,
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    return next(
        entry for entry in store.read_range("local", from_sequence=1) if entry.kind == "effect"
    )


def test_a_capture_rule_bounds_and_marks_what_it_captures() -> None:
    entry = _captured(CapturePolicy((CaptureRule("example.effect", 16),)), b"a" * 32)
    assert entry.body["capture"] == {
        "captured": True,
        "provider": "none",
        "bytes": 16,
        "truncated": True,
        "content": "a" * 16,
    }


def test_a_capture_rule_never_applies_to_another_capability() -> None:
    entry = _captured(
        CapturePolicy((CaptureRule("other.effect", 16),)),
        b"do not retain",
    )
    assert "capture" not in entry.body


class SpyRedactor:
    interface_version = 1
    name = "spy"

    def __init__(self) -> None:
        self.called = False

    def redact(self, *, scope: str, capability: str, content: bytes):  # type: ignore[no-untyped-def]
        self.called = True
        raise AssertionError("a payload-free record must not call the provider")


def test_the_redactor_never_sees_a_record_without_a_rule() -> None:
    store = InMemoryEvidenceStore()
    redactor = SpyRedactor()
    emitter = EvidenceEmitter(store, clock=Clock(), privacy_redactor=redactor)
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", Clock().now(), "policy-1"),
        payload=b"secret",
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    assert redactor.called is False


def test_a_rule_above_the_hard_ceiling_is_refused() -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        CaptureRule("example.effect", CAPTURE_HARD_CEILING + 1)


class FailingRedactor:
    interface_version = 1
    name = "failing"

    def redact(self, *, scope: str, capability: str, content: bytes):  # type: ignore[no-untyped-def]
        raise RuntimeError("synthetic failure")


def test_a_raising_redactor_withholds_the_capture_and_keeps_the_record() -> None:
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(
        store,
        clock=Clock(),
        capture_policy=CapturePolicy((CaptureRule("example.effect", 16),)),
        privacy_redactor=FailingRedactor(),
    )
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", Clock().now(), "policy-1"),
        payload=b"secret",
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    effect = next(
        entry for entry in store.read_range("local", from_sequence=1) if entry.kind == "effect"
    )
    assert effect.body["capture"] == {
        "captured": False,
        "provider": "failing",
        "withheld": "redaction_failed",
    }


class FailedRedactor:
    interface_version = 1
    name = "failed"

    def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction:
        return Redaction(b"must not be recorded", "failed", self.name)


def test_a_failed_redaction_withholds_the_capture_and_keeps_the_record() -> None:
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(
        store,
        clock=Clock(),
        capture_policy=CapturePolicy((CaptureRule("example.effect", 16),)),
        privacy_redactor=FailedRedactor(),
    )
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=Principal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", Clock().now(), "policy-1"),
        payload=b"secret",
    )
    assert emitter.flush("local", timeout=2)
    emitter.close()
    effect = next(
        entry for entry in store.read_range("local", from_sequence=1) if entry.kind == "effect"
    )
    assert effect.body["capture"] == {
        "captured": False,
        "provider": "failed",
        "withheld": "redaction_failed",
    }


def _capture_of(redactor: object, payload: bytes, *, max_bytes: int = 16) -> dict:
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(
        store,
        clock=Clock(),
        capture_policy=CapturePolicy((CaptureRule("example.effect", max_bytes),)),
        privacy_redactor=redactor,  # type: ignore[arg-type]
    )
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
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
    return dict(effect.body["capture"])  # type: ignore[arg-type]


class TwoFacedRedaction:
    """A redaction that answers honestly while it is read and lies afterwards.

    Its members are properties, so what the emitter checks and what the emitter
    writes into the chain are two reads of memory the provider owns. The
    provider picks what the second one says by counting the first.
    """

    def __init__(self, first: bytes, later: bytes) -> None:
        self._first = first
        self._later = later
        self._reads = 0

    @property
    def status(self) -> str:
        return "applied"

    @property
    def provider(self) -> str:
        return "a-provider-that-was-never-composed"

    @property
    def content(self) -> bytes:
        self._reads += 1
        return self._first if self._reads == 1 else self._later


class TwoFacedRedactor:
    interface_version = 1
    name = "two-faced"

    def __init__(self, first: bytes, later: bytes) -> None:
        self._first = first
        self._later = later

    def redact(self, *, scope: str, capability: str, content: bytes) -> object:
        return TwoFacedRedaction(self._first, self._later)


def test_the_capture_describes_the_content_it_holds_and_no_other() -> None:
    """Article 11: the record's claim is about the bytes the record carries.

    `truncated` was computed from a second read of the provider's `content`, so
    a provider could have the chain say a short capture was cut from something
    longer. The content is read once and every member of the capture is derived
    from that one read.
    """
    capture = _capture_of(TwoFacedRedactor(b"[redacted]", b"x" * 512), b"the-payload")
    assert capture == {
        "captured": True,
        "provider": "two-faced",
        "bytes": len("[redacted]"),
        "truncated": False,
        "content": "[redacted]",
    }


def test_the_capture_names_the_provider_this_daemon_composed() -> None:
    """Articles 2 and 8: a name the answer chooses is not evidence of who redacted.

    The name was taken from the answer, so a provider could attribute its work
    to any other. The core read the composed provider's name once, at
    composition, and it is that name the record carries.
    """
    capture = _capture_of(TwoFacedRedactor(b"[redacted]", b"[redacted]"), b"the-payload")
    assert capture["provider"] == "two-faced"


class NotARedaction:
    interface_version = 1
    name = "not-a-redaction"

    def redact(self, *, scope: str, capability: str, content: bytes) -> object:
        return object()


def test_an_answer_that_is_not_a_redaction_withholds_the_capture() -> None:
    """Article 3: what the core cannot take into itself, it does not record."""
    assert _capture_of(NotARedaction(), b"the-payload") == {
        "captured": False,
        "provider": "not-a-redaction",
        "withheld": "redaction_failed",
    }
