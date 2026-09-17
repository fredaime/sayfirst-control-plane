# SPDX-License-Identifier: Apache-2.0
"""Bounded emission that says what it lost.

Article 10: evidence is emitted asynchronously and bounded, and the pipeline
declares its gaps — sequence numbers and an explicit dropped marker, "so a store
under pressure never produces a clean record by losing part of one". The
interesting case is therefore the one where the buffer overflows, and the
assertion is not that nothing was lost but that the loss is stated.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sayfirst_boundary.evidence import OutcomeLog, Record

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
DIGEST = "sha256:" + "3" * 64


def _log(capacity: int, written: list[Record]) -> OutcomeLog:
    return OutcomeLog(capacity=capacity, sink=written.append, clock=lambda: NOW)


def test_records_are_numbered_from_one_and_consecutively() -> None:
    written: list[Record] = []
    log = _log(8, written)
    for _ in range(3):
        log.record(capability="example.effect", decision_ref="dec-1", outcome_digest=DIGEST)
    log.flush()
    assert [record.sequence for record in written] == [1, 2, 3]


def test_a_record_carries_what_it_is_a_record_of() -> None:
    written: list[Record] = []
    log = _log(8, written)
    log.record(capability="example.effect", decision_ref="dec-7", outcome_digest=DIGEST)
    log.flush()
    assert (written[0].capability, written[0].decision_ref, written[0].outcome_digest) == (
        "example.effect",
        "dec-7",
        DIGEST,
    )
    assert written[0].at == NOW.isoformat()


def test_nothing_dropped_means_the_marker_is_zero() -> None:
    written: list[Record] = []
    log = _log(8, written)
    log.record(capability="example.effect", decision_ref="dec-1", outcome_digest=None)
    log.flush()
    assert written[0].dropped_before == 0


def test_a_full_buffer_drops_and_the_next_record_says_how_many() -> None:
    written: list[Record] = []
    log = _log(2, written)
    for index in range(5):
        log.record(capability="example.effect", decision_ref=f"dec-{index}", outcome_digest=None)
    log.flush()
    assert [record.sequence for record in written] == [4, 5]
    assert written[0].dropped_before == 3, "the gap was not declared"


def test_the_sequence_still_counts_what_was_dropped() -> None:
    """A sequence that skipped silently would hide the gap it exists to reveal."""
    written: list[Record] = []
    log = _log(1, written)
    for index in range(4):
        log.record(capability="example.effect", decision_ref=f"dec-{index}", outcome_digest=None)
    log.flush()
    assert written[-1].sequence == 4


def test_an_absent_outcome_digest_is_recorded_as_absent_not_as_empty() -> None:
    written: list[Record] = []
    log = _log(4, written)
    log.record(capability="example.effect", decision_ref="dec-1", outcome_digest=None)
    log.flush()
    assert written[0].outcome_digest is None


def test_a_failing_sink_is_a_declared_gap_to_the_records_behind_it() -> None:
    """A sink that refuses is back pressure, and back pressure is a declared gap.

    The first version of this test built a SECOND log and asserted the second
    started at zero, which is true of any fresh log and says nothing about the
    first. What must hold is that the log whose sink failed tells the next reader
    so — and it can only do that on a record emitted after the failure.
    """
    written: list[Record] = []
    refuse_first = {"done": False}

    def sometimes(record: Record) -> None:
        if not refuse_first["done"]:
            refuse_first["done"] = True
            raise OSError("the store is unavailable")
        written.append(record)

    log = OutcomeLog(capacity=4, sink=sometimes, clock=lambda: NOW)
    log.record(capability="example.effect", decision_ref="dec-1", outcome_digest=None)
    log.record(capability="example.effect", decision_ref="dec-2", outcome_digest=None)
    log.flush()
    assert [record.decision_ref for record in written] == ["dec-2"], "the refused one was kept"
    assert written[0].dropped_before == 1, "the refusal was not declared to the record behind it"
    assert log.dropped == 1


def test_a_record_that_survives_later_drops_declares_them_when_it_leaves() -> None:
    """The defect this module was first written with, pinned.

    Stamping the marker at creation under-reports: with room for two and five
    records made, sequence 4 survives but was stamped while only two had been
    lost. The reader's first record then declares two gaps where three had
    opened. Under-reporting a gap is the same failure as not declaring one.
    """
    written: list[Record] = []
    log = _log(2, written)
    for index in range(5):
        log.record(capability="example.effect", decision_ref=f"dec-{index}", outcome_digest=None)
    log.flush()
    assert [record.sequence for record in written] == [4, 5]
    assert [record.dropped_before for record in written] == [3, 3]
