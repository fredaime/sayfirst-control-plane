# SPDX-License-Identifier: Apache-2.0
"""The bounded events sink: what it keeps, what it drops, and what it says it is.

Article 3 puts every fact this system holds in one of three planes, and this one
is an **observation**: it can be absent or stale, it is rebuildable from
nothing, and it is an authority for nothing. Article 10 is the other half — a
bounded pipeline **declares its gaps**, "so a store under pressure never
produces a clean record by losing part of one" — which is why a sequence and a
dropped count are part of the surface rather than a diagnostic somebody adds
later. A reader that could not tell "nothing happened" from "the sink lost it"
would be the false all-clear article 2 forbids.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sayfirst_control_plane.application.events import DEFAULT_EVENT_CAPACITY, BoundedEvents

AT = datetime(2026, 9, 15, 12, tzinfo=UTC)


def _record(events: BoundedEvents, kind: str, **details: object) -> None:
    events.record(kind, details, at=AT)


def test_a_sink_nothing_has_reached_says_so_rather_than_answering_nothing() -> None:
    """Article 2: empty and lossy are different facts, and both are readable."""
    events = BoundedEvents()
    assert events.since(0) == ()
    assert events.dropped() == 0
    # The other half of the readout, and the number the deployment document
    # publishes: a drop count beside no bound cannot be judged.
    assert events.capacity == DEFAULT_EVENT_CAPACITY


def test_the_entries_are_read_back_in_order_with_the_details_they_carried() -> None:
    """An observation an operator can consult: the kind, the instant and the details."""
    events = BoundedEvents()
    _record(events, "approval.resolved", approval_ref="approval-1", person="user:1000")
    _record(events, "approval.expired", approval_ref="approval-2")

    read = events.since(0)

    assert [entry.kind for _, entry in read] == ["approval.resolved", "approval.expired"]
    assert [sequence for sequence, _ in read] == [1, 2]
    assert read[0][1].details == {"approval_ref": "approval-1", "person": "user:1000"}
    assert read[0][1].at == AT


def test_a_reader_asks_for_what_followed_the_sequence_it_last_saw() -> None:
    """A poll reads forward; it does not re-read what it already has."""
    events = BoundedEvents()
    for index in range(3):
        _record(events, "decision.recorded", decision_ref=f"decision-{index}")

    assert [sequence for sequence, _ in events.since(2)] == [3]
    assert events.since(3) == ()


def test_the_sink_is_bounded_and_says_how_much_it_dropped() -> None:
    """Article 10: a bounded pipeline declares its gaps rather than losing them quietly.

    What is kept is the most recent, because an operator consulting this after
    an act is asking about the act that just happened. What was dropped is
    counted, and the sequence does not restart, so the gap is visible from both
    ends: the count says how many, and the first sequence read back says which.
    """
    events = BoundedEvents(capacity=2)
    for index in range(5):
        _record(events, "decision.recorded", decision_ref=f"decision-{index}")

    read = events.since(0)

    assert [entry.details["decision_ref"] for _, entry in read] == ["decision-3", "decision-4"]
    assert [sequence for sequence, _ in read] == [4, 5]
    # The pair an operator reads together: three entries gone, out of room for
    # two. Either number alone says nothing about how much history is held.
    assert events.dropped() == 3
    assert events.capacity == 2


def test_the_sink_copies_the_details_it_is_handed() -> None:
    """The core builds the details in the call, and an honest sink keeps its own copy."""
    events = BoundedEvents()
    details: dict[str, object] = {"approval_ref": "approval-1"}

    events.record("approval.resolved", details, at=AT)
    details["approval_ref"] = "approval-rewritten"

    assert events.since(0)[0][1].details == {"approval_ref": "approval-1"}


def test_the_sink_says_in_its_docstring_that_it_is_an_observation_and_no_authority() -> None:
    """Article 3: the plane a structure belongs to is stated where it is implemented."""
    stated = BoundedEvents.__doc__ or ""
    assert "observation" in stated
    assert "authority" in stated
    assert "article 3" in stated.lower()
