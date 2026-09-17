# SPDX-License-Identifier: Apache-2.0
"""Where a suspended approval is kept, how its wait ends, and who may end it.

Article 12 ships the simple form in the open core: one person approves or
rejects, behind the port a richer provider implements. The port already
published suspend and resume, and the core already judges what a provider
answers. What these cases hold is the part that was named as missing and not
built — the store the daemon keeps a suspension in, the instant its wait runs
out, and the single execution one resolution authorises.

The clock is a value the cases move by hand. Every property here is about an
instant relative to a deadline, and a property asserted against the wall clock
is a property asserted about whatever the machine was doing that second.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from functools import partial
from threading import Barrier

import pytest
from sayfirst_control_plane.application.approvals import (
    ApprovalAlreadyClaimed,
    ApprovalStore,
    ApprovalUnknown,
    EventsRecorder,
    SimpleApprovalProvider,
    write_resolution,
)
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.domain.approval import Approval, ApprovalState, Question
from sayfirst_control_plane.plugins.approval import (
    RefusedProviderAnswer,
    resume_through_provider,
)
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalAlreadyExists,
    ApprovalAlreadyResolved,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)

REQUESTED_AT = datetime(2026, 9, 15, 12, tzinfo=UTC)
DEADLINE = REQUESTED_AT + timedelta(seconds=300)
DIGEST = "sha256:" + "a" * 64
ALICE = "user:alice"
BUILD = "service:build"
#: Long after every wait these cases open has run out.
LATER = DEADLINE + timedelta(days=7)


class Clock:
    """An instant the case moves, and the callable the store is composed with."""

    def __init__(self, now: datetime = REQUESTED_AT) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class Recorder:
    """The recorder port, as an append-only list the case can read."""

    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, resolution: ResolvedApproval) -> None:
        self.records.append(resolution)

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        self.records.append(refusal)


def _question(**changes: str) -> Question:
    members: dict[str, str] = {
        "scope": "local",
        "principal_reference": BUILD,
        "capability": "mail.send",
        "arguments_digest": DIGEST,
    }
    members.update(changes)
    return Question(**members)


def _pending(
    approval_ref: str = "approval-1",
    *,
    question: Question | None = None,
    requested_at: datetime = REQUESTED_AT,
    deadline: datetime = DEADLINE,
) -> Approval:
    return Approval(
        approval_ref=approval_ref,
        decision_ref=f"decision-for-{approval_ref}",
        question=question if question is not None else _question(),
        requested_at=requested_at,
        deadline=deadline,
    )


def _store(clock: Callable[[], datetime] | None = None) -> ApprovalStore:
    return ApprovalStore(clock=clock if clock is not None else Clock())


class _CountingReads(dict):  # type: ignore[type-arg]
    """The record index, counting every record the caller reached for.

    A read is a `__getitem__` or a `get`; a walk of the whole index is counted
    as the records it visits, because that is what it costs. Nothing else about
    the store is changed: this is the same mapping, answering the same way.
    """

    def __init__(self, records: dict[tuple[str, str], Approval]) -> None:
        super().__init__(records)
        self.count = 0

    def __getitem__(self, key: object) -> Approval:
        self.count += 1
        return super().__getitem__(key)  # type: ignore[no-any-return]

    def get(self, key: object, default: object = None) -> object:
        self.count += 1
        return super().get(key, default)

    def __iter__(self) -> Iterator[object]:
        self.count += len(self)
        return super().__iter__()


@contextmanager
def _counting_reads(store: ApprovalStore) -> Iterator[_CountingReads]:
    """Count what a sweep reads, by standing in for the index it reads from.

    The cost under test is not a duration — a machine under load would make
    that a coin toss — but how many records one sweep touches, which is a fact
    about the algorithm and the same on every machine.
    """
    original = store._by_reference
    counting = _CountingReads(original)
    store._by_reference = counting  # type: ignore[assignment]
    try:
        yield counting
    finally:
        # Through the items view, which is not the walk this stands in for:
        # putting the records back must not be counted against the sweep.
        original.clear()
        original.update(counting.items())
        store._by_reference = original


# -- where a suspended approval is kept ---------------------------------------


def test_the_store_says_in_its_docstring_that_nothing_survives_a_restart() -> None:
    """Article 2: a limit of the simple form is stated where it is implemented."""
    stated = ApprovalStore.__doc__ or ""
    assert "restart" in stated
    assert "lost" in stated


def test_an_opened_approval_is_read_back_as_it_was_kept() -> None:
    """Article 3: the store is the authority, so it answers with the record it holds."""
    store = _store()
    opened = store.open(_pending())
    assert store.read("local", "approval-1") == opened
    assert opened.state is ApprovalState.PENDING


def test_a_reference_opened_twice_in_one_scope_is_refused() -> None:
    """Article 3: a suspension is a new record, never an edit of the one before it."""
    store = _store()
    store.open(_pending())
    with pytest.raises(ApprovalAlreadyExists, match="approval-1"):
        store.open(_pending())


def test_the_same_reference_in_two_scopes_is_two_approvals() -> None:
    """Article 5: the key is the scope and the reference, so neither alone collides."""
    store = _store()
    store.open(_pending())
    store.open(_pending(question=_question(scope="other")))
    assert store.read("local", "approval-1").scope == "local"
    assert store.read("other", "approval-1").scope == "other"


def test_the_store_refuses_to_open_an_approval_that_is_already_over() -> None:
    """Only a wait can be opened: a terminal record has nothing left to wait for."""
    store = _store()
    resolved = Approval(
        approval_ref="approval-1",
        decision_ref="decision-1",
        question=_question(),
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
        state=ApprovalState.APPROVED,
        resolved_at=REQUESTED_AT,
        person=ALICE,
    )
    with pytest.raises(ValueError, match="pending"):
        store.open(resolved)


def test_reading_an_approval_nobody_opened_is_refused_and_not_answered() -> None:
    """Article 2: « not found » is not a state, so it is not rendered as one."""
    store = _store()
    store.open(_pending())
    with pytest.raises(ApprovalUnknown):
        store.read("local", "approval-2")
    with pytest.raises(ApprovalUnknown):
        store.read("other", "approval-1")


def test_the_pending_list_holds_what_has_not_been_ended() -> None:
    """The sweep and the status surface read the same list."""
    store = _store()
    store.open(_pending("approval-2"))
    store.open(_pending("approval-1"))
    assert tuple(item.approval_ref for item in store.pending()) == ("approval-1", "approval-2")


# -- the question a re-ask asks again -----------------------------------------


def test_the_same_question_finds_the_approval_it_suspended() -> None:
    """A re-ask of the suspended question finds its approval instead of opening a second."""
    store = _store()
    opened = store.open(_pending())
    assert store.find_for_question(_question()) == opened


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("scope", "other"),
        ("principal_reference", "user:someone-else"),
        ("capability", "mail.read"),
        ("arguments_digest", "sha256:" + "b" * 64),
    ],
)
def test_a_question_differing_in_any_member_finds_nothing(member: str, value: str) -> None:
    """Article 3: a changed question is a new question, so it finds no old answer."""
    store = _store()
    store.open(_pending())
    assert store.find_for_question(_question(**{member: value})) is None


def test_the_most_recent_approval_for_a_question_is_the_last_one_opened() -> None:
    """« Most recent » is the store's own order, never a caller's `requested_at`.

    The two are given in opposite orders on purpose: the approval opened second
    carries the *earlier* `requested_at`, so a rule reading the instants would
    answer the other one. `requested_at` is a value the caller supplies and the
    store records; the order it opened them in is a fact the store holds.
    """
    store = _store()
    store.open(
        _pending(
            "approval-2",
            requested_at=REQUESTED_AT + timedelta(seconds=1),
            deadline=DEADLINE + timedelta(seconds=1),
        )
    )
    last_opened = store.open(_pending("approval-1"))
    found = store.find_for_question(_question())
    assert found == last_opened
    assert found is not None and found.requested_at < REQUESTED_AT + timedelta(seconds=1)


def _rejected_wait(clock: Clock) -> ApprovalStore:
    """A store holding one rejected approval, rejected well inside its wait."""
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.REJECT,
        reason="the recipient is not on the list",
        now=clock.now,
    )
    return store


def test_a_rejection_answers_its_question_while_the_wait_is_still_running() -> None:
    """Article 12: « reject » is one of the two acts, so it answers — for its wait."""
    clock = Clock()
    store = _rejected_wait(clock)
    clock.now = DEADLINE - timedelta(seconds=1)
    found = store.find_for_question(_question())
    assert found is not None and found.state is ApprovalState.REJECTED


def test_a_rejection_stops_answering_at_the_deadline_and_stays_rejected() -> None:
    """The wait was bounded, so the answer is too — and the record is not.

    A rejection that answered for ever would deny every re-ask of that question
    for the life of the process, on a wait that was supposed to run out. What
    lapses is its usefulness to a re-ask; the record still says what the person
    decided, because a rejection does not become « expired » — nothing converts
    it and no sweep touches it.
    """
    clock = Clock()
    store = _rejected_wait(clock)
    clock.now = DEADLINE
    assert store.find_for_question(_question()) is None
    clock.now = DEADLINE + timedelta(days=365)
    assert store.find_for_question(_question()) is None
    assert store.expire_past(clock.now) == ()
    kept = store.read("local", "approval-1")
    assert kept.state is ApprovalState.REJECTED
    assert kept.state_at(clock.now) is ApprovalState.REJECTED
    assert kept.person == ALICE
    assert kept.resolution_reason == "the recipient is not on the list"


def test_an_approval_answers_its_question_past_the_deadline_until_it_is_consumed() -> None:
    """An act a caller may still spend is not discarded by the clock.

    The asymmetry with a rejection is deliberate and is the fail-closed one: an
    unconsumed approval is one person's act and the execution it authorises has
    not happened yet, so losing it at the deadline would throw away a decision
    somebody made. A stale rejection costs nothing to drop — the re-ask simply
    asks again.
    """
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    clock.now = DEADLINE + timedelta(days=1)
    found = store.find_for_question(_question())
    assert found is not None and found.state is ApprovalState.APPROVED
    store.claim("local", "approval-1")
    store.consume("local", "approval-1")
    assert store.find_for_question(_question()) is None


def test_an_approval_whose_wait_ran_out_finds_nothing_before_any_sweep() -> None:
    """Article 2: the read does not depend on a sweep having run."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    clock.now = DEADLINE
    assert store.find_for_question(_question()) is None
    assert store.read("local", "approval-1").state is ApprovalState.PENDING


def test_a_consumed_approval_finds_nothing_because_it_authorised_its_execution() -> None:
    """One resolution authorises one execution, so the next ask is a new question."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    assert store.find_for_question(_question()) is not None
    store.claim("local", "approval-1")
    store.consume("local", "approval-1")
    assert store.find_for_question(_question()) is None


# -- who ends the wait, and how --------------------------------------------


@pytest.mark.parametrize(
    ("resolution", "state"),
    [
        (ApprovalResolution.APPROVE, ApprovalState.APPROVED),
        (ApprovalResolution.REJECT, ApprovalState.REJECTED),
    ],
)
def test_one_act_records_the_person_the_reason_and_the_instant(
    resolution: ApprovalResolution, state: ApprovalState
) -> None:
    """Article 12: one person, one act; attribution is the whole content of the record."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    clock.now = REQUESTED_AT + timedelta(seconds=30)
    resolved = store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=resolution,
        reason="a reason the person gave",
        now=clock.now,
    )
    assert resolved.state is state
    assert resolved.person == ALICE
    assert resolved.resolution_reason == "a reason the person gave"
    assert resolved.resolved_at == clock.now
    assert store.read("local", "approval-1") == resolved


def test_the_person_who_asked_may_be_the_person_who_approves() -> None:
    """Article 12: the simple form is « one person », and it judges nothing about who."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending(question=_question(principal_reference=ALICE)))
    resolved = store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    assert resolved.state is ApprovalState.APPROVED


def test_an_act_after_the_deadline_expires_the_wait_and_is_refused() -> None:
    """Article 12: `expired` is not a resolution any person can act."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    clock.now = DEADLINE + timedelta(seconds=1)
    with pytest.raises(ApprovalAlreadyResolved, match="approval-1"):
        store.resolve(
            "local",
            "approval-1",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason=None,
            now=clock.now,
        )
    kept = store.read("local", "approval-1")
    assert kept.state is ApprovalState.EXPIRED
    assert kept.resolved_at == DEADLINE
    assert kept.person is None


def test_an_act_at_the_deadline_instant_itself_is_already_too_late() -> None:
    """The bound is inclusive here as in `state_at`, and the record says the same thing.

    At the deadline the wait is over, so the instant a person's act arrives at
    the deadline is an instant nobody could act at. Asserted at exactly
    `now == deadline` rather than a second later, because that one instant is
    the whole of the rule.
    """
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    clock.now = DEADLINE
    with pytest.raises(ApprovalAlreadyResolved, match="expired"):
        store.resolve(
            "local",
            "approval-1",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason=None,
            now=clock.now,
        )
    kept = store.read("local", "approval-1")
    assert kept.state is ApprovalState.EXPIRED
    assert kept.resolved_at == DEADLINE
    assert kept.person is None


def test_a_second_act_on_a_resolved_approval_is_refused_and_never_overwrites_it() -> None:
    """Article 3: a resolution is a record, and a record is not edited by the next caller."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    first = store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    with pytest.raises(ApprovalAlreadyResolved, match="approval-1"):
        store.resolve(
            "local",
            "approval-1",
            person="user:mallory",
            resolution=ApprovalResolution.REJECT,
            reason="a verdict nobody asked for",
            now=clock.now,
        )
    assert store.read("local", "approval-1") == first


def test_resolving_an_approval_nobody_opened_is_refused() -> None:
    """Article 2: there is nothing to resolve, and no state to answer with."""
    store = _store()
    with pytest.raises(ApprovalUnknown):
        store.resolve(
            "local",
            "approval-1",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason=None,
            now=REQUESTED_AT,
        )


# -- what a resolution authorises ---------------------------------------------


def test_an_approval_is_consumed_once() -> None:
    """One resolution authorises one execution, and the second attempt says so."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    store.claim("local", "approval-1")
    consumed = store.consume("local", "approval-1")
    assert consumed.consumed is True
    with pytest.raises(ValueError, match="already"):
        store.consume("local", "approval-1")


@pytest.mark.parametrize("resolution", [None, ApprovalResolution.REJECT])
def test_only_an_approved_approval_can_be_consumed(
    resolution: ApprovalResolution | None,
) -> None:
    """Nothing but an approval authorises an execution, so nothing else is spent."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    if resolution is not None:
        store.resolve(
            "local",
            "approval-1",
            person=ALICE,
            resolution=resolution,
            reason=None,
            now=clock.now,
        )
    with pytest.raises(ValueError, match="approved"):
        store.consume("local", "approval-1")


def test_consuming_an_approval_nobody_opened_is_refused() -> None:
    """The same absence, refused the same way as a read."""
    store = _store()
    with pytest.raises(ApprovalUnknown):
        store.consume("local", "approval-1")


# -- who expires one ----------------------------------------------------------


def test_the_sweep_ends_exactly_the_waits_that_ran_out() -> None:
    """Article 2: the record says it ended at its deadline, not when the sweep noticed."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending("approval-2"))
    store.open(_pending("approval-1", deadline=DEADLINE + timedelta(seconds=60)))
    expired = store.expire_past(DEADLINE)
    assert tuple(item.approval_ref for item in expired) == ("approval-2",)
    assert expired[0].state is ApprovalState.EXPIRED
    assert expired[0].resolved_at == DEADLINE
    assert store.read("local", "approval-1").state is ApprovalState.PENDING
    assert tuple(item.approval_ref for item in store.pending()) == ("approval-1",)


def test_the_sweep_returns_what_it_ended_in_store_key_order() -> None:
    """Two waits ending in one sweep come back by key, not by the order they were opened.

    Opened in the reverse of their key order, so an implementation returning
    them in insertion order would answer the other way round. A caller's record
    of a sweep must not depend on a dictionary's insertion order.
    """
    store = _store()
    store.open(_pending("approval-b"))
    store.open(_pending("approval-a"))
    ended = store.expire_past(DEADLINE)
    assert tuple(item.approval_ref for item in ended) == ("approval-a", "approval-b")
    assert all(item.resolved_at == DEADLINE for item in ended)
    assert store.pending() == ()


def test_the_sweep_ends_a_wait_whose_deadline_is_the_instant_it_runs() -> None:
    """The bound is inclusive here too, for the same reason `state_at` has it."""
    store = _store()
    store.open(_pending())
    assert tuple(item.approval_ref for item in store.expire_past(DEADLINE)) == ("approval-1",)


def test_a_second_sweep_ends_nothing_and_changes_nothing() -> None:
    """The sweep runs when it runs, so running it twice must be running it once."""
    store = _store()
    store.open(_pending())
    first = store.expire_past(DEADLINE)
    assert store.expire_past(DEADLINE) == ()
    assert store.read("local", "approval-1") == first[0]


def test_the_sweep_leaves_a_resolved_approval_alone() -> None:
    """A wait a person ended did not run out, whatever the clock says afterwards."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    resolved = store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    assert store.expire_past(DEADLINE + timedelta(days=1)) == ()
    assert store.read("local", "approval-1") == resolved


def test_the_sweep_reads_only_the_waits_that_are_due() -> None:
    """It walked the whole store under its lock on every request and every wake.

    `expire_past` and `forget_lapsed` each sorted every reference the store
    holds, and the daemon calls the sweep on every decision request and on
    every held-grant wake, so the cost of one request grew with the number of
    approvals the process had ever seen. A due-time index answers the same
    question by looking at the front of it.
    """
    store = _store()
    for index in range(2_000):
        store.open(_pending(f"a-{index}", deadline=REQUESTED_AT + timedelta(seconds=3600)))
    store.open(_pending("a-due", deadline=REQUESTED_AT + timedelta(seconds=1)))

    with _counting_reads(store) as reads:
        ended = store.expire_past(REQUESTED_AT + timedelta(seconds=2))

    assert [item.approval_ref for item in ended] == ["a-due"]
    assert reads.count < 10, f"the sweep read {reads.count} records to end one"


def test_the_forgetting_sweep_reads_only_the_records_that_have_lapsed() -> None:
    """The other half of the same walk, and it runs in the same breath as the first."""
    store = _store()
    for index in range(2_000):
        store.open(_pending(f"a-{index}", deadline=REQUESTED_AT + timedelta(seconds=3600)))
    store.open(_pending("a-due", deadline=REQUESTED_AT + timedelta(seconds=1)))
    store.expire_past(REQUESTED_AT + timedelta(seconds=2))

    with _counting_reads(store) as reads:
        forgotten = store.forget_lapsed(REQUESTED_AT + timedelta(seconds=3600))

    assert [item.approval_ref for item in forgotten] == ["a-due"]
    assert reads.count < 10, f"the sweep read {reads.count} records to forget one"


def test_an_approved_approval_nobody_spent_is_never_forgotten_by_the_index() -> None:
    """The one record this store may hold for the life of the process.

    `forget_lapsed`'s docstring is the rule: "the act stands until the
    execution it authorises is taken, so nothing here drops it". A due-time
    index is a performance fix, and a performance fix that dropped this record
    would be a correctness regression wearing one — the person's act would
    vanish while the execution it authorised was still to come.
    """
    clock = Clock()
    store = _store(clock)
    approved = store.open(_pending())
    store.resolve(
        approved.scope,
        approved.approval_ref,
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )

    assert store.expire_past(LATER) == ()
    assert store.forget_lapsed(LATER) == ()
    kept = store.read(approved.scope, approved.approval_ref)
    assert kept.state is ApprovalState.APPROVED
    assert kept.person == ALICE


# -- what the store stops keeping ---------------------------------------------

#: One wait-length, which is also how long a resolved record stays readable.
LAPSE = DEADLINE - REQUESTED_AT


def test_a_spent_approval_is_forgotten_one_wait_after_the_act_that_authorised_it() -> None:
    """It authorised its one execution and the execution was taken, so the record lapses.

    The wait-length is counted from the act, not from the spending: the caller
    that asked is the caller that reads it and it was already willing to wait
    that long. What makes this case the spent one, and not the rule for every
    approval, is the case below it — unspent, the same record is never dropped.
    """
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    store.claim("local", "approval-1")
    store.consume("local", "approval-1")
    # Spent, but still readable by reference for one wait-length: a reader asking
    # after it learns it was approved, never « unknown ».
    assert store.forget_lapsed(clock.now) == ()
    assert store.read("local", "approval-1").consumed is True
    forgotten = store.forget_lapsed(clock.now + (DEADLINE - REQUESTED_AT))
    assert tuple(item.approval_ref for item in forgotten) == ("approval-1",)
    with pytest.raises(ApprovalUnknown):
        store.read("local", "approval-1")
    assert store.find_for_question(_question()) is None


def test_an_approved_approval_nobody_spent_is_never_forgotten() -> None:
    """Article 12: a person's act is not thrown away at a deadline and asked again.

    The one exception to the wait-length rule, and the reason it exists. An
    approved approval is the authorisation for one execution; it answers a
    re-ask until it is consumed (`find_for_question` states that rule), so a
    sweep that dropped it would leave the caller that comes back late — a job
    that retries in ten minutes, a boundary restarted — suspended anew on a new
    reference, a second human asked for an effect already approved, and
    `read_approval` answering `approval_unknown` about a decision a person
    made. A claimed approval is the same case one step on.
    """
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )

    clock.now = REQUESTED_AT + timedelta(days=365)

    assert store.forget_lapsed(clock.now) == ()
    kept = store.read("local", "approval-1")
    assert kept.state is ApprovalState.APPROVED
    assert kept.person == ALICE
    # And it is still the answer to the question it suspended, which is the
    # whole point of keeping it.
    found = store.find_for_question(_question())
    assert found is not None and found.approval_ref == "approval-1"
    # Claimed by an ask that is about to spend it: still nobody's to drop.
    store.claim("local", "approval-1")
    assert store.forget_lapsed(clock.now) == ()
    # Spent, and only then does the wait-length rule apply — counted from the
    # act, which is where the record's own lifetime has always been measured.
    store.consume("local", "approval-1")
    assert store.forget_lapsed(REQUESTED_AT + LAPSE - timedelta(seconds=1)) == ()
    assert tuple(item.approval_ref for item in store.forget_lapsed(REQUESTED_AT + LAPSE)) == (
        "approval-1",
    )


def test_a_rejection_is_forgotten_only_one_wait_after_it_was_decided() -> None:
    """A reader who asked was willing to wait that long; past it the record is of no use."""
    clock = Clock()
    store = _rejected_wait(clock)
    resolved_at = store.read("local", "approval-1").resolved_at
    assert resolved_at is not None
    assert store.forget_lapsed(resolved_at + LAPSE - timedelta(seconds=1)) == ()
    assert store.read("local", "approval-1").state is ApprovalState.REJECTED
    forgotten = store.forget_lapsed(resolved_at + LAPSE)
    assert tuple(item.approval_ref for item in forgotten) == ("approval-1",)
    with pytest.raises(ApprovalUnknown):
        store.read("local", "approval-1")


def test_a_lapsed_wait_is_forgotten_one_wait_after_the_deadline_it_ended_at() -> None:
    """The sweep ends it first, and the lapse is counted from the deadline, not the sweep."""
    store = _store()
    store.open(_pending())
    store.expire_past(DEADLINE)
    assert store.forget_lapsed(DEADLINE + LAPSE - timedelta(seconds=1)) == ()
    assert tuple(item.approval_ref for item in store.forget_lapsed(DEADLINE + LAPSE)) == (
        "approval-1",
    )


def test_a_pending_approval_is_never_forgotten_however_late_the_clock() -> None:
    """It is somebody's open wait until a sweep ends it, and the clock does not end it."""
    store = _store()
    store.open(_pending())
    assert store.forget_lapsed(DEADLINE + timedelta(days=365)) == ()
    assert tuple(item.approval_ref for item in store.pending()) == ("approval-1",)


def test_forgetting_returns_what_it_forgot_in_store_key_order() -> None:
    """Opened in the reverse of their key order, so insertion order would answer otherwise."""
    store = _store()
    store.open(_pending("approval-b"))
    store.open(_pending("approval-a", question=_question(capability="mail.read")))
    store.expire_past(DEADLINE)
    forgotten = store.forget_lapsed(DEADLINE + LAPSE)
    assert tuple(item.approval_ref for item in forgotten) == ("approval-a", "approval-b")
    assert store.pending() == ()


def test_forgetting_empties_the_question_index_and_not_only_the_record() -> None:
    """Both indexes, or the store leaks the list `find_for_question` walks.

    Proven through the store's own surface rather than by reading a private
    member: once the record is forgotten its reference is free to open again,
    which it would not be if the reference index still held it, and the
    question answers nothing, which it would not if the question index still
    named it.
    """
    store = _store()
    store.open(_pending())
    store.expire_past(DEADLINE)
    assert store.forget_lapsed(DEADLINE + LAPSE)
    assert store.find_for_question(_question()) is None
    reopened = store.open(_pending(requested_at=DEADLINE, deadline=DEADLINE + LAPSE))
    assert store.find_for_question(_question()) == reopened


# -- two asks at once ---------------------------------------------------------


def test_opening_when_nothing_answers_the_question_opens_exactly_this_one() -> None:
    """The not-found half of the atomic operation: the offered wait becomes the wait."""
    store = _store()
    opened = store.open_if_absent(_pending())
    assert opened.approval_ref == "approval-1"
    assert store.pending() == (opened,)


def test_opening_when_something_still_answers_the_question_opens_nothing() -> None:
    """Article 3: one question, one wait — so a second ask joins the first, never doubles it.

    Two asks that both looked and then both opened would leave one question
    with two waits, and a re-ask is answered the most recent: the person who
    resolved the one their caller was told about would have their act
    discarded without a word.
    """
    store = _store()
    first = store.open_if_absent(_pending())
    again = store.open_if_absent(_pending("approval-2"))
    assert again == first
    assert tuple(item.approval_ref for item in store.pending()) == ("approval-1",)


def test_a_claimed_approval_answers_no_question_until_it_is_spent_or_given_back() -> None:
    """One resolution authorises one execution, and the claim is where that is settled."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    claimed = store.claim("local", "approval-1")
    assert claimed.claimed is True
    # A reader asking what still answers this question is not told about an
    # execution another ask is in the middle of spending.
    assert store.find_for_question(_question()) is None
    # A caller about to open a new wait is, and opens nothing: a wait over a
    # person's act would be newer than the act and would hide it from every
    # later ask.
    in_flight = store.open_if_absent(_pending("approval-2"))
    assert in_flight.approval_ref == "approval-1"
    assert in_flight.claimed is True
    assert tuple(item.approval_ref for item in store.pending()) == ()
    assert store.read("local", "approval-1").state is ApprovalState.APPROVED


def test_only_one_ask_claims_the_one_execution() -> None:
    """The second claim is refused by its own class: not a fault, not the caller's execution."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    store.claim("local", "approval-1")
    with pytest.raises(ApprovalAlreadyClaimed):
        store.claim("local", "approval-1")


@pytest.mark.parametrize("resolution", [None, ApprovalResolution.REJECT])
def test_nothing_but_an_approval_can_be_claimed(resolution: ApprovalResolution | None) -> None:
    """A claim is the execution an approval authorises; nothing else authorises one."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    if resolution is not None:
        store.resolve(
            "local",
            "approval-1",
            person=ALICE,
            resolution=resolution,
            reason=None,
            now=clock.now,
        )
    with pytest.raises(ValueError, match="approved"):
        store.claim("local", "approval-1")


def test_an_unclaimed_approval_is_not_spent() -> None:
    """Article 3: the execution is taken under the lock before the record is written."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    with pytest.raises(ValueError, match="not claimed"):
        store.consume("local", "approval-1")


def test_a_claim_given_back_answers_the_question_again() -> None:
    """Nothing a person granted is lost because a record could not be written."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    store.claim("local", "approval-1")
    released = store.release_claim("local", "approval-1")
    assert released.claimed is False
    assert store.find_for_question(_question()) == released


def test_a_spent_execution_is_not_given_back() -> None:
    """The record exists, so the execution happened; a claim behind one is not returned."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    store.claim("local", "approval-1")
    store.consume("local", "approval-1")
    with pytest.raises(ValueError, match="consumed"):
        store.release_claim("local", "approval-1")


def test_one_question_asked_by_many_threads_at_once_opens_one_wait() -> None:
    """The property the lock is for, driven rather than argued.

    Sixteen asks of one question, each offering its own reference: exactly one
    wait exists afterwards and every ask was answered that same one.
    """
    store = _store()
    answers: list[str] = []
    barrier = Barrier(16)

    def ask(index: int) -> None:
        barrier.wait()
        answers.append(store.open_if_absent(_pending(f"approval-{index}")).approval_ref)

    with ThreadPoolExecutor(max_workers=16) as pool:
        for outcome in [pool.submit(ask, index) for index in range(16)]:
            outcome.result()
    assert len(set(answers)) == 1
    assert len(store.pending()) == 1


def test_one_approved_question_claimed_by_many_threads_at_once_is_spent_once() -> None:
    """The other half: one execution, whoever asks, however many ask at once."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    claimed: list[str] = []
    barrier = Barrier(16)

    def claim() -> None:
        barrier.wait()
        # Losing is the ordinary outcome for fifteen of the sixteen, and it is
        # the one this case is counting.
        with suppress(ApprovalAlreadyClaimed):
            claimed.append(store.claim("local", "approval-1").approval_ref)

    with ThreadPoolExecutor(max_workers=16) as pool:
        for outcome in [pool.submit(claim) for _ in range(16)]:
            outcome.result()
    assert claimed == ["approval-1"]


# -- a wait nobody took up ----------------------------------------------------


def test_a_wait_nobody_took_up_is_dropped_from_both_indexes() -> None:
    """The ask that opened a wait its provider refused leaves nothing behind.

    Both indexes, because either one left behind is a wait that still answers
    something: the reference index would let a retry read it, and the question
    index would let a retry be answered `suspend` on it and never reach the
    provider again.
    """
    store = _store()
    store.open(_pending())
    dropped = store.abandon("local", "approval-1")
    assert dropped.approval_ref == "approval-1"
    assert store.find_for_question(_question()) is None
    assert store.pending() == ()
    with pytest.raises(ApprovalUnknown):
        store.read("local", "approval-1")
    # The reference is free again, which is the proof the question index let go
    # of it too: `open` refuses a reference it still holds.
    reopened = store.open(_pending())
    assert store.find_for_question(_question()) == reopened


def test_a_wait_somebody_could_be_answering_is_not_dropped() -> None:
    """Article 3: only the ask that opened a wait nobody answered may retire it."""
    clock = Clock()
    store = _store(clock)
    store.open(_pending())
    store.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    with pytest.raises(ValueError, match="abandoned"):
        store.abandon("local", "approval-1")
    store.claim("local", "approval-1")
    with pytest.raises(ValueError, match="abandoned"):
        store.abandon("local", "approval-1")
    assert store.read("local", "approval-1").state is ApprovalState.APPROVED


def test_abandoning_a_wait_nobody_opened_is_refused_the_same_way_as_a_read() -> None:
    store = _store()
    with pytest.raises(ApprovalUnknown):
        store.abandon("local", "approval-1")


# -- the simple form of the port ----------------------------------------------


def _request(approval_ref: str = "approval-1") -> ApprovalRequest:
    return ApprovalRequest(
        approval_ref=approval_ref,
        decision_ref=f"decision-for-{approval_ref}",
        scope="local",
        capability="mail.send",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


def _provider(clock: Clock) -> tuple[SimpleApprovalProvider, ApprovalStore]:
    store = _store(clock)
    return SimpleApprovalProvider(store), store


def _opened(
    provider: SimpleApprovalProvider, store: ApprovalStore, approval_ref: str = "approval-1"
) -> SuspendedApproval:
    """The daemon's order: the core opens the wait it holds the question for,
    then puts the request to the provider for its own act."""
    store.open(_pending(approval_ref))
    return provider.suspend(_request(approval_ref))


def _writer(store: ApprovalStore) -> Callable[[ResolvedApproval], Approval]:
    """The core's own writer, handed to the judgement as the resolution route hands it.

    The store transition is the core's and no provider's, so a case that drives
    the seam and then asks what the store holds hands this in exactly as
    `ApprovalRoutes.resolve` does. A case that asks only what the judgement
    answers hands in nothing, and then nothing is written — which is the
    difference the seam's own cases below depend on.
    """
    return partial(write_resolution, store)


def test_the_simple_provider_is_a_provider_of_the_published_port() -> None:
    """Article 8: the open core's own provider stands behind the port it publishes."""
    provider, _ = _provider(Clock())
    assert isinstance(provider, ApprovalProvider)


def test_the_port_s_own_one_argument_call_is_the_call_this_provider_answers() -> None:
    """Article 8: the shipped provider is the published port, called the published way.

    One positional request and no keyword, so the plugin registry can compose
    it and the composition record names the provider that actually judges the
    acts. The question the port cannot carry is not smuggled in beside it: the
    daemon opens the wait in the store, where the question is a member of the
    record, and this call is the provider's own act on a wait that exists.
    """
    clock = Clock()
    provider, store = _provider(clock)
    port: ApprovalProvider = provider
    store.open(_pending())
    assert port.suspend(_request()) == SuspendedApproval(request=_request(), scope="local")


def test_suspending_a_reference_the_core_does_not_hold_is_refused() -> None:
    """Article 3: the provider opens no record of its own, so it refuses what it cannot find.

    A second record of a suspension is a second authority, and two authorities
    disagree. A request naming a wait this core is not keeping — and one naming
    a different decision than the wait it names — is refused rather than
    answered as a suspension nobody opened.
    """
    clock = Clock()
    provider, store = _provider(clock)
    with pytest.raises(ApprovalRequestMismatch):
        provider.suspend(_request())
    store.open(_pending())
    elsewhere = ApprovalRequest(
        approval_ref="approval-1",
        decision_ref="a-decision-nobody-suspended",
        scope="local",
        capability="mail.send",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )
    with pytest.raises(ApprovalRequestMismatch):
        provider.suspend(elsewhere)


def test_taking_up_a_wait_answers_the_suspension_the_core_keeps() -> None:
    """The record the answer describes is the store's, with the question it was opened for."""
    clock = Clock()
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    assert isinstance(suspended, SuspendedApproval)
    assert suspended.approval_ref == "approval-1"
    assert suspended.scope == "local"
    kept = store.read("local", "approval-1")
    assert kept.state is ApprovalState.PENDING
    assert kept.decision_ref == "decision-for-approval-1"
    assert kept.requested_at == REQUESTED_AT
    assert kept.deadline == DEADLINE
    assert store.find_for_question(_question()) == kept


def test_resuming_through_the_core_answers_the_person_who_acted_and_records_it() -> None:
    """Article 3: the resolution is a new record, appended before any caller resumes on it."""
    clock = Clock()
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    recorder = Recorder()
    clock.now = REQUESTED_AT + timedelta(seconds=30)
    answer = resume_through_provider(
        provider,
        suspended,
        ApprovalAction(
            approval_ref="approval-1",
            scope="local",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason="the recipient is on the list",
        ),
        recorder=recorder,
        apply=_writer(store),
    )
    assert answer == ResolvedApproval(
        approval_ref="approval-1",
        decision_ref="decision-for-approval-1",
        scope="local",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason="the recipient is on the list",
    )
    assert recorder.records == [answer]
    assert store.read("local", "approval-1").state is ApprovalState.APPROVED


def test_a_rejecting_act_resumes_as_a_rejection() -> None:
    """The other act of the simple form, through the same judgement."""
    clock = Clock()
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    answer = resume_through_provider(
        provider,
        suspended,
        ApprovalAction(
            approval_ref="approval-1",
            scope="local",
            person=ALICE,
            resolution=ApprovalResolution.REJECT,
            reason=None,
        ),
        recorder=Recorder(),
        apply=_writer(store),
    )
    assert isinstance(answer, ResolvedApproval)
    assert answer.resolution is ApprovalResolution.REJECT
    assert answer.reason is None
    assert store.read("local", "approval-1").state is ApprovalState.REJECTED


def test_a_second_resume_of_one_suspension_is_refused() -> None:
    """Article 3: the second caller does not overwrite the first person's act.

    The refusal is the writer's, under the store's own lock: whether a wait is
    still open is a question only the instant of the write can answer, and the
    second act's own recorder stays empty because nothing was applied.
    """
    clock = Clock()
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    action = ApprovalAction(
        approval_ref="approval-1",
        scope="local",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
    )
    resume_through_provider(provider, suspended, action, recorder=Recorder(), apply=_writer(store))
    second = Recorder()
    with pytest.raises(ApprovalAlreadyResolved):
        resume_through_provider(provider, suspended, action, recorder=second, apply=_writer(store))
    assert second.records == []


def test_an_act_for_another_approval_never_reaches_the_store() -> None:
    """The refusal that reaches the caller is the **provider's**, not the judgement's.

    Worth spelling out, because the obvious reading of the seam is wrong. The
    core's judgement does compute that no act was legitimately put to the
    provider for this suspension — `_acts_put_to` answers an empty tuple — and
    it then hands the provider the act anyway; what it refuses is an *answer*
    with no act behind it, one hop later. So a mismatched act reaches the
    provider, and it is this provider that raises `ApprovalRequestMismatch`,
    exactly as `SingleApprover` does. The class survives to the caller, which
    is what lets a route publish `request_malformed` for it rather than the
    code for a component that gave no answer (articles 1 and 2).

    What is recorded is a refusal and not a resolution. An act a provider
    declined is an act that ended nowhere, and a log that held nothing for it
    could not tell it from an act nobody ever made (article 2); the entry
    carries the core's own facts and the class name, never a verdict and never
    anything the provider said.
    """
    clock = Clock()
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    recorder = Recorder()
    with pytest.raises(ApprovalRequestMismatch):
        resume_through_provider(
            provider,
            suspended,
            ApprovalAction(
                approval_ref="approval-2",
                scope="local",
                person=ALICE,
                resolution=ApprovalResolution.APPROVE,
                reason=None,
            ),
            recorder=recorder,
            apply=_writer(store),
        )
    (refused,) = recorder.records
    assert isinstance(refused, RefusedProviderAnswer)
    assert refused.person == ALICE
    assert refused.complaint == "the provider refused the act with ApprovalRequestMismatch"
    assert store.read("local", "approval-1").state is ApprovalState.PENDING


def test_an_act_naming_another_scope_never_reaches_the_store() -> None:
    """Article 5: the scope is part of the identity, so a different one is a different act."""
    clock = Clock()
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    with pytest.raises(ApprovalRequestMismatch):
        resume_through_provider(
            provider,
            suspended,
            ApprovalAction(
                approval_ref="approval-1",
                scope="other",
                person=ALICE,
                resolution=ApprovalResolution.APPROVE,
                reason=None,
            ),
            recorder=Recorder(),
            apply=_writer(store),
        )
    assert store.read("local", "approval-1").state is ApprovalState.PENDING


def test_resuming_a_suspension_this_provider_never_opened_is_refused() -> None:
    """A suspension no store holds is not this provider's to resolve."""
    clock = Clock()
    provider, _ = _provider(clock)
    with pytest.raises(ApprovalRequestMismatch):
        provider.resume(
            SuspendedApproval(request=_request(), scope="local"),
            ApprovalAction(
                approval_ref="approval-1",
                scope="local",
                person=ALICE,
                resolution=ApprovalResolution.APPROVE,
                reason=None,
            ),
        )


def test_resuming_a_suspension_of_another_request_is_refused() -> None:
    """The reference matches and the request does not, which is not this suspension."""
    clock = Clock()
    provider, store = _provider(clock)
    _opened(provider, store)
    elsewhere = ApprovalRequest(
        approval_ref="approval-1",
        decision_ref="a-decision-nobody-suspended",
        scope="local",
        capability="mail.send",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )
    with pytest.raises(ApprovalRequestMismatch):
        provider.resume(
            SuspendedApproval(request=elsewhere, scope="local"),
            ApprovalAction(
                approval_ref="approval-1",
                scope="local",
                person=ALICE,
                resolution=ApprovalResolution.APPROVE,
                reason=None,
            ),
        )


def test_an_act_is_dated_by_the_clock_of_the_store_the_provider_answers_from() -> None:
    """Article 2: one clock behind the wait and the act, after the store is adopted.

    The provider is built before a composition root can say which clock the
    deployment runs on, so it keeps none: adopting the store adopts its clock,
    and the instant a person's act is written at is the instant that store
    measures its waits by. Two clocks would refuse an act as late by one and
    accept it by the other.

    The write is the core's, so the clock is read where the write happens and
    the provider reads none at all — which is the same property one step over,
    and the reason this case drives both halves rather than `resume` alone.
    """
    composed = Clock(REQUESTED_AT + timedelta(seconds=30))
    provider = SimpleApprovalProvider()
    assert provider.store.clock() != composed.now
    adopted = provider.keep_waits_in(_store(composed))
    assert provider.store is adopted
    suspended = _opened(provider, adopted)
    resolved = provider.resume(
        suspended,
        ApprovalAction(
            approval_ref="approval-1",
            scope="local",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason=None,
        ),
    )
    assert resolved.resolution is ApprovalResolution.APPROVE
    # Judged and not written: the wait is untouched until the core applies it.
    assert adopted.read("local", "approval-1").state is ApprovalState.PENDING
    write_resolution(adopted, resolved)
    assert adopted.read("local", "approval-1").resolved_at == composed.now


# -- what the daemon's log says a wait ended as -------------------------------


def test_the_recorder_writes_one_persons_act_with_the_person_named() -> None:
    """Article 12: the act and the person behind it are one record, or neither is."""
    events = MemoryEvents()
    clock = Clock(REQUESTED_AT + timedelta(seconds=7))
    EventsRecorder(events, clock=clock).record(
        ResolvedApproval(
            approval_ref="approval-1",
            decision_ref="decision-for-approval-1",
            scope="local",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason="the change is reviewed",
        )
    )
    (recorded,) = events.of_kind("approval.resolved")
    assert recorded.at == clock.now
    assert dict(recorded.details) == {
        "approval_ref": "approval-1",
        "decision_ref": "decision-for-approval-1",
        "scope": "local",
        "person": ALICE,
        "resolution": "approve",
        "reason": "the change is reviewed",
    }


def test_the_recorder_writes_a_rejection_as_the_act_it_was() -> None:
    """Article 1: a rejection is one of the two acts, not the absence of the other."""
    events = MemoryEvents()
    EventsRecorder(events, clock=Clock()).record(
        ResolvedApproval(
            approval_ref="approval-1",
            decision_ref="decision-for-approval-1",
            scope="local",
            person=ALICE,
            resolution=ApprovalResolution.REJECT,
        )
    )
    (recorded,) = events.of_kind("approval.resolved")
    assert recorded.details["resolution"] == "reject"
    assert recorded.details["reason"] is None


def test_the_recorder_writes_a_refused_provider_answer_and_no_verdict() -> None:
    """Article 12: a refusal is a refusal in the record, and never a decision.

    What is recorded is what the core holds — the suspension, the person whose
    act was put to the provider, and the complaint — and nothing the provider
    said, so the entry cannot be read as a resolution that happened.
    """
    events = MemoryEvents()
    EventsRecorder(events, clock=Clock()).record_refusal(
        RefusedProviderAnswer(
            approval_ref="approval-1",
            decision_ref="decision-for-approval-1",
            scope="local",
            person=ALICE,
            complaint="it attributes the act of somebody else",
        )
    )
    (recorded,) = events.of_kind("approval.refused")
    assert dict(recorded.details) == {
        "approval_ref": "approval-1",
        "decision_ref": "decision-for-approval-1",
        "scope": "local",
        "person": ALICE,
        "complaint": "it attributes the act of somebody else",
    }
    assert "resolution" not in recorded.details
    assert events.of_kind("approval.resolved") == ()


def test_the_recorder_dates_an_act_by_the_clock_it_was_composed_with() -> None:
    """Article 2: the log of an act and the record of it are dated by one clock."""
    events = MemoryEvents()
    clock = Clock()
    recorder = EventsRecorder(events, clock=clock)
    provider, store = _provider(clock)
    suspended = _opened(provider, store)
    resume_through_provider(
        provider,
        suspended,
        ApprovalAction(
            approval_ref="approval-1",
            scope="local",
            person=ALICE,
            resolution=ApprovalResolution.APPROVE,
            reason=None,
        ),
        recorder=recorder,
        apply=_writer(store),
    )
    (recorded,) = events.of_kind("approval.resolved")
    assert recorded.at == clock.now == store.read("local", "approval-1").resolved_at
