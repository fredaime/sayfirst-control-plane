# SPDX-License-Identifier: Apache-2.0
"""Where a suspended approval waits, and the simple form of the port it waits behind.

Article 12 puts one half of approvals in the open core — one person approves or
rejects — and leaves the counting of signatures to a provider behind the port.
The port published suspend and resume; `plugins/approval.py` judges what a
provider answers. This module is the part between them that had no home: the
store a suspension is kept in, the deadline its wait is measured against, and
the single execution one resolution authorises.

Three rulings the code holds rather than invents. The wait is bounded by a
deadline its **caller** computed, so nothing here invents one. The person is a
string the caller verified — the connection's principal reference — and this
module records it and judges nothing about it, because the simple form is « one
person » and a designation registry is an organisational object (article 12).
And a read renders the state as of the instant it is taken, so no reader
depends on the sweep having run (article 2).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from heapq import heappop, heappush
from threading import RLock

from ..domain.approval import Approval, ApprovalState, Question
from ..plugins.approval import RefusedProviderAnswer
from ..plugins.interfaces import (
    ApprovalAction,
    ApprovalAlreadyExists,
    ApprovalAlreadyResolved,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)
from .events import Events

_STATE_OF: dict[ApprovalResolution, ApprovalState] = {
    ApprovalResolution.APPROVE: ApprovalState.APPROVED,
    ApprovalResolution.REJECT: ApprovalState.REJECTED,
}


class ApprovalAlreadyClaimed(RuntimeError):
    """Another ask holds the one execution this approval authorises.

    Not a fault of the caller and not a state a reader sees: the approval is
    still approved and still unspent. It says only that this ask is not the one
    that may spend it, so this ask waits anew rather than recording a second
    allow on one person's act (article 3).
    """


class ApprovalUnknown(LookupError):
    """No approval of that reference is kept in that scope.

    A distinct refusal rather than an absent answer: article 2 forbids
    rendering « did not look » and « looked and found nothing » alike, and a
    caller that reads an approval by reference is asking about one it was told
    exists.
    """


class EventsRecorder:
    """`ApprovalResolutionRecorder` over the daemon's event log.

    Two things are recorded and they are not the same thing. A resolution is
    one person's act, applied and written down. A refusal is an act that ended
    nowhere — the core declining a provider's answer that no act supports
    (article 8's Why), or the provider declining the act itself — and it
    carries no verdict, because a refusal is a refusal in the record and never
    a decision (article 12).

    Neither is an evidence entry, and this widens no evidence vocabulary: the
    durable record of a resolution is the resumed decision the ask path
    appends, which is already on the chain with the reference it acted on —
    with the approval's reference, that is, and not with the person.

    Where these entries go is whatever events sink the deployment composed, and
    `bootstrap.compose` composes a bounded one: an operator reading the process
    that recorded them sees the most recent of them, and a count of what the
    bound dropped (article 10). That makes it an observation an operator can
    consult and never a record to rely on — no operation of this generation
    serves it over the socket, and a restart loses it — so nothing here is
    evidence and nothing here says it is (articles 2 and 3). What survives an
    act is the approval record, which carries the person for as long as the
    store keeps it and which `read_approval` renders, and the resumed decision
    above.

    The instant is the caller's clock — the store's, where a route composes one
    — for the reason the store keeps only one: two clocks would date an act
    differently from the record it produced.
    """

    def __init__(self, events: Events, *, clock: Callable[[], datetime] | None = None) -> None:
        self._events = events
        self._clock = clock or (lambda: datetime.now(UTC))

    def record(self, resolution: ResolvedApproval) -> None:
        """One person's act on one suspension, with the person named."""
        self._events.record(
            "approval.resolved",
            {
                "approval_ref": resolution.approval_ref,
                "decision_ref": resolution.decision_ref,
                "scope": resolution.scope,
                "person": resolution.person,
                "resolution": resolution.resolution.value,
                "reason": resolution.reason,
            },
            at=self._clock(),
        )

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        """One refused act, as the core's own facts spell it and nothing else."""
        self._events.record(
            "approval.refused",
            {
                "approval_ref": refusal.approval_ref,
                "decision_ref": refusal.decision_ref,
                "scope": refusal.scope,
                "person": refusal.person,
                "complaint": refusal.complaint,
            },
            at=self._clock(),
        )


class ApprovalStore:
    """In memory, by reference and by question.

    Nothing here survives a restart — a suspended decision is already a durable
    record and the resolution becomes one when the ask is resumed; an approval
    pending across a restart is lost and the re-ask suspends anew, with a new
    reference. That is a stated limit of the simple form (article 2), not a
    property this module quietly holds: the durable half is the decision
    record, and this is the wait.

    The other limit is growth, and it is stated here beside the first because
    it is the one an operator meets sooner. Every record and every index entry
    this store keeps, it keeps until something removes it, and only
    `forget_lapsed` removes one: a daemon that suspends and resolves asks
    without sweeping grows for the life of the process, and a question asked
    repeatedly grows a reference list `find_for_question` walks. The daemon's
    sweep calls it, in the tick that also ends the grants and expires the waits
    that ran out, so the growth is bounded by that tick running — and the tick
    runs on the paths a request already takes, never on a clock of its own. The
    two due-time indexes are lazy and hold an entry after its record is gone,
    which is bounded the same way: the sweep takes such an entry out the first
    time the clock passes its instant.

    One record outlives that bound, and it is stated here because it is a
    limit an operator can meet: an approved approval nobody spends is kept for
    the life of the process. Only the execution it authorises being taken
    removes it, because the alternative is to throw away a person's act at a
    deadline and ask another human for an effect already approved (article 12).
    A deployment that approves effects whose programs never come back therefore
    accumulates one record per such act, and the way to bound that is a policy
    whose waits are answered, not a sweep that discards them.

    The second index is the suspended **question** — scope, principal
    reference, capability, arguments digest — so a re-ask of the same question
    finds the approval it already suspended instead of opening a second wait.
    A near miss is not a match: any member differing is a different question
    (article 3). A consumed approval answers none, a claimed one answers none
    until it is spent or given back, and a rejection answers only while the
    wait it ended is still running.

    Two operations exist because two asks can run at once, and the daemon is
    threaded. `open_if_absent` looks and opens under one lock, so one question
    never ends with two waits; `claim` takes the one execution an approved
    approval authorises under the same lock, so two asks never both record an
    allow on one person's act. Between them they are why « one resolution
    authorises one execution » is a property and not a hope.

    A lock, because the daemon serves more than one connection and every other
    in-memory authority here holds one.
    """

    def __init__(self, *, clock: Callable[[], datetime]) -> None:
        #: The one clock every wait in this store is measured by: the instant a
        #: read renders a state as of, and the instant an act is judged
        #: against. Readable, because the provider that answers acts on this
        #: store has to use this clock and not one of its own — two clocks
        #: would refuse a person's act as late by one of them and accept it by
        #: the other (article 2).
        self.clock = clock
        self._lock = RLock()
        self._by_reference: dict[tuple[str, str], Approval] = {}
        #: Every reference opened for one question, in the order it was opened,
        #: so the most recent is the last and a lapsed one stays readable by
        #: reference after it stops answering its question.
        self._by_question: dict[Question, list[tuple[str, str]]] = {}
        #: The pending waits by deadline, and the resolved ones by the instant
        #: they become of no further use. A heap rather than a sorted walk: the
        #: sweep runs on every decision request and on every held-grant wake,
        #: and a walk of the whole store made the cost of one request grow with
        #: everything the process had ever suspended. Entries are lazy — a
        #: record whose state moved is skipped when it surfaces, and one whose
        #: reference has been opened again is put back at the deadline the
        #: record actually holds — so nothing here is an authority about a
        #: wait; `_by_reference` is. An entry outlives the record it names at
        #: most until the clock passes its instant, which is when the sweep
        #: takes it out.
        self._due: list[tuple[datetime, tuple[str, str]]] = []
        self._lapsing: list[tuple[datetime, tuple[str, str]]] = []

    def open(self, approval: Approval) -> Approval:
        """Keep a PENDING approval, under its scope and its reference.

        A reference already kept in that scope is refused rather than replaced:
        a suspension is a new record, never an edit of the one before it
        (article 3).
        """
        if approval.state is not ApprovalState.PENDING:
            raise ValueError(
                f"only a pending approval can be opened, not a {approval.state.value} one"
            )
        key = (approval.scope, approval.approval_ref)
        with self._lock:
            if key in self._by_reference:
                raise ApprovalAlreadyExists(
                    f"approval {approval.approval_ref!r} is already open in scope "
                    f"{approval.scope!r}"
                )
            self._by_reference[key] = approval
            self._by_question.setdefault(approval.question, []).append(key)
            heappush(self._due, (approval.deadline, key))
        return approval

    def read(self, scope: str, approval_ref: str) -> Approval:
        """The approval as it is kept; rendering `state_at` is the reader's business."""
        with self._lock:
            kept = self._by_reference.get((scope, approval_ref))
        if kept is None:
            raise ApprovalUnknown(f"no approval {approval_ref!r} is kept in scope {scope!r}")
        return kept

    def find_for_question(self, question: Question) -> Approval | None:
        """The most recent approval still answering this question, or None.

        Most recent is the **last opened**, which is the order this store
        holds; `requested_at` is a caller's value and is not read here.

        Still answering means three things, read against the clock's now and
        before any sweep has run. Not consumed: one resolution authorises one
        execution. Not lapsed: a wait that has run out answers nothing. And a
        rejection answers only while `now < deadline` — « deny » is one of the
        two acts of the simple form and it stands for the wait it ended, no
        longer, because the wait was bounded and a record that outlived its
        bound would deny every re-ask of that question for the life of the
        process.

        What lapses is the answer, never the record. The rejection stays
        `rejected` — `state_at` converts only a pending approval, and
        `expire_past` touches only a pending one — so a reader still reads what
        the person decided; only its usefulness to a re-ask ends. An approved
        approval is not bounded this way: it is the authorisation for one
        execution and it answers until it is consumed, because losing it at the
        deadline would discard a person's act the caller is still entitled to
        spend. Claimed is the fourth thing and the same rule as consumed, one
        step earlier: an execution another ask is about to take is not one this
        question can be answered with.
        """
        with self._lock:
            return self._newest_live(question, self.clock(), in_flight=False)

    def open_if_absent(self, approval: Approval) -> Approval:
        """The approval this question already has, or this one, opened — under one lock.

        Two asks of one question that both find nothing and both open a wait
        leave that question with two waits, and a re-ask is answered the most
        recent of them: the person who resolves the one their caller was
        actually told about has their act shadowed by the other and silently
        discarded. Nothing in either ask is wrong; the gap between looking and
        opening is. So the look and the open are one operation here, and a
        question has at most one wait somebody could still resolve (article 3).

        An approval another ask has **claimed** counts as one this question
        already has, and is answered rather than shadowed by a new wait. It is
        in flight, not gone: the ask holding it either records the allow it
        authorises or gives it back, and a wait opened over it would be newer
        than a person's act and would hide that act from every later ask. What
        the caller does with an answer it cannot claim is the caller's rule —
        this store only refuses to lose it.

        The answer says which happened: a returned approval whose reference is
        not the one handed in is the one that was already there.
        """
        with self._lock:
            found = self._newest_live(approval.question, self.clock(), in_flight=True)
            return self.open(approval) if found is None else found

    def abandon(self, scope: str, approval_ref: str) -> Approval:
        """Drop a wait the ask that opened it could not use, from both indexes.

        One caller and one moment: the ask that just opened a wait, whose
        provider then refused to take it up, so no decision names this wait and
        nobody has been told to answer it. Leaving it would be worse than
        untidy — the ask's own retry would find it pending, answer `suspend`
        on it and never put the request to the provider again, so a provider
        failure would come back as a wait that provider never received
        (articles 2 and 12).

        Pending and unclaimed, checked here rather than trusted: a wait
        somebody could be resolving, or an execution another ask holds, is not
        this ask's to drop.
        """
        with self._lock:
            kept = self.read(scope, approval_ref)
            if kept.state is not ApprovalState.PENDING or kept.claimed:
                raise ValueError(
                    f"approval {approval_ref!r} is {kept.state.value}"
                    f"{' and claimed' if kept.claimed else ''}: only a wait nobody has "
                    "answered and nobody is spending can be abandoned"
                )
            key = (scope, approval_ref)
            del self._by_reference[key]
            references = self._by_question.get(kept.question)
            if references is not None:
                references.remove(key)
                if not references:
                    del self._by_question[kept.question]
        return kept

    def _newest_live(
        self, question: Question, now: datetime, *, in_flight: bool
    ) -> Approval | None:
        """The newest approval this question still has, by one walk for both callers.

        The caller holds the lock. Spent is gone, lapsed is gone, and a
        rejection is gone once the wait it ended has run out — that much is
        the same for everyone who asks. `in_flight` is the one difference, and
        it is the difference between the two questions this store is asked: a
        reader asking what still answers a question is not told about an
        execution another ask is in the middle of spending, while a caller
        about to open a *new* wait must be, or it would open one over a
        person's act and hide it.
        """
        for key in reversed(self._by_question.get(question, ())):
            kept = self._by_reference[key]
            if kept.consumed:
                continue
            if kept.claimed and not in_flight:
                continue
            if kept.state_at(now) is ApprovalState.EXPIRED:
                continue
            if kept.state is ApprovalState.REJECTED and now >= kept.deadline:
                continue
            return kept
        return None

    def resolve(
        self,
        scope: str,
        approval_ref: str,
        *,
        person: str,
        resolution: ApprovalResolution,
        reason: str | None,
        now: datetime,
    ) -> Approval:
        """One person's act on a wait that is still open.

        A wait that ran out is ended first — at its deadline, which is when it
        ended, not when somebody noticed — and only then is the act refused, so
        the record a caller reads afterwards says what happened rather than
        still saying `pending` (article 2). Any terminal state refuses the act
        without touching the record.
        """
        with self._lock:
            kept = self.read(scope, approval_ref)
            if kept.state is not ApprovalState.PENDING:
                raise ApprovalAlreadyResolved(
                    f"approval {approval_ref!r} is already {kept.state.value}"
                )
            key = (scope, approval_ref)
            if now >= kept.deadline:
                expired = replace(kept, state=ApprovalState.EXPIRED, resolved_at=kept.deadline)
                self._by_reference[key] = expired
                self._index_lapse(key, expired)
                raise ApprovalAlreadyResolved(
                    f"approval {approval_ref!r} is already expired: its wait ended at its deadline"
                )
            resolved = replace(
                kept,
                state=_STATE_OF[resolution],
                resolved_at=now,
                person=person,
                resolution_reason=reason,
            )
            self._by_reference[key] = resolved
            # A rejection lapses one wait-length after the act; an approval
            # nobody has spent has no such instant and is put on no index at
            # all, which is where the exception `forget_lapsed` states lives
            # once the walk is gone (`_lapse_instant`).
            self._index_lapse(key, resolved)
        return resolved

    def claim(self, scope: str, approval_ref: str) -> Approval:
        """Take the one execution an approved approval authorises, before spending it.

        The half of « one resolution, one execution » that two asks running at
        once need. Finding an approval and spending it are two acts, and
        between them a second ask found the same approval and recorded a second
        allow on one person's act — an outcome no lock inside `consume` can
        prevent, because by then both records exist. The claim moves the
        contested step to the one place that can settle it: under this lock,
        exactly one ask leaves with the execution, and the approval answers no
        other question until that ask spends it or gives it back.

        A claim on anything but an approved, unspent, unclaimed approval is
        refused; the refusal for « somebody else has it » is its own class,
        because it is not a fault and the caller's answer to it is to wait anew.
        """
        with self._lock:
            kept = self.read(scope, approval_ref)
            if kept.state is not ApprovalState.APPROVED:
                raise ValueError(
                    f"approval {approval_ref!r} is {kept.state.value}: only an approved "
                    "approval authorises an execution"
                )
            if kept.consumed or kept.claimed:
                raise ApprovalAlreadyClaimed(
                    f"approval {approval_ref!r} is already "
                    f"{'consumed' if kept.consumed else 'claimed'}: one resolution "
                    "authorises one execution"
                )
            claimed = replace(kept, claimed=True)
            self._by_reference[(scope, approval_ref)] = claimed
        return claimed

    def release_claim(self, scope: str, approval_ref: str) -> Approval:
        """Give back an execution this ask claimed and did not spend.

        The decision that would have spent it was never written and could not
        have been — the append refused before its first byte — so the person's
        act is still unspent and the next ask of that question is entitled to
        it. Article 3 from the other side: nothing is consumed without a
        record, and nothing is lost because a record was not written.

        An append that *cannot say* whether it committed is not this case. One
        allow on that act may already be readable, so it is consumed and never
        given back (`consume`, and `DecisionService._consume_claimed`): fail
        closed means « it may have been recorded » is read as « it was », and a
        caller that loses a wait to that is asked again rather than licensed
        twice.
        """
        with self._lock:
            kept = self.read(scope, approval_ref)
            if kept.consumed:
                raise ValueError(
                    f"approval {approval_ref!r} was consumed: the execution it authorised "
                    "happened, and a claim behind a record is not given back"
                )
            if not kept.claimed:
                raise ValueError(f"approval {approval_ref!r} is not claimed")
            released = replace(kept, claimed=False)
            self._by_reference[(scope, approval_ref)] = released
        return released

    def consume(self, scope: str, approval_ref: str) -> Approval:
        """Spend the one execution an approval authorises, claimed by this ask first.

        Two callers, and the second is the one worth naming. The first spends
        it behind a decision that is on the chain. The second spends it behind
        an append that began and could not say whether it committed: a record
        that may exist is treated as one that does, because the alternative is
        a second allow on one person's act (article 3, fail closed).
        """
        with self._lock:
            kept = self.read(scope, approval_ref)
            if kept.state is not ApprovalState.APPROVED:
                raise ValueError(
                    f"approval {approval_ref!r} is {kept.state.value}: only an approved "
                    "approval authorises an execution"
                )
            if kept.consumed:
                raise ValueError(
                    f"approval {approval_ref!r} was already consumed: one resolution "
                    "authorises one execution"
                )
            if not kept.claimed:
                raise ValueError(
                    f"approval {approval_ref!r} was not claimed: the execution is taken "
                    "under this lock before the decision that spends it is recorded"
                )
            consumed = replace(kept, consumed=True)
            key = (scope, approval_ref)
            self._by_reference[key] = consumed
            # Spending it is what gives it a lapse instant: until now it was
            # the one record this store keeps for the life of the process.
            self._index_lapse(key, consumed)
        return consumed

    def expire_past(self, now: datetime) -> tuple[Approval, ...]:
        """End every wait whose deadline is at or before `now`, at its deadline.

        Idempotent by construction: it ends pending waits, and what it ended is
        no longer pending. Returned in reference order so a caller's record of
        a sweep does not depend on a dictionary's insertion order.

        The front of the deadline index and nothing else: this runs on every
        decision request, and reading every record the process ever suspended
        to end the one that ran out made the cost of one request grow with the
        store. An entry whose record moved on, or was dropped, is skipped; an
        entry a re-opened reference has outdated is put back at the deadline
        the record itself holds, because the record is the authority and the
        index is a hint about when to ask it.
        """
        with self._lock:
            ended = []
            while self._due and self._due[0][0] <= now:
                _, key = heappop(self._due)
                kept = self._by_reference.get(key)
                if kept is None or kept.state is not ApprovalState.PENDING:
                    continue
                if now < kept.deadline:
                    heappush(self._due, (kept.deadline, key))
                    continue
                expired = replace(kept, state=ApprovalState.EXPIRED, resolved_at=kept.deadline)
                self._by_reference[key] = expired
                self._index_lapse(key, expired)
                ended.append(expired)
            return tuple(sorted(ended, key=_store_key))

    def forget_lapsed(self, now: datetime) -> tuple[Approval, ...]:
        """Drop from both indexes the records nothing can still need, in store-key order.

        One rule, about what a reader is still entitled to, and one exception
        to it. A record whose wait is over and whose execution is not
        outstanding — spent, rejected or expired — keeps answering
        `read_approval` for one more wait-length after it resolved,
        `resolved_at + (deadline - requested_at)`, because the caller that asked
        is the caller that reads it and it was already willing to wait that
        long; past that the record is of no use to anyone this store serves. A
        spent approval answers no re-ask from the moment it is consumed (the
        question index is what `consume` closes), but it is still read by
        reference for that wait-length, as approved.

        The exception is an approved approval nobody has spent, and it is the
        one record this store may hold for the life of the process: the act
        stands until the execution it authorises is taken, so nothing here
        drops it (`_is_of_no_further_use` says why, and
        `ApprovalStore`'s own docstring states the growth it costs).

        A pending approval is never forgotten either, whatever the clock says.
        The sweep ends it first — `expire_past` — and the lapse is then counted
        from the deadline it ended at, so nothing is dropped while it is still
        somebody's open wait.

        The daemon's sweep calls this, immediately after `expire_past` and with
        the same instant, and records the references it dropped. The growth it
        answers is stated in this store's own docstring rather than left to be
        discovered.

        The front of the lapse index and nothing else, for the reason
        `expire_past` gives: both halves of the sweep run on every decision
        request. The exception above is what an index makes structural rather
        than conditional — an approved approval nobody has spent has no instant
        at which it becomes of no further use, so it is never put on this index
        at all, and `consume` is what puts it there. Every record the index
        does surface is judged again by `_is_of_no_further_use` before it is
        dropped, because the record is the authority and the index is a hint.
        """
        with self._lock:
            forgotten = []
            while self._lapsing and self._lapsing[0][0] <= now:
                _, key = heappop(self._lapsing)
                kept = self._by_reference.get(key)
                if kept is None:
                    continue
                if not _is_of_no_further_use(kept, now):
                    # A stale entry: the reference holds another record than the
                    # one that was indexed. Put back where that record lapses,
                    # and nowhere at all while nothing can say when that is.
                    self._index_lapse(key, kept)
                    continue
                forgotten.append(kept)
                del self._by_reference[key]
                references = self._by_question.get(kept.question)
                if references is not None:
                    references.remove(key)
                    if not references:
                        del self._by_question[kept.question]
            return tuple(sorted(forgotten, key=_store_key))

    def _index_lapse(self, key: tuple[str, str], kept: Approval) -> None:
        """Index this record at the instant it becomes of no further use, where it has one.

        The caller holds the lock. A pending wait and an approved approval
        nobody has spent have no such instant — the first is somebody's open
        wait and the second is a person's act waiting to be spent — so neither
        is indexed, and the code that gives them one (`expire_past` and
        `consume`) is the code that indexes them.
        """
        lapses_at = _lapse_instant(kept)
        if lapses_at is not None:
            heappush(self._lapsing, (lapses_at, key))

    def pending(self) -> tuple[Approval, ...]:
        """The waits nothing has ended, in reference order.

        Kept-state pending, which is not the same as pending as of now: one
        whose deadline has passed and whose sweep has not run is here, and
        reads `expired`. That is the honest pair — the sweep's work list and
        the reader's state are different questions (article 2).
        """
        with self._lock:
            return tuple(
                self._by_reference[key]
                for key in sorted(self._by_reference)
                if self._by_reference[key].state is ApprovalState.PENDING
            )


def _store_key(approval: Approval) -> tuple[str, str]:
    """The key this store holds a record under, which is the order a sweep answers in.

    The return order is part of the contract with the caller that records the
    sweep, and the indexes answer in deadline order, so what a sweep collected
    is sorted by this before it is returned.
    """
    return (approval.scope, approval.approval_ref)


def _lapse_instant(kept: Approval) -> datetime | None:
    """When this record becomes of no further use, or None while nothing can say.

    The same rule `_is_of_no_further_use` states, read forwards: one wait-length
    after the act or the lapse that ended it. A pending wait has no such instant
    because it has not ended, and an approved approval nobody has spent has none
    because the act stands until the execution it authorises is taken. The two
    answers are one function apart so they cannot drift — an index that invented
    an instant for either would drop a record the store owes a reader.
    """
    if kept.state is ApprovalState.PENDING:
        return None
    if kept.state is ApprovalState.APPROVED and not kept.consumed:
        return None
    assert kept.resolved_at is not None, "a terminal approval carries the instant it ended"
    return kept.resolved_at + (kept.deadline - kept.requested_at)


def _is_of_no_further_use(kept: Approval, now: datetime) -> bool:
    """Whether `forget_lapsed` may drop this record as of `now`.

    Read as one predicate rather than inline, so the rule it holds is one thing
    a reader can check against the docstring that states it. A consumed
    approval is not dropped the instant it is spent: for that wait-length a
    reader asking after the reference still learns it was approved, instead of
    « unknown », which would read as if nobody had ever asked (article 2).

    An approved approval nobody has spent is never dropped, whatever the clock
    says, and that is the one exception to the wait-length rule. It is the
    authorisation for one execution and it answers a re-ask until it is
    consumed — the rule `find_for_question` states — so dropping it at a
    deadline would discard a person's act the caller is still entitled to
    spend, ask a second human for an effect already approved, and answer
    `approval_unknown` about a decision that was made (articles 2 and 12). A
    claim is the same case one step on: the ask holding it either spends it or
    gives it back, and either way this is not the code that decides.
    """
    lapses_at = _lapse_instant(kept)
    return lapses_at is not None and now >= lapses_at


def write_resolution(store: ApprovalStore, resolved: ResolvedApproval) -> Approval:
    """Apply one judged resolution to the wait it names — the store's one writer.

    The store is the core's record of a wait, so ending that wait is the core's
    act whatever provider judged it. It used to be written inside the shipped
    provider's `resume`, which made the transition a property of that one
    implementation instead of a property of the port: a provider from elsewhere
    — the configuration `docs/deployment.md` offers for designation and a
    second signature, and one the published conformance kit certifies — left
    the wait pending after answering a person `200`, so the act was recorded
    and then discarded and every re-ask was suspended again until the wait
    lapsed (articles 2, 3 and 12).

    So this is the one call of `ApprovalStore.resolve` in the daemon's source,
    and the resolution route is its one caller. It is called after the
    judgement and before the act is recorded, which is what makes its refusals
    answers rather than discrepancies: a wait another act ended first, and one
    that ran out between the read and the write, are settled here under the
    store's own lock, and nothing is recorded for an act that was never
    applied.

    The instant is the store's clock, because the deadline this act is judged
    against was set by that clock; a second clock would refuse as late an act
    the store accepts (article 2).
    """
    return store.resolve(
        resolved.scope,
        resolved.approval_ref,
        person=resolved.person,
        resolution=resolved.resolution,
        reason=resolved.reason,
        now=store.clock(),
    )


class SimpleApprovalProvider:
    """Article 12's simple form of the port: one person, one act, no signatures counted.

    The shipped `ApprovalProvider`, composed by the plugin registry under the
    name the composition chain records, so the provider an operator configured
    is the provider that judges the acts (article 2: one daemon, one name).
    Its `suspend` is the published one — one positional request, no keyword —
    which is what lets the registry compose it at all.

    Which leaves the question the port cannot carry. What makes a re-ask the
    *same* ask — the principal reference and the arguments digest — is
    established from the connection and from the ask, and a provider may not be
    trusted to tell the core either (article 3). So the daemon opens the wait
    in the store itself, where the question is a member of the record, and then
    puts the request to this provider for its own act. Here that act is to take
    up a wait this core is already keeping: the store is read for the
    reference, the decision it names is held against the request, and the
    suspension is answered. A request naming a suspension the store does not
    hold is refused — nothing here opens a record the daemon did not, because a
    second record is a second authority and two authorities disagree.

    The store is the provider's own when nobody hands it one, which is what
    makes the zero-argument factory of a plugin registration possible; the
    composition root then hands over the store it owns (`keep_waits_in`), so
    the daemon and the provider keep one store on one clock.

    This provider is the core's own and stands outside the conformance kit of
    article 8. The kit is the contract for a provider written elsewhere — it
    opens a wait through `suspend` and judges what comes back — and this one
    opens nothing: the wait is the core's record, kept before the request is
    put to it. Holding it to the kit would mean teaching the kit to open a wait
    in a store, which is the core's business and not a provider's contract.
    """

    def __init__(self, store: ApprovalStore | None = None) -> None:
        """Keep waits in the store given, or in one of this provider's own.

        No clock argument, deliberately: the clock is the store's, and the only
        code that reads it is the core's writer (`write_resolution`). A
        provider holding a clock beside a store's is the two-clocks fault
        written into the signature — one instant records the wait, another
        dates the act on it — so the only clock in reach here is the one a
        store was built with, and adopting a store adopts it.
        """
        #: Read by the composition root, which serves the reads and the sweep
        #: from this very store rather than keeping a second one.
        self.store = ApprovalStore(clock=lambda: datetime.now(UTC)) if store is None else store

    def keep_waits_in(self, store: ApprovalStore) -> ApprovalStore:
        """Adopt the store the composition root owns — and with it, its clock.

        A plugin registration's factory takes no arguments, so this provider is
        built before the daemon composing it can say which clock the deployment
        runs on. One clock is not a detail: the deadline a decision records, the
        instant a wait lapses, the sweep that ends it and the instant a person's
        act is recorded at are all measured against it, and two clocks would let
        an act be refused as late by one and accepted by the other (article 2).
        The clock comes with the store rather than beside it — this provider
        keeps none of its own, and the clock a person's act is dated by is
        `store.clock`, read by the core's writer — so adopting the store is
        adopting the clock, and there is no second thing for a caller to
        remember.
        """
        self.store = store
        return store

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        """Take up the wait this request names, which the core is already keeping.

        Article 12's act, in its simple form, needs nothing of its own: the
        wait, its deadline and the question it answers are the store's, so this
        reads the record and answers the suspension the request describes. A
        reference the store does not hold, or one that suspends another
        decision, is refused rather than opened — the daemon opens the wait,
        because the daemon is what holds the question.
        """
        try:
            kept = self.store.read(request.scope, request.approval_ref)
        except ApprovalUnknown as unknown:
            raise ApprovalRequestMismatch(
                f"approval {request.approval_ref!r} is not a suspension this core keeps"
            ) from unknown
        if kept.decision_ref != request.decision_ref:
            raise ApprovalRequestMismatch(
                f"approval {request.approval_ref!r} suspends another decision than this "
                "request names"
            )
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        """Judge one person's act against the wait this core keeps, and answer it.

        Nothing is written here. The store is the core's and the core is its
        single writer (`write_resolution`), so this provider does what a
        provider from elsewhere does: it holds the act against the suspension
        it was handed and answers the resolution that act makes. Writing the
        transition here is what made a conformant provider from elsewhere leave
        the wait pending, because the state change was this class's and not the
        port's (articles 3 and 12).

        What it does read the store for is the refusal it owes: a reference this
        core is not keeping, and one that suspends another decision, name no
        wait this act can end, and this provider opens no record of its own.

        Whether the wait is still *open* is deliberately not judged here. Only
        the writer can answer that, under the store's lock at the instant it
        writes: an answer taken before the write is one a second act, or the
        deadline, can invalidate in between (article 3).
        """
        approval_ref = suspended.approval_ref
        if action.approval_ref != approval_ref:
            raise ApprovalRequestMismatch(
                f"an act for {action.approval_ref!r} cannot resolve {approval_ref!r}"
            )
        if action.scope != suspended.scope:
            raise ApprovalRequestMismatch(
                f"an act in scope {action.scope!r} cannot resolve scope {suspended.scope!r}"
            )
        try:
            kept = self.store.read(suspended.scope, approval_ref)
        except ApprovalUnknown as unknown:
            raise ApprovalRequestMismatch(
                f"approval {approval_ref!r} is not a suspension this provider opened"
            ) from unknown
        if kept.decision_ref != suspended.request.decision_ref:
            raise ApprovalRequestMismatch(
                f"approval {approval_ref!r} suspends another decision than this suspension names"
            )
        return ResolvedApproval(
            approval_ref=kept.approval_ref,
            decision_ref=kept.decision_ref,
            scope=kept.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )
