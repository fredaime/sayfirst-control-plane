# SPDX-License-Identifier: Apache-2.0
"""A person meets a suspended effect through the published daemon, and ends its wait.

Article 12's simple form, walked end to end against the command an operator
runs: a governed program asks, the policy suspends it, a person reads the wait
and approves it, and the program's next ask allows — with the reason the
contract publishes for an approval, the grant an allow mints, and the body
running once. Then the other three endings: a rejection denies, a resolution
that already stands is refused, and a wait nobody answered runs out.

Everything here goes over the socket. The boundary is the one a program uses,
the reads and the acts go through the published client, and nothing in this
module reaches into the daemon's process — which is the only way the two sides
can be said to agree about the wire (article 13).

One fact is not observable from out here and is named rather than asserted: the
daemon's own event log is a bounded sink it keeps in memory, served by no
operation of this generation, so `approval.resolved` and `approval.expired`
cannot be read back over the socket however faithfully they are recorded. The
unit cases in `packages/control-plane/tests/test_approvals_store.py` and
`packages/control-plane/tests/test_decisions_approvals.py` hold the recording,
and `test_a_reader_can_consult_the_acts_the_daemon_recorded` in
`packages/control-plane/tests/e2e/test_composed_daemon.py` reads the sink in
the process that composed it.
"""

from __future__ import annotations

import time
from contextlib import closing, suppress

import pytest
from _daemon import ARGUMENTS, DENY, LAPSE_SECONDS, LAPSES, SUSPEND, _Daemon
from sayfirst_boundary import Denied, Suspended
from sayfirst_contract.approvals import ApprovalResolution, ApprovalState, Resolution
from sayfirst_contract.client import Answered, Refused
from sayfirst_contract.decisions import Outcome, Reason

#: How long anything this daemon does on its own clock has to happen.
POLL_SECONDS = 15
#: What the body claims it did, so the outcome log has something to carry.
OUTCOME = "sha256:" + "f" * 64


def _suspends(running: _Daemon, capability: str = "example.waits") -> Suspended:
    """One ask through the boundary that the policy suspends, and the reference it names."""
    boundary, _, _ = running.boundary()
    with (
        closing(boundary),
        pytest.raises(Suspended) as raised,
        boundary.request(capability, ARGUMENTS),
    ):
        pytest.fail("a suspended effect ran its body")
    assert raised.value.approval_ref, "a suspension the daemon keeps names its wait"
    return raised.value


def _denied_once(running: _Daemon) -> None:
    """One ordinary decision request, which is what drives the daemon's sweep.

    The sweep runs on the paths a request already takes and on no clock of its
    own, so a case about what a sweep did asks for something first. A denial is
    used because it touches no approval: the wait under test is neither ended
    nor re-opened by the request that makes the daemon look at it.
    """
    boundary, _, _ = running.boundary()
    with closing(boundary), suppress(Denied), boundary.request("example.refused", ARGUMENTS):
        pytest.fail("a denied act ran its body")


def test_a_person_approves_a_suspension_and_the_next_ask_runs_the_body(daemon) -> None:  # type: ignore[no-untyped-def]
    """The whole walk: suspend, read, approve, allow with a grant, and spent after one.

    Every step is a separate connection, as a person's would be. The third ask
    uses a boundary of its own because the second one holds the grant its allow
    minted and would answer from it without asking — which is what a grant is
    for, and is asserted here rather than worked around.
    """
    running = daemon(SUSPEND)
    reader = running.client()
    suspended = _suspends(running)
    reference = suspended.approval_ref

    pending = reader.read_approval("local", reference)
    assert isinstance(pending, Answered), pending
    assert pending.value.state is ApprovalState.PENDING
    assert pending.value.approval_ref == reference
    assert pending.value.decision_ref == suspended.decision_ref
    assert pending.value.capability == "example.waits"
    assert pending.value.resolved_at is None
    assert pending.value.resolution_reason is None
    assert pending.value.person is None, "nobody has acted, so the document names nobody"
    # The wait is bounded, and the bound is the rule's rather than this test's.
    assert pending.value.deadline > pending.value.requested_at

    approved = reader.resolve_approval(
        ApprovalResolution("local", reference, Resolution.APPROVE, "the walk approves")
    )
    assert isinstance(approved, Answered), approved
    assert approved.value.state is ApprovalState.APPROVED
    assert approved.value.resolution_reason == "the walk approves"
    assert approved.value.resolved_at is not None
    # Who acted is on the document the client reads back. The reference is the
    # connection's verified principal, which this walk cannot spell for itself
    # — that is the whole point of it not being a request member — so what is
    # asserted here is that the daemon named somebody.
    assert approved.value.person, "an act names the person the connection established"
    # And a read afterwards says the same thing: the answer was the record.
    read_again = reader.read_approval("local", reference)
    assert isinstance(read_again, Answered), read_again
    assert read_again.value.to_document() == approved.value.to_document()

    holder, counting, written = running.boundary()
    with closing(holder):
        with holder.request("example.waits", ARGUMENTS) as grant:
            allowed = grant.decision_ref
            grant.record_outcome(OUTCOME)
        # The allow minted a grant and this boundary holds it, so the second
        # act on the same question runs the body without asking again. That is
        # what a grant is (article 10) and it is asserted rather than worked
        # around — and it is the one place worth reading twice: the approval
        # authorises one DECISION, and that decision's grant then answers the
        # same question for its lifetime without another ask.
        with holder.request("example.waits", ARGUMENTS) as again:
            assert again.decision_ref == allowed
        assert counting.by_capability == {"example.waits": 1}
    assert [record.outcome_digest for record in written] == [OUTCOME, None]

    decided = reader.read_decision("local", allowed)
    assert isinstance(decided, Answered), decided
    assert decided.value.outcome is Outcome.ALLOW
    assert decided.value.reason is Reason.APPROVAL_GRANTED

    # One resolution authorises one execution: the next ask of the same
    # question finds the approval spent and waits anew, on a new reference.
    anew = _suspends(running)
    assert anew.approval_ref != reference
    assert anew.decision_ref != suspended.decision_ref


def test_a_person_rejects_a_suspension_and_the_next_ask_is_denied(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 1: a rejection is answered as a deny, with the reason the contract publishes."""
    running = daemon(SUSPEND)
    reader = running.client()
    reference = _suspends(running).approval_ref

    rejected = reader.resolve_approval(
        ApprovalResolution("local", reference, Resolution.REJECT, "not this time")
    )
    assert isinstance(rejected, Answered), rejected
    assert rejected.value.state is ApprovalState.REJECTED
    assert rejected.value.resolution_reason == "not this time"

    boundary, _, _ = running.boundary()
    with (
        closing(boundary),
        pytest.raises(Denied) as raised,
        boundary.request("example.waits", ARGUMENTS),
    ):
        pytest.fail("a denied act ran its body")
    assert raised.value.reason == "approval_rejected"


def test_a_resolution_that_already_stands_is_refused_and_not_overwritten(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 3: a resolution is a new record, so nothing edits the one a person made."""
    running = daemon(SUSPEND)
    reader = running.client()
    reference = _suspends(running).approval_ref
    first = reader.resolve_approval(ApprovalResolution("local", reference, Resolution.APPROVE))
    assert isinstance(first, Answered), first

    second = reader.resolve_approval(ApprovalResolution("local", reference, Resolution.REJECT))

    assert isinstance(second, Refused), second
    assert second.problem.code == "approval_resolved"
    assert second.problem.retryable is False
    still = reader.read_approval("local", reference)
    assert isinstance(still, Answered), still
    assert still.value.state is ApprovalState.APPROVED


def test_an_approval_nothing_keeps_is_refused_by_name_on_both_operations(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 2: the daemon looked and holds none, which is its own answer.

    Both clients of the contract read it as a refusal, because the registry's
    class column says so: the daemon looked in the scope it was given and
    answered that it keeps no such wait, which is a verdict on the question and
    not a missing answer. The case asserts the code and the class together.
    """
    running = daemon(SUSPEND)
    reader = running.client()

    read = reader.read_approval("local", "nothing-here")
    resolved = reader.resolve_approval(
        ApprovalResolution("local", "nothing-here", Resolution.APPROVE)
    )

    assert isinstance(read, Refused), read
    assert read.problem.code == "approval_unknown"
    assert isinstance(resolved, Refused), resolved
    assert resolved.problem.code == "approval_unknown"


def test_a_read_without_a_scope_is_refused_rather_than_defaulted(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 5: the default scope is for an ask, never for naming an existing record."""
    running = daemon(SUSPEND)
    reference = _suspends(running).approval_ref
    reader = running.client()
    operation = reader._operation("read_approval")
    target = operation.target(approval_ref=reference)

    status, document = reader._request("GET", f"{target}?contract_generation=1")

    assert status == 400, document
    assert document["code"] == "scope_required"


def test_a_wait_nobody_answered_reads_expired_and_is_then_forgotten(daemon) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 12: the wait is bounded, and the record follows the clock.

    Two facts, in the order they become true. The read renders the state as of
    the instant it is taken, so the lapse is visible with no sweep having run
    at all — nothing between the suspension and the poll below asks the daemon
    for a decision, and a sweep runs on nothing else. Then the sweep does run,
    on the ordinary requests of an ordinary caller, and past one further
    wait-length the record is of no use to anybody and is dropped: a read then
    says `approval_unknown`, which is the honest answer once nothing is kept.
    """
    running = daemon(LAPSES + "\n" + DENY)
    reader = running.client()
    reference = _suspends(running, "example.lapses").approval_ref

    lapsed = _until(
        lambda: _state(reader, reference) is ApprovalState.EXPIRED,
        lambda: _state(reader, reference),
    )
    assert lapsed is True

    forgotten = _until(
        lambda: _forgotten(reader, reference, running),
        lambda: reader.read_approval("local", reference),
    )
    assert forgotten is True


def _state(reader, reference: str) -> ApprovalState | None:  # type: ignore[no-untyped-def]
    answer = reader.read_approval("local", reference)
    return answer.value.state if isinstance(answer, Answered) else None


def _forgotten(reader, reference: str, running: _Daemon) -> bool:  # type: ignore[no-untyped-def]
    """Whether the sweep has dropped the record, after giving it something to sweep on."""
    _denied_once(running)
    answer = reader.read_approval("local", reference)
    return isinstance(answer, Refused) and answer.problem.code == "approval_unknown"


def _until(probe, describe) -> bool:  # type: ignore[no-untyped-def]
    """Poll until the probe holds, or fail at the deadline with what it last saw.

    The deadline is generous against the wait it is polling — the rule's is
    `LAPSE_SECONDS` — because what is being proven is that the lapse happens
    and not how promptly a loaded machine notices it.
    """
    deadline = time.monotonic() + POLL_SECONDS
    while True:
        if probe():
            return True
        assert time.monotonic() < deadline, (LAPSE_SECONDS, describe())
        time.sleep(0.2)
