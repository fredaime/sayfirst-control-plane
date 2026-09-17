# SPDX-License-Identifier: Apache-2.0
"""A wait read and ended through the verified transport, against the published daemon.

The same walk `test_a_person_resolves_an_approval.py` takes through the
binding's client, taken through the other client of the same contract: the
transport a governed caller opens, which verifies the far end before it writes
a byte and carries no credential of its own. Two clients of one contract is what
article 13 is for, and until a walk goes through this one, nothing held it to
the wire the daemon actually serves.

One fact about the answers is named here rather than asserted, because it is
not observable from out here and pretending otherwise would be the defect these
cases exist to prevent.

The published `approval-result` carries the person, and this client reads it
like the other one: who acted is the connection's verified principal, never a
member of the request, so a case here asserts that the daemon named somebody
and not which name a particular host would give. What this client cannot see is
the daemon's own event log, which is a bounded in-memory sink no operation of
this generation serves; the unit cases in
`packages/control-plane/tests/test_approvals_store.py` hold that the act is
recorded there.

And a refusal of an act reaches this transport as the registry classes its
code, which for every code at 404 and 409 is a refusal — the same reading the
binding's own client gives the same document, because the class is published
once beside the code and neither client derives it a second time. The cases
below assert against the published class itself rather than against a
hand-written verdict, so a class that moves in the registry moves here.
"""

from __future__ import annotations

from contextlib import closing

import pytest
from _daemon import ARGUMENTS, SUSPEND, _Daemon
from sayfirst_boundary import Suspended
from sayfirst_contract.approvals import ApprovalResolution, ApprovalState, Resolution
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.decisions import Outcome, Reason
from sayfirst_contract.problems import ProblemCode, problem_class, problem_retryable
from sayfirst_contract.transport.socket_client import SocketProfile, VerifiedConnection, connect

#: What the body claims it did, so the outcome log has something to carry.
OUTCOME = "sha256:" + "e" * 64


def _profile(running: _Daemon) -> SocketProfile:
    """This daemon's address, as the transport's profile names it."""
    return SocketProfile(str(running.socket_path), mode="per_user", daemon_user=None, scope="local")


def _suspends(running: _Daemon) -> Suspended:
    """One ask through the boundary the policy suspends, and the reference it names."""
    boundary, _, _ = running.boundary()
    with (
        closing(boundary),
        pytest.raises(Suspended) as raised,
        boundary.request("example.waits", ARGUMENTS),
    ):
        pytest.fail("a suspended effect ran its body")
    assert raised.value.approval_ref, "a suspension the daemon keeps names its wait"
    return raised.value


def _expected(code: ProblemCode) -> type[Refused] | type[CouldNotAsk]:
    """Which result this transport gives a published code, as the registry classes it."""
    return Refused if problem_class(code) == "refused" else CouldNotAsk


def test_the_transport_reads_a_wait_approves_it_and_the_next_ask_runs_the_body(daemon) -> None:  # type: ignore[no-untyped-def]
    """The whole walk over one verified connection: read, act, allow, and spent after one.

    The read and the act share a connection on purpose: the daemon answers both
    through its own handler and leaves the connection open, so a person's two
    steps are two requests and not two dials. A daemon that hung up after the
    read would fail here rather than silently work through a reconnect nobody
    asked for (rule C4).
    """
    running = daemon(SUSPEND)
    suspended = _suspends(running)
    reference = suspended.approval_ref

    with closing(connect(_profile(running))) as connection:
        pending = connection.read_approval("local", reference)
        assert isinstance(pending, Answered), pending
        assert pending.value.state is ApprovalState.PENDING
        assert pending.value.approval_ref == reference
        assert pending.value.decision_ref == suspended.decision_ref
        assert pending.value.capability == "example.waits"
        assert pending.value.resolved_at is None
        # The wait is bounded, and the bound is the rule's rather than this case's.
        assert pending.value.deadline > pending.value.requested_at

        approved = connection.resolve_approval(
            ApprovalResolution("local", reference, Resolution.APPROVE, "the transport approves")
        )
        assert isinstance(approved, Answered), approved
        assert approved.value.state is ApprovalState.APPROVED
        assert approved.value.resolution_reason == "the transport approves"
        assert approved.value.resolved_at is not None
        # The document names the person, read through the same member of the
        # same record both clients of this contract carry.
        assert approved.value.person, "an act names the person the connection established"
        assert "person" not in approved.value.extra, "a defined member is not an unknown one"
        # And a read afterwards says the same thing: the answer was the record.
        again = connection.read_approval("local", reference)
        assert isinstance(again, Answered), again
        assert again.value.to_document() == approved.value.to_document()

    holder, counting, written = running.boundary()
    with closing(holder):
        with holder.request("example.waits", ARGUMENTS) as grant:
            allowed = grant.decision_ref
            grant.record_outcome(OUTCOME)
        # The allow minted a grant this boundary holds, so the second act on
        # the same question runs the body without asking again (article 10).
        with holder.request("example.waits", ARGUMENTS) as repeated:
            assert repeated.decision_ref == allowed
        assert counting.by_capability == {"example.waits": 1}
    assert [record.outcome_digest for record in written] == [OUTCOME, None]

    with closing(connect(_profile(running))) as reader:
        decided = reader.read_decision("local", allowed)
    assert isinstance(decided, Answered), decided
    assert decided.value.outcome is Outcome.ALLOW
    assert decided.value.reason is Reason.APPROVAL_GRANTED

    # One resolution authorises one execution: the third ask of the same
    # question finds the approval spent and waits anew, on a new reference.
    anew = _suspends(running)
    assert anew.approval_ref != reference
    assert anew.decision_ref != suspended.decision_ref


def test_an_act_on_a_wait_that_is_already_over_is_answered_by_its_own_code(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 3: a resolution is a new record, so nothing edits the one a person made."""
    running = daemon(SUSPEND)
    reference = _suspends(running).approval_ref

    with closing(connect(_profile(running))) as connection:
        first = connection.resolve_approval(
            ApprovalResolution("local", reference, Resolution.APPROVE)
        )
        assert isinstance(first, Answered), first

        second = connection.resolve_approval(
            ApprovalResolution("local", reference, Resolution.REJECT, "changed my mind")
        )
        still = connection.read_approval("local", reference)

    assert type(second) is _expected(ProblemCode.APPROVAL_RESOLVED), second
    assert second.problem.code is ProblemCode.APPROVAL_RESOLVED
    assert second.problem.retryable is problem_retryable(ProblemCode.APPROVAL_RESOLVED)
    # The record a person made is untouched: the refused act changed nothing.
    assert isinstance(still, Answered), still
    assert still.value.state is ApprovalState.APPROVED
    assert still.value.resolution_reason is None


def test_an_approval_this_daemon_keeps_none_of_is_answered_by_name_on_both(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 2: the daemon looked and holds none, which is an answer of its own."""
    running = daemon(SUSPEND)

    with closing(connect(_profile(running))) as connection:
        read = connection.read_approval("local", "nothing-here")
        acted = connection.resolve_approval(
            ApprovalResolution("local", "nothing-here", Resolution.APPROVE)
        )

    for result in (read, acted):
        assert type(result) is _expected(ProblemCode.APPROVAL_UNKNOWN), result
        assert result.problem.code is ProblemCode.APPROVAL_UNKNOWN


def test_a_read_without_a_scope_is_refused_rather_than_defaulted(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 5: the default scope is for an ask, never for naming an existing record.

    The transport sends the scope it was given, so the empty one this case
    needs is built at the address. What is being held is the daemon's refusal
    reaching a transport caller as an answer with a code, not as a traceback.
    """
    running = daemon(SUSPEND)
    reference = _suspends(running).approval_ref

    with closing(connect(_profile(running))) as connection:
        result = _read_without_scope(connection, reference)

    assert type(result) is _expected(ProblemCode.SCOPE_REQUIRED), result
    assert result.problem.code is ProblemCode.SCOPE_REQUIRED


def _read_without_scope(connection: VerifiedConnection, reference: str):  # type: ignore[no-untyped-def]
    """The read this transport would never build, put on the wire through its own guard."""
    return connection._document_read(
        f"/approvals/{reference}?contract_generation={connection.negotiated_generation}",
        lambda document: document,
    )
