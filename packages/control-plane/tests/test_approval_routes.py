# SPDX-License-Identifier: Apache-2.0
"""The two approval operations, as the routes answer them.

Article 12's simple form becomes reachable by a person through exactly two
operations, and what these cases hold is the part that is the routes' own: the
person comes from the connection and never from the body, a read renders the
state as of now, a terminal approval is refused rather than overwritten, and
the claim protocol the ask path uses is invisible to a reader.

The clock is a value the cases move by hand, for the reason the store's own
cases give: every property here is about an instant relative to a deadline, and
one asserted against the wall clock is a property asserted about whatever the
machine was doing that second.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_control_plane.adapters.api.approval_routes import (
    ApprovalNotKept,
    ApprovalProviderUnavailable,
    ApprovalResolvedAlready,
    ApprovalRoutes,
    ApprovalScopeRequired,
    ResolutionMalformed,
)
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.approvals import ApprovalStore, SimpleApprovalProvider
from sayfirst_control_plane.application.decisions import DecisionService, GrantSettings
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.approval import Approval, ApprovalState, Question
from sayfirst_control_plane.plugins.approval import ApprovalAnswerRefused
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalProviderError,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)
from sayfirst_control_plane.ports.policy_store import (
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)
from sayfirst_testing.schemas import validate_document

START = datetime(2026, 9, 15, 12, tzinfo=UTC)
WAIT = 300
DEADLINE = START + timedelta(seconds=WAIT)
DIGEST = "sha256:" + "a" * 64
#: The person the connection established. Every case that resolves passes it in
#: as the route's caller does, because that is the whole ruling: the body never
#: carries one.
ALICE = "user:alice"
BUILD = "service:build"

_POLICY = (
    "format = 1\n"
    "[revision]\n"
    'reason = "a reviewed change"\n'
    "[[rule]]\n"
    'id = "waits"\n'
    'capability = "mail.send"\n'
    'principals = ["user:alice"]\n'
    'outcome = "suspend"\n'
    'reason = "one person reviews this effect"\n'
    f"review_deadline_seconds = {WAIT}\n"
).encode()


class Clock:
    """The one instant the service, the store and the provider all read."""

    def __init__(self, now: datetime = START) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now = self.now + timedelta(seconds=seconds)


class _ProtectedStore(FilePolicyStore):
    """The authority file, taken as protected: these cases test no host check."""

    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


def _service(
    tmp_path,  # type: ignore[no-untyped-def]
    *,
    clock: Clock,
    approvals_composed: bool = True,
    provider=None,  # type: ignore[no-untyped-def]
    system_mode: bool = False,
):
    """A decision service on one clock, with its approvals composed or not."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_POLICY)
    authority = _ProtectedStore(path, max_lifetime_seconds=3600, clock=clock)
    policy = PolicyService(authority, (MemoryPolicyProjection(),), clock=clock)
    policy.start(ProtectionExpectation.per_user(1000))
    approvals = ApprovalStore(clock=clock)
    composed = provider if provider is not None else SimpleApprovalProvider(approvals)
    events = MemoryEvents()
    service = DecisionService(
        policy,
        authority,
        MemoryDecisionStore(),
        GrantConnections(clock=clock),
        settings=GrantSettings(),
        clock=clock,
        system_mode=system_mode,
        events=events,
        approvals=approvals if approvals_composed else None,
        approval_provider=composed if approvals_composed else None,
    )
    return service, approvals, events


def _question(**changes: str) -> Question:
    members: dict[str, str] = {
        "scope": "local",
        "principal_reference": BUILD,
        "capability": "mail.send",
        "arguments_digest": DIGEST,
    }
    members.update(changes)
    return Question(**members)


def _pending(approval_ref: str = "approval-1", **changes: str) -> Approval:
    return Approval(
        approval_ref=approval_ref,
        decision_ref=f"decision-for-{approval_ref}",
        question=_question(**changes),
        requested_at=START,
        deadline=DEADLINE,
    )


def _act(**changes: object) -> dict[str, object]:
    """A body the published schema accepts, which the handler has already held."""
    body: dict[str, object] = {
        "contract_generation": CONTRACT_GENERATION,
        "scope": "local",
        "approval_ref": "approval-1",
        "resolution": "approve",
    }
    body.update(changes)
    return body


# -- the read ------------------------------------------------------------------


def test_a_read_answers_the_published_document_for_the_approval_it_names(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the answer is the contract's own document, and it validates."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())
    routes = ApprovalRoutes(service)

    document = routes.read("local", "approval-1")

    validate_document(document, "approval-result")
    assert document["state"] == "pending"
    assert document["approval_ref"] == "approval-1"
    assert document["decision_ref"] == "decision-for-approval-1"
    assert document["capability"] == "mail.send"
    assert document["deadline"] == "2026-09-15T12:05:00Z"
    assert document["resolved_at"] is None
    assert document["contract_generation"] == CONTRACT_GENERATION


def test_a_read_renders_the_state_as_of_now_and_not_as_of_the_last_sweep(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: a wait that ran out reads `expired` before any sweep has run."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())
    routes = ApprovalRoutes(service)
    clock.advance(WAIT)

    document = routes.read("local", "approval-1")

    assert document["state"] == "expired"
    # Nothing swept: the record itself is still the pending one it was.
    assert approvals.read("local", "approval-1").state is ApprovalState.PENDING


def test_a_read_of_a_reference_nothing_keeps_is_refused_by_name(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: « looked and found nothing » is its own answer, not an empty one."""
    clock = Clock()
    service, _, _ = _service(tmp_path, clock=clock)

    with pytest.raises(ApprovalNotKept) as refused:
        ApprovalRoutes(service).read("local", "nothing-here")

    assert refused.value.code == "approval_unknown"


def test_a_read_in_another_scope_does_not_find_the_approval(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 5: the record is keyed by its scope, so another scope holds none."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    with pytest.raises(ApprovalNotKept):
        ApprovalRoutes(service).read("elsewhere", "approval-1")


def test_a_read_that_names_no_scope_is_refused_rather_than_defaulted(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 5: the default scope never applies to a read."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    with pytest.raises(ApprovalScopeRequired) as refused:
        ApprovalRoutes(service).read("", "approval-1")

    assert refused.value.code == "scope_required"


def test_a_claimed_approval_reads_as_approved(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the published state vocabulary has no « claimed ».

    An ask about to spend an approval claims it first, which says only that the
    execution is in flight. The person's act is unchanged and the record is
    still approved, so that is what a reader is told; a state of this server's
    own invention would be vocabulary the contract never carried.
    """
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())
    approvals.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )
    approvals.claim("local", "approval-1")

    document = ApprovalRoutes(service).read("local", "approval-1")

    assert document["state"] == "approved"


# -- the resolution ------------------------------------------------------------


def test_the_person_of_a_resolution_is_the_one_the_caller_verified(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 3, 6 and 12: the act is attributed to the connection's principal.

    The body cannot say who acted — the published request defines no such
    member — so the route takes the person from its caller, which is the
    handler that read it off the connection. What the store then holds is that
    person and nobody else.
    """
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    document = ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    validate_document(document, "approval-result")
    assert document["state"] == "approved"
    assert document["resolved_at"] == "2026-09-15T12:00:00Z"
    assert approvals.read("local", "approval-1").person == ALICE


def test_a_resolution_in_system_mode_still_names_the_connections_principal(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 6: a daemon serving many accounts resolves as the caller, never as itself."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock, system_mode=True)
    approvals.open(_pending())

    ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    assert approvals.read("local", "approval-1").person == ALICE


def test_a_rejection_is_recorded_with_the_reason_the_person_gave(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 12: the two acts are approve and reject, and a reason is recorded as given."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    document = ApprovalRoutes(service).resolve(
        "approval-1",
        _act(resolution="reject", reason="the change is not reviewed"),
        person=ALICE,
    )

    assert document["state"] == "rejected"
    assert document["resolution_reason"] == "the change is not reviewed"
    assert approvals.read("local", "approval-1").resolution_reason == "the change is not reviewed"


def test_a_resolution_records_the_act_on_the_daemons_log(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 12: the act is written to whatever events sink was composed, person and all.

    A sink is composed here, so this holds what such a sink is given. It does
    not hold that a deployed daemon has one — `bootstrap.compose` composes
    none, so in a composed daemon this entry is discarded — and neither the
    recorder's docstring nor either shipped document says otherwise any more.
    """
    clock = Clock()
    service, approvals, events = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    ApprovalRoutes(service).resolve("approval-1", _act(reason="reviewed"), person=ALICE)

    (recorded,) = events.of_kind("approval.resolved")
    assert recorded.at == clock.now
    assert recorded.details["person"] == ALICE
    assert recorded.details["resolution"] == "approve"
    assert recorded.details["reason"] == "reviewed"
    assert recorded.details["decision_ref"] == "decision-for-approval-1"
    # And the person the store keeps, which is where the name survives the call.
    assert approvals.read("local", "approval-1").person == ALICE


def test_a_resolution_neither_claims_nor_spends_the_execution_it_authorises(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: the ask path takes the execution, under the lock, when it records.

    A route that claimed or consumed would hand out an execution no decision
    was written for, and the next ask would find a person's act already spent.
    """
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    kept = approvals.read("local", "approval-1")
    assert kept.claimed is False
    assert kept.consumed is False


def test_a_resolution_opens_nothing_when_the_reference_is_not_kept(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: an act on a wait nobody opened is refused, never opened into."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)

    with pytest.raises(ApprovalNotKept) as refused:
        ApprovalRoutes(service).resolve(
            "nothing-here", _act(approval_ref="nothing-here"), person=ALICE
        )

    assert refused.value.code == "approval_unknown"
    assert approvals.pending() == ()


def test_a_body_naming_another_approval_than_its_route_is_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: two statements that disagree are refused, and neither is preferred."""
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())

    with pytest.raises(ResolutionMalformed) as refused:
        ApprovalRoutes(service).resolve("approval-1", _act(approval_ref="approval-2"), person=ALICE)

    assert refused.value.code == "request_malformed"
    assert approvals.read("local", "approval-1").state is ApprovalState.PENDING


@pytest.mark.parametrize("resolution", ["approve", "reject"])
def test_a_second_act_on_a_resolved_approval_is_refused(tmp_path, resolution: str) -> None:  # type: ignore[no-untyped-def]
    """Article 3: a resolution is a new record, so nothing edits the one that stands."""
    clock = Clock()
    service, approvals, events = _service(tmp_path, clock=clock)
    approvals.open(_pending())
    routes = ApprovalRoutes(service)
    routes.resolve("approval-1", _act(resolution=resolution), person=ALICE)

    with pytest.raises(ApprovalResolvedAlready) as refused:
        routes.resolve("approval-1", _act(), person="user:someone-else")

    assert refused.value.code == "approval_resolved"
    kept = approvals.read("local", "approval-1")
    assert kept.person == ALICE
    assert len(events.of_kind("approval.resolved")) == 1


def test_an_act_on_a_wait_that_ran_out_is_refused_as_resolved(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: the wait ended at its deadline, whether or not a sweep noticed.

    The refusal says the approval is expired and the record then says so too:
    a person reading afterwards learns what happened rather than being told
    `pending` about a wait nobody can answer any more.
    """
    clock = Clock()
    service, approvals, events = _service(tmp_path, clock=clock)
    approvals.open(_pending())
    routes = ApprovalRoutes(service)
    clock.advance(WAIT)

    with pytest.raises(ApprovalResolvedAlready) as refused:
        routes.resolve("approval-1", _act(), person=ALICE)

    assert refused.value.code == "approval_resolved"
    assert "expired" in str(refused.value)
    assert routes.read("local", "approval-1")["state"] == "expired"
    assert events.of_kind("approval.resolved") == ()


# -- what the provider answers -------------------------------------------------


class _AnswersForSomebodyElse:
    """A provider whose answer no act supports: the person is not the one who acted."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        return ResolvedApproval(
            approval_ref=suspended.approval_ref,
            decision_ref=suspended.request.decision_ref,
            scope=suspended.scope,
            person="user:somebody-else",
            resolution=action.resolution,
            reason=action.reason,
        )


def test_a_provider_answer_no_act_supports_is_refused_and_recorded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8's Why: the core never takes a provider at its word, on this route either.

    The refusal is the core's, recorded from the core's own facts, and it is
    not a resolution: nothing is written to the record. What the caller is told
    is that the provider could not answer — a could-not-ask, because no act was
    applied and nothing decided — and not that anybody refused anything
    (articles 1 and 2).
    """
    clock = Clock()
    service, approvals, events = _service(tmp_path, clock=clock, provider=_AnswersForSomebodyElse())
    approvals.open(_pending())

    with pytest.raises(ApprovalProviderUnavailable) as refused:
        ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    assert refused.value.code == "approval_provider_unavailable"
    # The core's own refusal is the cause, kept rather than swallowed.
    assert isinstance(refused.value.__cause__, ApprovalAnswerRefused)
    (refusal,) = events.of_kind("approval.refused")
    assert refusal.details["person"] == ALICE
    assert "somebody-else" in str(refusal.details["complaint"])
    assert approvals.read("local", "approval-1").state is ApprovalState.PENDING


class _WillNotAnswer:
    """A provider whose backend is unreachable, in the two ways one can be."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        raise self._error

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        raise self._error


@pytest.mark.parametrize(
    ("error", "complaint"),
    [
        (RuntimeError("the backend is unreachable"), "it raised RuntimeError"),
        (
            ApprovalProviderError("not now"),
            "the provider refused the act with ApprovalProviderError",
        ),
    ],
    ids=["raises", "refuses through the port"],
)
def test_a_provider_that_cannot_answer_leaves_the_wait_as_it_was(  # type: ignore[no-untyped-def]
    tmp_path, error, complaint
) -> None:
    """Articles 1, 2 and 8: one answer for every way a provider fails to answer.

    An exception a provider raises is not a contract at all, and a refusal of
    the port it does not spell more precisely says only that it would not
    answer, so both arrive as the code the ask path already answers for a
    provider that could not take a suspension. The wait is untouched, which is
    what makes the answer retryable rather than a verdict.

    Both are also recorded. The port-spelled refusal is the one failure a
    provider is contractually allowed to signal, and it used to leave no entry
    at all: a log that holds nothing for it cannot tell an act a provider
    refused from an act nobody ever put (articles 2 and 8). The complaint names
    the class and nothing the provider said.
    """
    clock = Clock()
    service, approvals, events = _service(tmp_path, clock=clock, provider=_WillNotAnswer(error))
    approvals.open(_pending())

    with pytest.raises(ApprovalProviderUnavailable) as refused:
        ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    assert refused.value.code == "approval_provider_unavailable"
    assert approvals.read("local", "approval-1").state is ApprovalState.PENDING
    (recorded,) = events.of_kind("approval.refused")
    assert recorded.details["person"] == ALICE
    assert recorded.details["complaint"] == complaint
    assert events.of_kind("approval.resolved") == ()


class _RefusesTheSuspension:
    """A provider that never issued this suspension, and says so in the port's words."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        raise ApprovalRequestMismatch(
            f"approval {suspended.approval_ref!r} is not a suspension this provider opened"
        )


def test_an_act_naming_another_suspension_is_a_request_rejected_and_not_an_outage(  # type: ignore[no-untyped-def]
    tmp_path,
) -> None:
    """Article 1: a request received and rejected is not a component that gave no answer.

    `ApprovalRequestMismatch` is permanent. Answered as
    `approval_provider_unavailable` it was answered as retryable, so the person
    was told to try again at something that will never change, and the code
    named a component that had in fact answered (article 2). It keeps the
    route's own `request_malformed`, which is received-and-rejected, and the
    refusal is on the log either way.
    """
    clock = Clock()
    service, approvals, events = _service(tmp_path, clock=clock, provider=_RefusesTheSuspension())
    approvals.open(_pending())

    with pytest.raises(ResolutionMalformed) as refused:
        ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    assert refused.value.code == "request_malformed"
    assert isinstance(refused.value.__cause__, ApprovalRequestMismatch)
    assert approvals.read("local", "approval-1").state is ApprovalState.PENDING
    (recorded,) = events.of_kind("approval.refused")
    assert recorded.details["complaint"] == (
        "the provider refused the act with ApprovalRequestMismatch"
    )


def test_a_wait_already_over_is_still_answered_as_resolved_and_not_as_an_outage(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The one refusal of the port that is an answer keeps its own code.

    `ApprovalAlreadyResolved` is an `ApprovalProviderError`, so catching the
    outage case first would swallow it and tell a person their second act could
    not be put to the provider — when what happened is that the first one
    stands (article 2). The store refuses the act here, which is the race this
    route cannot pre-check away.
    """
    clock = Clock()
    service, approvals, _ = _service(tmp_path, clock=clock)
    approvals.open(_pending())
    routes = ApprovalRoutes(service)
    approvals.resolve(
        "local",
        "approval-1",
        person=ALICE,
        resolution=ApprovalResolution.APPROVE,
        reason=None,
        now=clock.now,
    )

    with pytest.raises(ApprovalResolvedAlready) as refused:
        routes.resolve("approval-1", _act(), person="user:someone-else")

    assert refused.value.code == "approval_resolved"


# -- a deployment that composed no approvals ------------------------------------


class _JudgesAfterTheSweep:
    """A provider whose judgement takes so long that the sweep forgets the wait meanwhile.

    The route reads the record before the act and the core writes it after the
    judgement; between the two, this provider advances the clock past the
    deadline and one wait-length more and runs both halves of the sweep, so
    the record it then answers for is no longer kept.
    """

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        #: The service's own store, handed over once the service is composed.
        self.store: ApprovalStore | None = None

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        assert self.store is not None, "the case hands the service's store over"
        self.clock.advance(2 * WAIT + 1)
        self.store.expire_past(self.clock())
        self.store.forget_lapsed(self.clock())
        return ResolvedApproval(
            approval_ref=suspended.approval_ref,
            decision_ref=suspended.request.decision_ref,
            scope=suspended.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )


def test_an_act_whose_record_the_sweep_forgot_meanwhile_is_answered_as_unknown(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: a reference no longer kept is answered as a read of it would be.

    The core's writer is the first to learn the record is gone, because the
    route read it while it was still pending. Its refusal is the store's own
    « unknown », and the route answers it with the code a read publishes for
    that — never as a failure the daemon cannot classify, and never as a
    provider that gave no answer, because this one did. Nothing is recorded as
    resolved: the write refused before the record was reached.
    """
    clock = Clock()
    judge = _JudgesAfterTheSweep(clock)
    service, approvals, events = _service(tmp_path, clock=clock, provider=judge)
    judge.store = approvals
    approvals.open(_pending())

    with pytest.raises(ApprovalNotKept) as refused:
        ApprovalRoutes(service).resolve("approval-1", _act(), person=ALICE)

    assert refused.value.code == "approval_unknown"
    assert approvals.pending() == ()
    assert events.of_kind("approval.resolved") == ()


def test_a_composition_without_approvals_serves_neither_operation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: no store means no wait either operation could be about."""
    clock = Clock()
    service, _, _ = _service(tmp_path, clock=clock, approvals_composed=False)

    assert ApprovalRoutes(service).served is False


def test_a_composition_with_approvals_serves_them(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The other half: composed, the routes answer out of the store the asks use."""
    clock = Clock()
    service, _, _ = _service(tmp_path, clock=clock)

    assert ApprovalRoutes(service).served is True
