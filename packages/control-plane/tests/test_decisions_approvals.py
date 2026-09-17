# SPDX-License-Identifier: Apache-2.0
"""What a re-ask of a suspended question answers, once an approval is held for it.

Article 12's simple form, read from the outside: the suspend path of the
decision service, the wait the rule gave it, and the four answers a re-ask can
get. One approval per question, one execution per resolution, and a consumption
that never happens without the record that explains it (article 3).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sayfirst.testing.approval import ApprovalProviderContract
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_contract.problems import ProblemCode
from sayfirst_control_plane.adapters.api.approval_routes import ApprovalRoutes
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.approvals import (
    ApprovalStore,
    ApprovalUnknown,
    SimpleApprovalProvider,
)
from sayfirst_control_plane.application.decisions import (
    DecisionAnswer,
    DecisionProblem,
    DecisionService,
    GrantSettings,
)
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.approval import ApprovalState, Question
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal
from sayfirst_control_plane.plugins.defaults import SingleApprover
from sayfirst_control_plane.plugins.interfaces import ApprovalRequest, ApprovalResolution
from sayfirst_control_plane.ports.decision_store import DecisionAppendIndeterminate
from sayfirst_control_plane.ports.policy_store import (
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

START = datetime(2026, 9, 15, 12, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64
OTHER_DIGEST = "sha256:" + "2" * 64
WAIT = 60
PERSON = "user:reviewer"

_POLICY = (
    "format = 1\n"
    "[revision]\n"
    'reason = "a reviewed change"\n'
    "[[rule]]\n"
    'id = "waits"\n'
    'capability = "example.waits"\n'
    'principals = ["user:build"]\n'
    'outcome = "suspend"\n'
    'reason = "one person reviews this effect"\n'
    f"review_deadline_seconds = {WAIT}\n"
).encode()


class Clock:
    """The one instant a test moves, read by the service, the store and the provider."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now = self.now + timedelta(seconds=seconds)


class _ProtectedStore(FilePolicyStore):
    """The authority file, taken as protected: this module tests no host check."""

    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


def _question(*, digest: str | None = DIGEST) -> DecisionQuestion:
    return DecisionQuestion(
        DecisionAsk("example.waits", arguments_digest=digest),
        Principal("process", 1001, "build", (2001,), ("ci",)),
    )


def _service(  # type: ignore[no-untyped-def]
    tmp_path,
    *,
    approvals_composed: bool = True,
    events: MemoryEvents | None = None,
    provider=None,
):
    """A decision service over one suspend rule, its approvals on one clock.

    `provider` composes something other than the shipped one behind the port,
    which is the configuration `docs/deployment.md` offers for designation and
    a second signature. The store stays the core's either way: the question a
    re-ask is matched by is established here and never taken from a provider.
    """
    path = tmp_path / "policy.toml"
    path.write_bytes(_POLICY)
    clock = Clock()
    authority = _ProtectedStore(path, max_lifetime_seconds=3600, clock=clock)
    policy = PolicyService(authority, (MemoryPolicyProjection(),), clock=clock)
    policy.start(ProtectionExpectation.per_user(1000))
    decisions = MemoryDecisionStore()
    approvals = ApprovalStore(clock=clock)
    service = DecisionService(
        policy,
        authority,
        decisions,
        GrantConnections(clock=clock),
        settings=GrantSettings(),
        clock=clock,
        events=events,
        id_factory=iter(f"id-{index}" for index in range(100)).__next__,
        approvals=approvals if approvals_composed else None,
        approval_provider=(
            (provider if provider is not None else SimpleApprovalProvider(approvals))
            if approvals_composed
            else None
        ),
    )
    return service, approvals, decisions, clock


def _answered(service: DecisionService, **asked: object) -> DecisionAnswer:
    answer = service.ask(_question(**asked))  # type: ignore[arg-type]
    assert isinstance(answer, DecisionAnswer)
    return answer


def _suspended(service: DecisionService, approvals: ApprovalStore, **asked: object) -> str:
    """One first ask, its reference, checked to be the suspension it claims."""
    answer = _answered(service, **asked)
    assert answer.decision.outcome is Outcome.SUSPEND
    reference = answer.decision.approval_ref
    assert reference is not None
    assert approvals.read("local", reference).state is ApprovalState.PENDING
    return reference


def _records_of(decisions: MemoryDecisionStore) -> tuple[Decision, ...]:
    """Every record this authority holds, read through its own published read.

    The identifiers are the ones `_service` hands the service, so a walk over
    them sees whatever was committed without reaching past `get`: a count taken
    over a private mapping is a count of something else (article 2).
    """
    found = [decisions.get("local", f"id-{index}") for index in range(100)]
    return tuple(record for record in found if record is not None)


def _resolve(
    approvals: ApprovalStore, reference: str, clock: Clock, resolution: ApprovalResolution
) -> None:
    approvals.resolve(
        "local",
        reference,
        person=PERSON,
        resolution=resolution,
        reason=None,
        now=clock.now,
    )


def test_a_first_ask_opens_the_wait_its_rule_names_and_answers_the_reference(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 12: the suspension a caller is answered is one the store holds."""
    service, approvals, decisions, _ = _service(tmp_path)
    answer = _answered(service)
    decision = answer.decision
    assert decision.outcome is Outcome.SUSPEND
    assert decision.reason is Reason.POLICY_REQUIRES_REVIEW
    reference = decision.approval_ref
    assert reference is not None
    kept = approvals.read("local", reference)
    assert kept.state is ApprovalState.PENDING
    assert kept.decision_ref == decision.decision_ref
    assert kept.requested_at == START
    assert kept.deadline == START + timedelta(seconds=WAIT)
    recorded = decisions.get("local", decision.decision_ref)
    assert recorded is not None
    # The record and the answer name one approval: a reference a caller reads
    # and a reference the chain carries that differed would be two waits.
    assert recorded.approval_ref == reference


def test_the_same_question_asked_again_answers_the_same_suspension(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 12: a re-ask of a pending question opens no second wait."""
    service, approvals, _, _ = _service(tmp_path)
    first = _suspended(service, approvals)
    again = _answered(service)
    assert again.decision.outcome is Outcome.SUSPEND
    assert again.decision.reason is Reason.POLICY_REQUIRES_REVIEW
    assert again.decision.approval_ref == first
    assert len(approvals.pending()) == 1


def test_an_approved_question_allows_once_with_a_grant_and_is_then_consumed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 12: one resolution authorises one execution, and the next ask waits again."""
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    decision = answer.decision
    assert decision.outcome is Outcome.ALLOW
    assert decision.reason is Reason.APPROVAL_GRANTED
    assert decision.approval_ref == reference
    assert answer.grant is not None
    assert decision.extra["grant_id"] == answer.grant.grant_id
    recorded = decisions.get("local", decision.decision_ref)
    assert recorded is not None and recorded.approval_ref == reference
    assert approvals.read("local", reference).consumed is True
    second = _answered(service)
    assert second.decision.outcome is Outcome.SUSPEND
    assert second.decision.reason is Reason.POLICY_REQUIRES_REVIEW
    assert second.decision.approval_ref not in (None, reference)


def test_a_rejected_question_denies_until_its_deadline_and_then_waits_anew(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 12: a rejection stands for the wait it ended, and no longer.

    Two bounds run here and they are not the same bound, which is why the act
    is timed inside its wait rather than at the head of it. A rejection answers
    a re-ask while `now < deadline`; the record of it is readable for one
    wait-length after it was made, and the daemon's sweep forgets it past that
    (`ApprovalStore.forget_lapsed`). Rejecting at the start of the wait makes
    the two instants the same one, and the case could then no longer say which
    of them it had proven.
    """
    service, approvals, _, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    clock.advance(10)
    _resolve(approvals, reference, clock, ApprovalResolution.REJECT)
    denied = _answered(service)
    assert denied.decision.outcome is Outcome.DENY
    assert denied.decision.reason is Reason.APPROVAL_REJECTED
    assert denied.decision.approval_ref == reference
    assert denied.grant is None
    # Past the deadline the rejection ended, and inside the wait-length its
    # record is kept for.
    clock.advance(WAIT - 5)
    after = _answered(service)
    assert after.decision.outcome is Outcome.SUSPEND
    assert after.decision.reason is Reason.POLICY_REQUIRES_REVIEW
    assert after.decision.approval_ref not in (None, reference)
    # The record of the person's act is not what lapsed; only its answer to a
    # later ask (article 2).
    assert approvals.read("local", reference).state is ApprovalState.REJECTED


def test_a_wait_that_ran_out_with_no_sweep_is_not_answered_as_pending(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: a re-ask does not depend on a sweep having run."""
    service, approvals, _, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    clock.advance(WAIT)
    again = _answered(service)
    assert again.decision.outcome is Outcome.SUSPEND
    assert again.decision.approval_ref not in (None, reference)
    assert approvals.read("local", reference).state_at(clock.now) is ApprovalState.EXPIRED


def test_another_arguments_digest_is_another_question_and_another_approval(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: a near miss is not a match, so one act authorises one effect."""
    service, approvals, _, _ = _service(tmp_path)
    first = _suspended(service, approvals)
    other = _suspended(service, approvals, digest=OTHER_DIGEST)
    assert other != first
    assert len(approvals.pending()) == 2


def test_an_ask_with_no_digest_is_one_question_the_same_way(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: an absent digest is one question, not a question that matches any."""
    service, approvals, _, _ = _service(tmp_path)
    reference = _suspended(service, approvals, digest=None)
    again = _answered(service, digest=None)
    assert again.decision.approval_ref == reference
    pinned = _answered(service)
    assert pinned.decision.approval_ref not in (None, reference)


def test_a_service_composed_with_no_approvals_suspends_as_it_always_did(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: a composition that keeps no approval claims no reference."""
    service, approvals, _, _ = _service(tmp_path, approvals_composed=False)
    answer = _answered(service)
    assert answer.decision.outcome is Outcome.SUSPEND
    assert answer.decision.reason is Reason.POLICY_REQUIRES_REVIEW
    assert answer.decision.approval_ref is None
    assert approvals.pending() == ()


def test_an_indeterminate_append_consumes_the_approval_it_may_have_spent(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3, fail closed: an act that may have been recorded is not licensed twice.

    The append began and cannot say whether it finished, so one allow on this
    person's act may already be committed and readable. Giving the claim back
    was what shipped, and it landed two committed allows on one act: the caller
    read a could-not-ask, asked again, and was granted the same approval a
    second time.

    So the approval is spent here. The answer is unchanged — the existing
    could-not-ask for an append that may have committed — and the cost is
    charged the other way: a caller whose record did not in fact commit
    suspends anew and a second person answers, which is an effect asked for
    twice rather than licensed twice.
    """
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)

    class Uncertain:
        """The C2 case: the write may have committed, and this store cannot say."""

        VERSION = 1

        def append(self, decision):  # type: ignore[no-untyped-def]
            decisions.append(decision)
            raise DecisionAppendIndeterminate("sync failed after the write began")

        def get(self, scope, decision_ref):  # type: ignore[no-untyped-def]
            return decisions.get(scope, decision_ref)

        def location(self):  # type: ignore[no-untyped-def]
            return decisions.location()

    service.decisions = Uncertain()
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.DECISION_STORE_UNAVAILABLE
    kept = approvals.read("local", reference)
    assert kept.consumed is True
    # Spent, so the store offers it to nothing: the act is neither held in
    # flight by an ask that ended nor answerable to the next one.
    assert approvals.find_for_question(_the_question()) is None

    service.decisions = decisions
    again = service.ask(_question(), grant_connection=True)
    assert isinstance(again, DecisionAnswer)
    assert again.decision.outcome is Outcome.SUSPEND
    assert again.decision.reason is Reason.POLICY_REQUIRES_REVIEW
    assert again.decision.approval_ref not in (None, reference)
    # The property the give-back broke: one act, one committed allow, counted
    # over everything the decision authority holds.
    allows = [
        record
        for record in _records_of(decisions)
        if record.outcome is Outcome.ALLOW and record.approval_ref == reference
    ]
    assert len(allows) == 1


# -- two asks at once, and the collaborators that can refuse -------------------


class _Refuses:
    """A decision authority that refuses before its first byte: nothing committed.

    The one shape of append failure that gives a person's act back. Its
    neighbour — an append that began and cannot say whether it finished — is
    the fail-closed case and spends the act instead, which is why the two are
    driven by two doubles and not by one.
    """

    VERSION = 1

    def __init__(self, decisions: MemoryDecisionStore) -> None:
        self._decisions = decisions

    def append(self, decision):  # type: ignore[no-untyped-def]
        raise RuntimeError("the authority refused the write and wrote nothing")

    def get(self, scope, decision_ref):  # type: ignore[no-untyped-def]
        return self._decisions.get(scope, decision_ref)

    def location(self):  # type: ignore[no-untyped-def]
        return self._decisions.location()


def test_an_execution_another_ask_holds_is_answered_as_contention(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 1 and 2: nobody failed, nothing was decided, and nothing is buried.

    The ask that did not get the execution is told to ask again. It must not be
    answered `suspend` on a wait of its own: that wait would be newer than the
    person's act, and every later ask of the question would be answered the
    wait instead of the act — which is how one act gets silently discarded.
    """
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)
    # As another ask would, under the store's lock, an instant before this one —
    # and this one never gives it back, so the spin runs out.
    approvals.claim("local", reference)
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.DECISION_CONTENDED
    assert answer.problem.retryable is True
    kept = approvals.read("local", reference)
    assert kept.state is ApprovalState.APPROVED and kept.consumed is False
    # Nothing was opened over the act, and nothing was recorded.
    assert approvals.pending() == ()
    assert approvals.find_for_question(_the_question()) is None
    assert decisions.get("local", "id-2") is None


def test_two_asks_of_one_approved_question_record_exactly_one_allow(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The property the claim exists for, driven with real threads.

    Two decisions on one person's act is the failure this is about: both would
    be committed records, and the second would be answered to nobody. Exactly
    one ask is granted, the other is told to wait — with a reference of its
    own, because the approval it did not get is not its to name.
    """
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)
    barrier = Barrier(2)
    answers: list[DecisionAnswer] = []

    def ask() -> None:
        barrier.wait()
        answer = service.ask(_question())
        assert isinstance(answer, DecisionAnswer)
        answers.append(answer)

    with ThreadPoolExecutor(max_workers=2) as pool:
        for outcome in [pool.submit(ask) for _ in range(2)]:
            outcome.result()
    granted = [item for item in answers if item.decision.outcome is Outcome.ALLOW]
    waiting = [item for item in answers if item.decision.outcome is Outcome.SUSPEND]
    assert len(granted) == 1 and len(waiting) == 1
    assert granted[0].decision.reason is Reason.APPROVAL_GRANTED
    assert granted[0].decision.approval_ref == reference
    assert waiting[0].decision.approval_ref not in (None, reference)
    assert approvals.read("local", reference).consumed is True
    recorded = [
        decisions.get("local", item.decision.decision_ref).outcome  # type: ignore[union-attr]
        for item in answers
    ]
    assert recorded.count(Outcome.ALLOW) == 1


def test_an_append_that_never_committed_gives_the_execution_back(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: nothing a person granted is lost because a record could not be written.

    Refused before the first byte, so nothing committed and nothing could
    have: this is the half of the rule where the give-back is right. The other
    half — an append that cannot say — is above, and it consumes.
    """
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)
    service.decisions = _Refuses(decisions)
    assert isinstance(service.ask(_question()), DecisionProblem)
    kept = approvals.read("local", reference)
    assert kept.consumed is False and kept.claimed is False
    service.decisions = decisions
    answer = _answered(service)
    assert answer.decision.outcome is Outcome.ALLOW
    assert answer.decision.reason is Reason.APPROVAL_GRANTED
    assert answer.decision.approval_ref == reference
    assert approvals.read("local", reference).consumed is True


def test_a_spend_that_refuses_after_the_record_releases_the_reservation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """C2 and article 10: a raise after a committed append holds no grant capacity.

    The refusal is a contradiction — this ask claimed the execution under the
    store's lock — so it is not swallowed. What it must not do is leave the
    principal's reservation counted for the life of the process, which is
    invisible and never recovers.
    """
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)

    class Refusing:
        """The store, with the one call that can raise after a committed append."""

        def __init__(self, store: ApprovalStore) -> None:
            self._store = store

        def __getattr__(self, name: str) -> object:
            return getattr(self._store, name)

        def consume(self, scope: str, approval_ref: str) -> object:
            raise RuntimeError("the store refused the spend")

    service.approvals = Refusing(approvals)  # type: ignore[assignment]
    before = service.grants._reserved_total
    with pytest.raises(RuntimeError, match="refused the spend"):
        service.ask(_question(), grant_connection=True)
    # The count the registry admits connections against: a reservation the
    # raise left behind would sit here for the life of the process.
    assert service.grants._reserved_total == before


def test_a_provider_that_cannot_answer_is_a_published_could_not_ask(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 8: a plugin raising is not a server failure nobody can classify."""
    service, approvals, _, _ = _service(tmp_path)

    class Raising:
        def suspend(self, request: ApprovalRequest) -> object:
            raise RuntimeError("this provider is not answering today")

        def resume(self, suspended: object, action: object) -> object:
            raise AssertionError("this case drives suspend only")

    service.approval_provider = Raising()  # type: ignore[assignment]
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE
    assert answer.problem.retryable is True
    assert "approval provider" in answer.problem.message


@pytest.mark.parametrize("approvals_composed", [True, False])
def test_a_verdict_that_suspends_without_a_rule_is_a_contradiction_in_every_composition(  # type: ignore[no-untyped-def]
    tmp_path, monkeypatch, approvals_composed: bool
) -> None:
    """The contradiction is held whatever this service is composed with.

    `policy_absent` and `capability_unknown` name no rule and are denials, and
    every suspension comes from the rule that suspended it — so a suspend
    verdict with no rule is not a case to answer. A guard that only ran when
    approvals were composed would not run in the composition every other case
    of this daemon uses, which is the composition it would have to catch it in.
    """
    from sayfirst_control_plane.application import decisions as module
    from sayfirst_control_plane.domain.policy import Verdict

    service, _, _, _ = _service(tmp_path, approvals_composed=approvals_composed)
    monkeypatch.setattr(
        module,
        "evaluate",
        lambda policy, question: Verdict(
            Outcome.SUSPEND, Reason.POLICY_REQUIRES_REVIEW, None, None
        ),
    )
    with pytest.raises(AssertionError, match="names the rule"):
        service.ask(_question())


def _the_question() -> Question:
    """The question the module's asks form, as the store indexes it."""
    return Question(
        scope="local",
        principal_reference="user:build",
        capability="example.waits",
        arguments_digest=DIGEST,
    )


def test_a_wait_the_provider_refused_is_not_left_for_the_retry_to_find(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 12: a provider failure does not come back as a clean suspension.

    The answer is retryable, so a caller retries — and the wait this ask opened
    before asking the provider would be found pending by that retry, answered
    `suspend`, and the provider would never see the request at all. For the
    core's own provider that is harmless; for a provider written elsewhere, no
    signature is ever counted and a later resume puts an act to a provider that
    never received the suspension. So the wait goes when the provider refuses,
    and the retry asks again.
    """
    service, approvals, _, _ = _service(tmp_path)
    calls: list[str] = []

    class Raising:
        def suspend(self, request: ApprovalRequest) -> object:
            calls.append(request.approval_ref)
            raise RuntimeError("this provider is not answering today")

        def resume(self, suspended: object, action: object) -> object:
            raise AssertionError("this case drives suspend only")

    service.approval_provider = Raising()  # type: ignore[assignment]
    first = service.ask(_question())
    assert isinstance(first, DecisionProblem)
    assert first.problem.code is ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE
    assert approvals.pending() == ()
    assert approvals.find_for_question(_the_question()) is None
    # The retry the answer invites reaches the provider a second time, with a
    # wait of its own rather than the one that was abandoned.
    second = service.ask(_question())
    assert isinstance(second, DecisionProblem)
    assert second.problem.code is ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE
    assert len(calls) == 2
    assert calls[0] != calls[1]


def test_an_execution_given_back_is_the_next_ask_s_and_is_not_shadowed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The interaction of the two fixes: a contested claim, then a failed append.

    The ask that lost the claim opened no wait, so when the winner's append
    fails and the execution is given back, the next ask of that question finds
    the person's act and not a suspension nobody answered.
    """
    service, approvals, decisions, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)
    approvals.claim("local", reference)
    contended = service.ask(_question())
    assert isinstance(contended, DecisionProblem)
    assert contended.problem.code is ProblemCode.DECISION_CONTENDED
    # The winner's append fails, so it gives the execution back.
    approvals.release_claim("local", reference)
    answer = _answered(service)
    assert answer.decision.outcome is Outcome.ALLOW
    assert answer.decision.reason is Reason.APPROVAL_GRANTED
    assert answer.decision.approval_ref == reference
    assert approvals.read("local", reference).consumed is True


def test_a_claim_no_record_followed_is_given_back_however_the_ask_ended(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: one exit for the claim, including a raise this service does not expect.

    The window this closes is between the claim and the append — building the
    decision, reserving, minting the grant. Nothing there is expected to raise,
    which is exactly why nothing would have released the claim if it did, and
    the approval would answer no question until its wait lapsed.
    """
    service, approvals, _, clock = _service(tmp_path)
    reference = _suspended(service, approvals)
    _resolve(approvals, reference, clock, ApprovalResolution.APPROVE)

    def refuse(principal_uid: int) -> object:
        raise RuntimeError("the registry refused the reservation")

    service.grants.reserve = refuse  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="refused the reservation"):
        service.ask(_question(), grant_connection=True)
    kept = approvals.read("local", reference)
    assert kept.claimed is False and kept.consumed is False
    assert approvals.find_for_question(_the_question()) == kept


# -- the tick that ends the grants ends the waits too --------------------------


def test_the_tick_expires_a_wait_that_ran_out_and_records_it(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: the record catches up with the clock, and says which wait ran out.

    A read never depended on this — `state_at` renders a lapse as of the
    instant it is taken — so what the sweep adds is the record itself ending,
    at the deadline it ended at, and an entry naming the wait and the decision
    it suspended.
    """
    events = MemoryEvents()
    service, approvals, _, clock = _service(tmp_path, events=events)
    reference = _suspended(service, approvals)
    decision_ref = approvals.read("local", reference).decision_ref
    clock.advance(WAIT)

    service.sweep()

    ended = approvals.read("local", reference)
    assert ended.state is ApprovalState.EXPIRED
    assert ended.resolved_at == ended.deadline
    (recorded,) = events.of_kind("approval.expired")
    assert dict(recorded.details) == {
        "approval_ref": reference,
        "decision_ref": decision_ref,
        "scope": "local",
        "deadline": "2026-09-15T12:01:00Z",
    }


def test_the_tick_is_idempotent_over_a_wait_it_already_ended(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A sweep runs when it runs, so running it twice must not record twice."""
    events = MemoryEvents()
    service, approvals, _, clock = _service(tmp_path, events=events)
    _suspended(service, approvals)
    clock.advance(WAIT)

    service.sweep()
    service.sweep()

    assert len(events.of_kind("approval.expired")) == 1


def test_the_tick_forgets_a_record_nothing_can_still_need_and_names_it(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The store's growth is bounded by this tick, and the bound is a rule about readers.

    A terminal approval answers a read for one more wait-length after it
    resolved, because the caller that asked is the caller that reads it and it
    was already willing to wait that long. Past that the record is of no use to
    anybody this store serves, and the sweep drops it — which is a fact about
    this store's memory, so the entry carries the references and no act.
    """
    events = MemoryEvents()
    service, approvals, _, clock = _service(tmp_path, events=events)
    reference = _suspended(service, approvals)
    clock.advance(WAIT)
    service.sweep()
    assert approvals.read("local", reference).state is ApprovalState.EXPIRED

    clock.advance(WAIT)
    service.sweep()

    with pytest.raises(ApprovalUnknown):
        approvals.read("local", reference)
    (forgotten,) = events.of_kind("approval.forgotten")
    assert forgotten.details == {"approval_refs": [reference]}


def test_the_tick_records_nothing_when_no_wait_ended_and_none_was_forgotten(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: an empty sweep is not an event, because nothing happened."""
    events = MemoryEvents()
    service, approvals, _, _ = _service(tmp_path, events=events)
    _suspended(service, approvals)

    service.sweep()

    assert events.of_kind("approval.expired") == ()
    assert events.of_kind("approval.forgotten") == ()
    assert len(approvals.pending()) == 1


def test_the_tick_of_a_composition_without_approvals_sweeps_the_grants_alone(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A deployment that kept no store has no wait to end, and says nothing about one."""
    events = MemoryEvents()
    service, _, _, clock = _service(tmp_path, approvals_composed=False, events=events)
    clock.advance(WAIT)

    service.sweep()

    assert events.of_kind("approval.expired") == ()
    assert events.of_kind("approval.forgotten") == ()


# -- a provider from elsewhere, behind the same port ---------------------------


def _resolve_through_the_route(service: DecisionService, reference: str) -> dict[str, object]:
    """One person's act, as the route a connection reaches applies it."""
    return ApprovalRoutes(service).resolve(
        reference,
        {
            "contract_generation": CONTRACT_GENERATION,
            "scope": "local",
            "approval_ref": reference,
            "resolution": "approve",
            "reason": "the change is reviewed",
        },
        person=PERSON,
    )


def test_a_conformant_provider_from_elsewhere_ends_the_wait_the_core_keeps(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2, 3 and 12: the transition is the core's, whatever provider judged the act.

    The provider composed here is the port's own reference implementation — the
    one the published conformance kit certifies, and the shape of the provider
    `docs/deployment.md` offers for designation and a second signature. It
    keeps records of its own and writes nothing to this core's store, because
    the store is not a provider's to write.

    Written as a walk rather than as a unit, because the defect it holds shut
    was invisible one call at a time: every part answered correctly, the act
    was recorded, and the wait stayed pending — so the person was answered
    `200 pending` over an act the daemon had just logged, and the re-ask was
    suspended again on the same wait until it lapsed.
    """
    ApprovalProviderContract().assert_conforms(SingleApprover)
    events = MemoryEvents()
    service, approvals, _, _ = _service(tmp_path, events=events, provider=SingleApprover())
    reference = _suspended(service, approvals)

    document = _resolve_through_the_route(service, reference)

    assert document["state"] == "approved"
    assert document["resolution_reason"] == "the change is reviewed"
    kept = approvals.read("local", reference)
    assert kept.state is ApprovalState.APPROVED
    assert kept.person == PERSON
    (recorded,) = events.of_kind("approval.resolved")
    assert recorded.details["person"] == PERSON
    # And the half the person actually asked for: the effect runs.
    again = service.ask(_question(), grant_connection=True)
    assert isinstance(again, DecisionAnswer)
    assert again.decision.outcome is Outcome.ALLOW
    assert again.decision.reason is Reason.APPROVAL_GRANTED
    assert again.decision.approval_ref == reference
    assert approvals.read("local", reference).consumed is True


@pytest.mark.parametrize(
    "provider",
    [None, SingleApprover],
    ids=["the shipped provider", "a provider from elsewhere"],
)
def test_one_act_is_written_to_the_store_exactly_once(tmp_path, provider, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 3: one writer, so one person's act cannot be written twice.

    Counted rather than argued, and counted on both sides of the port, because
    the arrangement that shipped had two candidate writers — the route and the
    shipped provider — and which of them ran decided what the person was told.
    `tests/test_one_writer_of_a_resolution.py` holds the other half: that the
    one writer is the core's and stays there.
    """
    service, approvals, _, _ = _service(tmp_path, provider=None if provider is None else provider())
    reference = _suspended(service, approvals)
    written: list[tuple[str, str]] = []
    unwrapped = ApprovalStore.resolve

    def counted(self, scope, approval_ref, **members):  # type: ignore[no-untyped-def]
        written.append((scope, approval_ref))
        return unwrapped(self, scope, approval_ref, **members)

    monkeypatch.setattr(ApprovalStore, "resolve", counted)

    _resolve_through_the_route(service, reference)

    assert written == [("local", reference)]
