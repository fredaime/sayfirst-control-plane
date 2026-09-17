# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from inspect import signature
from pathlib import Path
from typing import get_args, get_type_hints

import pytest
from sayfirst.testing import ApprovalProviderContract, PrivacyRedactorContract
from sayfirst_contract.decisions import Outcome, Reason
from sayfirst_control_plane.plugins.approval import (
    ApprovalAnswerRefused,
    RefusedProviderAnswer,
    UnrecordedApprovalResolution,
    resume_through_provider,
)
from sayfirst_control_plane.plugins.defaults import SingleApprover
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalAlreadyExists,
    ApprovalAlreadyResolved,
    ApprovalProvider,
    ApprovalProviderError,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    Redaction,
    ResolvedApproval,
    SuspendedApproval,
)
from sayfirst_control_plane.plugins.privacy.none import NoRedaction


class LiarRedactor:
    """A no-op provider that answers `applied` over content it did not touch."""

    interface_version = 1
    name = "claimed-protection"

    def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction:
        return Redaction(content, "applied", self.name)


class LiarApprover:
    """A structurally valid provider that falsifies the person's decision."""

    def __init__(self) -> None:
        self.delegate = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self.delegate.suspend(request)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        resolved = self.delegate.resume(suspended, action)
        return ResolvedApproval(
            approval_ref=resolved.approval_ref,
            decision_ref="a-different-decision",
            scope=resolved.scope,
            person="somebody-else",
            resolution=ApprovalResolution.REJECT,
        )


class RejectionRewritingApprover:
    """A provider that rewrites every rejection as an approval."""

    def __init__(self) -> None:
        self.delegate = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self.delegate.suspend(request)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        resolved = self.delegate.resume(suspended, action)
        return ResolvedApproval(
            approval_ref=resolved.approval_ref,
            decision_ref=resolved.decision_ref,
            scope=resolved.scope,
            person=resolved.person,
            resolution=ApprovalResolution.APPROVE,
            reason=resolved.reason,
        )


class NineDesignatedPeopleApprover:
    """A permitted provider whose own registry requires nine designated people."""

    designated = tuple(f"designated-person-{number}" for number in range(9))

    def __init__(self) -> None:
        self.requests: dict[str, ApprovalRequest] = {}
        self.actions: dict[str, list[ApprovalAction]] = {}
        self.resolved: set[str] = set()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        self.requests[request.approval_ref] = request
        self.actions[request.approval_ref] = []
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        request = self.requests.get(suspended.approval_ref)
        if (
            request != suspended.request
            or action.approval_ref != suspended.approval_ref
            or action.scope != suspended.scope
        ):
            raise ApprovalRequestMismatch("not this suspension")
        if suspended.approval_ref in self.resolved:
            raise ApprovalAlreadyResolved("already resolved")
        if action.person not in self.designated:
            raise ApprovalRequestMismatch("person is not designated")
        actions = self.actions[suspended.approval_ref]
        actions.append(action)
        if len(actions) < len(self.designated):
            return suspended
        self.resolved.add(suspended.approval_ref)
        return ResolvedApproval(
            approval_ref=request.approval_ref,
            decision_ref=request.decision_ref,
            scope=request.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )


def _nine_person_completion(
    request: ApprovalRequest, resolution: ApprovalResolution
) -> tuple[ApprovalAction, ...]:
    return tuple(
        ApprovalAction(
            approval_ref=request.approval_ref,
            scope=request.scope,
            person=person,
            resolution=resolution,
            reason="designated review",
        )
        for person in NineDesignatedPeopleApprover.designated
    )


class ScopeBlindApprover:
    """A provider that checks request identity but lets another scope act."""

    def __init__(self) -> None:
        self.request: ApprovalRequest | None = None

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        self.request = request
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        if action.approval_ref != suspended.approval_ref or suspended.request != self.request:
            raise ApprovalRequestMismatch("not this suspension")
        return ResolvedApproval(
            approval_ref=suspended.approval_ref,
            decision_ref=suspended.request.decision_ref,
            scope=suspended.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )


class ForgingApprover:
    """A provider that resolves any well-shaped suspension it never issued."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        if action.approval_ref != suspended.approval_ref or action.scope != suspended.scope:
            raise ApprovalRequestMismatch("not this suspension")
        return ResolvedApproval(
            approval_ref=suspended.approval_ref,
            decision_ref=suspended.request.decision_ref,
            scope=suspended.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )


def test_the_two_open_providers_pass_the_published_contract_suites() -> None:
    PrivacyRedactorContract().assert_conforms(NoRedaction)
    ApprovalProviderContract().assert_conforms(SingleApprover)


def test_the_approval_contract_rejects_a_provider_that_falsifies_the_action() -> None:
    assert isinstance(LiarApprover(), ApprovalProvider)

    with pytest.raises(AssertionError, match="no act supports"):
        ApprovalProviderContract().assert_conforms(LiarApprover)


def test_the_approval_contract_rejects_a_provider_that_rewrites_rejections() -> None:
    with pytest.raises(AssertionError, match="no act supports"):
        ApprovalProviderContract().assert_conforms(RejectionRewritingApprover)


def _always_approving_completion(
    request: ApprovalRequest, resolution: ApprovalResolution
) -> tuple[ApprovalAction, ...]:
    """A fixture that ignores the case it is asked to put to the provider."""
    return (
        ApprovalAction(
            approval_ref=request.approval_ref,
            scope=request.scope,
            person="conformance-person",
            resolution=ApprovalResolution.APPROVE,
        ),
    )


def test_a_provider_supplied_fixture_cannot_skip_the_rejection_case() -> None:
    """Article 12: the fixture owns the people, never which act the case puts."""
    contract = ApprovalProviderContract(completion_actions=_always_approving_completion)

    with pytest.raises(AssertionError, match="does not put the reject case"):
        contract.assert_conforms(RejectionRewritingApprover)
    with pytest.raises(AssertionError, match="does not put the reject case"):
        contract.assert_conforms(SingleApprover)


def test_the_approval_contract_accepts_provider_owned_completion_fixtures() -> None:
    ApprovalProviderContract(completion_actions=_nine_person_completion).assert_conforms(
        NineDesignatedPeopleApprover
    )


def test_the_privacy_contract_rejects_a_no_op_that_claims_protection() -> None:
    with pytest.raises(AssertionError, match="no-op cannot claim protection"):
        PrivacyRedactorContract().assert_conforms(LiarRedactor)


def test_the_approval_contract_requires_scope_isolation() -> None:
    with pytest.raises(AssertionError, match="different scope"):
        ApprovalProviderContract().assert_conforms(ScopeBlindApprover)


def test_the_approval_contract_rejects_a_forged_suspension_reference() -> None:
    with pytest.raises(AssertionError, match="never issued"):
        ApprovalProviderContract().assert_conforms(ForgingApprover)


def test_the_no_op_privacy_provider_is_none_and_never_claims_protection() -> None:
    provider = NoRedaction()
    content = b"keep this value: 7"

    answer = provider.redact(scope="local", capability="files.write", content=content)

    assert (answer.content, answer.status, answer.provider) == (content, "not_applicable", "none")
    assert provider.name == "none"


def test_a_single_approver_resolves_a_suspension_and_cannot_sign_twice() -> None:
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    action = ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="uid:1000",
        resolution=ApprovalResolution.APPROVE,
        reason="reviewed",
    )

    resolved = provider.resume(suspended, action)

    assert resolved.approval_ref == request.approval_ref
    assert resolved.decision_ref == request.decision_ref
    assert suspended.scope == request.scope
    assert resolved.scope == request.scope
    assert resolved.person == "uid:1000"
    assert resolved.resolution is ApprovalResolution.APPROVE

    with pytest.raises(ApprovalAlreadyResolved):
        provider.resume(suspended, action)


def test_a_duplicate_suspension_is_not_misreported_as_already_resolved() -> None:
    provider = SingleApprover()
    request = _request()
    provider.suspend(request)

    with pytest.raises(ApprovalAlreadyExists):
        provider.suspend(request)


class ForeignBindingApprover:
    """A hostile provider whose answer is bound to another request entirely."""

    def __init__(self, **binding: object) -> None:
        self.binding = binding

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        members: dict[str, object] = {
            "approval_ref": suspended.approval_ref,
            "decision_ref": suspended.request.decision_ref,
            "scope": suspended.scope,
            "person": action.person,
            "resolution": action.resolution,
            "reason": action.reason,
        }
        members.update(self.binding)
        return ResolvedApproval(**members)  # type: ignore[arg-type]


class ForeignWaitApprover:
    """A hostile provider that keeps waiting, but on another decision."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> SuspendedApproval:
        elsewhere = ApprovalRequest(
            approval_ref=suspended.approval_ref,
            decision_ref="decision-ELSEWHERE",
            scope=suspended.scope,
            capability="files.write",
            requested_at=REQUESTED_AT,
            deadline=DEADLINE,
        )
        return SuspendedApproval(request=elsewhere, scope=elsewhere.scope)


def test_approval_provider_can_only_resolve_the_request_it_received() -> None:
    """Backbone 4.10: the hostile provider is the one this guard is about."""
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    action = ApprovalAction(
        approval_ref="approval-2",
        scope=request.scope,
        person="uid:1000",
        resolution=ApprovalResolution.APPROVE,
    )

    with pytest.raises(ApprovalRequestMismatch):
        provider.resume(suspended, action)

    hostile = ForeignBindingApprover(
        approval_ref="approval-OTHER",
        decision_ref="decision-OTHER",
        scope="scope-ELSEWHERE",
        person="somebody-who-never-acted",
        resolution=ApprovalResolution.APPROVE,
        reason="widened",
    )
    sink = RecordingSink()
    rejection = ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="uid:1000",
        resolution=ApprovalResolution.REJECT,
    )

    with pytest.raises(ApprovalAnswerRefused):
        resume_through_provider(hostile, hostile.suspend(request), rejection, recorder=sink)
    assert sink.recorded == []
    assert [refusal.complaint for refusal in sink.refused] == ["it names another approval"]


@pytest.mark.parametrize(
    ("binding", "complaint"),
    [
        ({"approval_ref": "approval-OTHER"}, "it names another approval"),
        ({"decision_ref": "decision-OTHER"}, "it names another decision"),
        ({"scope": "scope-ELSEWHERE"}, "it names another scope"),
    ],
)
def test_the_core_refuses_a_provider_result_bound_to_another_request(
    binding: dict[str, object], complaint: str
) -> None:
    """Article 5 for the scope, article 3 for the reference the record names."""
    request = _request()
    provider = ForeignBindingApprover(**binding)
    sink = RecordingSink()

    with pytest.raises(ApprovalAnswerRefused, match=complaint):
        resume_through_provider(
            provider, provider.suspend(request), _action(request), recorder=sink
        )
    assert sink.recorded == []
    assert [refusal.complaint for refusal in sink.refused] == [complaint]


def test_the_core_refuses_a_provider_wait_bound_to_another_request() -> None:
    """A wait is a claim about this suspension too, and is bound the same way."""
    request = _request()
    provider = ForeignWaitApprover()
    sink = RecordingSink()

    with pytest.raises(ApprovalAnswerRefused, match="another suspended request"):
        resume_through_provider(
            provider, provider.suspend(request), _action(request), recorder=sink
        )
    assert sink.recorded == []


def test_the_core_refuses_a_resolution_no_act_of_this_approval_supports() -> None:
    """Articles 3 and 12: the core judges the act too, by the kit's one rule.

    The kit is not involved here — the seam is driven directly. The last line
    shows the same provider failing the kit, which is the point: one rule, held
    on both sides, so a provider that never runs the kit is judged all the same.
    """
    request = _request()
    provider = ForeignBindingApprover(person="somebody-who-never-acted")
    sink = RecordingSink()

    with pytest.raises(ApprovalAnswerRefused, match="attributes the act of"):
        resume_through_provider(
            provider, provider.suspend(request), _action(request), recorder=sink
        )

    assert sink.recorded == []
    assert [refusal.person for refusal in sink.refused] == ["uid:1000"]
    with pytest.raises(AssertionError, match="no act"):
        ApprovalProviderContract().assert_conforms(lambda: ForeignBindingApprover(person="x"))


REQUESTED_AT = datetime(2026, 9, 4, tzinfo=UTC)
DEADLINE = REQUESTED_AT + timedelta(seconds=60)


def _request(approval_ref: str = "approval-1") -> ApprovalRequest:
    return ApprovalRequest(
        approval_ref=approval_ref,
        decision_ref="decision-1",
        scope="local",
        capability="files.write",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


def _action(request: ApprovalRequest, person: str = "uid:1000") -> ApprovalAction:
    return ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person=person,
        resolution=ApprovalResolution.APPROVE,
    )


def test_an_approval_request_carries_the_bounded_wait_of_the_contract() -> None:
    """Article 12: the port carries the deadline generation one already publishes."""
    request = _request()

    assert request.deadline == DEADLINE
    assert request.requested_at == REQUESTED_AT
    with pytest.raises(ValueError, match="offset-aware"):
        ApprovalRequest("a", "d", "local", "files.write", datetime(2026, 9, 4), DEADLINE)
    with pytest.raises(ValueError, match="deadline"):
        ApprovalRequest("a", "d", "local", "files.write", DEADLINE, REQUESTED_AT)


def test_the_provider_result_is_only_the_persons_approve_or_reject_act() -> None:
    """Backbone 4.10: expiry is an authority state, not a provider resolution."""
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    action = ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="uid:1000",
        resolution=ApprovalResolution.REJECT,
    )

    resolved = provider.resume(suspended, action)

    assert isinstance(resolved, ResolvedApproval)
    assert resolved.person == "uid:1000"
    assert resolved.resolution is ApprovalResolution.REJECT


def test_expiry_is_not_an_approval_provider_result() -> None:
    """Backbone 4.10: the provider result only carries a person's act."""
    resume = get_type_hints(ApprovalProvider.resume)

    assert "now" not in signature(ApprovalProvider.resume).parameters
    assert set(get_args(resume["return"])) == {SuspendedApproval, ResolvedApproval}


class NeverResolvingApprover:
    """A structurally valid provider that answers every action with the suspension."""

    def __init__(self) -> None:
        self.issued: dict[str, ApprovalRequest] = {}

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        self.issued[request.approval_ref] = request
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> SuspendedApproval:
        if action.approval_ref != suspended.approval_ref or action.scope != suspended.scope:
            raise ApprovalRequestMismatch("not this suspension")
        if self.issued.get(suspended.approval_ref) != suspended.request:
            raise ApprovalRequestMismatch("not this suspension")
        return suspended


def test_the_approval_contract_fails_a_provider_that_never_resolves() -> None:
    """Article 8: a provider that does not pass the kit is not a provider."""
    assert isinstance(NeverResolvingApprover(), ApprovalProvider)

    with pytest.raises(AssertionError, match="did not resolve after its completion fixture"):
        ApprovalProviderContract().assert_conforms(NeverResolvingApprover)


class RecordingSink:
    """A recorder that remembers the order in which it was told."""

    def __init__(self) -> None:
        self.recorded: list[ResolvedApproval] = []
        self.refused: list[RefusedProviderAnswer] = []
        self.released: list[str] = []

    def record(self, resolution: ResolvedApproval) -> None:
        self.released.append("recorded")
        self.recorded.append(resolution)

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        self.released.append("refused")
        self.refused.append(refusal)


class RefusingSink:
    """A recorder that cannot append, as a store under pressure cannot."""

    def record(self, resolution: ResolvedApproval) -> None:
        raise RuntimeError("the resolution could not be appended")

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        raise RuntimeError("the refusal could not be appended")


class ResumedEffect:
    """The effect a resolution releases, writing into the recorder's own order."""

    def __init__(self, sink: RecordingSink) -> None:
        self.sink = sink
        self.resumed: list[ResolvedApproval] = []

    def resume_on(self, progress: SuspendedApproval | ResolvedApproval) -> None:
        assert isinstance(progress, ResolvedApproval)
        self.sink.released.append("resumed")
        self.resumed.append(progress)


def test_provider_resolution_is_recorded_before_resume() -> None:
    """Article 3: the resolution is a record before it can release the effect.

    Ordering is asserted against an effect that resumes on what the seam returns,
    so the assertion is about the seam and not about the recorder writing its own
    marker. The second half is what gives it teeth: when the record cannot be
    appended, the effect must not resume at all.
    """
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    sink = RecordingSink()
    effect = ResumedEffect(sink)

    effect.resume_on(resume_through_provider(provider, suspended, _action(request), recorder=sink))

    assert sink.released == ["recorded", "resumed"]
    assert effect.resumed == sink.recorded

    blocked = SingleApprover()
    blocked_sink = RecordingSink()
    blocked_effect = ResumedEffect(blocked_sink)

    with pytest.raises(UnrecordedApprovalResolution):
        blocked_effect.resume_on(
            resume_through_provider(
                blocked, blocked.suspend(request), _action(request), recorder=RefusingSink()
            )
        )

    assert blocked_effect.resumed == []
    assert blocked_sink.released == []


def test_a_resolution_that_cannot_be_recorded_never_reaches_the_caller() -> None:
    """Article 3: fail-closed is never the property traded away."""
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)

    with pytest.raises(UnrecordedApprovalResolution):
        resume_through_provider(provider, suspended, _action(request), recorder=RefusingSink())


def test_progress_that_resolves_nothing_records_nothing() -> None:
    """Article 3: only a terminal result is a record; a wait still waiting is not."""
    provider = NeverResolvingApprover()
    request = _request()
    suspended = provider.suspend(request)
    sink = RecordingSink()

    progress = resume_through_provider(provider, suspended, _action(request), recorder=sink)

    assert isinstance(progress, SuspendedApproval)
    assert sink.recorded == []


def test_the_approval_port_returns_no_policy_verdict() -> None:
    """Article 12: the core never adds an outcome; the three of article 1 are complete."""
    forbidden = (
        {item.value for item in Outcome}
        | {item.value for item in Reason}
        | {
            "outcome",
            "reason_code",
            "policy",
            "policy_version",
            "regime",
            "verdict",
            "grant",
        }
    )
    carried = {
        field.name
        for shape in (
            ApprovalRequest,
            ApprovalAction,
            SuspendedApproval,
            ResolvedApproval,
        )
        for field in fields(shape)
    }
    assert len(carried) >= 8
    assert carried & forbidden == set()
    assert {item.value for item in ApprovalResolution} == {"approve", "reject"}


class RogueAnswer:
    """A value outside the v1 contract, shaped to pass a binding check.

    It copies every member a derivation check would compare — the references,
    the person, the verdict, the reason — and adds what article 12 forbids the
    core to carry: an outcome and a policy verdict. Only its type gives it away.
    """

    def __init__(self, suspended: SuspendedApproval, action: ApprovalAction) -> None:
        self.approval_ref = suspended.approval_ref
        self.decision_ref = suspended.request.decision_ref
        self.scope = suspended.scope
        self.person = action.person
        self.resolution = action.resolution
        self.reason = action.reason
        self.outcome = "allow"
        self.policy_verdict = "widened by the provider"


class RogueApprover:
    """A hostile provider that answers with something that is not a resolution."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> object:
        return RogueAnswer(suspended, action)


class AnsweringApprover:
    """A provider that resolves whatever it is handed, refusing nothing.

    It keeps every object it handed back, so a test can ask whether the core
    recorded one of them or a value of its own.
    """

    def __init__(self) -> None:
        self.answered: list[ResolvedApproval] = []

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        answer = ResolvedApproval(
            approval_ref=suspended.approval_ref,
            decision_ref=suspended.request.decision_ref,
            scope=suspended.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )
        self.answered.append(answer)
        return answer


def test_the_core_refuses_a_provider_answer_that_is_not_a_v1_resolution() -> None:
    """Articles 3 and 12, with the conformance kit not involved: a hostile
    provider returns ``allow`` with no act behind it, and the core refuses it.

    Manifest 4.10: "un provider hostile renvoie un allow". The kit catches this
    for a provider that runs the kit; the core is the only code between a
    third-party provider and the effect, so it holds the same rule itself.
    """
    provider = RogueApprover()
    request = _request()
    suspended = provider.suspend(request)
    sink = RecordingSink()

    with pytest.raises(ApprovalProviderError) as refused:
        resume_through_provider(provider, suspended, _action(request), recorder=sink)

    assert isinstance(refused.value, ApprovalAnswerRefused)
    assert "not a value of the ApprovalProvider v1 contract" in str(refused.value)
    assert sink.recorded == []
    assert sink.released == ["refused"]
    assert sink.refused == [
        RefusedProviderAnswer(
            approval_ref=request.approval_ref,
            decision_ref=request.decision_ref,
            scope=request.scope,
            person="uid:1000",
            complaint="it is not a value of the ApprovalProvider v1 contract",
        )
    ]
    assert "allow" not in str(sink.refused[0])


def test_a_refused_provider_answer_is_recorded_as_a_refusal_not_a_decision() -> None:
    """Article 12: the core adds no outcome to express what it refused."""
    forbidden = {item.value for item in Outcome} | {
        "outcome",
        "resolution",
        "policy",
        "policy_verdict",
        "verdict",
        "grant",
    }

    assert {field.name for field in fields(RefusedProviderAnswer)} & forbidden == set()


def test_the_core_refuses_an_answer_to_an_action_of_another_approval() -> None:
    """No act was legitimately put, so no resolution at all is derivable."""
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    sink = RecordingSink()
    foreign = ApprovalAction(
        approval_ref="approval-OTHER",
        scope=request.scope,
        person="uid:1000",
        resolution=ApprovalResolution.APPROVE,
    )

    with pytest.raises(ApprovalRequestMismatch):
        resume_through_provider(provider, suspended, foreign, recorder=sink)

    with pytest.raises(ApprovalAnswerRefused, match="no act of any person was put to it"):
        resume_through_provider(AnsweringApprover(), suspended, foreign, recorder=sink)
    assert sink.recorded == []


def test_a_refusal_that_cannot_be_recorded_still_fails_closed() -> None:
    """Article 3: fail-closed is never the property traded away."""
    provider = RogueApprover()
    request = _request()
    suspended = provider.suspend(request)

    with pytest.raises(UnrecordedApprovalResolution, match="refusal could not be recorded"):
        resume_through_provider(provider, suspended, _action(request), recorder=RefusingSink())


class TwoFacedAnswer:
    """An answer that tells the truth while it is checked and lies afterwards.

    It is not a `ResolvedApproval` and it says it is: `__class__` is a property,
    so `isinstance` — a question the object gets to answer about itself — says
    yes without a subclass and without a monkeypatch. Its members are properties
    too, so the value read while the core checks and the value read after the
    core has checked are two reads of memory the provider owns, and the provider
    chooses what the second one says by counting the first.
    """

    def __init__(self, honest: ResolvedApproval, *, grace: int) -> None:
        self._honest = honest
        self._grace = grace
        self._reads = 0

    @property  # type: ignore[misc]
    def __class__(self) -> type:  # type: ignore[override]
        return ResolvedApproval

    @property
    def approval_ref(self) -> str:
        return self._honest.approval_ref

    @property
    def decision_ref(self) -> str:
        return self._honest.decision_ref

    @property
    def scope(self) -> str:
        return self._honest.scope

    @property
    def reason(self) -> str | None:
        return self._honest.reason

    def _honest_yet(self) -> bool:
        self._reads += 1
        return self._reads <= self._grace

    @property
    def person(self) -> str:
        return self._honest.person if self._honest_yet() else "somebody-who-never-acted"

    @property
    def resolution(self) -> ApprovalResolution:
        if self._honest_yet():
            return self._honest.resolution
        return (
            ApprovalResolution.REJECT
            if self._honest.resolution is ApprovalResolution.APPROVE
            else ApprovalResolution.APPROVE
        )


class TwoFacedApprover:
    """An honestly structured provider whose answer changes between two reads."""

    def __init__(self, *, grace: int = 2) -> None:
        self._honest = SingleApprover()
        self._grace = grace
        self.answered: list[object] = []

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self._honest.suspend(request)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> object:
        honest = self._honest.resume(suspended, action)
        if not isinstance(honest, ResolvedApproval):
            return honest
        answer = TwoFacedAnswer(honest, grace=self._grace)
        self.answered.append(answer)
        return answer


def test_a_provider_answer_that_changes_between_two_reads_is_refused() -> None:
    """Articles 3 and 12: the core never takes a provider at its word, once or twice.

    An answer whose members are read again after the check is an answer the
    provider can rewrite after the check. The type gate is the first line: an
    object is not a value of the v1 contract because it says it is.
    """
    provider = TwoFacedApprover(grace=2)
    request = _request()
    suspended = provider.suspend(request)
    sink = RecordingSink()

    with pytest.raises(ApprovalAnswerRefused, match="not a value of the ApprovalProvider v1"):
        resume_through_provider(provider, suspended, _action(request), recorder=sink)

    assert sink.recorded == []
    assert sink.released == ["refused"]
    assert sink.refused[0].person == "uid:1000"


def test_the_record_and_the_resumption_are_the_core_s_own_value() -> None:
    """Article 3: what is recorded and handed on is built from the facts the core holds.

    `suspended.request` and the act put to the provider are the whole of a
    resolution, so the seam never has to hand on the object it judged — and does
    not, because an object read a second time is a second answer.

    The record and the resumption are equal and are two objects. This asserted
    that they were one, which was the seam's own defect written down as a
    property: the recorder is a port, and the object it is handed is one it can
    write to, so the one it is handed is never the one the caller resumes on.
    """
    provider = AnsweringApprover()
    request = _request()
    suspended = provider.suspend(request)
    action = _action(request)
    sink = RecordingSink()

    resumed = resume_through_provider(provider, suspended, action, recorder=sink)

    expected = ResolvedApproval(
        approval_ref=request.approval_ref,
        decision_ref=request.decision_ref,
        scope=request.scope,
        person=action.person,
        resolution=action.resolution,
        reason=action.reason,
    )
    assert type(resumed) is ResolvedApproval
    assert resumed == expected
    assert sink.recorded == [expected]
    assert resumed is not sink.recorded[0]
    assert all(recorded is not answer for recorded in sink.recorded for answer in provider.answered)


class UnderSigningApprover(NineDesignatedPeopleApprover):
    """Promises nine designated people and resolves on the first act it is given.

    Everything else about it is the honest provider's: it refuses another
    request, another scope, a suspension it never issued and a second act on a
    terminal approval, and the resolution it returns is derivable from the act
    that produced it. The only thing wrong with it is the count, which is the
    one thing article 12 leaves to the provider — and therefore the one thing
    the kit is named as the contract for.
    """

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        progress = super().resume(suspended, action)
        if isinstance(progress, ResolvedApproval):
            return progress
        request = self.requests[suspended.approval_ref]
        self.resolved.add(suspended.approval_ref)
        return ResolvedApproval(
            approval_ref=request.approval_ref,
            decision_ref=request.decision_ref,
            scope=request.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )


def test_a_provider_that_takes_fewer_signatures_than_it_promised_fails_the_kit() -> None:
    """Article 12: the multi-signature rule is the provider's, with the kit as its contract.

    A fixture is the provider's own statement of the finite sequence that
    completes a case. A provider that resolves before the sequence is spent took
    fewer signatures than it promised, and a kit that stops driving on the first
    resolution can never see it — act one already carries the case under test, so
    everything the kit goes on to check is derivable from it.
    """
    contract = ApprovalProviderContract(completion_actions=_nine_person_completion)

    with pytest.raises(AssertionError, match="resolved after 1 of the 9 acts"):
        contract.assert_conforms(UnderSigningApprover)


# -- the shipped provider, and the kit it stands outside of -------------------


def test_the_shipped_approval_provider_is_the_core_s_own_store_backed_one() -> None:
    """Articles 2 and 12: the provider the chain names is the provider that judges.

    The registration an operator's configuration selects by name is what the
    registry instantiates and what the composition record carries, so a
    registration naming one provider while the daemon called another would be a
    chain entry about something that never ran.
    """
    from sayfirst_control_plane.application.approvals import (
        ApprovalStore,
        SimpleApprovalProvider,
    )
    from sayfirst_control_plane.plugins.defaults import SINGLE_APPROVER_REGISTRATION

    assert SINGLE_APPROVER_REGISTRATION.provider_name == "single-approver"
    provider = SINGLE_APPROVER_REGISTRATION.factory()
    assert isinstance(provider, SimpleApprovalProvider)
    assert isinstance(provider, ApprovalProvider)
    assert isinstance(provider.store, ApprovalStore)
    assert signature(provider.suspend) == signature(SingleApprover().suspend)


def test_the_conformance_kit_is_not_run_against_the_core_s_own_provider() -> None:
    """Article 8: the kit is the contract for a provider written elsewhere.

    The core's provider opens no wait of its own — the core keeps the record,
    with the question a re-ask is matched by inside it, before the request is
    put to the provider — and the kit opens every suspension through `suspend`.
    So it is outside the kit by construction, the kit's own docstring says so,
    and this reads every case in the tree to hold that nobody quietly points
    the kit at it: a list of modules would be somebody's memory.
    """
    from sayfirst.testing import approval as kit

    assert "stands **outside** it" in (kit.__doc__ or "")
    tests = Path(__file__).resolve().parents[1] / "tests"
    pointed = []
    for module in sorted(tests.rglob("*.py")):
        source = module.read_text(encoding="utf-8")
        for line in source.splitlines():
            if "assert_conforms(" not in line:
                continue
            named = line.split("assert_conforms(", 1)[1]
            if "SimpleApprovalProvider" in named or "SINGLE_APPROVER_REGISTRATION" in named:
                pointed.append(f"{module.name}: {line.strip()}")
    assert pointed == [], pointed
