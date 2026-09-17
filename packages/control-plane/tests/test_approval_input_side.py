# SPDX-License-Identifier: Apache-2.0
"""The other half of `domain/foreign.py`: what the core hands *to* a port.

`test_foreign_values.py` holds the output side — a value a port returns is
memory that port owns, so the core reads it once and keeps its own. The input
side had no rule at all, and the approval seam is where that cost something.

The seam judged a provider's answer against "the acts legitimately put to the
provider". It built that list out of the very object it then handed the
provider, so `object.__setattr__` on the argument rewrote the evidence the
judgement was about. No global patch, no frame inspection, no knowledge of any
fixture's names: the provider is simply given a mutable value the core is also
relying on, and a frozen dataclass is frozen against `setattr`, never against
`object.__setattr__`.

The first outside read executed this end to end (`counterexamples.py`): a
provider that renamed the act **passed `ApprovalProviderContract.assert_conforms`**
— the kit shares the defect, because it too keeps the objects it submits — and
through the runtime seam the person who approved became somebody who never
acted, with a reason nobody submitted, in the record and in what was handed
back.

Articles 3, 8 and 12: the core is the only code between a third-party provider
and the effect, and attribution is the whole content of an approval record.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest
from sayfirst.testing import ApprovalProviderContract
from sayfirst_control_plane.domain.foreign import ForeignValueRefused, core_owned_input
from sayfirst_control_plane.plugins.approval import (
    ApprovalAnswerRefused,
    RefusedProviderAnswer,
    resume_through_provider,
)
from sayfirst_control_plane.plugins.defaults import SingleApprover
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)

REQUESTED_AT = datetime(2026, 9, 4, 12, tzinfo=UTC)
DEADLINE = REQUESTED_AT + timedelta(seconds=60)


class Recorder:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, resolution: ResolvedApproval) -> None:
        self.records.append(resolution)

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        self.records.append(refusal)


class RewritesTheAct(SingleApprover):
    """Rewrites the act it is handed, then answers honestly from what it wrote."""

    def resume(self, suspended, action):  # type: ignore[no-untyped-def]
        object.__setattr__(action, "person", "mallory")
        object.__setattr__(action, "reason", "a reason nobody submitted")
        return super().resume(suspended, action)


class RewritesTheSuspension(SingleApprover):
    """Rewrites the suspension it is handed, so the judge reads its own decision."""

    def resume(self, suspended, action):  # type: ignore[no-untyped-def]
        object.__setattr__(suspended.request, "decision_ref", "a-decision-nobody-suspended")
        return super().resume(suspended, action)


class RewritesTheRequestPutToSuspend(SingleApprover):
    """Rewrites the request it is handed to `suspend`, then answers honestly.

    The second outside read's case, reproduced here: one line, no monkeypatch,
    and the whole conformance kit passed it. The kit took its own copy of the
    request inside `_answer` — *after* `suspend` had had the object — so the
    decision every later check judged against was the decision this provider
    wrote, and `suspended.request != request` compared the rewritten object
    with itself.
    """

    def suspend(self, request):  # type: ignore[no-untyped-def]
        object.__setattr__(request, "decision_ref", "a-decision-nobody-suspended")
        return super().suspend(request)


def _request() -> ApprovalRequest:
    return ApprovalRequest(
        approval_ref="approval-1",
        decision_ref="decision-1",
        scope="local",
        capability="storage.write",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


def _action(request: ApprovalRequest) -> ApprovalAction:
    return ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="alice",
        resolution=ApprovalResolution.APPROVE,
        reason="approved by Alice",
    )


def test_a_provider_that_rewrites_the_act_is_refused_by_the_seam() -> None:
    """`counterexamples.py`, at the runtime seam: attribution is the core's own."""
    provider = RewritesTheAct()
    request = _request()
    suspended = provider.suspend(request)
    action = _action(request)
    recorder = Recorder()

    with pytest.raises(ApprovalAnswerRefused) as refused:
        resume_through_provider(provider, suspended, action, recorder=recorder)

    assert "alice" in str(refused.value)
    assert "mallory" in str(refused.value)
    assert len(recorder.records) == 1
    refusal = recorder.records[0]
    assert isinstance(refusal, RefusedProviderAnswer)
    # The refusal is written from the act that was submitted, never from the
    # object the provider rewrote.
    assert refusal.person == "alice"
    assert refusal.decision_ref == "decision-1"


def test_a_provider_that_rewrites_the_suspension_is_refused_by_the_seam() -> None:
    """The same defect through the other argument: the decision an approval names."""
    provider = RewritesTheSuspension()
    request = _request()
    suspended = provider.suspend(request)
    recorder = Recorder()

    with pytest.raises(ApprovalAnswerRefused) as refused:
        resume_through_provider(provider, suspended, _action(request), recorder=recorder)

    assert "another decision" in str(refused.value)
    assert isinstance(recorder.records[0], RefusedProviderAnswer)
    assert recorder.records[0].decision_ref == "decision-1"


def test_the_kit_fails_a_provider_that_rewrites_what_it_is_handed() -> None:
    """Article 8: what the kit accepts and what the seam accepts are one rule."""
    with pytest.raises(AssertionError):
        ApprovalProviderContract().assert_conforms(RewritesTheAct)
    with pytest.raises(AssertionError):
        ApprovalProviderContract().assert_conforms(RewritesTheSuspension)


def test_the_kit_fails_a_provider_that_rewrites_the_request_put_to_suspend() -> None:
    """The input side covers every argument the kit hands over, `suspend`'s too.

    Article 12: a resolution is the record of the acts of the people, against
    the decision that was suspended. A provider that moves the decision as it
    is asked to suspend it resolves against a decision nobody suspended — and
    it passed, because the request the kit judged by was the request it had
    already given away.
    """
    with pytest.raises(AssertionError):
        ApprovalProviderContract().assert_conforms(RewritesTheRequestPutToSuspend)


def test_a_rewritten_request_never_becomes_the_decision_the_kit_judges_by() -> None:
    """The copy is what makes the check above a check, so it is named directly.

    A provider that rewrites the request in `suspend` cannot move the kit's
    decision, because the kit's decision was taken before the call. Without the
    copy this assertion reads `'a-decision-nobody-suspended' == …`, which is
    the whole of why the conformance run passed.
    """
    request = _request()
    judged = core_owned_input(ApprovalRequest, request)

    RewritesTheRequestPutToSuspend().suspend(request)

    assert request.decision_ref == "a-decision-nobody-suspended"
    assert judged.decision_ref == "decision-1"


def test_an_honest_provider_still_resolves_and_is_recorded() -> None:
    """Non-vacuity: the copy is a copy, not a refusal of everything."""
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    recorder = Recorder()

    answer = resume_through_provider(provider, suspended, _action(request), recorder=recorder)

    assert isinstance(answer, ResolvedApproval)
    assert (answer.person, answer.reason) == ("alice", "approved by Alice")
    assert answer.decision_ref == "decision-1"
    assert recorder.records == [answer]


def test_the_input_guard_builds_the_core_s_own_value_and_never_the_one_given() -> None:
    """`core_owned_input`: a copy, of the core's own type, that is not the argument."""
    request = _request()
    action = _action(request)

    held = core_owned_input(ApprovalAction, action)

    assert held == action
    assert held is not action
    assert type(held) is ApprovalAction
    object.__setattr__(action, "person", "mallory")
    assert held.person == "alice"


def test_the_input_guard_refuses_a_value_it_cannot_rebuild() -> None:
    """Article 3: a value the core cannot take is refused, never taken on trust."""

    class NotAnAct:
        approval_ref = "approval-1"

    with pytest.raises(ForeignValueRefused):
        core_owned_input(ApprovalAction, NotAnAct())


def test_the_input_guard_refuses_a_value_that_answers_with_itself() -> None:
    """The copy must be a copy: a `kind` that hands the argument back is refused."""

    class Aliasing(SuspendedApproval):
        instances: ClassVar[list[object]] = []

        def __new__(cls, *args: object, **members: object) -> object:  # type: ignore[misc]
            if Aliasing.instances:
                return Aliasing.instances[0]
            made = super().__new__(cls)
            Aliasing.instances.append(made)
            return made

    request = _request()
    first = Aliasing(request=request, scope=request.scope)

    with pytest.raises(ForeignValueRefused):
        core_owned_input(Aliasing, first)


class RewritesTheRecordItIsHandedToRecord:
    """Rewrites the terminal record the seam hands it, then keeps the rewrite.

    The third outside read, one hop later on the same call path as the two
    above. `ApprovalResolutionRecorder` is a `Protocol` exported from the
    plugins package, so it is a seam a product implements; the seam built the
    resolution from its own copies of the act and the suspension, and then
    handed the recorder the very object it returns. `frozen=True` refuses
    `setattr` and refuses nothing to `object.__setattr__`, so an act submitted
    as alice/approve came back to the caller as mallory/reject, and
    `answer is recorder.records[0]` was true.
    """

    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, resolution: ResolvedApproval) -> None:
        self.records.append(resolution)
        object.__setattr__(resolution, "person", "mallory")
        object.__setattr__(resolution, "resolution", ApprovalResolution.REJECT)

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        self.records.append(refusal)


def test_a_recorder_cannot_rewrite_the_record_the_caller_resumes_on() -> None:
    """Articles 3 and 12: what a recorder is handed is not the caller's answer.

    Article 3 says a mutable execution state never rewrites an immutable
    governance decision, and article 12 says attribution is the whole content
    of an approval record. Both are about this object: the caller resumes the
    suspended effect on what it is answered with here.
    """
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    recorder = RewritesTheRecordItIsHandedToRecord()

    answer = resume_through_provider(provider, suspended, _action(request), recorder=recorder)

    assert isinstance(answer, ResolvedApproval)
    assert (answer.person, answer.resolution) == ("alice", ApprovalResolution.APPROVE)
    assert (answer.reason, answer.decision_ref) == ("approved by Alice", "decision-1")
    assert answer is not recorder.records[0]


def test_the_record_a_recorder_is_handed_says_what_the_caller_is_answered() -> None:
    """Non-vacuity: the copy is a copy of this resolution, not some other value."""
    provider = SingleApprover()
    request = _request()
    suspended = provider.suspend(request)
    recorder = Recorder()

    answer = resume_through_provider(provider, suspended, _action(request), recorder=recorder)

    recorded = recorder.records[0]
    assert type(recorded) is ResolvedApproval
    assert recorded == answer
    assert recorded is not answer
