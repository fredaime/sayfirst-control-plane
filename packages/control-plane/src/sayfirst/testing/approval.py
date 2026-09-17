# SPDX-License-Identifier: Apache-2.0
"""The ApprovalProvider v1 conformance suite.

One rule judges every answer a provider gives, on every path the kit drives:
a result must be *derivable* from the acts of the people the kit has put to the
provider — their identity, their verdict, their reason, their order — and from
the suspension those acts belong to. A result no act supports fails, whichever
fixture, refusal, completion or replay produced it. Every call the kit makes
goes through one guarded seam (``_answer``), so a path added later is judged by
the same rule rather than by a list of cases someone remembered to extend.

The rule itself is the core's — ``unsupported_by_acts`` is imported from the
seam every provider answer passes through at runtime, not restated here — so
what the kit accepts and what the control plane accepts cannot drift apart.

Who this kit is for: a provider written elsewhere, which opens its own
suspension when ``suspend`` is called and answers acts put to it afterwards.
The control plane's own one-person provider stands **outside** it and is not
run against it. That provider opens nothing — the wait is a record the core
keeps, with the question a re-ask is matched by as one of its members, and it
is opened before the request is put to the provider at all — so holding it to
this kit would mean teaching the kit to open a wait in the core's store, which
is the core's business and not a provider's contract (articles 8 and 12).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from sayfirst_control_plane.plugins.approval import (
    core_owned_act,
    core_owned_request,
)
from sayfirst_control_plane.plugins.approval import (
    unsupported_by_acts as unsupported_by_acts,
)
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalProvider,
    ApprovalProviderError,
    ApprovalRequest,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)

REQUESTED_AT = datetime(2026, 9, 4, tzinfo=UTC)
DEADLINE = REQUESTED_AT + timedelta(seconds=60)

ApprovalCompletionActions = Callable[
    [ApprovalRequest, ApprovalResolution], Sequence[ApprovalAction]
]


def _request(approval_ref: str, decision_ref: str) -> ApprovalRequest:
    return ApprovalRequest(
        approval_ref=approval_ref,
        decision_ref=decision_ref,
        scope="conformance",
        capability="storage.write",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


def _action(
    request: ApprovalRequest,
    person: str,
    resolution: ApprovalResolution = ApprovalResolution.APPROVE,
) -> ApprovalAction:
    return ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person=person,
        resolution=resolution,
    )


def _one_person_completion(
    request: ApprovalRequest, resolution: ApprovalResolution
) -> tuple[ApprovalAction, ...]:
    return (_action(request, "conformance-person", resolution),)


class ApprovalProviderContract:
    """Assertions every ApprovalProvider v1 implementation must satisfy.

    ``completion_actions`` supplies the provider's valid people and the finite
    sequence it promises will complete each approve and reject case. Designation
    and signature count stay with the provider, as article 12 requires; which act
    each case puts to the provider does not — the kit refuses a fixture whose
    terminal act does not carry the case under test, so a provider cannot bring a
    fixture that never exercises rejection.

    What the kit holds about the count is that the provider keeps to the one it
    declared: the whole fixture is put, and a resolution before the last act is a
    provider taking fewer signatures than its own fixture promised. The kit does
    not judge how many signatures are enough — that is the provider's rule and
    the deployment's — only that the number it publishes here is the number it
    takes.
    """

    def __init__(
        self, *, completion_actions: ApprovalCompletionActions = _one_person_completion
    ) -> None:
        self._completion_actions = completion_actions

    def assert_conforms(self, provider_factory: Callable[[], ApprovalProvider]) -> None:
        provider = provider_factory()
        if not isinstance(provider, ApprovalProvider):
            raise AssertionError("provider does not implement ApprovalProvider v1")
        self._assert_refuses_another_request(provider)
        for resolution in ApprovalResolution:
            self._assert_reaches_a_terminal_resolution(provider_factory(), resolution)

    def _answer(
        self,
        provider: ApprovalProvider,
        suspended: SuspendedApproval,
        action: ApprovalAction,
        *,
        request: ApprovalRequest,
        acts: Sequence[ApprovalAction],
        unexpected: str | None = None,
    ) -> SuspendedApproval | ResolvedApproval:
        """Put one act to the provider and hold the derivation rule on its answer.

        ``unexpected`` names what the provider would have accepted if it answers
        at all where the contract requires it to refuse.

        The kit's own copies of the request and of the acts are taken before
        the provider is given them — the acts here, the request in ``_suspend``
        — for the reason the core takes them
        (`domain/foreign.py`, input side): the provider is handed those very
        objects, ``object.__setattr__`` writes a frozen dataclass, and a kit
        that judged an answer against evidence the provider had just rewritten
        would pass the provider it exists to fail — as it did.
        """
        judged = core_owned_request(request)
        submitted = tuple(core_owned_act(act) for act in acts)
        progress = provider.resume(suspended, action)
        unsupported = unsupported_by_acts(progress, judged, submitted)
        if unexpected is not None:
            raise AssertionError(
                f"{unexpected}: {unsupported or 'it answered where it must refuse'}"
            )
        if unsupported is not None:
            raise AssertionError(f"provider returned a result no act supports: {unsupported}")
        return progress

    def _suspend(
        self, provider: ApprovalProvider, request: ApprovalRequest
    ) -> tuple[SuspendedApproval, ApprovalRequest]:
        """Open a suspension, and answer with the request the kit will judge by.

        The same rule as ``_answer`` and the earlier half of it. ``suspend`` is
        handed a request, and the request is what every later check is *about*
        — the decision the resolution must name, the approval and scope the
        acts must carry. A kit that kept the object it had just given away
        judged by whatever the provider wrote into it: one
        ``object.__setattr__`` on a frozen dataclass moved the decision, and the
        provider then resolved an approval nobody suspended and passed.

        So the kit's own copy is taken here, before the call, and returned;
        from here on the request the provider was handed is the provider's, and
        every check reads a value it has never seen.
        """
        judged = core_owned_request(request)
        suspended = provider.suspend(request)
        if suspended.request != judged:
            raise AssertionError("suspend returned a different request")
        if suspended.scope != judged.scope:
            raise AssertionError("suspend returned a different scope")
        return suspended, judged

    def _witness(
        self, request: ApprovalRequest, resolution: ApprovalResolution
    ) -> tuple[ApprovalAction, ...]:
        """Take the provider's people, and check they put this case to it.

        A fixture is the provider's own witness; the kit will not treat acts it
        cannot recognise as the acts of this request, nor a sequence that ends on
        an approval as an exercise of rejection.
        """
        acts = tuple(self._completion_actions(request, resolution))
        if not acts:
            raise AssertionError("completion fixture supplied no person actions")
        for act in acts:
            if act.approval_ref != request.approval_ref:
                raise AssertionError("completion fixture acts on another approval")
            if act.scope != request.scope:
                raise AssertionError("completion fixture acts from another scope")
        if acts[-1].resolution is not resolution:
            raise AssertionError(
                f"completion fixture does not put the {resolution.value} case to the provider"
            )
        return acts

    def _assert_refuses(
        self,
        provider: ApprovalProvider,
        suspended: SuspendedApproval,
        action: ApprovalAction,
        *,
        request: ApprovalRequest,
        unexpected: str,
    ) -> None:
        """Hold a path where no act is legitimately put: refusal is the only answer.

        What the contract requires is *a* refusal, not a particular error: the
        kit suppresses the published base of the shipped errors, so a provider
        that refuses with any of them refuses, and the kit does not smuggle a
        requirement the documentation never states (article 2).
        """
        with suppress(ApprovalProviderError):
            self._answer(
                provider,
                suspended,
                action,
                request=request,
                acts=(),
                unexpected=unexpected,
            )

    def _assert_refuses_another_request(self, provider: ApprovalProvider) -> None:
        suspended, request = self._suspend(
            provider, _request("conformance-refusals", "conformance-decision-refusals")
        )

        self._assert_refuses(
            provider,
            suspended,
            ApprovalAction(
                approval_ref="another-approval",
                scope=request.scope,
                person="conformance-person",
                resolution=ApprovalResolution.APPROVE,
            ),
            request=request,
            unexpected="provider accepted an action for another request",
        )
        self._assert_refuses(
            provider,
            suspended,
            ApprovalAction(
                approval_ref=request.approval_ref,
                scope="another-scope",
                person="conformance-person",
                resolution=ApprovalResolution.APPROVE,
            ),
            request=request,
            unexpected="provider accepted an action from a different scope",
        )

        forged_request = _request("never-issued-approval", "never-issued-decision")
        self._assert_refuses(
            provider,
            SuspendedApproval(request=forged_request, scope=request.scope),
            _action(forged_request, "conformance-person"),
            request=forged_request,
            unexpected="provider accepted a suspension it never issued",
        )

    def _assert_reaches_a_terminal_resolution(
        self, provider: ApprovalProvider, resolution: ApprovalResolution
    ) -> None:
        """Drive one provider-owned finite fixture through the case under test.

        The whole fixture is put, never a prefix of it. Designation and
        signature count stay with the provider (article 12), and the fixture is
        the provider's own statement of the finite sequence that completes this
        case — so a provider that resolves before the sequence is spent took
        fewer signatures than it promised, which is the one thing article 12
        names the kit as the contract for. A drive that stopped on the first
        resolution could never see it: act one already carries the case under
        test, so every later check is derivable from that act alone.
        """
        approval_ref = f"conformance-{resolution.value}"
        decision_ref = f"conformance-decision-{resolution.value}"
        suspended, request = self._suspend(provider, _request(approval_ref, decision_ref))
        acts = self._witness(request, resolution)
        submitted: list[ApprovalAction] = []
        progress: SuspendedApproval | ResolvedApproval = suspended
        for action in acts:
            submitted.append(action)
            progress = self._answer(provider, suspended, action, request=request, acts=submitted)
            if isinstance(progress, ResolvedApproval):
                if len(submitted) != len(acts):
                    raise AssertionError(
                        f"provider resolved after {len(submitted)} of the {len(acts)} acts "
                        "its own completion fixture promised would be needed"
                    )
                break
            suspended = progress
        else:
            raise AssertionError("provider did not resolve after its completion fixture")

        assert isinstance(progress, ResolvedApproval)
        if progress.resolution is not resolution:
            raise AssertionError(
                f"provider did not record the {resolution.value} case it was driven through"
            )
        # Against the literals this drive issued, and not against any object a
        # provider has held: the two are the same only while nobody has written
        # to the request, which is the thing being checked.
        if (progress.approval_ref, progress.decision_ref) != (approval_ref, decision_ref):
            raise AssertionError(
                "provider resolved an approval or a decision other than the one the kit issued"
            )
        try:
            self._answer(
                provider,
                suspended,
                submitted[-1],
                request=request,
                acts=submitted,
                unexpected="provider accepted a second action on a terminal approval",
            )
        except ApprovalProviderError:
            return
