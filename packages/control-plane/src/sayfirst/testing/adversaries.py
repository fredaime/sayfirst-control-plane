# SPDX-License-Identifier: Apache-2.0
"""The approval kit's own adversarial catalogue.

Article 8: "a provider that does not pass it is not a provider". A kit is only
worth that sentence if it is known to fail the providers it exists to fail, so
the kit ships the liars with the suite: one deliberately wrong provider per way
an approval answer can fail to be derivable from the acts of the people, and one
deliberately wrong completion fixture per way a provider could try to escape the
suite through the fixture it supplies. ``test_approval_conformance_kit.py``
asserts the kit fails every one of them. A future path that escapes the kit fails
that meta-test, rather than a review three rounds later.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from sayfirst_control_plane.plugins.defaults import SingleApprover
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)

from .approval import DEADLINE, REQUESTED_AT, ApprovalCompletionActions


@dataclass(frozen=True)
class AdversarialApprovalProvider:
    """One deliberately wrong provider, and the lie it tells."""

    name: str
    lie: str
    factory: Callable[[], ApprovalProvider]


@dataclass(frozen=True)
class AdversarialCompletionFixture:
    """One deliberately wrong completion fixture, and the lie it tells."""

    name: str
    lie: str
    fixture: ApprovalCompletionActions


class _HonestlyStructured:
    """An adversary that answers honestly, then rewrites part of the answer.

    Everything about it is well formed — it refuses another request, another
    scope and a suspension it never issued — so nothing but the derivation rule
    catches it.
    """

    def __init__(self) -> None:
        self._honest = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self._honest.suspend(request)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        return self._rewrite(self._honest.resume(suspended, action), action)

    def _rewrite(
        self, resolved: ResolvedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        raise NotImplementedError


def _rebuild(resolved: ResolvedApproval, **changes: object) -> ResolvedApproval:
    members: dict[str, object] = {
        "approval_ref": resolved.approval_ref,
        "decision_ref": resolved.decision_ref,
        "scope": resolved.scope,
        "person": resolved.person,
        "resolution": resolved.resolution,
        "reason": resolved.reason,
    }
    members.update(changes)
    return ResolvedApproval(**members)  # type: ignore[arg-type]


class InvertingApprover(_HonestlyStructured):
    """Records the opposite of every verdict a person gives."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        opposite = (
            ApprovalResolution.REJECT
            if resolved.resolution is ApprovalResolution.APPROVE
            else ApprovalResolution.APPROVE
        )
        return _rebuild(resolved, resolution=opposite)


class ApprovesOnRejectionApprover(_HonestlyStructured):
    """Passes approvals through untouched and records rejections as approvals."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        return _rebuild(resolved, resolution=ApprovalResolution.APPROVE)


class ReattributingApprover(_HonestlyStructured):
    """Records one person's act under another person's name."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        return _rebuild(resolved, person="somebody-who-never-acted")


class ReasonInventingApprover(_HonestlyStructured):
    """Records a reason no person gave."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        return _rebuild(resolved, reason="reviewed elsewhere")


class ForeignApprovalApprover(_HonestlyStructured):
    """Answers for another approval than the one suspended."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        return _rebuild(resolved, approval_ref="another-approval")


class ForeignDecisionApprover(_HonestlyStructured):
    """Answers for another decision than the one the approval suspends."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        return _rebuild(resolved, decision_ref="another-decision")


class ForeignScopeApprover(_HonestlyStructured):
    """Answers in another scope than the one the request belongs to (article 5)."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> ResolvedApproval:
        return _rebuild(resolved, scope="another-scope")


class ForeignWaitApprover(_HonestlyStructured):
    """Keeps waiting, but on another decision than the one it was given."""

    def _rewrite(self, resolved: ResolvedApproval, action: ApprovalAction) -> SuspendedApproval:
        request = ApprovalRequest(
            approval_ref=resolved.approval_ref,
            decision_ref="another-decision",
            scope=resolved.scope,
            capability="storage.write",
            requested_at=REQUESTED_AT,
            deadline=DEADLINE,
        )
        return SuspendedApproval(request=request, scope=request.scope)


class ActlessApprover:
    """Resolves any suspension it is shown, with no act of any person behind it."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        return ResolvedApproval(
            approval_ref=suspended.approval_ref,
            decision_ref=suspended.request.decision_ref,
            scope=suspended.scope,
            person="conformance-person",
            resolution=ApprovalResolution.APPROVE,
        )


class TwoFacedAnswer:
    """An answer that tells the truth while it is read and lies once it is not.

    It is not a `ResolvedApproval`, and it says it is: `__class__` is a property,
    so `isinstance` — a question the object answers about itself — says yes with
    no subclass and no monkeypatch. Its members are properties too, so what a
    check reads and what a recorder or a caller reads afterwards are two reads of
    memory the provider owns, and the provider picks the second by counting the
    first.

    It stays honest for `_GRACE` reads, which no single drive of the kit or of
    the core's seam reaches. That is the point: a finite drive cannot outlast a
    patient liar, so what catches this one is not how often it is read but what
    it is. `type(result) in (...)` is that check; `isinstance` is not.
    """

    _GRACE = 64

    def __init__(self, honest: ResolvedApproval) -> None:
        self._honest = honest
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
        return self._reads <= self._GRACE

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
    """Answers with something that says it is a resolution and rewrites itself."""

    def __init__(self) -> None:
        self._honest = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self._honest.suspend(request)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> object:
        honest = self._honest.resume(suspended, action)
        if not isinstance(honest, ResolvedApproval):
            return honest
        return TwoFacedAnswer(honest)


class RewritingTheActApprover:
    """Rewrites the act it is handed, then answers honestly from what it wrote.

    Nothing about the answer looks wrong: it is derived from the action this
    provider was given, and the judgement is about that same action. The whole
    of the attack is that the two were one object — ``object.__setattr__``
    writes a frozen dataclass, and no global patch, frame inspection or
    knowledge of the caller's fixture is needed for it.
    """

    def __init__(self) -> None:
        self._honest = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self._honest.suspend(request)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        object.__setattr__(action, "person", "somebody-who-never-acted")
        object.__setattr__(action, "reason", "a reason nobody submitted")
        return self._honest.resume(suspended, action)


class RewritingTheSuspensionApprover:
    """Rewrites the suspension it is handed, so the judge reads its own decision.

    The other argument, the same defect. The decision an approval references is
    the core's fact about which effect is waiting; a provider that can move it
    resolves an approval against a decision nobody suspended.
    """

    def __init__(self) -> None:
        self._honest = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        return self._honest.suspend(request)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        object.__setattr__(suspended.request, "decision_ref", "a-decision-nobody-suspended")
        return self._honest.resume(suspended, action)


class RewritingTheRequestInSuspendApprover:
    """Rewrites the request it is handed to `suspend`, then answers honestly.

    The third argument, and the earliest one. `suspend` is where the core says
    which decision is waiting; a provider that rewrites that request in place
    moves the decision every later check reads, and then every answer it gives
    is derivable from what it wrote. It resolves an approval nobody suspended
    and passes, because the judge and the liar were reading one object.
    """

    def __init__(self) -> None:
        self._honest = SingleApprover()

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        object.__setattr__(request, "decision_ref", "a-decision-nobody-suspended")
        return self._honest.suspend(request)

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        return self._honest.resume(suspended, action)


class NeverResolvingApprover:
    """Answers every act with the same wait, so no act ever ends anything."""

    def __init__(self) -> None:
        self._issued: dict[str, ApprovalRequest] = {}

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        self._issued[request.approval_ref] = request
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> SuspendedApproval:
        if (
            action.approval_ref != suspended.approval_ref
            or action.scope != suspended.scope
            or self._issued.get(suspended.approval_ref) != suspended.request
        ):
            raise ApprovalRequestMismatch("not this suspension")
        return suspended


ADVERSARIAL_APPROVAL_PROVIDERS: tuple[AdversarialApprovalProvider, ...] = (
    AdversarialApprovalProvider("inverting", "inverts-the-verdict", InvertingApprover),
    AdversarialApprovalProvider(
        "approves-on-rejection", "approves-on-rejection", ApprovesOnRejectionApprover
    ),
    AdversarialApprovalProvider("reattributing", "re-attributes-the-act", ReattributingApprover),
    AdversarialApprovalProvider("reason-inventing", "invents-a-reason", ReasonInventingApprover),
    AdversarialApprovalProvider(
        "foreign-approval", "answers-for-another-approval", ForeignApprovalApprover
    ),
    AdversarialApprovalProvider(
        "foreign-decision", "answers-for-another-decision", ForeignDecisionApprover
    ),
    AdversarialApprovalProvider("foreign-scope", "answers-for-another-scope", ForeignScopeApprover),
    AdversarialApprovalProvider("foreign-wait", "waits-on-another-decision", ForeignWaitApprover),
    AdversarialApprovalProvider("actless", "resolves-with-no-act", ActlessApprover),
    AdversarialApprovalProvider("never-resolving", "never-resolves", NeverResolvingApprover),
    AdversarialApprovalProvider(
        "rewrites-the-act", "rewrites-the-act-put-to-it", RewritingTheActApprover
    ),
    AdversarialApprovalProvider(
        "rewrites-the-suspension",
        "rewrites-the-suspension-put-to-it",
        RewritingTheSuspensionApprover,
    ),
    AdversarialApprovalProvider(
        "rewrites-the-request-in-suspend",
        "rewrites-the-request-put-to-suspend",
        RewritingTheRequestInSuspendApprover,
    ),
    AdversarialApprovalProvider(
        "two-faced",
        "rewrites-itself-after-the-check",
        TwoFacedApprover,  # type: ignore[arg-type]
    ),
)


def _always_approving(
    request: ApprovalRequest, resolution: ApprovalResolution
) -> tuple[ApprovalAction, ...]:
    return (
        ApprovalAction(
            approval_ref=request.approval_ref,
            scope=request.scope,
            person="conformance-person",
            resolution=ApprovalResolution.APPROVE,
        ),
    )


def _foreign_approval(
    request: ApprovalRequest, resolution: ApprovalResolution
) -> tuple[ApprovalAction, ...]:
    return (
        ApprovalAction(
            approval_ref="another-approval",
            scope=request.scope,
            person="conformance-person",
            resolution=resolution,
        ),
    )


def _foreign_scope(
    request: ApprovalRequest, resolution: ApprovalResolution
) -> tuple[ApprovalAction, ...]:
    return (
        ApprovalAction(
            approval_ref=request.approval_ref,
            scope="another-scope",
            person="conformance-person",
            resolution=resolution,
        ),
    )


def _no_act(request: ApprovalRequest, resolution: ApprovalResolution) -> Sequence[ApprovalAction]:
    return ()


ADVERSARIAL_COMPLETION_FIXTURES: tuple[AdversarialCompletionFixture, ...] = (
    AdversarialCompletionFixture(
        "always-approving", "never-puts-the-rejection-case", _always_approving
    ),
    AdversarialCompletionFixture("foreign-approval", "acts-on-another-approval", _foreign_approval),
    AdversarialCompletionFixture("foreign-scope", "acts-from-another-scope", _foreign_scope),
    AdversarialCompletionFixture("no-act", "puts-no-act-at-all", _no_act),
)
