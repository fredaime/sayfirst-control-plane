# SPDX-License-Identifier: Apache-2.0
"""The two approval operations, answered from the one store the daemon keeps.

Article 12's simple form becomes reachable by a person here: a read that says
where a suspension stands, and one act that ends it. Neither operation judges
anything of its own — the provider behind the port judges the act (article 3),
and the store is the authority for the wait — so this module is the translation
between a connection and those two, plus the one write that translation owes.

That write is here because the store is the core's. The provider judges; the
core applies. It used to be applied inside the shipped provider, which left a
conformant provider from elsewhere answering a person over a wait it never
ended (articles 2, 3 and 12), so `write_resolution` is handed to the judgement
from here and is the daemon's one writer of a resolution.

Three properties of the translation itself are the rest of the design.

The person is the connection's verified principal, never a member of the
request. The published `approval-resolve-request` carries no such member, and a
body that names one is refused as any unknown member is: a request that could
say who acted would let one caller record another's act (articles 3 and 6).

Every read renders the state AS OF now, which is the record's own rule
(`Approval.state_at`) and the reason a wait that ran out reads `expired`
before any sweep has run (article 2). The instant is the store's clock and not
one of this module's, because a route with a clock of its own would judge an
act late that the store accepted.

And the claim protocol is invisible here. An ask that is about to spend an
approval claims it first; a claimed approval is still `approved` and still
somebody's act, so that is what a reader is told — the published state
vocabulary has no « claimed », and inventing one would be vocabulary the
contract never carried (article 13). Nothing here claims, consumes or opens:
opening a wait is the ask path's, because the question a re-ask is matched by
is established from the connection and the ask, and the one execution a
resolution authorises is spent where the decision that spends it is recorded.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from typing import Final

from sayfirst_contract.generation import CONTRACT_GENERATION

from ...application.approvals import (
    ApprovalStore,
    ApprovalUnknown,
    EventsRecorder,
    write_resolution,
)
from ...application.decisions import DecisionService
from ...domain.approval import TERMINAL, Approval
from ...plugins.approval import UnrecordedApprovalResolution, resume_through_provider
from ...plugins.interfaces import (
    ApprovalAction,
    ApprovalAlreadyResolved,
    ApprovalProvider,
    ApprovalProviderError,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    SuspendedApproval,
)


class ApprovalScopeRequired(ValueError):
    """A read named no scope. Article 5: the default never applies to a read."""

    code = "scope_required"


class ApprovalNotKept(LookupError):
    """No approval of that reference is kept in that scope.

    The store's own refusal, answered as the code the registry publishes for
    it — registered exactly as `decision_not_found` is, so that the two « no
    such record » codes of this contract say the same thing about themselves.
    """

    code = "approval_unknown"


class ApprovalResolvedAlready(ValueError):
    """An act on an approval whose wait is over, refused rather than applied.

    Article 3: a resolution is a new record referencing the suspended decision,
    never an edit of one, so a second act on a terminal approval is refused —
    the question was received and rejected, which is what this code's class
    says of it.
    """

    code = "approval_resolved"


class ResolutionMalformed(ValueError):
    """The act does not describe the approval its own route names."""

    code = "request_malformed"


class ApprovalProviderUnavailable(RuntimeError):
    """The provider behind the port could not answer, so no act was applied.

    A could-not-ask, never a refusal, and the same code the ask path answers
    when a suspension could not be put to the provider: a component outage
    decided nothing, and telling the person their approval was rejected would
    be an absent answer rendered as a refusal (articles 1 and 2). It is
    retryable: where the provider gave no answer, nothing happened and the
    record is still pending, so the person may act again once the provider
    answers; where the provider answered and only the record of the act could
    not be appended, the resolution is already written, and a second act is
    answered `approval_resolved` — the truthful answer to a wait that is over.

    Every way a provider can fail *to answer* arrives here: an exception it
    raises is not a contract at all, and a refusal of the port it does not
    spell more precisely says only that it would not answer. So does the one
    arm on which the act *was* applied — a resolution the recorder could not
    append after the core wrote it — with a message that says so. The
    alternative to catching those three is the daemon answering « it failed
    for a reason it cannot classify » for a plugin doing exactly what a plugin
    does (articles 2 and 8).

    The refusals of the port that *are* answers are taken out first and keep
    their own codes: a wait already over is `approval_resolved`, and an act or
    a suspension naming another request is `request_malformed` — received and
    rejected, permanent, and never a component this deployment should be told
    to retry (article 1).
    """

    code = "approval_provider_unavailable"


READ_REFUSALS: Final[tuple[type[Exception], ...]] = (
    ApprovalScopeRequired,
    ApprovalNotKept,
)
"""What `read_approval` answers, which is what that route publishes and no more."""

RESOLVE_REFUSALS: Final[tuple[type[Exception], ...]] = (
    ApprovalNotKept,
    ApprovalResolvedAlready,
    ResolutionMalformed,
    ApprovalProviderUnavailable,
)
"""What `resolve_approval` answers, likewise.

Two tuples rather than one, because the two routes publish two sets of codes
and a shared tuple lets either answer a code its own route does not publish —
`scope_required` on the resolution, `approval_resolved` on the read. Neither is
reachable today (the read raises no act's refusal, and the resolution's scope is
held non-empty by the published schema), which is exactly when a boundary is
cheap to draw (article 13).
"""


class ApprovalRoutes:
    """Serve the read and the resolution out of the composed store and provider.

    Built over the decision service rather than over the two directly, because
    the service composes them as a pair and refuses the halves: a route that
    read a store from one place and a provider from another could be handed an
    act for a wait the provider knows nothing about. The provider is the one
    the plugin registry composed and the composition record names, and the
    store is the one the ask path opens waits in — one store, one clock, one
    authority (articles 2 and 3).
    """

    def __init__(self, decisions: DecisionService) -> None:
        self.decisions = decisions

    @property
    def served(self) -> bool:
        """Whether this deployment composed approvals at all.

        A composition that kept neither store nor provider suspends with no
        reference, and there is no approval for either operation to be about.
        Neither publishes a code for « there is no approval authority here »,
        and answering `approval_unknown` would claim a store was consulted
        (article 2), so such a deployment does not serve them.
        """
        return self.decisions.approvals is not None

    def read(self, scope: str, approval_ref: str) -> dict[str, object]:
        """The approval as of now, as the published `approval-result` document."""
        store = self._store()
        return self._kept(store, scope, approval_ref).to_document(
            store.clock(), CONTRACT_GENERATION
        )

    def resolve(
        self, approval_ref: str, document: Mapping[str, object], *, person: str
    ) -> dict[str, object]:
        """Apply one person's act to a pending approval, and answer the record it left.

        The act crosses the port through `resume_through_provider`, which judges
        what the provider answers, applies the judged resolution through the
        core's own writer, and records it before this caller can act on it
        (articles 3 and 8). The answer is read back out of the store afterwards
        rather than built from the act: what a person is told is what was
        written down, and a provider that answered a continued suspension has
        changed nothing, so the record still reads `pending` and says so.

        Two refusals are answers here and keep their own codes: a wait already
        over is `approval_resolved`, and an act naming another request than the
        one it is applied to is `request_malformed`. Every other one is
        `approval_provider_unavailable`: the code the ask path already answers
        for a provider that could not take a suspension, published on this
        route too, and a could-not-ask rather than a refusal (articles 1 and
        2). Where the provider gave no answer the record stays pending and the
        person may act again; where it answered and only the record of the act
        could not be appended, the resolution is written and a second act is
        answered `approval_resolved`. A reference the sweep forgot between the
        read and the write is `approval_unknown`, as a read of it would say.
        """
        store = self._store()
        provider = self._provider()
        asked = self._act_names(document, approval_ref)
        scope = asked.scope
        kept = self._kept(store, scope, approval_ref)
        # One reading of the clock for one judgement: asking twice would judge
        # the state against one instant and report it against another.
        state = kept.state_at(store.clock())
        if state in TERMINAL:
            raise ApprovalResolvedAlready(f"approval {approval_ref!r} is already {state.value}")
        action = ApprovalAction(
            approval_ref=approval_ref,
            scope=scope,
            person=person,
            resolution=asked.resolution,
            reason=asked.reason,
        )
        try:
            resume_through_provider(
                provider,
                _suspension_of(kept),
                action,
                recorder=EventsRecorder(self.decisions.events, clock=store.clock),
                # The store is the core's and this route is its one writer, so
                # the transition belongs to the core whatever provider judged
                # the act: a conformant provider from elsewhere ends the wait
                # exactly as the shipped one does (articles 3 and 12).
                apply=partial(write_resolution, store),
            )
        except ApprovalUnknown as unknown:
            # The wait ran out and the sweep forgot the record between the
            # read above and the write: the reference is no longer kept, which
            # is what a read of it would now say too, so the same code answers
            # (article 2) rather than a failure the daemon cannot classify.
            raise ApprovalNotKept(str(unknown)) from unknown
        except ApprovalAlreadyResolved as resolved:
            # The store ended the wait between the read above and the act — it
            # ran out, or another act landed first. The store is the authority
            # for that, so its refusal is the answer and not a defect.
            raise ApprovalResolvedAlready(str(resolved)) from resolved
        except ApprovalRequestMismatch as mismatch:
            # An act, or a suspension, naming another request than the one it
            # is applied to. The provider answered — it refused — so nothing
            # was retried into existence by asking again, and article 1 keeps
            # a request received and rejected apart from a component that gave
            # no answer at all (article 2).
            raise ResolutionMalformed(str(mismatch)) from mismatch
        except UnrecordedApprovalResolution as unrecorded:
            # The provider answered and the core wrote the resolution; only the
            # record of the act could not be appended. The wait is over, so a
            # retry is answered `approval_resolved` — and this answer says what
            # happened rather than claiming nothing did (article 2).
            raise ApprovalProviderUnavailable(
                f"the act was applied but could not be recorded: {unrecorded}"
            ) from unrecorded
        except ApprovalProviderError as unavailable:
            # Caught after the two refusals above, because both are subclasses
            # of this one and both are answers rather than outages.
            raise ApprovalProviderUnavailable(
                f"the approval provider could not answer, so no act was applied: {unavailable}"
            ) from unavailable
        return self.read(scope, approval_ref)

    def _act_names(self, document: Mapping[str, object], approval_ref: str) -> _Act:
        """The act this body describes, held against the route that carried it.

        The body's own `approval_ref` is a member of the published request, so
        a body naming one approval on the route of another is two statements
        that disagree; neither is preferred and the request is refused
        (article 2). The schema has already held the types and the resolution's
        two values before anything reaches here.
        """
        named = document.get("approval_ref")
        if named != approval_ref:
            raise ResolutionMalformed(
                f"approval_ref {named!r} is not the approval this route names"
            )
        scope = document.get("scope")
        assert isinstance(scope, str), "the published schema has held scope"
        resolution = document.get("resolution")
        assert isinstance(resolution, str), "the published schema has held resolution"
        reason = document.get("reason")
        return _Act(
            scope=scope,
            resolution=ApprovalResolution(resolution),
            reason=reason if isinstance(reason, str) else None,
        )

    def _kept(self, store: ApprovalStore, scope: str, approval_ref: str) -> Approval:
        if not scope:
            raise ApprovalScopeRequired("scope is required")
        try:
            return store.read(scope, approval_ref)
        except ApprovalUnknown as unknown:
            raise ApprovalNotKept(str(unknown)) from unknown

    def _store(self) -> ApprovalStore:
        store = self.decisions.approvals
        assert store is not None, "an unserved operation is refused before it is answered"
        return store

    def _provider(self) -> ApprovalProvider:
        provider = self.decisions.approval_provider
        assert provider is not None, "a store and its provider are composed together"
        return provider


@dataclass(frozen=True)
class _Act:
    """What the body said, once the schema has held it: scope, verdict, reason."""

    scope: str
    resolution: ApprovalResolution
    reason: str | None


def _suspension_of(kept: Approval) -> SuspendedApproval:
    """The port's suspension, rebuilt from the record this core holds.

    The port's request carries the question's bounds and not the question: what
    makes a re-ask the same ask is the core's to hold, and a provider is never
    asked to supply it (article 3). Every member here is read off the stored
    approval, so nothing a caller sent describes the suspension an act is
    applied to.
    """
    return SuspendedApproval(
        request=ApprovalRequest(
            approval_ref=kept.approval_ref,
            decision_ref=kept.decision_ref,
            scope=kept.scope,
            capability=kept.capability,
            requested_at=kept.requested_at,
            deadline=kept.deadline,
        ),
        scope=kept.scope,
    )
