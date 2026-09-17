# SPDX-License-Identifier: Apache-2.0
"""The seam that judges an approval provider's answer and records it.

One rule judges every answer, here and in the conformance kit alike: a result
must be *derivable* from the acts legitimately put to the provider for this
suspension — their identity, their verdict, their reason — and from the
suspension those acts belong to. The rule lives here, in the core, because the
core is the only code between a third-party provider and the effect; the kit
(article 8) imports it rather than keeping a second copy, so a provider that
runs the kit is judged by the rule that will judge it at runtime, and a provider
that never runs the kit is judged all the same.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import NoReturn, Protocol

from ..domain.foreign import ForeignValueRefused, core_owned_input
from .interfaces import (
    ApprovalAction,
    ApprovalProvider,
    ApprovalProviderError,
    ApprovalRequest,
    ResolvedApproval,
    SuspendedApproval,
)


def core_owned_request(request: ApprovalRequest) -> ApprovalRequest:
    """The core's own copy of a request that is about to cross the port."""
    return core_owned_input(ApprovalRequest, request)


def core_owned_suspension(suspended: SuspendedApproval) -> SuspendedApproval:
    """The core's own copy of a suspension, its request rebuilt with it."""
    return core_owned_input(SuspendedApproval, suspended, request=core_owned_request)


def core_owned_act(action: ApprovalAction) -> ApprovalAction:
    """The core's own copy of the act a person submitted.

    This is the value the derivation rule is *about*. It has to be the core's
    own and not the object the provider is handed, because `frozen=True`
    refuses `setattr` and refuses nothing to `object.__setattr__`: a provider
    given the act the judgement compares against can rewrite the judgement's
    own evidence, and the answer it then returns is derivable from an act
    nobody made (articles 3, 8 and 12).
    """
    return core_owned_input(ApprovalAction, action)


class UnrecordedApprovalResolution(RuntimeError):
    """A terminal record could not be appended, so no caller may act on it."""


class ApprovalAnswerRefused(ApprovalProviderError):
    """A provider answer no act of this approval supports, refused by the core."""


@dataclass(frozen=True)
class RefusedProviderAnswer:
    """The record a refused provider answer leaves, built from the core's facts.

    Article 12: the three outcomes of article 1 are complete, so this shape
    carries no verdict of its own and nothing the provider said — only the
    suspension the act was put for, the person who made it, and why it was
    refused. A refusal is a refusal in the record, never a decision.

    One shape for the two refusals there are: the core declining an answer no
    act supports, and the provider declining an act it may decline. They differ
    in who raises and in what the caller publishes, never in what the record
    holds, because neither is a verdict and both leave a wait unanswered.
    """

    approval_ref: str
    decision_ref: str
    scope: str
    person: str
    complaint: str


class ApprovalResolutionRecorder(Protocol):
    def record(self, resolution: ResolvedApproval) -> None:
        """Append one terminal approval record referencing its suspended decision."""
        ...

    def record_refusal(self, refusal: RefusedProviderAnswer) -> None:
        """Append the refusal of a provider answer that no act supports."""
        ...


def unsupported_by_acts(
    result: object,
    request: ApprovalRequest,
    acts: Sequence[ApprovalAction],
) -> str | None:
    """Say why ``result`` is not derivable from ``acts``, or ``None`` if it is.

    ``acts`` are the acts legitimately put to the provider for ``request``, in
    order; on a path where no act was legitimately put — an action for another
    approval, a suspension the provider never issued — ``acts`` is empty and no
    resolution at all is derivable. A value that is not one of the two shapes of
    the v1 contract is not an answer, whatever members it copies.

    Two properties of *how* this reads matter as much as what it compares.
    ``type(result) in`` and not ``isinstance``: ``isinstance`` asks the object
    what class it belongs to, and an object that defines ``__class__`` as a
    property answers whatever it likes, with no subclass and no monkeypatch.
    And every member is read into a local exactly once, so what the checks
    compare and what a caller of this function goes on to use are one value —
    a member read twice is a member a provider can answer twice, differently.
    """
    if type(result) not in (SuspendedApproval, ResolvedApproval):
        return "it is not a value of the ApprovalProvider v1 contract"
    if result.approval_ref != request.approval_ref:
        return "it names another approval"
    if result.scope != request.scope:
        return "it names another scope"
    if type(result) is SuspendedApproval:
        if result.request != request:
            return "it names another suspended request"
        return None
    assert type(result) is ResolvedApproval
    decision_ref = result.decision_ref
    person = result.person
    resolution = result.resolution
    reason = result.reason
    if decision_ref != request.decision_ref:
        return "it names another decision"
    if not acts:
        return "no act of any person was put to it"
    act = acts[-1]
    if person != act.person:
        return f"it attributes the act of {act.person!r} to {person!r}"
    if resolution is not act.resolution:
        return (
            f"it records {resolution.value!r} where the person's act was {act.resolution.value!r}"
        )
    if reason != act.reason:
        return "it rewrites the reason the person gave"
    return None


def _acts_put_to(
    action: ApprovalAction, suspended: SuspendedApproval
) -> tuple[ApprovalAction, ...]:
    """The acts this call legitimately puts to the provider for this suspension.

    An action that names another approval or another scope is not an act of this
    approval; a provider must refuse it, and a provider that answers anyway is
    answering with no act behind it.
    """
    if action.approval_ref != suspended.approval_ref or action.scope != suspended.scope:
        return ()
    return (action,)


def resume_through_provider(
    provider: ApprovalProvider,
    suspended: SuspendedApproval,
    action: ApprovalAction,
    *,
    recorder: ApprovalResolutionRecorder,
    apply: Callable[[ResolvedApproval], object] | None = None,
) -> SuspendedApproval | ResolvedApproval:
    """Judge a provider's answer, then record a terminal one before it can resume.

    Article 3: an approval or a rejection is a new record that references the
    suspended decision, and fail-closed is never the property traded away — a
    resolution the store could not append is not handed back to a caller that
    would resume on it. Article 12 and article 8's Why: the core never takes a
    provider at its word. An answer that is not derivable from the act put to it
    — a value outside the v1 contract, a result bound to another approval,
    decision or scope, a verdict, person or reason no act supports — is refused
    here, recorded as a refusal, and never handed back or recorded as a decision,
    so the plugin port cannot become a way to widen policy. A provider's own
    refusal of the act is recorded the same way and then re-raised as the
    provider spelled it: the record must hold every act that ended nowhere, and
    the class must survive, because what a caller publishes for « this act
    names another suspension » is not what it publishes for « this component
    gave no answer » (articles 1, 2 and 8).

    What is recorded and what is handed back is the core's own value, built from
    ``suspended.request`` and the act put to the provider — never the object the
    provider returned. The provider owns that object's memory, so every read of
    it after the check is a fresh answer it can choose; the core holds every
    fact a resolution carries, so it never has to take one. And what is recorded
    and what is handed back are two objects, because the recorder is a port as
    much as the provider is: one object crossing both ways is a record whose
    keeper answers the caller.

    And the facts the core holds are taken as its own *before* the call, for
    the mirror-image reason (`domain/foreign.py`, input side). Both arguments
    are handed to the provider, and both were also what the judgement read
    afterwards: the act it compares against and the request whose decision it
    names. A frozen dataclass is frozen against ``setattr`` and open to
    ``object.__setattr__``, so a provider given those objects rewrote the
    evidence it was about to be judged by — one line, no monkeypatch, no
    knowledge of any caller. From here on ``held`` and ``acts`` are copies
    nothing outside the core has ever seen, and ``suspended`` and ``action``
    are the provider's to do as it likes with.

    ``apply`` is the core's own writer of the wait this act ends, and it is the
    reason a resolution is applied at all. The store a suspension waits in is
    the core's; no provider owns it, and the shipped provider that used to
    write it made the transition a property of that implementation rather than
    of the port — a conformant provider from elsewhere answered a person and
    left the wait pending (articles 2, 3 and 12). So the caller that owns the
    store hands its writer in here, and every provider's judged answer is
    applied by it.

    It is called after the judgement and before the record. A writer that
    refuses the act — a wait another act ended first, one that ran out —
    refuses it under the store's own lock, and a refusal there must leave no
    record of an act nothing applied; its refusal is the caller's to classify
    and passes through untouched. A caller that hands none judges an answer and
    writes nothing, which is what a case exercising the judgement alone wants.
    """
    try:
        held = core_owned_suspension(suspended)
        submitted = core_owned_act(action)
    except ForeignValueRefused as refused:
        raise ApprovalAnswerRefused(
            f"an approval this core cannot take as its own was put to a provider: {refused}"
        ) from refused
    acts = _acts_put_to(submitted, held)
    try:
        progress = provider.resume(suspended, action)
    except ApprovalProviderError as refused:
        # The port's own vocabulary: a provider refusing an act it may refuse
        # is the contract working, and the refusal reaches the caller as the
        # provider spelled it — the class is what a caller publishes a code
        # for, and an act naming another suspension is a request received and
        # rejected, not a component that gave no answer (articles 1 and 2).
        #
        # Recorded first, all the same. This is the one failure the port
        # contractually allows a provider to signal, and it used to leave no
        # entry at all: an operator reading the log could not tell an act a
        # provider refused from an act nobody ever put (articles 2 and 8). The
        # complaint names the class and nothing the provider said, for the
        # reason `RefusedProviderAnswer` gives.
        _record_refusal(
            held,
            submitted,
            f"the provider refused the act with {type(refused).__name__}",
            recorder=recorder,
        )
        raise
    except Exception as error:
        # Anything else is not an answer at all. A provider is code this
        # project did not write, so « it raised » is as much a provider
        # behaviour as « it answered »; the core records the refusal from its
        # own facts and refuses, rather than letting a foreign exception become
        # the daemon's unclassified failure (articles 2 and 8).
        _refuse(held, submitted, f"it raised {type(error).__name__}", recorder=recorder)
    complaint = unsupported_by_acts(progress, held.request, acts)
    if complaint is not None:
        _refuse(held, submitted, complaint, recorder=recorder)
    if type(progress) is SuspendedApproval:
        # The rule has already held that the provider is still waiting on this
        # request; `held` is the core's own value that says so.
        return held
    assert acts, "a resolution with no act behind it is refused above"
    # The core's own writer, before the record and from the core's own facts.
    # Its own value, for the reason `_resolution_of` gives: three ports are
    # handed a resolution here, and each is handed one no other has held.
    if apply is not None:
        apply(_resolution_of(held, acts[-1]))
    # The recorder is a port too, and the rule reaches one hop further than the
    # provider: what this function returns is what the caller resumes the
    # suspended effect on. Handing the recorder that object let it answer the
    # caller — one `object.__setattr__` on a frozen record inside `record`, and
    # an act submitted as one person approving came back as another person
    # rejecting. So the record and the answer are two objects, each built here
    # from `held` and `acts[-1]`, and the answer is built *after* the call, the
    # way `_refuse` reads nothing of the refusal back and the way the answer to
    # the provider is built after `resume` (articles 3 and 12).
    try:
        recorder.record(_resolution_of(held, acts[-1]))
    except Exception as error:
        raise UnrecordedApprovalResolution(
            f"approval {held.approval_ref!r} resolved but could not be recorded"
        ) from error
    return _resolution_of(held, acts[-1])


def _resolution_of(suspended: SuspendedApproval, act: ApprovalAction) -> ResolvedApproval:
    """The terminal record, built from the core's own facts and nothing else.

    Called once per recipient rather than once in all — the core's writer, the
    recorder, and the caller's answer: a frozen record is frozen against
    ``setattr`` and open to ``object.__setattr__``, so the object a recorder is
    handed is an object a recorder can write to, and the caller is answered
    with one no port has ever held. The writer is the core's own and could take
    the same object; it is given its own so that a reader does not have to work
    out which of the three may be written to.
    """
    return ResolvedApproval(
        approval_ref=suspended.approval_ref,
        decision_ref=suspended.request.decision_ref,
        scope=suspended.scope,
        person=act.person,
        resolution=act.resolution,
        reason=act.reason,
    )


def _record_refusal(
    suspended: SuspendedApproval,
    action: ApprovalAction,
    complaint: str,
    *,
    recorder: ApprovalResolutionRecorder,
) -> None:
    """Record one refused act from the core's own facts; the caller raises.

    Two refusals reach here and they are not the same refusal. One is the
    core's, of an answer no act of this approval supports. The other is the
    provider's own, of an act it may refuse — which is the contract working,
    and which still leaves a wait somebody was told to answer unanswered, so
    the record holds it too (article 2). What is written is the same either
    way, because the entry carries only the core's facts and no verdict: a
    refusal is a refusal in the record and never a decision (article 12).

    Split out of `_refuse` because who raises differs. The core's refusal is
    raised as the core's own class; the provider's is re-raised exactly as the
    provider spelled it, so the caller can publish the code its class means.
    """
    refusal = RefusedProviderAnswer(
        approval_ref=suspended.approval_ref,
        decision_ref=suspended.request.decision_ref,
        scope=suspended.scope,
        person=action.person,
        complaint=complaint,
    )
    try:
        recorder.record_refusal(refusal)
    except Exception as error:
        raise UnrecordedApprovalResolution(
            f"the act on approval {suspended.approval_ref!r} was refused "
            f"({complaint}) and the refusal could not be recorded"
        ) from error


def _refuse(
    suspended: SuspendedApproval,
    action: ApprovalAction,
    complaint: str,
    *,
    recorder: ApprovalResolutionRecorder,
) -> NoReturn:
    """Record the core's own refusal, then raise it as the core's. Never returns."""
    _record_refusal(suspended, action, complaint, recorder=recorder)
    raise ApprovalAnswerRefused(
        f"provider answer for approval {suspended.approval_ref!r} is refused: {complaint}"
    )
