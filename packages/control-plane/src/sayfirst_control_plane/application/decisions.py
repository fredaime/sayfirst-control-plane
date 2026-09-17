# SPDX-License-Identifier: Apache-2.0
"""The fixed-order service that turns one question into one 2.1 decision."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from time import sleep
from uuid import uuid4

from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_contract.grants import Grant as PublishedGrant
from sayfirst_contract.grants import GrantConditions as PublishedGrantConditions
from sayfirst_contract.problems import Problem, ProblemCode, problem_retryable

from ..domain.approval import Approval, ApprovalState, Question
from ..domain.evidence_chain import EVALUATION_RECIPE
from ..domain.foreign import core_owned, core_owned_input, core_owned_instant
from ..domain.grant import Grant, mint_grant
from ..domain.policy import DecisionQuestion, Principal, Rule, evaluate, references_read
from ..domain.published_schema import refused_by
from ..plugins.approval import core_owned_request
from ..plugins.interfaces import ApprovalProvider, ApprovalRequest
from ..ports.decision_store import (
    DecisionAppendIndeterminate,
    DecisionPosition,
    DecisionStore,
    core_owned_position,
)
from ..ports.policy_archive import ArchivedPolicy, ArchiveState, PolicyArchive
from ..ports.policy_store import (
    AccessState,
    AccessVerdict,
    LoadedPolicy,
    PolicyStore,
    PolicyUnavailable,
)
from .approvals import ApprovalAlreadyClaimed, ApprovalStore
from .events import Events, NullEvents
from .grants import GrantConnection, GrantConnections, GrantReservation, GrantSignal
from .policy import PolicyService

#: How many times one ask looks for the approval its question has, and how long
#: it pauses between looks, before it answers « contended ». The ask holding the
#: execution is between its own claim and its own append, which is microseconds
#: of work: a few tries over about fifty milliseconds is long enough for that
#: ask to finish — after which this one either finds the approval spent and
#: opens a wait, or finds it given back and claims it — and short enough that
#: nobody waits on a decision. Past that, a retryable answer is better than a
#: loop, because something is wrong that waiting will not fix.
_CLAIM_TRIES = 5
_CLAIM_PAUSE_SECONDS = 0.012

#: The published schema every ask is judged by, whichever surface carried it.
_ASK_SCHEMA = "decision-ask-request"

#: What an ask that pins no arguments digest spells in the question an approval
#: answers. A question with an empty member would match whatever it is compared
#: against, and every member of a `Question` must be there; an absent digest is
#: one question, so the absence is written as a value no digest can take — the
#: published grammar is `sha256:` and sixty-four hexadecimal characters.
_NO_DIGEST = "-"


def _instant(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class GrantSettings:
    default_lifetime_seconds: int = 300
    max_lifetime_seconds: int = 3600
    heartbeat_seconds: int = 5

    def __post_init__(self) -> None:
        if not 1 <= self.max_lifetime_seconds <= 86400:
            raise ValueError("maximum grant lifetime is out of range")
        if not 1 <= self.default_lifetime_seconds <= self.max_lifetime_seconds:
            raise ValueError("default grant lifetime is out of range")
        if not 1 <= self.heartbeat_seconds <= 60:
            raise ValueError("grant heartbeat is out of range")


@dataclass(frozen=True)
class DecisionAnswer:
    decision: Decision
    grant: Grant | None
    connection: GrantConnection | None
    #: Where the store committed the record (C2): fixed when the append
    #: completed, read from the store's own answer, and copied into the effect
    #: so recovery can pair the decision with its evidence by identity.
    position: DecisionPosition | None = None


@dataclass(frozen=True)
class DecisionProblem:
    problem: Problem


class _ApprovalUnavailable(RuntimeError):
    """The approval provider was asked and gave no usable answer.

    Raised only where the provider was actually called, so the published code
    it becomes names a component that really did fail. Not a decision — article
    1 keeps allow, deny and suspend the three things a policy or a person
    decided — so the caller reads a could-not-ask, never a server failure it
    cannot classify and never an outcome nothing decided.
    """


class _DecisionContended(RuntimeError):
    """Another ask of this question holds the one execution its approval authorises.

    Nothing failed: a person's act is being spent by the ask that claimed it,
    and this one may not spend it too. It is its own answer rather than the
    provider's, because the provider was never asked — and its own published
    code, because « ask again in a moment » is a different instruction to a
    caller than « the approval provider is not answering » (article 2).
    """


@dataclass(frozen=True)
class _Consulted:
    """What consulting the approval store made of a `suspend` verdict.

    The outcome is one of article 1's three and the reason is one of the
    contract's: a resolution is answered as an `allow` or a `deny` of its own,
    never as a fourth answer (article 12). `spend` says whether this answer is
    the one execution an approval authorises, so the spending happens where the
    record has already been written and nowhere else (article 3).
    """

    outcome: Outcome
    reason: Reason
    approval_ref: str
    spend: bool


class DecisionService:
    def __init__(
        self,
        policy: PolicyService,
        authority: PolicyStore,
        decisions: DecisionStore,
        grants: GrantConnections,
        *,
        archive: PolicyArchive | None = None,
        settings: GrantSettings | None = None,
        system_mode: bool = False,
        configuration_access: Callable[[int, tuple[int, ...]], AccessVerdict] | None = None,
        configuration_path: str = "",
        events: Events | None = None,
        approvals: ApprovalStore | None = None,
        approval_provider: ApprovalProvider | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.policy = policy
        self.authority = authority
        self.decisions = decisions
        #: Where the exact bytes of every version a decision names are kept
        #: before the decision is committed (A1). `None` composes no archive,
        #: which is for tests and for a composition that takes no decision.
        self.archive = archive
        self.grants = grants
        self.settings = settings or GrantSettings()
        if self.authority.max_lifetime_seconds != self.settings.max_lifetime_seconds:
            raise ValueError("policy validation and grant issuance must use the same maximum")
        self.system_mode = system_mode
        #: The second protection article 8 asks of the configuration: in system
        #: mode, whether the asking principal has effective write access to the
        #: file the deployment's own words were read from, or to a directory it
        #: could be replaced through. It is a function and not a port because
        #: nothing of the core crosses it: two integers go out and a verdict
        #: comes back, so there is no object for an implementation to rewrite
        #: in place (article 3, input side). A composition that holds none —
        #: every per-user one, and any deployment that read no file — makes no
        #: claim about a configuration, rather than a claim about a file nobody
        #: read (article 2).
        self.configuration_access = configuration_access
        #: The name the deployment gave, kept so the refusal can say which file
        #: it is about: the component that granted the write may be a directory
        #: above it, and "a directory is writable" tells an operator nothing
        #: about which file it puts at risk.
        self.configuration_path = configuration_path
        if (approvals is None) != (approval_provider is None):
            raise ValueError("an approval store and its provider are composed together")
        #: Where a suspension waits, and what opens one. Composed together or
        #: not at all, which is why the half composition is refused above: a
        #: store nothing opens into would answer every re-ask with a new wait,
        #: and a provider with no store would be asked to match a question
        #: against nothing. A composition that keeps neither suspends exactly
        #: as this service always did, with no reference — honest, because it
        #: holds no approval to name (article 2).
        self.approvals = approvals
        self.approval_provider = approval_provider
        self.events = events or NullEvents()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._id = id_factory or (lambda: str(uuid4()))
        # Composing the two collaborators is what makes a version change reach
        # every connected boundary, not only the one asking (article 10). No
        # caller has to remember it, and registering twice still signals once.
        self.policy.on_version_change(self.grants.policy_version_changed)

    def sweep(self, now: datetime | None = None) -> None:
        """Consult the policy reload age once, and sweep the grant registry with it.

        Article 10 binds a grant to the version it was issued under and to the
        connection that delivered it: the control plane "signals a change of
        version to every connected boundary over the connection that issued the
        grant", and a hit is honoured "only while the version is current on a
        live connection". Nothing signals a change nothing noticed, and
        noticing is the cache age `PolicyService.reload_if_due` already holds —
        consulted here rather than scanned for by a timer of this service's
        own, because the age is the whole design and a scheduler beside it
        would be a second answer to when a version is current.

        The registry's own sweep runs in the same breath and with the version
        the reload just settled: a grant whose lifetime is spent ends as
        `expired` on its connection rather than being left live until someone
        closes it, and a boundary due a heartbeat is written one, which is what
        makes "has not heard from it within the grant's lifetime" a fact the
        boundary can read.

        Two paths call this, and both are paths the daemon already runs. Every
        decision request calls it before it answers — before the system-mode
        refusal and before the ask is validated, so a request this service
        refuses still carries the change to every other boundary, where a
        refusal reaches no policy load of its own. And the daemon calls it
        while it holds an issuing connection, which is the boundary that asks
        nothing more. A connection nothing is holding and nothing is asking for
        is not swept, and the Guard of article 10 says so.

        The waits are ended in the same breath, and for the same reason the
        grants are: a suspension whose deadline has passed is over, and the
        record must say so rather than stay pending until somebody reads it.
        A read does not depend on this having run — `read_approval` renders the
        state as of the instant it is taken — so what this adds is the record
        catching up with the clock, and the event that says a wait ran out.
        """
        at = self._now() if now is None else now
        self.policy.reload_if_due()
        self.grants.tick(at, current_policy_version=self.policy.current_version)
        self._end_the_waits_that_ran_out(at)

    def _end_the_waits_that_ran_out(self, now: datetime) -> None:
        """Expire every wait past its deadline, then forget what nothing can need.

        Two steps in one order, because the second depends on the first: a
        pending approval is never forgotten, so the lapse is counted from the
        deadline `expire_past` ended it at (`ApprovalStore.forget_lapsed`).

        One event per expiry, naming the wait and the decision it suspended,
        and one event per sweep for what was forgotten — the references and
        nothing else, since a record dropped for want of a reader is a fact
        about this store's memory and not about anybody's act.
        """
        approvals = self.approvals
        if approvals is None:
            return
        for expired in approvals.expire_past(now):
            self.events.record(
                "approval.expired",
                {
                    "approval_ref": expired.approval_ref,
                    "decision_ref": expired.decision_ref,
                    "scope": expired.scope,
                    "deadline": _instant(expired.deadline),
                },
                at=now,
            )
        forgotten = approvals.forget_lapsed(now)
        if forgotten:
            self.events.record(
                "approval.forgotten",
                {"approval_refs": [approval.approval_ref for approval in forgotten]},
                at=now,
            )

    def ask(
        self,
        question: DecisionQuestion,
        *,
        grant_connection: bool = False,
        signal_writer: Callable[[GrantSignal], None] | None = None,
        deliver: Callable[[DecisionAnswer], None] | None = None,
    ) -> DecisionAnswer | DecisionProblem:
        """Decide, record, deliver the answer, and only then register its grant.

        `deliver` writes the answer on the connection that will carry the
        grant's signals. It runs before the grant is registered, so a version
        change can never end a grant on a channel that does not yet exist
        (article 10). The registry counts the reservation, not the connection,
        until then; a stop that lands in that instant ends the grant as it
        registers, on the channel the answer went out on (S5).
        """
        now = self._now()
        # Before anything this request could be refused over (article 10): a
        # version change reaches every connected boundary at the next decision
        # request the daemon serves, whatever that request's own answer is.
        self.sweep(now)
        if self.system_mode:
            # Article 3, input side: the principal is a fact this decision is
            # built and recorded from — its name and uid go into the record a
            # few lines below — and the authority is a port. Handing it the
            # core's object let a store rewrite the principal the record
            # attributes the decision to, in place, with one line.
            access = self.authority.write_access_of(core_owned_input(Principal, question.principal))
            if access.kind is not AccessState.NOT_WRITABLE:
                problem = self._problem(
                    ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL,
                    f"principal could write or replace policy at {access.component}",
                )
                self.events.record(
                    "decision.refused",
                    {
                        "principal": question.principal.reference,
                        "problem_code": problem.code.value,
                    },
                    at=now,
                )
                return DecisionProblem(problem)
            # And the file that chose which file that authority is. Article 8:
            # "a governed program that could write its own configuration could
            # activate the plugin that frees it". It is asked second so that a
            # principal that could write both reads the nearer fact first, and
            # under its own code, because "could write the policy" and "could
            # choose which file the policy is" are two facts and an operator
            # acts differently on each (article 2).
            if self.configuration_access is not None:
                reach = self.configuration_access(question.principal.uid, question.principal.gids)
                if reach.kind is not AccessState.NOT_WRITABLE:
                    problem = self._problem(
                        ProblemCode.CONFIGURATION_WRITABLE_BY_PRINCIPAL,
                        f"principal could write or replace the configuration "
                        f"{self.configuration_path} at {reach.component} ({reach.reason})",
                    )
                    self.events.record(
                        "decision.refused",
                        {
                            "principal": question.principal.reference,
                            "problem_code": problem.code.value,
                        },
                        at=now,
                    )
                    return DecisionProblem(problem)
        if problem := self._validate(question):
            return DecisionProblem(problem)
        loaded = self.policy.load_for_decision()
        if isinstance(loaded, PolicyUnavailable):
            return DecisionProblem(
                self._problem(
                    ProblemCode.POLICY_UNAVAILABLE,
                    f"policy authority is unavailable ({loaded.reason})",
                )
            )
        if self.archive is not None and (problem := self._archive(loaded)) is not None:
            return DecisionProblem(problem)
        verdict = evaluate(loaded.policy, question)
        if verdict.outcome is Outcome.SUSPEND and verdict.rule is None:
            # A contradiction, not a case, and held whatever this service is
            # composed with: `policy_absent` and `capability_unknown` name no
            # rule and are denials, and every suspension comes from the rule
            # that suspended it. A composition without approvals would not
            # notice, which is exactly why the guard is not inside one.
            raise AssertionError("a suspend verdict names the rule that suspended it")
        decision_ref = self._id()
        # Before the decision is built, because what the store holds for this
        # question is part of what the decision *is*: a suspension already
        # approved is an allow, and one already rejected is a deny (article 12).
        try:
            consulted = (
                self._consult_approvals(question, verdict.rule, decision_ref, now)
                if verdict.outcome is Outcome.SUSPEND and self.approvals is not None
                else None
            )
        except _ApprovalUnavailable as unsettled:
            # The provider was asked and gave no usable answer, and nothing was
            # recorded: a could-not-ask under the code that names it, retryable,
            # no decision taken (articles 1 and 2).
            return DecisionProblem(
                self._problem(ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE, str(unsettled))
            )
        except _DecisionContended as contended:
            # Nobody failed: another ask is spending the execution this
            # question's approval authorises. Its own code, because « ask
            # again in a moment » is a different instruction from « the
            # approval provider is not answering », and naming the provider
            # here would name a component that was never even asked.
            return DecisionProblem(self._problem(ProblemCode.DECISION_CONTENDED, str(contended)))
        # One exit for the claim, from here to the record. An execution
        # claimed and not recorded is given back — whatever happened in
        # between, including a raise this service does not anticipate —
        # because nothing a person granted is lost for want of a record.
        # Once the record exists, **or may exist**, it is not given back:
        # releasing behind a committed record would license a second allow on
        # one act, and an append that cannot say whether it committed is that
        # same case as far as article 3's fail-closed rule is concerned. The
        # flag therefore means « the record may be there », and the
        # indeterminate branch below sets it and spends the execution.
        recorded = False
        try:
            outcome = verdict.outcome if consulted is None else consulted.outcome
            reason = verdict.reason if consulted is None else consulted.reason
            extra: dict[str, object] = {
                "principal": {
                    "kind": question.principal.kind,
                    "uid": question.principal.uid,
                    "name": question.principal.user_name,
                },
                "arguments_digest": question.ask.arguments_digest,
                "rule_id": verdict.rule_id,
                "grant_id": None,
                # What the evaluation read, so a reader can repeat it without a
                # directory; under which recipe; and who chose the correlation
                # bytes, since the daemon cannot prove they are an identifier
                # (M1, M3, article 11).
                "principal_references": list(references_read(loaded.policy, question)),
                "evaluation_recipe": EVALUATION_RECIPE,
                "correlation_source": (
                    "absent" if question.ask.correlation is None else "boundary_supplied"
                ),
            }
            decision = Decision(
                decision_ref,
                question.ask.scope,
                question.ask.capability,
                outcome,
                reason,
                loaded.policy_version,
                None if consulted is None else consulted.approval_ref,
                _instant(now),
                question.ask.correlation,
                CONTRACT_GENERATION,
                extra,
            )
            on_connection = grant_connection or signal_writer is not None
            reservation = (
                self.grants.reserve(question.principal.uid)
                # The answered outcome and not the verdict's: a suspension whose
                # approval was granted is an allow, and it takes the grant path an
                # allow takes, reservation and lifetime alike.
                if outcome is Outcome.ALLOW and on_connection
                else None
            )
            grant = self._prepare_grant(
                decision,
                verdict.rule.grant_lifetime_seconds if verdict.rule is not None else None,
                now,
                loaded.policy_version,
                reservation,
            )
            if grant is not None:
                extra["grant_id"] = grant.grant_id
                decision = replace(decision, extra=extra)
            try:
                # The same, on the way out: `decision` is read again after this
                # call — into the recorded event, and into the answer the caller is
                # given — so the store is handed the core's own copy of it, `extra`
                # rebuilt with it because a mapping is written to more easily still.
                position = core_owned_position(
                    self.decisions.append(core_owned_input(Decision, decision, extra=dict))
                )
            except DecisionAppendIndeterminate as error:
                # The write began: the record may have committed, and nothing here
                # can say. No usable answer, the reservation released, and never
                # the claim that no decision was taken (C2, articles 1 and 2).
                #
                # And the execution is SPENT, not given back. One allow on this
                # act may already be committed and readable; giving the claim
                # back would let the next ask of this question license a second
                # one on the same person's act, which is the outcome article 3
                # exists to forbid. Fail closed charges the other cost instead:
                # if the record did not commit, a person's act ends a wait that
                # authorised nothing, and the re-ask suspends anew for a second
                # answer. The flag is set first, so a store that refuses the
                # consumption still leaves the claim held rather than released.
                recorded = True
                self._consume_claimed(decision.scope, consulted)
                if reservation is not None:
                    reservation.cancel()
                return DecisionProblem(
                    self._problem(
                        ProblemCode.DECISION_STORE_UNAVAILABLE,
                        f"the decision may have committed but could not be answered: {error}",
                    )
                )
            except Exception as error:
                # Before the first byte: a known refusal, nothing committed.
                if reservation is not None:
                    reservation.cancel()
                return DecisionProblem(
                    self._problem(
                        ProblemCode.DECISION_STORE_UNAVAILABLE,
                        f"the decision authority could not record the decision: {error}",
                    )
                )
            # The record exists from here: whatever happens next, the
            # execution this ask claimed was spent on a decision somebody can
            # read.
            recorded = True
            if consulted is not None and consulted.spend:
                # After the append and only after it. A consumption without a
                # record is an execution nobody can trace, so the branch that
                # refused before the first byte gives the claim back; the one
                # that cannot say whether it committed spends it there, for the
                # reason written beside it (article 3, C2). The execution
                # is this ask's: it was claimed under the store's lock before the
                # record was written, so no other ask can have spent it in between
                # and a refusal here would be a contradiction. It is still not left
                # to escape as one: the reservation this decision took is released
                # first, because a raise between a committed append and the return
                # would otherwise hold a principal's grant capacity for the life of
                # the process — the same release the delivery path below does for
                # the same reason.
                assert self.approvals is not None, "a consultation implies a composed store"
                try:
                    self.approvals.consume(decision.scope, consulted.approval_ref)
                except Exception:
                    if reservation is not None:
                        reservation.cancel()
                    raise
            self.events.record(
                "decision.recorded",
                {"scope": decision.scope, "decision_ref": decision.decision_ref},
                at=now,
            )
            answer_extra = {
                **extra,
                "grant": None if grant is None else self._grant_document(grant),
            }
            answer = DecisionAnswer(replace(decision, extra=answer_extra), grant, None, position)
            if grant is None or reservation is None:
                return answer
            if deliver is not None:
                try:
                    deliver(answer)
                except Exception:
                    reservation.cancel()
                    raise
            connection = reservation.open(grant, signal_writer)
            # A version that moved between minting and registering is signalled now,
            # on the channel the answer has already been written to (article 10).
            if self.policy.current_version != grant.policy_version:
                self.grants.policy_version_changed(self.policy.current_version)
            return replace(answer, connection=connection)
        finally:
            if not recorded:
                self._release_claim(question.ask.scope, consulted)

    def _consult_approvals(
        self,
        question: DecisionQuestion,
        rule: Rule,
        decision_ref: str,
        now: datetime,
    ) -> _Consulted:
        """What a re-ask of this suspended question answers, and what it spends.

        Article 12's simple form, read from this side of it. The question is
        the four facts that make a re-ask the *same* ask — the scope, the
        principal reference, the capability and the arguments digest — and the
        store answers with the approval still open for it, or opens the one
        offered here.

        Four answers, and each is one of article 1's three outcomes: a wait
        still pending suspends again on the same reference, so a caller that
        asks twice is told about one wait and not two; an approval granted and
        unspent allows, with the reason the contract now publishes for it, and
        that one allow is the one execution the person's act authorised; a
        rejection denies while the wait it ended is still running. Nothing
        still answering — none, spent, or a wait that ran out — opens a new
        one, because the alternative is to treat an absence as a refusal, and
        article 1 keeps a refusal something a policy or a person decided.

        Two asks of one question can run at once, so neither branch is written
        as look-then-act. The store looks and opens under one lock
        (`open_if_absent`), so one question never ends with two waits and a
        person's act is never shadowed by a second one; and it hands out the
        one execution under the same lock (`claim`), so two asks never both
        record an allow on one act. Losing the claim is not a failure — the
        other ask has the execution in flight — so this one looks again a
        few times over one append's worth of time; a claimed approval counts
        as in flight, so nothing new is opened over it. Only a question that
        stays contested for every look is answered as contended, which is a
        could-not-ask and not a decision.

        The wait itself is opened here, not by the provider: the question is a
        member of the record and it is established from the connection and the
        ask, neither of which a provider may be trusted to tell the core
        (article 3). The provider's own act is then put to it through the
        port's published call, and a provider that cannot answer leaves this
        ask with no decision rather than an outcome nobody decided.
        """
        approvals = self.approvals
        provider = self.approval_provider
        assert approvals is not None and provider is not None, (
            "an approval store and its provider are composed together"
        )
        if rule.review_deadline_seconds is None:
            # The loader puts a wait on every `suspend` rule it accepts, so
            # this is unreachable — and unreachable is not a licence to guess
            # how long somebody has to answer.
            raise AssertionError("a suspend rule carries the wait its suspension is measured by")
        asked = Question(
            scope=question.ask.scope,
            # The one spelling of a principal's reference this core has, so the
            # question a re-ask is matched by and the references the record
            # carries cannot drift apart.
            principal_reference=question.principal.reference,
            capability=question.ask.capability,
            arguments_digest=question.ask.arguments_digest or _NO_DIGEST,
        )
        opening = Approval(
            approval_ref=self._id(),
            decision_ref=decision_ref,
            question=asked,
            requested_at=now,
            deadline=now + timedelta(seconds=rule.review_deadline_seconds),
        )
        for attempt in range(_CLAIM_TRIES):
            found = approvals.open_if_absent(opening)
            if found.approval_ref == opening.approval_ref:
                self._open_with(provider, approvals, opening)
                return _Consulted(
                    Outcome.SUSPEND, Reason.POLICY_REQUIRES_REVIEW, found.approval_ref, spend=False
                )
            if found.state is ApprovalState.PENDING:
                return _Consulted(
                    Outcome.SUSPEND, Reason.POLICY_REQUIRES_REVIEW, found.approval_ref, spend=False
                )
            if found.state is ApprovalState.REJECTED:
                return _Consulted(
                    Outcome.DENY, Reason.APPROVAL_REJECTED, found.approval_ref, spend=False
                )
            if found.state is not ApprovalState.APPROVED:
                raise AssertionError(
                    "the store answers a question with a pending, approved or rejected "
                    "approval only"
                )
            if not found.claimed:
                try:
                    approvals.claim(found.scope, found.approval_ref)
                except ApprovalAlreadyClaimed:
                    pass
                else:
                    return _Consulted(
                        Outcome.ALLOW, Reason.APPROVAL_GRANTED, found.approval_ref, spend=True
                    )
            # In flight: another ask claimed this execution and is recording the
            # allow it authorises, or is about to give it back. Waiting is not
            # a wait on a person — it is a wait on one append — and the
            # alternative, opening a wait of this ask's own, would bury a
            # person's act under a newer suspension nobody has answered.
            if attempt + 1 < _CLAIM_TRIES:
                sleep(_CLAIM_PAUSE_SECONDS)
        raise _DecisionContended(
            "another ask of this question holds the one execution its approval authorises, "
            "so this ask was not decided; ask again"
        )

    def _open_with(
        self, provider: ApprovalProvider, approvals: ApprovalStore, opened: Approval
    ) -> None:
        """Put the wait this ask just opened to the provider, and drop it if it refuses.

        The wait exists before the provider is asked, because the question is a
        member of the record and the core is what holds it. If the provider
        cannot take it up, the wait must not be left behind: this ask's answer
        is retryable, and a retry would find its own pending wait, answer
        `suspend` on it, and never reach the provider again — a provider
        failure laundered into a suspension that provider never received
        (articles 2 and 12). Nobody else can hold this wait: it was minted by
        this ask, opened an instant ago, and no answer naming it has left the
        daemon.
        """
        try:
            self._put_the_suspension_to(provider, opened)
        except _ApprovalUnavailable:
            with suppress(Exception):
                approvals.abandon(opened.scope, opened.approval_ref)
            raise

    def _put_the_suspension_to(self, provider: ApprovalProvider, opened: Approval) -> None:
        """Put the wait this core just opened to the provider, as its own act.

        The core's own copy of the request is taken before the call and the
        provider is handed the other one: `frozen=True` refuses `setattr` and
        refuses nothing to `object.__setattr__`, so a fact read back out of the
        object just given away would be a fact the provider chose
        (`domain/foreign.py`, input side). Nothing is read back out of the
        answer either — the reference this ask goes on to record is the one the
        core minted.

        Every failure of a provider is one answer here. A provider is code this
        project did not write, its refusals are its own classes and an
        exception it raises is not a contract at all, so the alternative to
        catching both is the daemon answering « the server failed for a reason
        it cannot classify » for a plugin doing exactly what a plugin does
        (articles 2 and 8).
        """
        request = ApprovalRequest(
            approval_ref=opened.approval_ref,
            decision_ref=opened.decision_ref,
            scope=opened.scope,
            capability=opened.capability,
            requested_at=opened.requested_at,
            deadline=opened.deadline,
        )
        core_owned_request(request)
        try:
            provider.suspend(request)
        except Exception as error:
            raise _ApprovalUnavailable(
                f"the approval provider could not answer, so no decision is taken: {error}"
            ) from error

    def _release_claim(self, scope: str, consulted: _Consulted | None) -> None:
        """Give back an execution this ask claimed and did not record.

        Article 3 from the other side of the consumption rule: nothing is spent
        without a record, and nothing a person granted is lost because a record
        could not be written. Reached only where nothing was written and
        nothing could have been — a refusal before the first byte, or a raise
        this service does not anticipate — because an append that may have
        committed spends the execution instead (`_consume_claimed`).

        The give-back is itself best effort: a store that refuses it leaves the
        execution claimed for as long as the record is kept — and an approved
        record nobody spends is kept for the life of the process — so every
        later ask of that question is answered as contended, which is a
        question nobody can spend rather than an act licensed twice.
        """
        if consulted is None or not consulted.spend or self.approvals is None:
            return
        with suppress(Exception):
            self.approvals.release_claim(scope, consulted.approval_ref)

    def _consume_claimed(self, scope: str, consulted: _Consulted | None) -> None:
        """Spend an execution behind a record that may have committed (article 3).

        The mirror of `_release_claim`, and the fail-closed half of the rule.
        An indeterminate append began the write and cannot say whether it
        finished, so one allow on this person's act may already be committed
        and readable by anyone; giving the claim back would let the next ask of
        the same question license a second allow on that one act, which is the
        outcome article 3 forbids outright. « It may have been recorded » is
        therefore treated as « it was », here as everywhere else in this
        service.

        The cost of being wrong is charged on purpose and in this direction: if
        the record did not commit, one person's act ends a wait that authorised
        nothing, and the re-ask opens a new wait a second person answers — an
        effect asked for twice rather than licensed twice.

        Best effort, like the give-back: a store that refuses leaves the
        execution claimed, which is again a wait nobody can spend.
        """
        if consulted is None or not consulted.spend or self.approvals is None:
            return
        with suppress(Exception):
            self.approvals.consume(scope, consulted.approval_ref)

    def _archive(self, loaded: LoadedPolicy) -> Problem | None:
        """Keep the exact bytes this question is decided on, or refuse the question (A1).

        Before the decision is appended, so that no committed decision names a
        version whose bytes were never kept; before the grant is reserved, so
        that a refusal has nothing to cancel. The bytes are the ones the
        authority read for this very load, under the version it hashed them
        to; an authority that supplied none, a keep the host refused, and a
        version already kept whose bytes no longer hash to their name are one
        answer each and the same refusal: no decision is committed, and the
        caller reads a could-not-ask, never a denial (articles 1, 2, 3).
        """
        assert self.archive is not None
        if loaded.content is None:
            return self._problem(
                ProblemCode.POLICY_ARCHIVE_UNAVAILABLE,
                "the policy authority supplied no bytes to keep for this version",
            )
        try:
            kept = core_owned(
                ArchivedPolicy,
                self.archive.keep(loaded.policy_version, bytes(loaded.content)),
                version=str,
                state=ArchiveState,
                content=lambda raw: None if raw is None else bytes(raw),
            )
        except Exception as error:
            return self._problem(
                ProblemCode.POLICY_ARCHIVE_UNAVAILABLE,
                f"the policy bytes could not be kept before deciding: {error}",
            )
        if kept.state is not ArchiveState.present or kept.version != loaded.policy_version:
            return self._problem(
                ProblemCode.POLICY_ARCHIVE_UNAVAILABLE,
                f"the archived policy version is {kept.state.value}, so the bytes this "
                "question would be decided on cannot be kept",
            )
        return None

    def _now(self) -> datetime:
        """One instant from the composed clock, as a value this service owns.

        The clock is a seam like any other (`domain/foreign.py`): an instant is
        written into a record and compared against another, and both live on the
        type, so a `datetime` subclass answers them itself.
        """
        return core_owned_instant(self._clock())

    def _prepare_grant(
        self,
        decision: Decision,
        rule_lifetime: int | None,
        now: datetime,
        policy_version: str,
        reservation: GrantReservation | None,
    ) -> Grant | None:
        if decision.outcome is not Outcome.ALLOW or reservation is None:
            return None
        lifetime = min(
            bound
            for bound in (
                rule_lifetime,
                self.settings.default_lifetime_seconds,
                self.settings.max_lifetime_seconds,
            )
            if bound is not None
        )
        return mint_grant(
            decision,
            now,
            lifetime_seconds=lifetime,
            policy_version=policy_version,
            heartbeat_seconds=self.settings.heartbeat_seconds,
        )

    @staticmethod
    def _validate(question: DecisionQuestion) -> Problem | None:
        """Hold the ask to the schema the contract publishes for it.

        The bounds are read from `decision-ask-request.schema.json` rather than
        spelled again here. They were spelled again here, and the second
        spelling had drifted: it carried the three patterns and dropped
        `capability`'s published `maxLength` and `correlation`'s altogether, so
        an ask that no published reader would accept was answered and written
        onto the chain (articles 10 and 13).

        This runs for every ask, whichever surface carried it — the socket
        route validates the request document it received, and this validates
        the question whatever composed it, including one built in process.
        """
        ask = question.ask
        document: dict[str, object] = {
            "contract_generation": CONTRACT_GENERATION,
            "capability": ask.capability,
            "scope": ask.scope,
        }
        if ask.arguments_digest is not None:
            document["arguments_digest"] = ask.arguments_digest
        if ask.correlation is not None:
            document["correlation"] = ask.correlation
        complaint = refused_by(document, _ASK_SCHEMA)
        if complaint is None:
            return None
        return DecisionService._problem(ProblemCode.REQUEST_MALFORMED, complaint)

    @staticmethod
    def _problem(code: ProblemCode, message: str) -> Problem:
        return Problem(code, message, problem_retryable(code), CONTRACT_GENERATION)

    @staticmethod
    def _grant_document(grant: Grant) -> Mapping[str, object]:
        return PublishedGrant(
            grant.grant_id,
            grant.decision_ref,
            grant.policy_version,
            _instant(grant.issued_at),
            grant.lifetime_seconds,
            _instant(grant.expires_at),
            grant.heartbeat_seconds,
            PublishedGrantConditions(
                grant.conditions.scope,
                grant.conditions.capability,
                grant.conditions.principal_reference,
                grant.conditions.arguments_digest,
            ),
        ).to_document()
