# SPDX-License-Identifier: Apache-2.0 OR MIT-0
"""A scenario-scripted fake that never computes policy."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Final

from sayfirst_contract.approvals import Approval, ApprovalResolution, ApprovalState, Resolution
from sayfirst_contract.client import Answered, CouldNotAsk, Refused, Result
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_contract.evidence_recipes import (
    MANIFEST_V3,
    ChainVerdict,
    InvalidBundle,
    chained_document,
    manifest_hash,
    verify_chain,
)
from sayfirst_contract.generation import CONTRACT_GENERATION, SUPPORTED_GENERATIONS
from sayfirst_contract.golden import Regime, Scenario, load_scenarios
from sayfirst_contract.policy import PolicyStatus, ProjectionStatus, ProjectionStep
from sayfirst_contract.problems import (
    Problem,
    ProblemCode,
    problem_class_of,
    problem_retryable,
)
from sayfirst_contract.status import (
    Authority,
    GradeBasis,
    IntegrityGrade,
    IntegrityGradeStatus,
    Principal,
    Status,
)
from sayfirst_contract.whoami import (
    ESTABLISHED_BY_PEER_CREDENTIAL,
    Peer,
    WhoAmI,
)
from sayfirst_contract.whoami import (
    Principal as IdentityPrincipal,
)

#: The largest page of evidence the published binding lets a caller ask for.
_PAGE_BOUND: Final = 100


def _sequence(entry: Mapping[str, object]) -> int:
    return int(entry["sequence"])  # type: ignore[call-overload]


def _range(
    chain: list[dict[str, object]], from_sequence: int, to_sequence: int
) -> list[dict[str, object]]:
    return [entry for entry in chain if from_sequence <= _sequence(entry) <= to_sequence]


def _policy_bytes(policy: Mapping[str, Regime]) -> bytes:
    """The bytes this fake hashes a scenario's rules to, written once.

    One recipe, read by everything that names a version: the decision it
    answers, the policy status it serves, the effect it puts on the chain and
    the attachment an export carries. Two spellings of one hash is how a fake
    comes to serve a decision under a version its own export cannot resolve.
    """
    return json.dumps({key: value.value for key, value in policy.items()}, sort_keys=True).encode()


def _policy_version(policy: Mapping[str, Regime]) -> str:
    return "sha256:" + hashlib.sha256(_policy_bytes(policy)).hexdigest()


#: What an effect names where its decision named no version at all. A scenario
#: that gives this fake no rule produces a decision whose `policy_version` is
#: honestly null, and the published effect body has no null to put there — so
#: what goes on the chain is the version of the policy the fake actually holds,
#: which for such a scenario is the empty one. Nothing is invented: an export
#: attaches those exact bytes under that exact name, and a reader re-derives
#: from them.
_ABSENT_POLICY_VERSION: Final = _policy_version({})


class Stub:
    """A non-authoritative fake selected explicitly by scenario name."""

    def __init__(
        self,
        scenario: str,
        *,
        scenarios: Mapping[str, Scenario] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        available = scenarios or load_scenarios()
        if scenario not in available:
            raise ValueError(f"unknown scenario {scenario!r}")
        self.scenario = available[scenario]
        if self.scenario.given.server is not None:
            # A scenario that scripts a foreign server's answers arranges a
            # world this fake is not; anything else it can serve, whichever
            # side the scenario binds (article 13).
            raise ValueError(f"scenario {scenario!r} scripts a server this fake is not")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._decisions: list[Decision] = []
        #: One chain of evidence entries per scope, written with the published
        #: recipe as a server writes them (article 13).
        self._entries: dict[str, list[dict[str, object]]] = {}
        self._approvals: dict[tuple[str, str], Approval] = {}
        self._approval_records: list[Approval] = []
        #: The approvals whose one execution has been taken. Article 12: one
        #: resolution authorises one execution, so a spent approval answers no
        #: later ask and the scenario's own outcome stands again.
        self._spent: set[tuple[str, str]] = set()
        self._policy_changed = False

    def change_policy(self) -> None:
        """Advance a scripted policy-change scenario to its second decision."""
        self._policy_changed = True

    @property
    def decision_count(self) -> int:
        return len(self._decisions)

    @property
    def approval_records(self) -> tuple[Approval, ...]:
        return tuple(self._approval_records)

    def read_status(self) -> Result[Status]:
        uid = os.getuid()
        try:
            name = pwd.getpwuid(uid).pw_name
        except KeyError:
            name = None
        value = Status(
            contract_generation=CONTRACT_GENERATION,
            supported_generations=SUPPORTED_GENERATIONS,
            integrity_grade=IntegrityGradeStatus(
                IntegrityGrade.UNVERIFIED,
                GradeBasis.ACCESS_NOT_ESTABLISHED,
                self._now().isoformat(),
                "file",
                30,
                {},
            ),
            privacy_provider="none",
            principal=Principal("user", uid, name),
            store_authority=Authority.AUTHORITATIVE,
            store_kind="file",
            extra={},
        )
        return Answered(value, CONTRACT_GENERATION)

    def read_whoami(self) -> Result[WhoAmI]:
        uid, gid = os.geteuid(), os.getegid()
        try:
            name = pwd.getpwuid(uid).pw_name
        except KeyError:
            name = None
        captured_at = self._now().isoformat()
        value = WhoAmI(
            contract_generation=CONTRACT_GENERATION,
            connection_id=f"connection-{self.scenario.name}",
            socket_path=f"/{self.scenario.name}.sock",
            mode="per_user",
            peer=Peer(uid=uid, gid=gid, pid=os.getpid(), captured_at=captured_at),
            principal=IdentityPrincipal(
                kind="user",
                uid=uid,
                gid=gid,
                name=name,
                groups=None,
                groups_status="unknown",
                unnamed_group_ids=(),
                established_by=ESTABLISHED_BY_PEER_CREDENTIAL,
                established_at=captured_at,
            ),
            status="established",
            refresh_due_at=None,
            group_lifetime_seconds=60,
            delegation=None,
            extra={},
        )
        return Answered(value, CONTRACT_GENERATION)

    def ask_decision(self, ask: DecisionAsk) -> Result[Decision]:
        expected = self.scenario.expect
        if self.scenario.given.policy_unavailable:
            return self._published(
                ProblemCode.POLICY_UNAVAILABLE, "policy authority is unavailable"
            )
        after = expected.after_policy_change if self._policy_changed else None
        outcome_value = after.get("outcome") if after is not None else expected.outcome
        reason_value = after.get("reason") if after is not None else expected.reason
        settled = self._answered_by_a_person(ask)
        if settled is not None:
            # Not scripted: this is the one part of a decision a scenario's own
            # `expect` cannot state, because it is what the *second* ask gets.
            # Article 12 fixes it entirely — a question one person has already
            # answered is an allow or a deny, on the reason published for that
            # act — so the fake follows the rule rather than a second fixture.
            approved = settled.state is ApprovalState.APPROVED
            outcome_value = "allow" if approved else "deny"
            reason_value = "approval_granted" if approved else "approval_rejected"
        if outcome_value is None or reason_value is None:
            return self._published(ProblemCode.INTERNAL, "scenario has no server decision")
        now = self._now()
        decision_ref = f"decision-{len(self._decisions) + 1}"
        outcome = Outcome(outcome_value)
        approval_ref = (
            f"approval-{len(self._approvals) + 1}"
            if outcome is Outcome.SUSPEND
            # A resumed decision names the approval it acted on, the way a
            # suspension names the wait it opened: one act, one reference.
            else (settled.approval_ref if settled is not None else None)
        )
        policy = self.scenario.given.policy
        # A scenario with no rule gives a decision that names no version, and
        # says so with a null rather than with the hash of an empty file.
        policy_version = _policy_version(policy) if policy else None
        decision = Decision(
            decision_ref=decision_ref,
            scope=ask.scope or "local",
            capability=ask.capability,
            outcome=outcome,
            reason=Reason(reason_value),
            policy_version=policy_version,
            approval_ref=approval_ref,
            decided_at=now.isoformat(),
            correlation=ask.correlation,
            contract_generation=CONTRACT_GENERATION,
            extra={
                "principal": {
                    "kind": "user",
                    "uid": os.getuid(),
                    "name": pwd.getpwuid(os.getuid()).pw_name,
                },
                "arguments_digest": ask.arguments_digest,
                "rule_id": None if reason_value == "policy_absent" else "scenario-rule",
                "grant": (
                    {"grant_id": "grant-1"}
                    if (
                        (after.get("grant") if after is not None else expected.grant) == "present"
                        and self.scenario.given.signal_channel
                        and outcome is Outcome.ALLOW
                    )
                    else None
                ),
            },
        )
        self._decisions.append(decision)
        self._record(decision)
        if approval_ref is not None:
            approval = Approval(
                approval_ref=approval_ref,
                decision_ref=decision_ref,
                scope=decision.scope,
                capability=decision.capability,
                state=ApprovalState.PENDING,
                requested_at=now.isoformat(),
                deadline=(now + timedelta(seconds=60)).isoformat(),
                resolved_at=None,
                resolution_reason=None,
                contract_generation=CONTRACT_GENERATION,
                extra={},
            )
            self._approvals[(decision.scope, approval_ref)] = approval
            self._approval_records.append(approval)
        if settled is not None and settled.state is ApprovalState.APPROVED:
            # Spent here and not when the person acted: the allow this ask was
            # answered is the one execution that act authorised (article 3).
            self._spent.add((settled.scope, settled.approval_ref))
        return Answered(decision, CONTRACT_GENERATION)

    def _answered_by_a_person(self, ask: DecisionAsk) -> Approval | None:
        """The approval a re-ask of this question is answered from, if there is one.

        The half of article 12 that only a second ask reaches. An approved
        approval answers until the one execution it authorises is spent; a
        rejection answers while the wait it ended is still running, and no
        longer, because the wait was bounded. A wait still pending, one already
        spent and one that ran out answer nothing, and the scenario's own
        outcome stands.

        The question is the scope and the capability, which is all a scenario
        varies: the real daemon matches four facts, two of which — the
        principal's reference and the arguments digest — a fake serving one
        scripted caller cannot vary and must not pretend to hold (article 2).
        """
        scope = ask.scope or "local"
        # Over a copy, because `_expire` writes back the record it ended.
        for approval in tuple(self._approvals.values()):
            if (approval.scope, approval.capability) != (scope, ask.capability):
                continue
            if (approval.scope, approval.approval_ref) in self._spent:
                continue
            settled = self._expire(approval)
            if settled.state is ApprovalState.APPROVED:
                return settled
            if settled.state is ApprovalState.REJECTED and self._now() < datetime.fromisoformat(
                settled.deadline
            ):
                return settled
        return None

    def read_decision(self, scope: str, decision_ref: str) -> Result[Decision]:
        """A decision this fake took, read back by reference in its own scope.

        Scripted, never computed: this fake decides nothing and answers only
        what a scenario already made it answer (article 13). The pair a
        published read is for — ask, then read back what was answered — is the
        whole of what a third party can build an explanation against, and this
        face answered `operation_unknown` for it until now.
        """
        for decision in self._decisions:
            if decision.scope == scope and decision.decision_ref == decision_ref:
                return Answered(decision, CONTRACT_GENERATION)
        return self._published(ProblemCode.DECISION_NOT_FOUND, "decision is not known")

    def read_policy_status(self) -> Result[PolicyStatus]:
        """What this fake would say about the policy a scenario gave it.

        `authority` is the one value the published document defines, and the
        version is the one the fake's own decisions name, taken under the one
        recipe above. `projection` is `unknown` throughout and not `yes`: this
        fake keeps no projection at all, and an unknown is the honest third
        value where a reader might expect two (article 2).
        """
        policy = self.scenario.given.policy or {}
        value = PolicyStatus(
            authority="file",
            policy_version=_policy_version(policy),
            format=1,
            loaded_at=self._now().isoformat(),
            rule_count=len(policy),
            projection=ProjectionStatus(
                kind="unknown", policy_version=None, in_step=ProjectionStep.UNKNOWN
            ),
            contract_generation=CONTRACT_GENERATION,
            extra={},
        )
        return Answered(value, CONTRACT_GENERATION)

    def read_approval(self, scope: str, approval_ref: str) -> Result[Approval]:
        key = (scope, approval_ref)
        if key not in self._approvals:
            return self._published(ProblemCode.APPROVAL_UNKNOWN, "approval is not known")
        approval = self._expire(self._approvals[key])
        return Answered(approval, CONTRACT_GENERATION)

    def resolve_approval(self, resolution: ApprovalResolution) -> Result[Approval]:
        """End one wait, and answer the record the act left behind.

        The person is the account this fake runs as, because the published
        request carries no member that could name one and a server takes who
        acted from the connection (article 6). A fake has no verified peer to
        read, so it answers for the only principal it can honestly name — its
        own — and it names one, because a resolution without a person would let
        a conformance client read `approved` with nobody behind it and believe
        that is the shape a server serves (articles 12 and 13).
        """
        key = (resolution.scope, resolution.approval_ref)
        if key not in self._approvals:
            return self._published(ProblemCode.APPROVAL_UNKNOWN, "approval is not known")
        approval = self._expire(self._approvals[key])
        if approval.state is not ApprovalState.PENDING:
            return self._published(ProblemCode.APPROVAL_RESOLVED, "approval is already terminal")
        state = (
            ApprovalState.APPROVED
            if resolution.resolution is Resolution.APPROVE
            else ApprovalState.REJECTED
        )
        resolved = replace(
            approval,
            state=state,
            resolved_at=self._now().isoformat(),
            resolution_reason=resolution.reason,
            person=f"user:{os.getuid()}",
        )
        self._approvals[key] = resolved
        self._approval_records.append(resolved)
        return Answered(resolved, CONTRACT_GENERATION)

    def read_evidence(
        self, scope: str, from_sequence: int, page_size: int = _PAGE_BOUND
    ) -> Result[dict[str, object]]:
        """One page of this fake's own chain, with the published verifier's verdict.

        The page was a placeholder — no entries, an empty verdict written here
        by hand — so a conformance client could read its shape and nothing
        else, and the one thing an evidence read exists for, a chain that
        verifies, was proven only against the daemon. What is paged now is a
        real chain, placed by `chained_document` and judged by `verify_chain`,
        which is the same pair the server reads (article 13).
        """
        # The scope before the range, as the daemon resolves them (article 13).
        refusal = self._scope_refusal(scope)
        refusal = refusal or self._range_refusal(from_sequence, page_size=page_size)
        if refusal is not None:
            return refusal
        chain = self._entries.get(scope, [])
        head = _sequence(chain[-1]) if chain else None
        if head is None or from_sequence > head:
            page: list[dict[str, object]] = []
            requested_end = None
            next_from = None
        else:
            requested_end = min(head, from_sequence + page_size - 1)
            page = _range(chain, from_sequence, requested_end)
            next_from = requested_end + 1 if requested_end < head else None
        verdict = self._verify(page, scope, from_sequence, requested_end)
        if isinstance(verdict, Refused | CouldNotAsk):
            return verdict
        document: dict[str, object] = {
            "contract_version": str(CONTRACT_GENERATION),
            "scope": scope,
            "from_sequence": from_sequence,
            "to_sequence": verdict.to_sequence,
            "entries": page,
            "verification": verdict.to_document(),
            "next_from": next_from,
        }
        return Answered(document, CONTRACT_GENERATION)

    def export_evidence(
        self, scope: str, from_sequence: int, to_sequence: int | None = None
    ) -> Result[dict[str, object]]:
        """The same range as a bundle, with the attachments and the digest it publishes.

        A digest is taken under the published v3 recipe, after every other
        member is in place, because that recipe binds all of them; the policy
        bytes an included effect names are attached as the export publishes
        them. So an export this fake serves is one a holder of the
        contract wheel alone can verify — which is what an export is for.

        **This fake never continues an export.** The daemon bounds what it
        will serve at once and points a caller at the rest with `next_from`;
        this fake keeps no such bound and answers `next_from` as null always,
        because a scenario's chain is a handful of entries and a range it
        answered is the whole of the range that was asked for. So a
        conformance client can exercise the shape of an export against this
        fake and cannot exercise continuation against it at all — that one is
        proven against a daemon or it is not proven (article 2).
        """
        refusal = self._scope_refusal(scope)
        refusal = refusal or self._range_refusal(from_sequence, to_sequence=to_sequence)
        if refusal is not None:
            return refusal
        chain = self._entries.get(scope, [])
        head = _sequence(chain[-1]) if chain else None
        desired_end = head if to_sequence is None else to_sequence
        if head is None or desired_end is None or from_sequence > head:
            entries: list[dict[str, object]] = []
            bounded_end = None
        else:
            bounded_end = min(desired_end, head)
            entries = _range(chain, from_sequence, bounded_end)
        verdict = self._verify(entries, scope, from_sequence, bounded_end)
        if isinstance(verdict, Refused | CouldNotAsk):
            return verdict
        bundle: dict[str, object] = {
            "contract_version": str(CONTRACT_GENERATION),
            "scope": scope,
            "from_sequence": from_sequence,
            "to_sequence": verdict.to_sequence,
            "entry_count": len(entries),
            "entries": entries,
            "verification": verdict.to_document(),
            # Always null, and the docstring says what that costs a reader.
            "next_from": None,
            "manifest_version": MANIFEST_V3,
            "policy_versions": self._attachments(entries),
            "recovery_context": [],
        }
        bundle["manifest_hash"] = manifest_hash(bundle, version=MANIFEST_V3)
        return Answered(bundle, CONTRACT_GENERATION)

    def _record(self, decision: Decision) -> None:
        """Append this decision's effect entry to the scope's chain, as a writer does.

        `chained_document` is the published recipe, so what this fake serves
        and what the server serves are placed by one piece of code (article
        13) — which is the whole reason the recipe is published as executable
        code.

        The chain opens with the grade this fake's own status read reports:
        unverified, on the basis that access was not established. A first
        decision therefore leaves two entries and not one, so the first page a
        caller reads carries a link rather than a lone entry that proves
        nothing about linking.
        """
        chain = self._entries.setdefault(decision.scope, [])
        if not chain:
            self._append(
                chain,
                decision.scope,
                "grade",
                self._now().isoformat(),
                {
                    "grade": IntegrityGrade.UNVERIFIED.value,
                    "basis": GradeBasis.ACCESS_NOT_ESTABLISHED.value,
                    "evaluated_at": self._now().isoformat(),
                    "paths_inspected": 0,
                },
            )
        self._append(
            chain,
            decision.scope,
            "effect",
            decision.decided_at,
            {
                "capability": decision.capability,
                "decision_id": decision.decision_ref,
                "outcome": decision.outcome.value,
                "decided_at": decision.decided_at,
                "policy_version": decision.policy_version or _ABSENT_POLICY_VERSION,
            },
        )

    def _append(
        self,
        chain: list[dict[str, object]],
        scope: str,
        kind: str,
        recorded_at: str,
        body: Mapping[str, object],
    ) -> None:
        chain.append(
            chained_document(
                {
                    "scope": scope,
                    "kind": kind,
                    "recorded_at": recorded_at,
                    "connection_id": f"connection-{self.scenario.name}",
                    "principal": {"kind": "user", "id": str(os.getuid()), "via": []},
                    "body": dict(body),
                },
                chain[-1] if chain else None,
            )
        )

    def _attachments(self, entries: list[dict[str, object]]) -> dict[str, object]:
        """The exact bytes of every version the included effects name.

        This fake holds one policy — the rules its scenario gave it — so every
        effect in a range names one version, and the bytes attached under it
        are the bytes that were hashed to make it.
        """
        named = {
            str(entry["body"]["policy_version"])  # type: ignore[index]
            for entry in entries
            if entry["kind"] == "effect"
        }
        content = base64.b64encode(_policy_bytes(self.scenario.given.policy or {})).decode("ascii")
        return {version: {"state": "present", "content": content} for version in sorted(named)}

    def _range_refusal(
        self,
        from_sequence: int,
        *,
        page_size: int | None = None,
        to_sequence: int | None = None,
    ) -> Refused | CouldNotAsk | None:
        """The published refusal for a range outside the bounds the binding names.

        The socket face refuses these before this one is reached; they are here
        because the in-process face is a published object too, and a caller that
        asks it for a range it cannot serve is owed a result and not an
        exception out of a verifier (articles 1 and 2).
        """
        invalid = from_sequence < 1
        invalid = invalid or (page_size is not None and not 1 <= page_size <= _PAGE_BOUND)
        invalid = invalid or (to_sequence is not None and to_sequence < from_sequence)
        if invalid:
            return self._published(ProblemCode.EVIDENCE_RANGE_INVALID, "evidence range is invalid")
        return None

    def _scope_refusal(self, scope: str) -> Refused | CouldNotAsk | None:
        """The published refusal for a scope the contract's own pattern rejects.

        Asked of the published verifier rather than matched here: `verify_chain`
        holds a caller's scope to the contract, and an empty range from sequence
        one is the one call to it that can fail for the scope and for nothing
        else. So this fake answers the code the daemon answers for the same
        input without keeping a second copy of the pattern (articles 2 and 13).
        """
        try:
            verify_chain((), scope=scope, from_sequence=1)
        except InvalidBundle:
            return self._published(ProblemCode.SCOPE_INVALID, "scope is malformed")
        return None

    def _verify(
        self,
        entries: list[dict[str, object]],
        scope: str,
        from_sequence: int,
        to_sequence: int | None,
    ) -> ChainVerdict | Refused | CouldNotAsk:
        """The published verdict over this range, or the defect that stopped it.

        `verify_chain` raises for the CALLER's arguments alone and for an entry
        document this generation cannot read as an entry; the scope and the
        range were both held above, so what is left is an entry this fake
        placed that the published reader cannot read. That is a defect of this
        fake and is answered as one — `internal`, and the verifier's own
        complaint carried with it (rule P1).

        Narrow on purpose. Answering `scope_invalid` for every `InvalidBundle`
        would report a future entry-shape failure as a complaint about the
        caller's scope, which is a statement about something that was read and
        found good (article 2).
        """
        try:
            return verify_chain(
                entries, scope=scope, from_sequence=from_sequence, to_sequence=to_sequence
            )
        except InvalidBundle as complaint:
            return self._published(
                ProblemCode.INTERNAL, f"this fake placed an entry it cannot read back: {complaint}"
            )

    def _expire(self, approval: Approval) -> Approval:
        """End a wait that ran out, at the deadline it ran out at.

        `resolved_at` is the deadline and can be nothing else: a server's own
        record refuses any other value for an expired wait, and a lapse dated
        by the instant somebody happened to read it would name an instant
        nothing decided (article 2). A fake that served `expired` with no
        instant would serve a document no daemon can, which is the one thing
        the arbiter of a contract must not do (article 13).
        """
        if approval.state is ApprovalState.PENDING and self._now() >= datetime.fromisoformat(
            approval.deadline
        ):
            expired = replace(approval, state=ApprovalState.EXPIRED, resolved_at=approval.deadline)
            self._approvals[(approval.scope, approval.approval_ref)] = expired
            self._approval_records.append(expired)
            return expired
        return approval

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("stub clock must return an offset-aware instant")
        return value

    def _published(self, code: ProblemCode, message: str) -> Refused | CouldNotAsk:
        """One problem this fake publishes, classed exactly as the registry classes it.

        Retryability was already read from the registry here; the class is the
        other column of the same row, and reading one while deciding the other
        by hand is how a fake comes to answer something no daemon answers. A
        consumer whose governed program passes against this fake and fails
        against a daemon has been told the opposite of what the conformance kit
        is for (article 13).

        `internal` is where it shows: the registry classes it « could not ask »,
        because a server that cannot say why it failed has not refused the
        question — it has failed to answer it (articles 1 and 2).
        """
        problem = Problem(
            code,
            message,
            problem_retryable(code),
            CONTRACT_GENERATION,
            control_plane_answered=True,
        )
        return Refused(problem) if problem_class_of(problem) == "refused" else CouldNotAsk(problem)


class StubSession:
    def __init__(self, scenario: Scenario) -> None:
        self._now = datetime(2026, 9, 4, tzinfo=UTC)
        self.client = Stub(
            scenario.name,
            scenarios={scenario.name: scenario},
            clock=lambda: self._now,
        )

    def pass_deadline(self) -> None:
        self._now += timedelta(seconds=61)

    def change_policy(self, policy: Mapping[str, object]) -> None:
        self.client.change_policy()

    def close(self) -> None:
        pass


class StubHarness:
    def arrange(self, scenario: Scenario) -> StubSession:
        return StubSession(scenario)
