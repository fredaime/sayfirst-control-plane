# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from sayfirst_contract.approvals import Approval, ApprovalResolution
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_contract.golden import Regime, Scenario, load_scenarios
from sayfirst_contract.problems import Problem, ProblemCode, problem_retryable
from sayfirst_contract.replay import RunVerdict, Side, Verdict, compare, replay
from sayfirst_contract_stub.stub import StubHarness
from sayfirst_control_plane.adapters.api.approval_routes import (
    READ_REFUSALS,
    RESOLVE_REFUSALS,
    ApprovalProviderUnavailable,
    ApprovalRoutes,
)
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.approvals import ApprovalStore, SimpleApprovalProvider
from sayfirst_control_plane.application.decisions import (
    DecisionAnswer,
    DecisionProblem,
    DecisionService,
)
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.policy import (
    DecisionQuestion,
    PolicyInvalid,
    Principal,
    parse_policy,
)
from sayfirst_control_plane.ports.policy_store import (
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)
from scenario_daemon import REVIEW_DEADLINE_SECONDS, Clock


class _ProtectedPolicyStore(FilePolicyStore):
    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


_OUTCOME_OF = {Regime.AUTO: "allow", Regime.REVIEW: "suspend", Regime.DENY: "deny"}


#: The person every act replayed here is attributed to. In the daemon it is the
#: connection's verified principal; this harness has one principal and it is the
#: one below, so an act it records is the act of the caller that asked.
PERSON = "user:scenario"


def _policy_document(
    policy: Mapping[str, Regime],
    *,
    arrangement: tuple[str, ...] | None = None,
    arranged_capability: str | None = None,
) -> bytes:
    """Write the scenario's policy, expanding the arranged capability in its own order.

    A scenario that scripts `applying_outcomes` scripts an arrangement of several
    applying rules, and their file order is part of what it proves, so the rules
    are written one per entry and in the entry order (articles 9 and 13).

    A suspend rule carries the wait above; the loader refuses the member on any
    other outcome, so it is written where it belongs and nowhere else.
    """
    lines = ["format = 1", "[revision]", 'reason = "scenario arrangement"']
    index = 0
    for capability, regime in policy.items():
        outcomes = (
            arrangement
            if arrangement is not None and capability == arranged_capability
            else (_OUTCOME_OF[regime],)
        )
        for outcome in outcomes:
            lines.extend(
                (
                    "[[rule]]",
                    f'id = "scenario-{index}"',
                    f'capability = "{capability}"',
                    f'principals = ["{PERSON}"]',
                    f'outcome = "{outcome}"',
                    'reason = "scenario rule"',
                )
            )
            if outcome == "suspend":
                lines.append(f"review_deadline_seconds = {REVIEW_DEADLINE_SECONDS}")
            index += 1
    return ("\n".join(lines) + "\n").encode()


class _ServerClient:
    """The client of this in-process run: the routes a connection would reach.

    Each operation goes through the same route object the socket surface calls
    and answers the same refusals, so what this run compares with the published
    fake is the server's own behaviour and not a second implementation of it.
    Where the surface would write a status, this maps the route's refusal to the
    result the published client makes of that status — a could-not-ask for a
    provider that gave no answer, a refusal for the rest — which is the one
    piece of translation a run without a transport under it has to do.
    """

    def __init__(
        self, service: DecisionService, approvals: ApprovalRoutes, scenario: Scenario
    ) -> None:
        self.service = service
        self.approvals = approvals
        self.scenario = scenario

    def ask_decision(self, ask: DecisionAsk):  # type: ignore[no-untyped-def]
        question = DecisionQuestion(
            ask,
            Principal("process", os.getuid(), "scenario", tuple(os.getgroups()), ()),
        )
        result = self.service.ask(
            question,
            grant_connection=self.scenario.given.signal_channel,
        )
        if isinstance(result, DecisionAnswer):
            return Answered(result.decision, result.decision.contract_generation)
        assert isinstance(result, DecisionProblem)
        if result.problem.code is ProblemCode.POLICY_UNAVAILABLE:
            return CouldNotAsk(result.problem)
        return Refused(result.problem)

    def read_status(self):  # type: ignore[no-untyped-def]
        raise AssertionError("status is outside these decision scenarios")

    def read_approval(self, scope: str, approval_ref: str):  # type: ignore[no-untyped-def]
        try:
            document = self.approvals.read(scope, approval_ref)
        except READ_REFUSALS as refused:
            return self._refused(refused)
        return Answered(Approval.from_document(document), CONTRACT_GENERATION)

    def resolve_approval(self, resolution: ApprovalResolution):  # type: ignore[no-untyped-def]
        try:
            document = self.approvals.resolve(
                resolution.approval_ref,
                resolution.to_document(CONTRACT_GENERATION),
                person=PERSON,
            )
        except RESOLVE_REFUSALS as refused:
            return self._refused(refused)
        return Answered(Approval.from_document(document), CONTRACT_GENERATION)

    def _refused(self, refused: Exception):  # type: ignore[no-untyped-def]
        """One route refusal, as a result carrying the code the registry publishes."""
        code = ProblemCode(refused.code)  # type: ignore[attr-defined]
        problem = Problem(code, str(refused), problem_retryable(code), CONTRACT_GENERATION)
        if isinstance(refused, ApprovalProviderUnavailable):
            # Nothing was applied, so no act was refused: article 1 keeps an
            # absent answer apart from a verdict.
            return CouldNotAsk(problem)
        return Refused(problem)


class _ServerSession:
    def __init__(self, root: Path, scenario: Scenario) -> None:
        self.scenario = scenario
        self.path = root / f"{scenario.name}.toml"
        initial = scenario.given.policy or {}
        self.path.write_bytes(
            _policy_document(
                initial,
                arrangement=scenario.given.applying_outcomes,
                arranged_capability=scenario.ask.capability,
            )
        )
        os.chmod(self.path, 0o600)
        authority = _ProtectedPolicyStore(self.path, clock=lambda: datetime(2026, 9, 4, tzinfo=UTC))
        policy = PolicyService(authority, (MemoryPolicyProjection(),))
        policy.start(ProtectionExpectation.per_user(os.getuid()))
        if scenario.given.policy_unavailable:
            self.path.unlink()
        self.clock = Clock()
        # Composed together or not at all, which is the service's own rule: a
        # store nothing opens into would answer every re-ask with a new wait.
        approvals = ApprovalStore(clock=self.clock)
        service = DecisionService(
            policy,
            authority,
            MemoryDecisionStore(),
            GrantConnections(),
            events=MemoryEvents(),
            approvals=approvals,
            approval_provider=SimpleApprovalProvider(approvals),
            clock=self.clock,
            id_factory=self._next_id,
        )
        self.client = _ServerClient(service, ApprovalRoutes(service), scenario)
        self._identifiers = iter(("decision-1", "grant-1", "decision-2", "grant-2"))

    def _next_id(self) -> str:
        return next(self._identifiers)

    def change_policy(self, policy: Mapping[str, object]) -> None:
        typed = {name: Regime(value) for name, value in policy.items()}
        self.path.write_bytes(_policy_document(typed))

    def pass_deadline(self) -> None:
        """Put this session's clock past the wait its own policy arranged.

        A controlled clock rather than a real wait, because the driver offers
        one and this session owns every clock the wait is measured by: the
        service that set the deadline and the store that renders the state read
        the same instant. Nothing sleeps, so a lapse is proven rather than
        raced, and the number stepped over is the number written into the rule.
        """
        self.clock.advance(REVIEW_DEADLINE_SECONDS + 1)

    def close(self) -> None:
        pass


class _ServerHarness:
    def __init__(self, root: Path) -> None:
        self.root = root

    def arrange(self, scenario: Scenario) -> _ServerSession:
        return _ServerSession(self.root, scenario)


# Every server-bound scenario is replayed here, the three that end a wait
# included: this harness composes an approval store and the simple provider
# beside it, its client answers the two published approval operations out of
# the same routes the socket surface calls, and its clock is one it can put
# past a deadline. Nothing is declared absent, so the run claims the whole
# side — which is the claim article 2 makes it earn (the run verdict below is
# `proven`, and it is `unknown` the moment one scenario stops being replayed).
EXPECTED_ABSENT: dict[str, str] = {}


def test_the_replay_arranges_every_applying_rule_in_the_scenario_order(
    tmp_path: Path,
) -> None:
    """Articles 9 and 13: the arrangement a scenario scripts is part of what it proves.

    `strictest_rule_wins` arranges three applying rules and asserts that the
    strictest one answers. A replay that wrote one rule, or wrote the three in
    another order, would report `proven` for a scenario it never ran.
    """
    scenario = load_scenarios()["strictest_rule_wins"]
    arrangement = scenario.given.applying_outcomes
    assert arrangement == ("allow", "suspend", "deny")
    session = _ServerHarness(tmp_path).arrange(scenario)
    policy = parse_policy(session.path.read_bytes())
    assert not isinstance(policy, PolicyInvalid)
    question = DecisionQuestion(
        scenario.ask,
        Principal("process", os.getuid(), "scenario", tuple(os.getgroups()), ()),
    )
    # Every arranged rule applies to the scenario's own ask, in the arranged order.
    assert tuple(rule.outcome.value for rule in policy.rules) == arrangement
    assert all(rule.applies(question) for rule in policy.rules)
    answered = session.client.ask_decision(scenario.ask)
    assert isinstance(answered, Answered)
    assert answered.value.outcome.value == scenario.expect.outcome
    # The deny rule is last in this arrangement, so the rule the answer names
    # changes the moment the replay reorders or collapses the rules.
    assert answered.value.extra["rule_id"] == policy.rules[-1].rule_id


def test_the_server_replays_every_scenario_that_binds_it(tmp_path: Path) -> None:
    """Article 13: the real server and published fake agree on every server-bound fixture."""
    scenarios = load_scenarios()
    bound = {name for name, item in scenarios.items() if item.binds_server()}
    assert len(bound) == 11
    server_report = replay(
        scenarios, _ServerHarness(tmp_path), Side.SERVER, expected_absent=EXPECTED_ABSENT
    )
    stub_report = replay(scenarios, StubHarness(), Side.SERVER, expected_absent=EXPECTED_ABSENT)
    assert server_report.failures() == (), [
        (item.name, item.detail) for item in server_report.failures()
    ]
    assert stub_report.failures() == ()
    assert compare(server_report, stub_report) == ()
    assert {item.name for item in server_report.proven()} == bound - set(EXPECTED_ABSENT)
    # The three scenarios that end a wait are the ones this run used to declare
    # absent; naming them keeps the change from being undone by a rewrite of
    # the set above (article 9).
    assert {"review_approve", "review_reject", "review_expire"} <= {
        item.name for item in server_report.proven()
    }


def test_no_server_bound_scenario_leaves_the_run_unaccounted_for(tmp_path: Path) -> None:
    """Article 9's anti-vacuity and article 2: an omission is recorded, never silent."""
    scenarios = load_scenarios()
    report = replay(
        scenarios, _ServerHarness(tmp_path), Side.SERVER, expected_absent=EXPECTED_ABSENT
    )
    reported = {item.name: item for item in report.scenarios}
    assert set(reported) == set(scenarios)
    for name, scenario in scenarios.items():
        item = reported[name]
        if not scenario.binds_server():
            assert item.detail == f"binds {scenario.binds.value}, not server"
        elif name in EXPECTED_ABSENT:
            assert item.verdict is Verdict.NOT_APPLICABLE
            assert item.detail == EXPECTED_ABSENT[name]
        else:
            assert item.verdict is Verdict.PROVEN, (name, item.detail)
    assert report.failures() == ()
    # The run verdict is three-valued, and nothing is declared absent any
    # more: every server-bound scenario was replayed and matched, so the run
    # claims the whole side. The `unknown` this asserted while three waits went
    # unreplayed is what article 2 required then and would require again.
    assert EXPECTED_ABSENT == {}
    assert report.verdict is RunVerdict.PROVEN
    assert report.succeeded()
    assert report.failure_reason() is None
