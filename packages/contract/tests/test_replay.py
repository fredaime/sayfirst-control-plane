# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import replace

import pytest
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.decisions import read_decision
from sayfirst_contract.generation import CONTRACT_GENERATION, NegotiatedClient
from sayfirst_contract.golden import ContractDefect, Expect, load_scenarios
from sayfirst_contract.problems import Problem, ProblemCode
from sayfirst_contract.replay import (
    Observed,
    RunVerdict,
    Side,
    Verdict,
    _matches,
    _observe,
    replay,
    scenario_asserts_an_observable,
)
from sayfirst_contract.status import (
    Authority,
    GradeBasis,
    IntegrityGrade,
    IntegrityGradeStatus,
    Principal,
    Status,
)


def test_the_replayer_runs_exactly_the_scenarios_bound_to_a_side() -> None:
    """Article 13: the side selector never runs a scenario that does not bind it."""
    arranged = []

    class Session:
        client = None

        def pass_deadline(self) -> None: ...

        def close(self) -> None: ...

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            arranged.append(scenario.name)
            raise RuntimeError("recorded")

    report = replay(load_scenarios(), Harness(), Side.CLIENT)
    assert set(arranged) == {
        name for name, scenario in load_scenarios().items() if scenario.binds_client()
    }
    assert all(
        item.verdict is Verdict.NOT_APPLICABLE
        for item in report.scenarios
        if item.name not in arranged
    )


def test_a_scenario_that_raises_is_a_failed_verdict_not_a_crash() -> None:
    """Article 13: one broken scenario remains a report entry."""

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            raise LookupError("exploded")

    report = replay({"allow": load_scenarios()["allow"]}, Harness(), Side.SERVER)
    assert len(report.failures()) == 1
    assert "LookupError" in report.failures()[0].detail


def test_a_decision_observation_reports_whether_a_grant_was_issued() -> None:
    """Articles 10 and 13: replay observations distinguish a grant from null."""
    decision = read_decision(
        {
            "contract_generation": 1,
            "authority": "authoritative",
            "decision_ref": "decision-1",
            "scope": "local",
            "capability": "example.effect",
            "outcome": "allow",
            "reason": "policy_allows",
            "policy_version": "sha256:" + "0" * 64,
            "approval_ref": None,
            "decided_at": "2026-09-04T00:00:00Z",
            "correlation": None,
            "grant": {"grant_id": "grant-1"},
        }
    )
    assert isinstance(decision, Answered)
    assert _observe(decision) == Observed(outcome="allow", reason="policy_allows", grant="present")


def test_expected_absence_is_named_and_never_arranged() -> None:
    """Article 13: a missing skeleton block is visible with its exact reason."""

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            raise AssertionError("an expected-absent scenario must not be arranged")

    reason = "requires the policy authority from block 2.3"
    report = replay(
        {"allow": load_scenarios()["allow"]},
        Harness(),
        Side.SERVER,
        expected_absent={"allow": reason},
    )
    item = report.scenarios[0]
    assert item.verdict is Verdict.NOT_APPLICABLE
    assert item.detail == reason
    assert report.proven() == ()
    assert not report.succeeded()
    assert report.failure_reason() == "1 server-bound scenario was not replayed"


def test_expected_absence_refuses_typos_and_empty_reasons() -> None:
    """Article 13: an expected absence cannot silently select nothing."""

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            raise AssertionError

    scenarios = {"allow": load_scenarios()["allow"]}
    with pytest.raises(ContractDefect, match="unknown scenario"):
        replay(scenarios, Harness(), Side.SERVER, expected_absent={"typo": "missing"})
    with pytest.raises(ContractDefect, match="non-empty reason"):
        replay(scenarios, Harness(), Side.SERVER, expected_absent={"allow": ""})


def test_a_run_that_checks_nothing_is_a_failure() -> None:
    """Articles 9 and 13: a scenario with no observable assertion never proves."""

    class Session:
        class Client:
            def ask_decision(self, ask):  # type: ignore[no-untyped-def]
                return Refused(
                    Problem(ProblemCode.INTERNAL, "planted refusal", None, CONTRACT_GENERATION)
                )

        client = Client()

        def pass_deadline(self) -> None: ...

        def close(self) -> None: ...

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            return Session()

    scenario = replace(load_scenarios()["review_approve"], expect=Expect())
    report = replay({scenario.name: scenario}, Harness(), Side.SERVER)
    assert len(report.failures()) == 1
    # The `then` block asserts two observables — where the wait ended, and what
    # the re-ask of that question was answered — so emptying `expect` leaves
    # two, not one, and the count is the fixture's own (article 9).
    assert report.failures()[0].assertion_count == 2
    assert report.failures()[0].expected == {
        "state": "approved",
        "after_resolution": {"outcome": "allow", "reason": "approval_granted"},
    }
    assert report.failures()[0].detail == (
        "state: expected 'approved', observed None; "
        "after_resolution: expected {'outcome': 'allow', 'reason': 'approval_granted'}, "
        "observed None"
    )
    assert report.proven() == ()
    assert not report.succeeded()
    assert report.verdict is RunVerdict.FAILED


def test_the_run_result_has_distinct_proven_failed_and_unknown_values() -> None:
    """Article 2: the run-level status is explicitly three-valued."""
    assert {item.value for item in RunVerdict} == {"proven", "failed", "unknown"}


def test_each_scenario_verdict_has_one_published_name() -> None:
    """Article 13: unreleased compatibility aliases do not duplicate vocabulary."""
    assert len(Verdict.__members__) == len(Verdict)


def test_an_incomplete_run_is_unknown_even_when_one_scenario_is_proven() -> None:
    """Articles 2 and 13: a partial replay cannot claim conformance."""

    class Session:
        class Client:
            def ask_decision(self, ask):  # type: ignore[no-untyped-def]
                return read_decision(
                    {
                        "contract_generation": CONTRACT_GENERATION,
                        "authority": "authoritative",
                        "decision_ref": "decision-1",
                        "scope": ask.scope,
                        "capability": ask.capability,
                        "outcome": "allow",
                        "reason": "policy_allows",
                        "policy_version": "sha256:" + "0" * 64,
                        "approval_ref": None,
                        "decided_at": "2026-09-04T00:00:00+00:00",
                        "correlation": None,
                        # The allow scenario expects a grant since block 2.3 (article 10).
                        "grant": {"grant_id": "grant-1"},
                    }
                )

        client = Client()

        def pass_deadline(self) -> None: ...

        def close(self) -> None: ...

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            assert scenario.name == "allow"
            return Session()

    scenarios = load_scenarios()
    report = replay(
        {"allow": scenarios["allow"], "deny": scenarios["deny"]},
        Harness(),
        Side.SERVER,
        expected_absent={"deny": "not available for this test"},
    )
    assert report.verdict is RunVerdict.UNKNOWN
    assert not report.succeeded()
    assert report.failure_reason() == "1 server-bound scenario was not replayed"


def test_a_run_with_no_scenario_at_all_never_reports_success() -> None:
    """Article 13: a vacuous acceptance run never reports success."""

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            raise AssertionError

    report = replay({}, Harness(), Side.SERVER)
    assert report.failures() == ()
    assert report.proven() == ()
    assert not report.succeeded()
    assert report.failure_reason() == "no scenario was proven"


def test_the_client_refuses_a_server_that_does_not_support_its_generation() -> None:
    """Article 13: negotiation blocks later operations before they are sent."""

    class Fake:
        def __init__(self) -> None:
            self.calls = []

        def read_status(self):  # type: ignore[no-untyped-def]
            self.calls.append("read_status")
            value = Status(
                99,
                (99,),
                IntegrityGradeStatus(
                    IntegrityGrade.UNVERIFIED,
                    GradeBasis.ACCESS_NOT_ESTABLISHED,
                    "2026-09-04T00:00:00+00:00",
                    "file",
                    30,
                    {},
                ),
                "none",
                Principal("user", 1000, None),
                Authority.AUTHORITATIVE,
                "file",
                {},
            )
            return Answered(value, 99)

        def ask_decision(self, ask):  # type: ignore[no-untyped-def]
            self.calls.append("ask_decision")
            raise AssertionError("must not be sent")

        def read_approval(self, scope, approval_ref):  # type: ignore[no-untyped-def]
            self.calls.append("read_approval")
            raise AssertionError("must not be sent")

        def resolve_approval(self, resolution):  # type: ignore[no-untyped-def]
            self.calls.append("resolve_approval")
            raise AssertionError("must not be sent")

    fake = Fake()
    client = NegotiatedClient(fake)
    scenario = load_scenarios()["allow"]
    results = (
        client.ask_decision(scenario.ask),
        client.read_approval("local", "approval-1"),
    )
    assert all(isinstance(result, CouldNotAsk) for result in results)
    assert all(result.problem.code is ProblemCode.GENERATION_UNSUPPORTED for result in results)
    assert fake.calls == ["read_status"]
    assert CONTRACT_GENERATION not in (99,)


def test_failed_generation_handshake_blocks_later_operations() -> None:
    """Article 13: an unreadable generation echo cannot be ignored after connect."""

    class Fake:
        def read_status(self):  # type: ignore[no-untyped-def]
            return CouldNotAsk(
                Problem(
                    ProblemCode.GENERATION_UNSUPPORTED,
                    "wrong response generation",
                    False,
                    42,
                )
            )

        def ask_decision(self, ask):  # type: ignore[no-untyped-def]
            raise AssertionError("must not be sent after a failed handshake")

    client = NegotiatedClient(Fake())
    result = client.ask_decision(load_scenarios()["allow"].ask)
    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED


def test_could_not_ask_is_never_rendered_as_deny() -> None:
    """Articles 1 and 2: client-bound failures preserve unknown instead of denial."""
    scenarios = {
        name: scenario
        for name, scenario in load_scenarios().items()
        if scenario.given.server is not None
    }

    class Client:
        def __init__(self, scenario) -> None:  # type: ignore[no-untyped-def]
            self.scenario = scenario

        def ask_decision(self, ask):  # type: ignore[no-untyped-def]
            if self.scenario.given.server == "unreachable":
                return CouldNotAsk(
                    Problem(ProblemCode.UNREACHABLE, "could not be reached", True, 1)
                )
            answers = self.scenario.given.server.members
            return read_decision(
                {
                    "contract_generation": 1,
                    "authority": "authoritative",
                    "decision_ref": "decision-1",
                    "scope": ask.scope,
                    "capability": ask.capability,
                    "outcome": answers["outcome"],
                    "reason": answers["reason"],
                    "policy_version": "sha256:" + "0" * 64,
                    "approval_ref": None,
                    "decided_at": "2026-09-04T00:00:00+00:00",
                    "correlation": None,
                }
            )

    class Session:
        def __init__(self, scenario) -> None:  # type: ignore[no-untyped-def]
            self.client = Client(scenario)

        def pass_deadline(self) -> None: ...

        def close(self) -> None: ...

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            return Session(scenario)

    report = replay(scenarios, Harness(), Side.CLIENT)
    assert report.failures() == ()
    unknown = next(item for item in report.bound() if item.name == "unknown_outcome")
    assert unknown.observed is not None
    assert unknown.observed.outcome is None
    assert unknown.observed.reported_outcome == "unknown"
    assert all(item.observed is None or item.observed.outcome != "deny" for item in report.bound())


def test_a_scenario_asserting_no_observable_fails_without_reaching_the_harness() -> None:
    """Articles 9 and 13: a scenario that compares nothing is a failure, never a proof.

    This is the anti-vacuity floor inside `replay`. `test_a_run_that_checks_nothing_is_a_failure`
    plants a scenario whose `then` still asserts a state, so it never reaches zero
    assertions; this one plants a scenario that asserts nothing at all — the shape a
    consumer can build from the published `Scenario` and hand to the published `replay`.
    Deleting the floor turns this red: the scenario reaches the harness, and a comparison
    over no member is what article 9 calls a verification that succeeds by checking nothing.
    """
    arranged = []

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            arranged.append(scenario.name)
            raise AssertionError("a scenario that asserts nothing must not be replayed")

    scenario = replace(load_scenarios()["allow"], expect=Expect(), then=None)
    report = replay({scenario.name: scenario}, Harness(), Side.SERVER)

    assert arranged == []  # article 2: the daemon was never asked, so nothing is claimed of it
    assert len(report.failures()) == 1
    failed = report.failures()[0]
    assert failed.verdict is Verdict.FAILED
    assert failed.detail == "scenario asserts no observable"
    assert failed.expected == {}
    assert failed.assertion_count == 0
    assert report.proven() == ()
    assert not report.succeeded()
    assert report.verdict is RunVerdict.FAILED


def test_the_comparison_of_no_members_is_never_a_match() -> None:
    """Article 9: the floor under the comparison itself, named once and held here.

    `_matches` is the second floor: `all()` over an empty mapping is `True`, so without
    it an empty expectation would prove every observation. The floor inside `replay`
    keeps this path unreachable through the public entry point, which is why it is
    exercised directly — a defence that no test can reach is a defence that can be
    deleted in silence, which is the defect this test exists to prevent.
    """
    assert scenario_asserts_an_observable({}) is False
    assert scenario_asserts_an_observable({"outcome": "allow"}) is True
    assert _matches({}, Observed(outcome="allow")) is False
    assert _matches({"outcome": "allow"}, Observed(outcome="allow")) is True
    assert _matches({"outcome": "allow"}, Observed(outcome="deny")) is False


def test_a_scenario_that_was_never_compared_reports_no_assertion_count() -> None:
    """Article 2: an absence is never rendered as a number, not even zero.

    `assertion_count` exists so a reader can see non-vacuity without parsing English.
    It must therefore count members the runner actually compared: a scenario that
    binds the other side, one declared absent, and one whose harness never reached a
    comparison made no assertion at all, and a count filled from the fixture would be
    the one machine-readable field that reads healthy when nothing happened.
    """

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            raise LookupError("no socket configured")

    scenarios = {
        name: scenario
        for name, scenario in load_scenarios().items()
        if name in {"allow", "deny", "unreachable"}
    }
    report = replay(
        scenarios,
        Harness(),
        Side.SERVER,
        expected_absent={"deny": "requires a separately configured daemon"},
    )
    counts = {item.name: item.assertion_count for item in report.scenarios}
    assert counts["unreachable"] is None  # binds the client: this side compared nothing
    assert counts["deny"] is None  # declared absent: the daemon was never asked
    assert counts["allow"] is None  # the harness never reached a comparison
    assert all(item.expected for item in report.scenarios)  # the fixture still states its asks


def test_a_compared_scenario_counts_the_members_it_compared() -> None:
    """Article 13: the count a reader may trust is the count of real comparisons."""

    expected = load_scenarios()["allow"].expect.members()

    class Session:
        class Client:
            def ask_decision(self, ask):  # type: ignore[no-untyped-def]
                return read_decision(
                    {
                        "contract_generation": 1,
                        "authority": "authoritative",
                        "decision_ref": "decision-1",
                        "scope": ask.scope,
                        "capability": ask.capability,
                        "outcome": expected["outcome"],
                        "reason": expected["reason"],
                        "policy_version": "sha256:" + "0" * 64,
                        "approval_ref": None,
                        "decided_at": "2026-09-04T00:00:00+00:00",
                        "correlation": None,
                        # The allow scenario expects a grant since block 2.3 (article 10).
                        "grant": {"grant_id": "grant-1"},
                    }
                )

        client = Client()

        def pass_deadline(self) -> None: ...

        def close(self) -> None: ...

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            return Session()

    scenarios = {"allow": load_scenarios()["allow"]}
    report = replay(scenarios, Harness(), Side.SERVER)
    proven = report.proven()
    assert len(proven) == 1
    assert proven[0].assertion_count == len(proven[0].expected)
    # Three since block 2.3 added `grant` to what the allow scenario asserts.
    assert proven[0].assertion_count == 3


def test_a_refused_status_handshake_blocks_later_operations_as_could_not_ask() -> None:
    """Articles 1 and 2: "could not ask" is never written as "was refused".

    A refusal is the server answering *this* request with a problem document. When the
    status handshake fails, every later operation is stopped inside the client and never
    leaves the process, so reporting it as a refusal states that a server refused an
    operation it was never sent. The problem is kept — it is why the connection is
    unusable — and only the kind changes.
    """

    class Fake:
        def __init__(self) -> None:
            self.sent: list[str] = []

        def read_status(self):  # type: ignore[no-untyped-def]
            self.sent.append("read_status")
            return Refused(Problem(ProblemCode.INTERNAL, "boom", None, CONTRACT_GENERATION))

        def ask_decision(self, ask):  # type: ignore[no-untyped-def]
            self.sent.append("ask_decision")
            raise AssertionError("must not be sent after a refused handshake")

        def read_approval(self, scope, approval_ref):  # type: ignore[no-untyped-def]
            self.sent.append("read_approval")
            raise AssertionError("must not be sent after a refused handshake")

    fake = Fake()
    client = NegotiatedClient(fake)

    # The status request itself was sent and was refused: that refusal stands as observed.
    assert isinstance(client.read_status(), Refused)

    results = (
        client.ask_decision(load_scenarios()["allow"].ask),
        client.read_approval("local", "approval-1"),
    )
    assert all(isinstance(result, CouldNotAsk) for result in results)
    assert all(result.problem.code is ProblemCode.INTERNAL for result in results)
    assert all(result.reported_outcome == "unknown" for result in results)
    assert fake.sent == ["read_status"]


def test_the_replayer_never_records_a_refusal_of_an_unsent_operation() -> None:
    """Article 2: the conformance report carries the distinction the client makes."""

    class Fake:
        def read_status(self):  # type: ignore[no-untyped-def]
            return Refused(Problem(ProblemCode.INTERNAL, "boom", None, CONTRACT_GENERATION))

        def ask_decision(self, ask):  # type: ignore[no-untyped-def]
            raise AssertionError("must not be sent after a refused handshake")

    class Session:
        client = NegotiatedClient(Fake())

        def pass_deadline(self) -> None: ...

        def close(self) -> None: ...

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            return Session()

    report = replay({"allow": load_scenarios()["allow"]}, Harness(), Side.SERVER)
    observed = report.scenarios[0].observed
    assert observed is not None
    assert observed.result == "could_not_ask"
    assert observed.problem == "internal"
    assert observed.reported_outcome == "unknown"


def test_the_whole_run_sentence_names_the_side_that_was_not_replayed() -> None:
    """Article 2: the report's only whole-run sentence is true on both sides.

    `failure_reason` is what the command prints as its single summary line. It named
    the server whatever side was replayed, so a client-side run said "server-bound" of
    its own unreplayed scenarios — a false sentence about the one thing a reader who
    reads nothing else will read.
    """

    class Harness:
        def arrange(self, scenario):  # type: ignore[no-untyped-def]
            raise AssertionError("declared absent, so never arranged")

    client_bound = {
        name: scenario for name, scenario in load_scenarios().items() if scenario.binds_client()
    }
    report = replay(
        client_bound,
        Harness(),
        Side.CLIENT,
        expected_absent=dict.fromkeys(client_bound, "no client under test"),
    )
    assert report.verdict is RunVerdict.UNKNOWN
    assert report.failure_reason() == (
        f"{len(client_bound)} client-bound scenarios were not replayed"
    )
