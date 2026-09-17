# SPDX-License-Identifier: Apache-2.0
"""A side-neutral runner for the authoritative scenarios."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final, Protocol

from .approvals import ApprovalResolution, Resolution
from .client import Answered, ControlPlaneClient, CouldNotAsk, Refused
from .decisions import DecisionAsk
from .golden import ContractDefect, Scenario


class Side(StrEnum):
    CLIENT = "client"
    SERVER = "server"


class Session(Protocol):
    client: ControlPlaneClient

    def pass_deadline(self) -> None: ...

    def change_policy(self, policy: Mapping[str, object]) -> None: ...

    def use_grant(self, grant: Mapping[str, object], ask: DecisionAsk) -> str:
        """Answer what the grant just issued covers, under this scenario's arrangement."""
        ...

    def close(self) -> None: ...


class Harness(Protocol):
    def arrange(self, scenario: Scenario) -> Session:
        """Prepare the scenario world and return a client bound to it."""
        ...


class ScenarioNotApplicable(RuntimeError):
    """The environment cannot exercise a bound scenario."""


class Verdict(StrEnum):
    PROVEN = "proven"
    FAILED = "failed"
    NOT_APPLICABLE = "not-applicable"


class RunVerdict(StrEnum):
    PROVEN = "proven"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Observed:
    outcome: str | None = None
    reason: str | None = None
    result: str | None = None
    problem: str | None = None
    reported_outcome: str | None = None
    state: str | None = None
    grant: str | None = None
    grant_use: str | None = None
    after_policy_change: Mapping[str, object] | None = None
    #: The outcome and reason a re-ask got once a person had acted. Two members
    #: and no more: what a grant covers after a resolved wait is a different
    #: property, and a member neither side is asked for would make the two
    #: reports differ over something no fixture asserts (articles 9 and 13).
    after_resolution: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ScenarioReport:
    name: str
    verdict: Verdict
    expected: Mapping[str, object]
    observed: Observed | None
    detail: str
    bound_to_side: bool = True
    #: Observable members this line's verdict actually rests on, or `None` when no
    #: comparison was made — the scenario binds the other side, was declared absent,
    #: or never reached the harness. Article 2: an absence is not a zero, and it is not
    #: the fixture's own count either. Defaulting to `None` keeps a caller that states
    #: no count from claiming one.
    assertion_count: int | None = None


@dataclass(frozen=True)
class Report:
    side: Side
    scenarios: tuple[ScenarioReport, ...]

    def failures(self) -> tuple[ScenarioReport, ...]:
        return tuple(item for item in self.scenarios if item.verdict is Verdict.FAILED)

    def bound(self) -> tuple[ScenarioReport, ...]:
        return tuple(item for item in self.scenarios if item.verdict is not Verdict.NOT_APPLICABLE)

    def proven(self) -> tuple[ScenarioReport, ...]:
        return tuple(item for item in self.scenarios if item.verdict is Verdict.PROVEN)

    @property
    def verdict(self) -> RunVerdict:
        """The honest whole-run claim, including bound scenarios not replayed."""
        if self.failures():
            return RunVerdict.FAILED
        incomplete = any(
            item.bound_to_side and item.verdict is Verdict.NOT_APPLICABLE for item in self.scenarios
        )
        if incomplete or not self.proven():
            return RunVerdict.UNKNOWN
        return RunVerdict.PROVEN

    def succeeded(self) -> bool:
        """Whether every bound scenario was replayed and proven."""
        return self.verdict is RunVerdict.PROVEN

    def failure_reason(self) -> str | None:
        """Explain why the whole run is not successful."""
        if self.failures():
            count = len(self.failures())
            return f"{count} scenario{'s' if count != 1 else ''} failed"
        missing = sum(
            item.bound_to_side and item.verdict is Verdict.NOT_APPLICABLE for item in self.scenarios
        )
        if missing:
            noun = "scenario was" if missing == 1 else "scenarios were"
            # Article 2: the run's only whole-run sentence names the side it ran.
            return f"{missing} {self.side.value}-bound {noun} not replayed"
        if not self.proven():
            return "no scenario was proven"
        return None


def _problem_code(result: Refused | CouldNotAsk) -> str:
    return (
        result.problem.code.value
        if hasattr(result.problem.code, "value")
        else result.problem.code.raw
    )


def _observe(result) -> Observed:  # type: ignore[no-untyped-def]
    if isinstance(result, Answered):
        value = result.value
        if hasattr(value, "outcome"):
            reason = value.reason.value if hasattr(value.reason, "value") else value.reason.raw
            grant = value.extra.get("grant") if hasattr(value, "extra") else None
            return Observed(
                outcome=value.outcome.value,
                reason=reason,
                grant="present" if grant is not None else "absent",
            )
        return Observed(
            state=value.state.value if hasattr(value.state, "value") else value.state.raw
        )
    if isinstance(result, Refused):
        return Observed(result="refused", problem=_problem_code(result), grant="absent")
    if isinstance(result, CouldNotAsk):
        return Observed(
            result="could_not_ask",
            problem=_problem_code(result),
            reported_outcome=result.reported_outcome,
            grant="absent",
        )
    return Observed(result="unknown")


def scenario_asserts_an_observable(expected: Mapping[str, object]) -> bool:
    """Article 9's floor: a scenario that names no observable member proves nothing.

    The one implementation of the rule. Both callers below go through it: `replay`
    refuses such a scenario before the harness is asked, and `_matches` refuses to
    call an empty comparison a match — `all()` over an empty mapping is `True`, so
    without this the absence of an assertion would prove every observation. Held by
    `test_a_scenario_asserting_no_observable_fails_without_reaching_the_harness` and
    `test_the_comparison_of_no_members_is_never_a_match`; removing it from either
    caller turns one of them red.
    """
    return bool(expected)


#: What `replay` says of a scenario refused by the floor above, before any harness is asked.
VACUOUS_SCENARIO_DETAIL: Final[str] = "scenario asserts no observable"


def _matches(expected: Mapping[str, object], observed: Observed) -> bool:
    return scenario_asserts_an_observable(expected) and all(
        getattr(observed, key) == value for key, value in expected.items()
    )


def _difference(expected: Mapping[str, object], observed: Observed) -> str:
    differences = (
        f"{key}: expected {value!r}, observed {getattr(observed, key)!r}"
        for key, value in expected.items()
        if getattr(observed, key) != value
    )
    return "; ".join(differences)


def expected_members(scenario: Scenario) -> dict[str, object]:
    """Every observable this scenario asserts, the `then` block's included.

    One implementation, because the run reports what a scenario expects in
    three places — the line for a scenario the side does not bind, the line for
    one declared absent, and the comparison itself — and three spellings of
    « what this scenario asserts » drift into a run that reports one set and
    compares another (articles 9 and 2).
    """
    expected = dict(scenario.expect.members())
    if scenario.then is not None:
        expected["state"] = scenario.then.expect_state
        if scenario.then.expect_after_resolution is not None:
            expected["after_resolution"] = scenario.then.expect_after_resolution
    return expected


def _run(scenario: Scenario, harness: Harness) -> tuple[Observed, Mapping[str, object]]:
    session = harness.arrange(scenario)
    try:
        result = session.client.ask_decision(scenario.ask)
        observed = _observe(result)
        expected = expected_members(scenario)
        if scenario.expect.grant_use is not None:
            # A scenario that says what a held grant covers is only run by a
            # side that holds one and answers; article 9 forbids reporting it
            # proven from the answer alone.
            grant = result.value.extra.get("grant") if isinstance(result, Answered) else None
            observed = replace(
                observed,
                grant_use=None
                if not isinstance(grant, Mapping)
                else session.use_grant(grant, scenario.ask),
            )
        if scenario.given.policy_changes_to is not None and isinstance(result, Answered):
            session.change_policy(scenario.given.policy_changes_to)
            changed = _observe(session.client.ask_decision(scenario.ask))
            observed = replace(
                observed,
                after_policy_change={
                    "outcome": changed.outcome,
                    "reason": changed.reason,
                    "grant": changed.grant,
                },
            )
        if scenario.then is not None and isinstance(result, Answered):
            approval_ref = result.value.approval_ref
            if not approval_ref:
                return observed, expected
            if scenario.then.resolve == "expire":
                session.pass_deadline()
            else:
                resolution = Resolution(scenario.then.resolve)
                session.client.resolve_approval(
                    ApprovalResolution(scenario.ask.scope, approval_ref, resolution)
                )
            approval = session.client.read_approval(scenario.ask.scope, approval_ref)
            approval_observed = _observe(approval)
            observed = replace(observed, state=approval_observed.state)
            if scenario.then.expect_after_resolution is not None:
                # Article 12: a question one person has answered is an allow or
                # a deny of its own, carrying the two reasons published for
                # exactly that. Asked after the read above, so the state a
                # reader sees is the state before the execution is spent.
                again = _observe(session.client.ask_decision(scenario.ask))
                observed = replace(
                    observed,
                    after_resolution={"outcome": again.outcome, "reason": again.reason},
                )
        return observed, expected
    finally:
        session.close()


def _validate_expected_absent(
    scenarios: Mapping[str, Scenario], side: Side, expected_absent: Mapping[str, str]
) -> None:
    for name, reason in expected_absent.items():
        if name not in scenarios:
            raise ContractDefect(f"expected absence names unknown scenario {name!r}")
        if not reason.strip():
            raise ContractDefect(f"expected absence for {name!r} needs a non-empty reason")
        scenario = scenarios[name]
        bound = scenario.binds_client() if side is Side.CLIENT else scenario.binds_server()
        if not bound:
            raise ContractDefect(f"expected absence for {name!r} does not bind side {side.value!r}")


def replay(
    scenarios: Mapping[str, Scenario],
    harness: Harness,
    side: Side,
    *,
    expected_absent: Mapping[str, str] | None = None,
) -> Report:
    """Run one side's scenarios, retaining every inapplicable entry and its reason."""
    absent = expected_absent or {}
    _validate_expected_absent(scenarios, side, absent)
    reports = []
    for scenario in scenarios.values():
        bound = scenario.binds_client() if side is Side.CLIENT else scenario.binds_server()
        expected = expected_members(scenario)
        if not bound:
            reports.append(
                ScenarioReport(
                    scenario.name,
                    Verdict.NOT_APPLICABLE,
                    expected,
                    None,
                    f"binds {scenario.binds.value}, not {side.value}",
                    False,
                )
            )
            continue
        if not scenario_asserts_an_observable(expected):
            reports.append(
                ScenarioReport(
                    scenario.name,
                    Verdict.FAILED,
                    expected,
                    None,
                    VACUOUS_SCENARIO_DETAIL,
                    assertion_count=0,
                )
            )
            continue
        if scenario.name in absent:
            reports.append(
                ScenarioReport(
                    scenario.name,
                    Verdict.NOT_APPLICABLE,
                    expected,
                    None,
                    absent[scenario.name],
                )
            )
            continue
        try:
            observed, expected = _run(scenario, harness)
            passed = _matches(expected, observed)
            reports.append(
                ScenarioReport(
                    scenario.name,
                    Verdict.PROVEN if passed else Verdict.FAILED,
                    expected,
                    observed,
                    "matched expected members" if passed else _difference(expected, observed),
                    assertion_count=len(expected),
                )
            )
        except ScenarioNotApplicable as exc:
            reports.append(
                ScenarioReport(
                    scenario.name,
                    Verdict.NOT_APPLICABLE,
                    expected,
                    None,
                    str(exc),
                )
            )
        except Exception as exc:  # the report, not the runner, owns a scenario failure
            reports.append(
                ScenarioReport(
                    scenario.name,
                    Verdict.FAILED,
                    expected,
                    None,
                    f"{type(exc).__name__}: {exc}",
                )
            )
    return Report(side, tuple(reports))


def compare(a: Report, b: Report) -> tuple[str, ...]:
    """Name shared scenarios whose observations differ."""
    right = {item.name: item for item in b.bound()}
    return tuple(
        item.name
        for item in a.bound()
        if item.name in right and item.observed != right[item.name].observed
    )
