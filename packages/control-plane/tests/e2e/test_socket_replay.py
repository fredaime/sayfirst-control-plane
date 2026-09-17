# SPDX-License-Identifier: Apache-2.0
"""The authoritative scenarios, replayed against the daemon over its own socket.

Article 13 makes the golden scenarios the arbiter between a client and a
server, and says the server replays them as its own acceptance suite. Until now
the server side was replayed in process, against the decision service with no
transport under it, so nothing held the socket surface to the same fixtures.
These cases start the composed daemon, one per scenario, and replay through the
published socket client — the same client a third party would write against.

Every server-bound scenario is replayed, the three that end a wait included:
the daemon serves both published approval operations, and this harness composes
the clock a wait is measured by, so a lapse is reached by moving that clock
rather than by waiting on one. Nothing is declared absent, and the run says so
by claiming the whole side (articles 2 and 9).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sayfirst_contract.golden import load_scenarios
from sayfirst_contract.replay import RunVerdict, Side, Verdict, replay
from sayfirst_contract_stub.stub import StubHarness
from scenario_daemon import DaemonHarness

#: Why a server-bound scenario is not replayed against the daemon. Empty: the
#: daemon answers every operation the server-bound scenarios need, and this
#: harness can reach every arrangement they script. A scenario that stops being
#: replayable belongs here with the fact that makes it so, never dropped from
#: the run (articles 2 and 9).
EXPECTED_ABSENT: dict[str, str] = {}

REPLAYED = (
    "allow",
    "deny",
    "grant_miss_after_policy_version_change",
    "missing_policy",
    "no_grant_on_deny",
    "no_grant_without_signal_channel",
    "policy_unavailable_is_could_not_ask",
    "review_approve",
    "review_expire",
    "review_reject",
    "strictest_rule_wins",
)
"""The server-bound scenarios this daemon answers, written out rather than
derived: a derivation from the absence list could not fail, and a scenario that
starts passing must be moved here by the change that makes it pass."""


@pytest.fixture
def daemons(tmp_path: Path):  # type: ignore[no-untyped-def]
    harness = DaemonHarness(tmp_path)
    try:
        yield harness
    finally:
        harness.close()


def test_the_daemon_replays_every_server_scenario_it_serves(daemons) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the server replays the scenarios it publishes, over its binding."""
    scenarios = load_scenarios()
    report = replay(scenarios, daemons, Side.SERVER, expected_absent=EXPECTED_ABSENT)

    assert report.failures() == (), [(item.name, item.detail) for item in report.failures()]
    assert {item.name for item in report.proven()} == set(REPLAYED)


def test_no_server_bound_scenario_leaves_this_run_unaccounted_for(daemons) -> None:  # type: ignore[no-untyped-def]
    """Article 2: nothing is declared absent, so the run claims the whole side."""
    scenarios = load_scenarios()
    report = replay(scenarios, daemons, Side.SERVER, expected_absent=EXPECTED_ABSENT)

    reported = {item.name: item for item in report.scenarios}
    assert set(reported) == set(scenarios)
    bound = {name for name, item in scenarios.items() if item.binds_server()}
    assert bound == set(REPLAYED) | set(EXPECTED_ABSENT)
    for name in EXPECTED_ABSENT:
        assert reported[name].verdict is Verdict.NOT_APPLICABLE
        assert reported[name].detail == EXPECTED_ABSENT[name]
    # The three scenarios that end a wait are named, so a rewrite of the list
    # above cannot quietly drop them back out of the run.
    for name in ("review_approve", "review_reject", "review_expire"):
        assert reported[name].verdict is Verdict.PROVEN, (name, reported[name].detail)
    assert report.verdict is RunVerdict.PROVEN
    assert report.succeeded()
    assert report.failure_reason() is None


def test_the_daemon_and_the_published_fake_observe_the_same_scenarios(daemons) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the scenarios are the arbiter, so a disagreement is a defect of one side."""
    from sayfirst_contract.replay import compare

    scenarios = load_scenarios()
    daemon_report = replay(scenarios, daemons, Side.SERVER, expected_absent=EXPECTED_ABSENT)
    stub_report = replay(scenarios, StubHarness(), Side.SERVER, expected_absent=EXPECTED_ABSENT)

    assert compare(daemon_report, stub_report) == ()
