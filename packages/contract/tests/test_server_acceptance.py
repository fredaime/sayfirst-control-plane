# SPDX-License-Identifier: Apache-2.0
"""Server acceptance cases, explicit when no arranged daemon is configured.

This is the published hook: point it at a directory of sockets, one per
scenario, and any daemon implementing the binding is replayed against the
fixtures it publishes. This distribution may not import a server (article 14),
so the daemon that arranges itself is replayed from the server's own suite,
which runs the same runner over the same fixtures — and declares no absence:
every server-bound scenario, the three that end a wait included, is replayed
there.

The absence these cases declare is a different one and belongs to this
distribution alone: no socket directory is configured, so there is no daemon
here to replay against. It covers every scenario equally, states an observed
configuration fact, and goes away the moment the variable below is set. A
daemon arranged for one of the three that end a wait must serve both approval
operations, suspend with a wait shorter than `--deadline-wait-seconds`, and
render `expired` as of the instant a read is taken; `SocketHarness` says so
where it waits.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest
from sayfirst_contract.binding.http_unix_socket.replay import SocketHarness
from sayfirst_contract.golden import load_scenarios
from sayfirst_contract.replay import Side, replay

_SERVER_SCENARIOS = tuple(
    name for name, scenario in load_scenarios().items() if scenario.binds_server()
)

#: The one variable that decides whether a daemon is arranged for these cases. The
#: absence reason below is built from this name, and the guard proves the name is the
#: one the code observes, so the sentence cannot drift into a claim about anything else.
_SOCKET_DIRECTORY_VARIABLE = "SAYFIRST_CONFORMANCE_SOCKET_DIR"
_MISSING_SOCKET_DIRECTORY = f"expected absent: {_SOCKET_DIRECTORY_VARIABLE} is not configured"


def _absence_reason() -> str | None:
    """The observed fact that makes the daemon cases inapplicable, or None if none is."""
    if os.environ.get(_SOCKET_DIRECTORY_VARIABLE) is None:
        return _MISSING_SOCKET_DIRECTORY
    return None


@pytest.mark.parametrize("scenario_name", _SERVER_SCENARIOS)
def test_skeleton_daemon_replays_the_server_scenario(scenario_name: str) -> None:
    """Article 13: each future daemon acceptance case is explicit in today's CI."""
    scenario = load_scenarios()[scenario_name]
    assert scenario.binds_server()
    reason = _absence_reason()
    if reason is not None:
        pytest.xfail(reason)
    socket_directory = os.environ[_SOCKET_DIRECTORY_VARIABLE]
    expected_uid = int(os.environ.get("SAYFIRST_CONFORMANCE_EXPECTED_UID", os.geteuid()))
    report = replay(
        {scenario_name: scenario},
        SocketHarness(
            {scenario_name: Path(socket_directory) / f"{scenario_name}.sock"},
            expected_uid=expected_uid,
        ),
        Side.SERVER,
    )
    assert report.succeeded(), report


#: The server-bound fixtures this suite has an acceptance case for, written out rather
#: than derived: the derivation is the one that produced `_SERVER_SCENARIOS` above, so a
#: comparison between the two cannot fail. Shipping a new server fixture turns this red,
#: which is the point — the daemon suite cannot grow a case nobody named.
_ACCEPTANCE_CASES = frozenset(
    {
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
    }
)


def test_every_server_scenario_has_an_acceptance_case() -> None:
    """Article 13: adding a server fixture cannot leave the daemon suite silent."""
    assert len(_ACCEPTANCE_CASES) == 11
    assert set(_SERVER_SCENARIOS) == set(_ACCEPTANCE_CASES)


def test_expected_absence_names_the_observed_missing_configuration(  # type: ignore[no-untyped-def]
    monkeypatch, tmp_path: Path
) -> None:
    """Articles 2 and 13: the absence reason is only used when the fact it states holds.

    The reason is this suite's unknown surface: six cases go green-adjacent on it every
    run. Comparing the sentence with its own literal would let any sentence stand, so
    this drives the code that emits it, in both directions. The name of the variable is
    load-bearing — setting it is what makes the absence go away — which is what pins the
    sentence to an observed fact rather than to a claim someone typed.
    """
    scenario_name = _SERVER_SCENARIOS[0]

    # The fact holds: the variable really is unset, and the reason says exactly that.
    monkeypatch.delenv(_SOCKET_DIRECTORY_VARIABLE, raising=False)
    assert _absence_reason() == _MISSING_SOCKET_DIRECTORY
    assert (
        f"expected absent: {_SOCKET_DIRECTORY_VARIABLE} is not configured"
    ) == _MISSING_SOCKET_DIRECTORY
    with pytest.raises(pytest.xfail.Exception) as absent:
        test_skeleton_daemon_replays_the_server_scenario(scenario_name)
    assert str(absent.value) == _MISSING_SOCKET_DIRECTORY

    # The fact does not hold: a directory is configured and holds no socket. The case
    # must fail — an absence that was not observed is never borrowed to excuse one.
    monkeypatch.setenv(_SOCKET_DIRECTORY_VARIABLE, str(tmp_path))
    assert _absence_reason() is None
    with pytest.raises(AssertionError) as observed:
        test_skeleton_daemon_replays_the_server_scenario(scenario_name)
    assert not isinstance(observed.value, pytest.xfail.Exception)
    assert _MISSING_SOCKET_DIRECTORY not in str(observed.value)


def test_the_default_gate_prints_expected_absence_reasons() -> None:
    """Article 2: the prescribed quiet gate still renders why cases are absent."""
    project_file = Path(__file__).resolve().parents[3] / "pyproject.toml"
    pytest_options = tomllib.loads(project_file.read_text(encoding="utf-8"))["tool"]["pytest"][
        "ini_options"
    ]
    assert "-rxX" in pytest_options["addopts"]
