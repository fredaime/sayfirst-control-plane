# SPDX-License-Identifier: Apache-2.0 OR MIT-0
from __future__ import annotations

import os
import socket
import threading
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

from sayfirst_contract.binding.http_unix_socket import SocketClient, SocketHarness
from sayfirst_contract.binding.http_unix_socket.addresses import scenario_address
from sayfirst_contract.cli import main
from sayfirst_contract.client import CouldNotAsk
from sayfirst_contract.golden import load_scenarios
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.replay import RunVerdict, Side, Verdict, replay
from sayfirst_contract_stub.stub import Stub
from sayfirst_contract_stub.stub_http import serve


def _serve_scenarios(root: Path, names: tuple[str, ...]):
    stack = ExitStack()
    now = {name: datetime(2026, 9, 4, tzinfo=UTC) for name in names}
    sockets = {}
    stubs = {}
    for name in names:
        stub = Stub(name, clock=lambda name=name: now[name])
        stubs[name] = stub
        sockets[name] = stack.enter_context(serve(stub, scenario_address(root, name)))
    return stack, now, sockets, stubs


def test_every_server_scenario_is_replayed_over_a_real_socket(tmp_path: Path) -> None:
    """Article 13: the acceptance runner proves every server-bound shipped fixture."""
    scenarios = load_scenarios()
    names = tuple(name for name, item in scenarios.items() if item.binds_server())
    stack, now, sockets, stubs = _serve_scenarios(tmp_path, names)
    with stack:
        harness = SocketHarness(
            sockets,
            expected_uid=os.geteuid(),
            pass_deadline=lambda scenario: now.__setitem__(
                scenario.name, now[scenario.name] + timedelta(seconds=61)
            ),
            change_policy=lambda scenario, policy: stubs[scenario.name].change_policy(),
        )
        report = replay(scenarios, harness, Side.SERVER)

    assert report.succeeded()
    assert {item.name for item in report.proven()} == set(names)
    assert all(
        item.verdict is Verdict.NOT_APPLICABLE
        for item in report.scenarios
        if item.name not in names
    )


def test_a_socket_observation_that_disagrees_is_failed(tmp_path: Path) -> None:
    """Article 13: a server disagreement is a failed scenario, never a proof."""
    socket_path = tmp_path / "allow.sock"
    with serve(Stub("deny"), socket_path):
        report = replay(
            {"allow": load_scenarios()["allow"]},
            SocketHarness({"allow": socket_path}),
            Side.SERVER,
        )
    item = report.scenarios[0]
    assert item.verdict is Verdict.FAILED
    assert item.detail == (
        "outcome: expected 'allow', observed 'deny'; "
        "reason: expected 'policy_allows', observed 'policy_denies'; "
        "grant: expected 'present', observed 'absent'"
    )
    assert not report.succeeded()


def test_the_command_reports_every_scenario_and_its_reason(tmp_path: Path) -> None:
    """Article 13: command output distinguishes proof, expected absence, and binding."""
    stack, _, sockets, _ = _serve_scenarios(tmp_path, ("allow",))
    missing = {
        name: "requires a separately configured daemon"
        for name, scenario in load_scenarios().items()
        if scenario.binds_server() and name != "allow"
    }
    output = StringIO()
    arguments = [
        "conformance",
        "replay",
        "--socket",
        f"allow={sockets['allow']}",
        *(
            item
            for name, reason in missing.items()
            for item in ("--expected-absent", f"{name}={reason}")
        ),
    ]
    with stack:
        exit_code = main(arguments, stdout=output)

    rendered = output.getvalue()
    # One scenario replayed and ten declared absent is an incomplete run, which
    # block 2.6's verdict reports as a failure of the whole run rather than as
    # a proof (article 2). What this test is about is the three per-scenario
    # reasons below, each of which is still rendered.
    assert exit_code == 1
    assert "run\tfailed\t10 server-bound scenarios were not replayed" in rendered
    assert "allow\tproven\tmatched expected members" in rendered
    for name, reason in missing.items():
        assert f"{name}\tnot-applicable\t{reason}" in rendered
    assert "unknown_outcome\tnot-applicable\tbinds client, not server" in rendered
    assert "unreachable\tnot-applicable\tbinds client, not server" in rendered


def test_the_command_fails_when_every_scenario_is_expected_absent() -> None:
    """Article 13: explicit absences do not turn a vacuous run green."""
    scenarios = load_scenarios()
    arguments = ["conformance", "replay"]
    for name, scenario in scenarios.items():
        if scenario.binds_server():
            arguments.extend(("--expected-absent", f"{name}=skeleton block not present"))
    output = StringIO()
    assert main(arguments, stdout=output) == 1
    assert "run\tfailed\t11 server-bound scenarios were not replayed" in output.getvalue()


def test_the_socket_client_refuses_an_unexpected_listener(tmp_path: Path) -> None:
    """Article 6: replay sends nothing through a listener with the wrong uid."""
    socket_path = tmp_path / "impostor.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen()
    received: list[bytes] = []

    def receive() -> None:
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(1)
            received.append(peer.recv(1))

    thread = threading.Thread(target=receive)
    thread.start()
    result = SocketClient(socket_path, expected_uid=os.geteuid() + 1).read_status()
    thread.join(timeout=2)
    listener.close()

    assert not thread.is_alive()
    assert received == [b""]
    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.IMPOSTOR


def test_the_command_refuses_a_socket_mapping_that_cannot_be_used() -> None:
    """Article 13: a misspelled or client-only mapping is not silently ignored."""
    output = StringIO()
    exit_code = main(
        ["conformance", "replay", "--socket", "unknown_outcome=/tmp/unused.sock"],
        stdout=output,
    )
    assert exit_code == 2
    assert "non-server scenarios" in output.getvalue()


# Why a client-bound scenario is not replayed against this fake. Empty: the
# three scenarios that end a wait used to be declared here, and both sides now
# record one — this fake answers the two published approval operations out of
# the lifecycle it keeps, the daemon answers them out of its own store, and the
# run below reaches a lapse by moving the clock it gave the fake rather than by
# waiting on one. A scenario that stops being replayable belongs here with the
# fact that makes it so, never dropped from the run (articles 2 and 9).
CLIENT_EXPECTED_ABSENT: dict[str, str] = {}


def test_every_client_scenario_this_fake_can_arrange_is_replayed(tmp_path: Path) -> None:
    """Articles 9 and 13: no client-bound scenario is published without a side running it.

    The grant family is what this run exists for: four scenarios that say what
    a held grant covers, and the two `given` members that arrange them, are
    read by nothing until a client-side run holds a grant and answers.
    """
    scenarios = load_scenarios()
    # `unknown_outcome` and `unreachable` arrange a foreign server this fake is
    # not; they are replayed against a scripted client in the contract package.
    names = tuple(
        name
        for name, item in scenarios.items()
        if item.binds_client() and item.given.server is None
    )
    assert {name for name in names if name.startswith("grant_")} == {
        "grant_hit_within_lifetime",
        "grant_expired_by_lifetime",
        "grant_void_on_connection_loss",
        "grant_void_on_arguments_change",
        "grant_miss_after_policy_version_change",
    }
    selected = {name: scenarios[name] for name in names}
    stack, now, sockets, stubs = _serve_scenarios(tmp_path, names)
    with stack:
        harness = SocketHarness(
            sockets,
            expected_uid=os.geteuid(),
            pass_deadline=lambda scenario: now.__setitem__(
                scenario.name, now[scenario.name] + timedelta(seconds=61)
            ),
            change_policy=lambda scenario, policy: stubs[scenario.name].change_policy(),
        )
        report = replay(selected, harness, Side.CLIENT, expected_absent=CLIENT_EXPECTED_ABSENT)

    assert report.failures() == (), [item.detail for item in report.failures()]
    # Nothing is declared absent any more, so this run claims every scenario it
    # selected — including the three that end a wait, named here so that a
    # rewrite of the absence set above cannot quietly drop them (article 2).
    assert report.verdict is RunVerdict.PROVEN
    assert {item.name for item in report.proven()} == set(names) - set(CLIENT_EXPECTED_ABSENT)
    assert {"review_approve", "review_reject", "review_expire"} <= {
        item.name for item in report.proven()
    }
    used = {
        item.name: item.observed.grant_use
        for item in report.proven()
        if item.observed is not None and item.observed.grant_use is not None
    }
    assert used == {
        "grant_hit_within_lifetime": "hit",
        "grant_expired_by_lifetime": "expired",
        "grant_void_on_connection_loss": "connection_lost",
        "grant_void_on_arguments_change": "arguments_changed",
    }


def test_a_held_grant_that_covers_nothing_is_a_failed_scenario(tmp_path: Path) -> None:
    """Article 9: the use verdict is asserted, so a wrong one cannot report proven."""
    scenarios = load_scenarios()
    scenario = scenarios["grant_hit_within_lifetime"]
    misread = replace(scenario, expect=replace(scenario.expect, grant_use="expired"))
    stack, _, sockets, _ = _serve_scenarios(tmp_path, (scenario.name,))
    with stack:
        report = replay(
            {scenario.name: misread},
            SocketHarness(sockets, expected_uid=os.geteuid()),
            Side.CLIENT,
        )
    assert report.failures()
    assert report.failures()[0].detail == "grant_use: expected 'expired', observed 'hit'"
