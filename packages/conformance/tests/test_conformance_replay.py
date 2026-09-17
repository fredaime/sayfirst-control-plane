# SPDX-License-Identifier: Apache-2.0 OR MIT-0
from __future__ import annotations

import copy
import os
import socket
import threading
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest
import sayfirst_contract.binding.http_unix_socket.client as client_transport
import sayfirst_contract.binding.http_unix_socket.replay as replay_transport
from sayfirst_conformance.main import main
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.binding.http_unix_socket.addresses import scenario_address
from sayfirst_contract.binding.http_unix_socket.client import (
    SocketClient,
    UnsupportedPlatform,
)
from sayfirst_contract.binding.http_unix_socket.replay import SocketHarness
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.generation import CONTRACT_GENERATION, NegotiatedClient
from sayfirst_contract.golden import load_scenarios, schema_examples
from sayfirst_contract.problems import ProblemCode, problem_retryable
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
    assert exit_code == 3
    assert "allow\tproven\tmatched expected members\tbound=true\tassertions=3" in rendered
    for name, reason in missing.items():
        assert f"{name}\tnot-applicable\t{reason}\tbound=true" in rendered
    assert "unknown_outcome\tnot-applicable\tbinds client, not server\tbound=false" in rendered
    assert "unreachable\tnot-applicable\tbinds client, not server\tbound=false" in rendered
    assert "run\tunknown\t10 server-bound scenarios were not replayed" in rendered


def test_the_command_fails_when_every_scenario_is_expected_absent() -> None:
    """Article 13: explicit absences do not turn a vacuous run green."""
    scenarios = load_scenarios()
    arguments = ["replay"]
    for name, scenario in scenarios.items():
        if scenario.binds_server():
            arguments.extend(("--expected-absent", f"{name}=skeleton block not present"))
    output = StringIO()
    assert main(arguments, stdout=output) == 3
    assert "run\tunknown\t11 server-bound scenarios were not replayed" in output.getvalue()


def test_the_command_returns_zero_for_a_complete_live_run(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 13: exit zero is proven against every shipped server fixture."""
    scenarios = load_scenarios()
    names = tuple(name for name, scenario in scenarios.items() if scenario.binds_server())
    stack, now, sockets, stubs = _serve_scenarios(tmp_path, names)

    def pass_deadline(seconds: float) -> None:
        assert seconds == 61.0
        for name in now:
            now[name] += timedelta(seconds=seconds)

    monkeypatch.setattr(replay_transport.time, "sleep", pass_deadline)
    # Block 2.3's version-change fixture needs the daemon's policy replaced
    # mid-scenario. The command knows socket paths and nothing else, so against
    # a real daemon that replacement is the operator's act; here the fake's is
    # performed the same way the deadline above is passed.
    monkeypatch.setattr(
        replay_transport._SocketSession,
        "change_policy",
        lambda self, policy: stubs[self.scenario.name].change_policy(),
    )
    arguments = ["replay"]
    for name, socket_path in sockets.items():
        arguments.extend(("--socket", f"{name}={socket_path}"))
    output = StringIO()
    with stack:
        exit_code = main(arguments, stdout=output)

    assert exit_code == 0
    assert "run\tproven\t11 scenarios proven" in output.getvalue()


def test_the_command_returns_one_for_a_live_disagreement(tmp_path: Path) -> None:
    """Article 13: exit one identifies an observed fixture disagreement."""
    socket_path = tmp_path / "allow.sock"
    arguments = ["replay", "--socket", f"allow={socket_path}"]
    for name, scenario in load_scenarios().items():
        if scenario.binds_server() and name != "allow":
            arguments.extend(("--expected-absent", f"{name}=not arranged for this test"))
    output = StringIO()
    with serve(Stub("deny"), socket_path):
        exit_code = main(arguments, stdout=output)

    assert exit_code == 1
    assert "allow\tfailed\t" in output.getvalue()
    assert "run\tfailed\t1 scenario failed" in output.getvalue()


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


def test_the_socket_client_routes_drift_with_the_published_binding(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 13: replay gets its method and path from the shipped OpenAPI document."""
    binding = copy.deepcopy(load_json("binding", "http-unix-socket", "openapi.json"))
    binding["paths"]["/decisions-v2"] = binding["paths"].pop("/decisions")
    monkeypatch.setattr(client_transport, "load_json", lambda *path: binding)
    client_transport._published_operations.cache_clear()

    class RecordingClient(SocketClient):
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            super().__init__(*args, **kwargs)
            self.calls = []

        def _read(self, method, target, document, reader, **selection):  # type: ignore[no-untyped-def]
            self.calls.append((method, target))
            return None

    try:
        client = RecordingClient(Path("unused"), expected_uid=os.geteuid())
        client.ask_decision(load_scenarios()["allow"].ask)
        assert client.calls == [("POST", "/decisions-v2")]
    finally:
        client_transport._published_operations.cache_clear()


@pytest.mark.parametrize(
    ("status", "example"), ((200, "decision-result"), (500, "problem-document"))
)
def test_every_response_must_echo_the_pinned_generation(status: int, example: str) -> None:
    """Article 13: a response from another generation is distinctly refused."""
    response_document = dict(schema_examples()[example])
    response_document["contract_generation"] = 42

    class WrongGenerationClient(SocketClient):
        def _request(self, method, target, document=None, **selection):  # type: ignore[no-untyped-def]
            return status, response_document

    result = WrongGenerationClient(Path("unused"), expected_uid=os.geteuid()).ask_decision(
        load_scenarios()["allow"].ask
    )
    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED


def test_a_newer_server_that_supports_the_client_generation_is_accepted() -> None:
    """Article 13: status negotiates support, not equal pinned generations."""
    status_document = dict(schema_examples()["status-result"])
    status_document.update(contract_generation=2, supported_generations=[1, 2])
    decision_document = dict(schema_examples()["decision-result"])

    class AheadServerClient(SocketClient):
        def __init__(self) -> None:
            super().__init__(Path("unused"), expected_uid=os.geteuid())
            self.calls = []

        def _request(self, method, target, document=None, **selection):  # type: ignore[no-untyped-def]
            self.calls.append((method, target, document))
            if target == "/status":
                return 200, status_document
            assert document["contract_generation"] == CONTRACT_GENERATION
            return 200, decision_document

    transport = AheadServerClient()
    client = NegotiatedClient(transport)
    status = client.read_status()
    result = client.ask_decision(load_scenarios()["allow"].ask)

    assert isinstance(status, Answered)
    assert status.value.contract_generation == 2
    assert status.value.supported_generations == (1, 2)
    assert isinstance(result, Answered)
    assert [target for _, target, _ in transport.calls] == ["/status", "/decisions"]


def test_a_generation_refusal_keeps_the_servers_pinned_generation() -> None:
    """Article 13: a generation refusal preserves the server's problem document."""
    problem_document = dict(schema_examples()["problem-document"])
    problem_document.update(
        contract_generation=2,
        code="generation_unsupported",
        message="client generation is outside this server's window",
        retryable=False,
        member="contract_generation",
    )

    class RefusingServerClient(SocketClient):
        def _request(self, method, target, document=None, **selection):  # type: ignore[no-untyped-def]
            return 400, problem_document

    result = RefusingServerClient(Path("unused"), expected_uid=os.geteuid()).ask_decision(
        load_scenarios()["allow"].ask
    )
    assert isinstance(result, Refused)
    assert result.problem.contract_generation == 2
    assert result.problem.message == "client generation is outside this server's window"
    assert result.problem.retryable is False
    assert result.problem.member == "contract_generation"


def test_answer_unreadable_uses_registry_retryability() -> None:
    """Article 2: replay does not invent certainty for client-side problems."""
    unreadable = dict(schema_examples()["decision-result"])
    del unreadable["decision_ref"]

    class UnreadableClient(SocketClient):
        def _request(self, method, target, document=None, **selection):  # type: ignore[no-untyped-def]
            return 200, unreadable

    result = UnreadableClient(Path("unused"), expected_uid=os.geteuid()).ask_decision(
        load_scenarios()["allow"].ask
    )
    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE
    assert result.problem.retryable is problem_retryable(ProblemCode.ANSWER_UNREADABLE)
    registry = load_json("domain", "problem-codes.json")["codes"]
    assert registry[ProblemCode.ANSWER_UNREADABLE.value]["origin"] == "client"


def test_unsupported_peer_credentials_are_not_applicable(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 6: an unsupported identity adapter is not a transport outage."""
    socket_path = tmp_path / "unsupported.sock"
    with serve(Stub("allow"), socket_path):
        monkeypatch.setattr(
            client_transport,
            "_peer_uid",
            lambda peer: (_ for _ in ()).throw(
                UnsupportedPlatform("peer identity is unsupported on this platform")
            ),
        )
        report = replay(
            {"allow": load_scenarios()["allow"]},
            SocketHarness({"allow": socket_path}),
            Side.SERVER,
        )
    assert report.scenarios[0].verdict is Verdict.NOT_APPLICABLE
    assert report.scenarios[0].detail == "peer identity is unsupported on this platform"
    assert report.verdict is RunVerdict.UNKNOWN


def test_the_command_refuses_a_socket_mapping_that_cannot_be_used() -> None:
    """Article 13: a misspelled or client-only mapping is not silently ignored."""
    output = StringIO()
    exit_code = main(
        ["replay", "--socket", "unknown_outcome=/tmp/unused.sock"],
        stdout=output,
    )
    assert exit_code == 2
    assert "run\tunknown\t" in output.getvalue()
    assert "non-server scenarios" in output.getvalue()


def test_a_run_that_compared_nothing_prints_no_assertion_count() -> None:
    """Article 2: a run in which nothing was replayed prints no healthy-looking number.

    `assertions=` was added so a reader could see non-vacuity without parsing the
    English detail. Filled from the fixture it was the one machine-readable field that
    read the same whether six daemons agreed or none was ever contacted; a line whose
    verdict rests on no comparison now says so.
    """
    scenarios = load_scenarios()
    arguments = ["replay"]
    for name, scenario in scenarios.items():
        if scenario.binds_server():
            arguments.extend(("--expected-absent", f"{name}=block not landed"))
    output = StringIO()
    assert main(arguments, stdout=output) == 3
    lines = [line for line in output.getvalue().splitlines() if not line.startswith("run\t")]
    assert len(lines) == len(scenarios)
    assert all(line.endswith("\tassertions=-") for line in lines), lines
