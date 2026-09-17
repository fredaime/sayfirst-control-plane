# SPDX-License-Identifier: Apache-2.0 OR MIT-0
from __future__ import annotations

import http.client
import json
import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from sayfirst_contract.approvals import Resolution
from sayfirst_contract.artifacts import domain_schema, load_json
from sayfirst_contract.binding.http_unix_socket import SocketClient
from sayfirst_contract.binding.http_unix_socket.addresses import (
    ADDRESS_MARGIN_BYTES,
    AddressTooLong,
    address_bytes,
    scenario_address,
    sun_path_limit,
)
from sayfirst_contract.binding.http_unix_socket.routes import (
    DOCUMENT_MEDIA_TYPE,
    STREAM_MEDIA_TYPE,
    selects_stream,
)
from sayfirst_contract.client import Answered, Refused
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.evidence import (
    MANIFEST_V3,
    ChainCondition,
    manifest_hash,
    verify_chain,
    verify_export,
)
from sayfirst_contract.generation import CONTRACT_GENERATION, NegotiatedClient
from sayfirst_contract.golden import Scenario, load_scenarios
from sayfirst_contract.policy import ProjectionStep
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.replay import Side, compare, replay
from sayfirst_contract_stub.stub import Stub, StubHarness
from sayfirst_contract_stub.stub_http import SocketStubHarness, serve
from sayfirst_testing.schemas import validate_document


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path):
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(self.socket_path))


def request(
    socket_path: Path, method: str, target: str, document: object | None = None
) -> tuple[int, dict[str, object]]:
    connection = UnixConnection(socket_path)
    body = None if document is None else json.dumps(document)
    headers = {} if body is None else {"Content-Type": "application/json"}
    connection.request(method, target, body=body, headers=headers)
    response = connection.getresponse()
    parsed = json.loads(response.read())
    connection.close()
    return response.status, parsed


def raw_request(socket_path: Path, method: str, target: str) -> tuple[int, str, bytes]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(socket_path))
    connection.sendall(
        f"{method} {target} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
    )
    connection.shutdown(socket.SHUT_WR)
    response = b""
    while chunk := connection.recv(65536):
        response += chunk
    connection.close()
    head, body = response.split(b"\r\n\r\n", 1)
    status_line, *header_lines = head.decode().split("\r\n")
    headers = "\n".join(header_lines).lower()
    return int(status_line.split()[1]), headers, body


class _Harness:
    """`SocketStubHarness`, with every session it arranges closed at the end.

    The cases that use it read through the published client, which is the
    point: what a third party builds a trace or an explanation against is this
    face of the fake and not the in-process object beside it.
    """

    def __init__(self, root: Path) -> None:
        self._inner = SocketStubHarness(root)
        self._arranged: list[Any] = []

    def arrange(self, scenario: Scenario) -> Any:
        session = self._inner.arrange(scenario)
        self._arranged.append(session)
        return session

    def close(self) -> None:
        for session in self._arranged:
            session.close()


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[_Harness]:
    arranged = _Harness(tmp_path)
    try:
        yield arranged
    finally:
        arranged.close()


def scenario(name: str) -> Scenario:
    return load_scenarios()[name]


def _ask() -> DecisionAsk:
    return scenario(GRANTING).ask


def _over_the_socket(session: Any, method: str, target: str) -> tuple[int, dict[str, object]]:
    """One request written straight at the fake, past the published client."""
    return request(session.socket_path, method, target)


#: The shipped scenario whose allow mints a grant: the one a decision read and
#: an evidence page both have something to say about.
GRANTING = "allow"


def test_the_stub_refuses_the_generation_before_anything_else(tmp_path: Path) -> None:
    """Article 13: generation errors precede all request validation."""
    stub = Stub("allow")
    with serve(stub, tmp_path / "stub.sock") as socket_path:
        status, missing = request(socket_path, "POST", "/decisions", {"future": True})
        assert status == 400
        assert missing["code"] == "generation_missing"
        status, unreadable = request(
            socket_path, "POST", "/decisions", {"contract_generation": "one"}
        )
        assert status == 400
        assert unreadable["code"] == "generation_unreadable"
        status, unsupported = request(
            socket_path, "POST", "/decisions", {"contract_generation": 99}
        )
        assert status == 409
        assert unsupported["code"] == "generation_unsupported"
    assert stub.decision_count == 0


def test_a_generation_refusal_records_no_decision(tmp_path: Path) -> None:
    """Article 13: refusing negotiation creates no decision record."""
    stub = Stub("allow")
    with serve(stub, tmp_path / "stub.sock") as socket_path:
        status, problem = request(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 99,
                "capability": "example.effect",
                "scope": "local",
            },
        )
    assert status == 409
    assert problem["code"] == "generation_unsupported"
    assert stub.decision_count == 0


def test_the_stub_refuses_an_undefined_request_member(tmp_path: Path) -> None:
    """Article 13: the fake rejects members this generation does not define."""
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        status, problem = request(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "principal": "claimed",
            },
        )
    assert status == 400
    assert problem["code"] == "member_unknown"
    assert problem["member"] == "principal"


def test_a_read_without_a_scope_is_refused(tmp_path: Path) -> None:
    """Article 5: a read never receives the writer's local default."""
    with serve(Stub("review_approve"), tmp_path / "stub.sock") as socket_path:
        status, problem = request(socket_path, "GET", "/approvals/approval-1?contract_generation=1")
    assert status == 400
    assert problem["code"] == "scope_required"


def test_an_ask_without_scope_is_recorded_in_local(tmp_path: Path) -> None:
    """Article 5: an omitted writer scope is explicitly recorded as local."""
    in_process = Stub("allow").ask_decision(load_scenarios()["allow"].ask)
    assert isinstance(in_process, Answered)
    assert in_process.value.scope == "local"
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        status, document = request(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "arguments_digest": "sha256:" + "0" * 64,
            },
        )
    assert status == 200
    assert document["scope"] == "local"


def test_the_two_evidence_reads_are_available_over_the_socket(tmp_path: Path) -> None:
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        page_status, page = request(
            socket_path,
            "GET",
            "/scopes/local/evidence?contract_generation=1&from_sequence=1",
        )
        export_status, bundle = request(
            socket_path,
            "GET",
            "/scopes/local/evidence/export?contract_generation=1&from_sequence=1",
        )
    assert page_status == export_status == 200
    assert page["verification"]["condition"] == "unverifiable"
    assert bundle["entry_count"] == 0


def test_a_repeated_evidence_query_key_is_refused(tmp_path: Path) -> None:
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        status, problem = request(
            socket_path,
            "GET",
            "/scopes/local/evidence?contract_generation=1&from_sequence=1&from_sequence=2",
        )
    assert status == 400
    assert problem["code"] == "evidence_range_invalid"


def test_an_unknown_route_answers_operation_unknown(tmp_path: Path) -> None:
    """Articles 4 and 13: unmatched operations use the registered domain problem."""
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        for method, target in (
            ("GET", "/nowhere"),
            ("POST", "/nowhere"),
            ("POST", "/status"),
            ("DELETE", "/decisions"),
        ):
            status, problem = request(socket_path, method, target)
            assert status in {404, 405}
            assert problem["code"] == "operation_unknown"
            assert problem["contract_generation"] == 1


def test_every_unlisted_method_answers_a_problem_document(tmp_path: Path) -> None:
    """Articles 4 and 13: every unlisted method uses the domain refusal."""
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        for method, target in (
            ("HEAD", "/decisions"),
            ("OPTIONS", "/status"),
            ("BREW", "/decisions"),
        ):
            status, headers, body = raw_request(socket_path, method, target)
            assert status == 405
            assert "content-type: application/json" in headers
            problem = json.loads(body)
            assert problem["code"] == "operation_unknown"
            assert problem["contract_generation"] == 1


def test_the_socket_file_is_private(tmp_path: Path) -> None:
    """Article 6: the fake's local admission file is mode 0700."""
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        assert socket_path.stat().st_mode & 0o777 == 0o700


def test_the_stub_over_the_socket_answers_as_the_stub_in_process(tmp_path: Path) -> None:
    """Article 13: both faces of the fake have identical scenario observations."""
    from sayfirst_contract_stub.stub_http import SocketStubHarness

    scenarios = load_scenarios()
    direct = replay(scenarios, StubHarness(), Side.SERVER)
    bound = replay(scenarios, SocketStubHarness(tmp_path), Side.SERVER)
    assert bound.failures() == ()
    assert compare(direct, bound) == ()


def test_the_stub_harness_reuses_the_published_negotiated_socket_stack(tmp_path: Path) -> None:
    """Articles 13 and 14: fake and acceptance paths use the negotiated client stack."""
    from sayfirst_contract_stub.stub_http import SocketStubHarness

    session = SocketStubHarness(tmp_path).arrange(load_scenarios()["allow"])
    try:
        assert isinstance(session.client, NegotiatedClient)
    finally:
        session.close()


def test_the_stub_streams_a_grant_and_scripted_policy_change(tmp_path: Path) -> None:
    """Articles 10 and 13: the shared scenario fake can exercise the grant stream."""
    scenario = load_scenarios()["grant_miss_after_policy_version_change"]
    with serve(Stub(scenario.name), tmp_path / "stub.sock") as socket_path:
        connection = UnixConnection(socket_path)
        connection.request(
            "POST",
            "/decisions",
            body=json.dumps(scenario.ask.to_document(1)),
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        )
        response = connection.getresponse()
        body = response.read()
        connection.close()
    assert response.status == 200
    assert response.headers["Content-Type"] == "text/event-stream"
    frames = [frame for frame in body.split(b"\n\n") if frame]
    assert [frame.split(b"\n", 1)[0] for frame in frames] == [
        b"event: decision",
        b"event: grant_ended",
    ]
    decision = json.loads(frames[0].split(b"data: ", 1)[1])
    signal = json.loads(frames[1].split(b"data: ", 1)[1])
    jsonschema.validate(decision, domain_schema("decision-result"))
    jsonschema.validate(decision["grant"], domain_schema("grant"))
    jsonschema.validate(signal, domain_schema("grant-signal"))
    assert signal["reason"] == "policy_version_changed"


def test_the_fake_answers_whoami_over_the_same_local_stream(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 6: whoami is a bound operation, so the fake answers it too."""
    import os

    from sayfirst_testing.schemas import validate_document

    harness = SocketStubHarness(tmp_path)
    session = harness.arrange(load_scenarios()["allow"])
    try:
        result = session.client.read_whoami()
    finally:
        session.close()
    assert isinstance(result, Answered)
    assert result.value.peer.uid == os.geteuid()
    assert result.value.principal is not None
    assert result.value.principal.reference == f"user:{os.geteuid()}"
    validate_document(result.value.to_document(), "whoami-result")


def test_every_served_stub_document_matches_the_published_schema(tmp_path: Path) -> None:
    """Article 13: the fake's actual response documents satisfy the domain contract."""
    validated = 0
    for scenario in load_scenarios().values():
        if not scenario.binds_server():
            continue
        with serve(Stub(scenario.name), scenario_address(tmp_path, scenario.name)) as socket_path:
            _, status_document = request(socket_path, "GET", "/status")
            jsonschema.validate(status_document, domain_schema("status-result"))
            validated += 1
            _, decision = request(
                socket_path,
                "POST",
                "/decisions",
                scenario.ask.to_document(1),
            )
            schema_name = (
                "problem-document" if scenario.given.policy_unavailable else "decision-result"
            )
            jsonschema.validate(decision, domain_schema(schema_name))
            validated += 1
            if decision.get("approval_ref") is not None:
                approval_ref = decision["approval_ref"]
                _, approval = request(
                    socket_path,
                    "GET",
                    f"/approvals/{approval_ref}?contract_generation=1&scope=local",
                )
                jsonschema.validate(approval, domain_schema("approval-result"))
                validated += 1
                resolution = Resolution.APPROVE.value
                _, resolved = request(
                    socket_path,
                    "POST",
                    f"/approvals/{approval_ref}/resolution",
                    {
                        "contract_generation": 1,
                        "scope": "local",
                        "approval_ref": approval_ref,
                        "resolution": resolution,
                    },
                )
                jsonschema.validate(resolved, domain_schema("approval-result"))
                validated += 1
            _, problem = request(socket_path, "GET", "/not-an-operation")
            jsonschema.validate(problem, domain_schema("problem-document"))
            validated += 1
    assert validated >= 18


@pytest.mark.parametrize(
    "accept",
    [None, "application/json", "*/*", "text/event-stream", "text/event-stream, application/json"],
)
def test_the_fake_answers_the_media_type_the_published_selector_names(
    accept: str | None, tmp_path: Path
) -> None:
    """Article 13: the shipped fake reads the selector the binding publishes.

    A grant is deliverable only on a connection that carries its signals, so a
    request that selected the plain document is answered without one (article
    10) — the same choice the real server makes from the same header.
    """
    scenario = load_scenarios()["allow"]
    headers = {"Content-Type": DOCUMENT_MEDIA_TYPE}
    if accept is not None:
        headers["Accept"] = accept
    with serve(Stub(scenario.name), tmp_path / "stub.sock") as socket_path:
        connection = UnixConnection(socket_path)
        connection.request(
            "POST",
            "/decisions",
            body=json.dumps(scenario.ask.to_document(1)),
            headers=headers,
        )
        response = connection.getresponse()
        body = response.read()
        connection.close()
    streaming = selects_stream(accept)
    assert response.status == 200
    assert response.headers.get_content_type() == (
        STREAM_MEDIA_TYPE if streaming else DOCUMENT_MEDIA_TYPE
    )
    document = (
        json.loads(body.split(b"data: ", 1)[1].split(b"\n\n", 1)[0])
        if streaming
        else json.loads(body)
    )
    jsonschema.validate(document, domain_schema("decision-result"))
    assert (document.get("grant") is not None) is streaming


def test_the_shipped_client_selects_the_stream_the_binding_publishes() -> None:
    """Article 13: the shipped client's request selects an answer the same rule names."""
    assert selects_stream(SocketClient.DECISION_ACCEPT)
    assert not selects_stream(SocketClient.DOCUMENT_ACCEPT)


def _published_selector() -> dict[str, object]:
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    assert isinstance(binding, dict)
    return binding["paths"]["/decisions"]["post"]["x-media-type-selector"]


@pytest.mark.parametrize(
    "name", sorted(name for name, item in load_scenarios().items() if item.binds_server())
)
def test_the_fake_serves_every_answer_in_the_media_type_the_binding_selects(
    name: str, tmp_path: Path
) -> None:
    """Article 13: the fake's answer media type depends on the header and nothing else.

    Whether a grant was minted is not one of the selector's conditions, so a
    deny, a suspend and an absent rule are served as the selected stream too.
    The selector names the 200 response it governs; a refusal publishes one
    media type, and the fake serves that one (article 2).
    """
    selector = _published_selector()
    scenario = load_scenarios()[name]
    with serve(Stub(name), tmp_path / "stub.sock") as socket_path:
        connection = UnixConnection(socket_path)
        connection.request(
            "POST",
            "/decisions",
            body=json.dumps(scenario.ask.to_document(1)),
            headers={
                "Content-Type": DOCUMENT_MEDIA_TYPE,
                str(selector["header"]): str(selector["selects"]),
            },
        )
        response = connection.getresponse()
        body = response.read()
        connection.close()
    expected = selector["selects"] if response.status == 200 else selector["otherwise"]
    assert response.headers.get_content_type() == expected, name
    if response.status != 200:
        assert scenario.expect.problem == json.loads(body)["code"]
        return
    frames = [frame for frame in body.split(b"\n\n") if frame]
    document = json.loads(frames[0].split(b"data: ", 1)[1])
    jsonschema.validate(document, domain_schema("decision-result"))
    assert document["outcome"] == scenario.expect.outcome
    assert (document.get("grant") is not None) == (scenario.expect.grant == "present")


def test_the_stub_accepts_the_delegation_this_generation_defines(tmp_path: Path) -> None:
    """Rule D1: a peer may declare, in the optional `delegation` member, for whom it acts."""
    declaration = {
        "status": "declared",
        "chain": [{"kind": "user", "name": "alice", "uid": 1001, "via": "privilege_tool"}],
    }
    jsonschema.validate(declaration, domain_schema("delegation"))
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        status, document = request(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "delegation": declaration,
            },
        )
    assert status == 200, document
    assert document["outcome"] == "allow"


def test_the_stub_refuses_a_delegation_outside_its_published_bounds(tmp_path: Path) -> None:
    """Rule D3: a declaration outside the bounds is `delegation_invalid`, and no decision."""
    stub = Stub("allow")
    link = {"kind": "user", "name": "alice", "uid": 1001, "via": "privilege_tool"}
    with serve(stub, tmp_path / "stub.sock") as socket_path:
        status, problem = request(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "delegation": {"status": "declared", "chain": [link] * 5},
            },
        )
        assert status == 400, problem
        assert problem["code"] == "delegation_invalid"
        status, unknown_member = request(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "delegation": {"chain": [{**link, "issuer": "somebody"}]},
            },
        )
        assert status == 400, unknown_member
        assert unknown_member["code"] == "delegation_invalid"
    assert stub.decision_count == 0


def test_an_address_that_leaves_no_margin_is_refused_before_it_is_bound(tmp_path: Path) -> None:
    """Article 13: the fake says which address will not fit, and says so with room left.

    This is the guard on the run's addresses. It is proven from both sides: an
    address at the margin is served, and one byte past it is refused by name
    rather than by `OSError: AF_UNIX path too long` from inside `bind`. A
    fixture leaf that grows back past the margin trips this wherever it is.
    """
    limit = sun_path_limit(sys.platform)
    room = limit - ADDRESS_MARGIN_BYTES - address_bytes(tmp_path)
    assert room > len(".sock"), (tmp_path, room)

    inside = tmp_path / f"{'a' * (room - len('.sock') - 1)}.sock"
    assert address_bytes(inside) + ADDRESS_MARGIN_BYTES == limit
    with serve(Stub("allow"), inside) as socket_path:
        assert socket_path.is_socket()

    past = tmp_path / f"{'a' * (room - len('.sock'))}.sock"
    with pytest.raises(AddressTooLong) as refused, serve(Stub("allow"), past):
        raise AssertionError("the fake bound an address past the margin")
    assert "socket_path_too_long" in str(refused.value)
    assert str(ADDRESS_MARGIN_BYTES) in str(refused.value)
    assert not past.exists()


def test_a_malformed_evidence_scope_answers_the_code_the_daemon_answers(tmp_path: Path) -> None:
    """A conformance client pins the code, so the fake and the daemon answer the same one.

    A scope that fails the contract's pattern is a malformed request, and the
    published binding lists `scope_invalid` at 400 on both evidence routes.
    Answering the range code instead would tell a third party its scope was out
    of range, which is a statement about something never read (article 2).
    """
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        status, problem = request(
            socket_path,
            "GET",
            "/scopes/bad%20scope%21/evidence?contract_generation=1&from_sequence=1",
        )
    assert status == 400
    assert problem["code"] == "scope_invalid"
    assert problem["contract_generation"] == 1


def test_the_stub_answers_the_decision_read_the_binding_declares(harness: _Harness) -> None:
    """It answered `operation_unknown`, so a client's explain or trace had no fake.

    Article 13 publishes four reads; a fake that serves two of them is a fake a
    third party cannot build a trace against, which is the barrier publishing
    the contract exists to remove.
    """
    session = harness.arrange(scenario(GRANTING))
    answer = session.client.ask_decision(_ask())
    assert isinstance(answer, Answered), answer
    read = session.client.read_decision("local", answer.value.decision_ref)
    assert isinstance(read, Answered), read
    assert read.value.decision_ref == answer.value.decision_ref
    assert read.value.outcome is answer.value.outcome


def test_the_decision_read_answers_the_record_shape_the_binding_publishes(
    harness: _Harness,
) -> None:
    """Article 13: the 200 of this read is a record, and a record is not a result.

    The wait a decision opened and the grant it minted belong to the answer
    that took it — article 10 binds the grant to the channel that carried it —
    so a later read carries the grant's identity and neither of those two. The
    daemon's own route drops the same pair; a fake that kept them would hand a
    conformance client a shape no server serves.
    """
    session = harness.arrange(scenario(GRANTING))
    answer = session.client.ask_decision(_ask())
    assert isinstance(answer, Answered), answer
    status, document = _over_the_socket(
        session,
        "GET",
        f"/decisions/{answer.value.decision_ref}"
        f"?contract_generation={CONTRACT_GENERATION}&scope=local",
    )
    assert status == 200, document
    validate_document(document, "decision-record")
    assert "approval_ref" not in document
    assert "grant" not in document
    assert document["grant_id"] == "grant-1"


def test_a_decision_the_stub_never_took_is_refused_by_reference(harness: _Harness) -> None:
    read = harness.arrange(scenario(GRANTING)).client.read_decision("local", "d-absent")
    assert isinstance(read, Refused), read
    assert read.problem.code is ProblemCode.DECISION_NOT_FOUND


def test_a_decision_read_that_names_no_scope_is_refused(harness: _Harness) -> None:
    """Article 5: the writer's default never applies to a read.

    Asked over the socket rather than through the client, because the client
    always sends a scope: the refusal is the fake's, and a third party's client
    that forgot the member has to meet it.
    """
    session = harness.arrange(scenario(GRANTING))
    status, document = _over_the_socket(
        session, "GET", f"/decisions/d-1?contract_generation={CONTRACT_GENERATION}"
    )
    assert status == 400, document
    assert document["code"] == "scope_required"


def test_the_stub_answers_the_policy_status_read(harness: _Harness) -> None:
    """Article 2: three values where a reader might expect two.

    This fake keeps no projection, so `in_step` is the published unknown and
    not a `yes` it has nothing behind. The authority is the one value the
    published document defines, read from the document rather than spelled
    again here.

    The schema is held against the bytes that were served, as the decision read
    beside this one does. Validating what the client parsed and rendered again
    would pass a served member the reader tolerates and the renderer
    normalises, which is the one disagreement a conformance fake exists to
    catch (article 13).
    """
    given = scenario(GRANTING)
    session = harness.arrange(given)
    status = session.client.read_policy_status()
    assert isinstance(status, Answered), status
    published = domain_schema("policy-status")["properties"]["authority"]["const"]
    assert status.value.authority == published
    assert status.value.rule_count == len(given.given.policy or {})
    assert status.value.projection.in_step is ProjectionStep.UNKNOWN

    code, document = _over_the_socket(
        session, "GET", f"/policy/status?contract_generation={CONTRACT_GENERATION}"
    )
    assert code == 200, document
    validate_document(document, "policy-status")
    assert document["authority"] == published
    assert document["projection"]["in_step"] == ProjectionStep.UNKNOWN.value


def test_the_policy_status_names_the_version_the_stubs_own_decision_names(
    harness: _Harness,
) -> None:
    """One recipe, so a consumer can join the two reads the way it joins them live."""
    session = harness.arrange(scenario(GRANTING))
    answer = session.client.ask_decision(_ask())
    status = session.client.read_policy_status()
    assert isinstance(answer, Answered) and isinstance(status, Answered)
    assert status.value.policy_version == answer.value.policy_version


def test_the_stubs_evidence_page_is_a_chain_the_published_verifier_calls_intact(
    harness: _Harness,
) -> None:
    """The page was a placeholder — no entries, a verdict written here by hand.

    A conformance client could read the page's shape and nothing else, so the
    one thing an evidence read exists for — a chain that verifies — was proven
    only against the daemon. The fake now arranges a real chain with
    `chained_document`, the same recipe the server writes with, so the replay
    covers the read end to end.
    """
    session = harness.arrange(scenario(GRANTING))
    session.client.ask_decision(_ask())
    page = session.client.read_evidence("local", 1)
    assert isinstance(page, Answered), page
    entries = page.value["entries"]
    assert len(entries) >= 2, "a chain of one entry proves no link"
    verdict = verify_chain(entries, scope="local", from_sequence=1)
    assert verdict.condition is ChainCondition.intact, verdict
    assert page.value["verification"]["condition"] == "intact"
    validate_document(page.value, "evidence-page-result")


def test_the_stubs_export_recomputes_its_own_manifest_digest(harness: _Harness) -> None:
    session = harness.arrange(scenario(GRANTING))
    session.client.ask_decision(_ask())
    bundle = session.client.export_evidence("local", 1)
    assert isinstance(bundle, Answered), bundle
    assert bundle.value["manifest_version"] == MANIFEST_V3
    assert manifest_hash(bundle.value, version=MANIFEST_V3) == bundle.value["manifest_hash"]
    validate_document(bundle.value, "evidence-export-result")


def test_the_stubs_export_carries_the_policy_bytes_its_effects_name(harness: _Harness) -> None:
    """A6: an export resolves every version an included effect names, or it proves less.

    The offline verifier is what says so: it is handed the bundle and nothing
    else, and it recomputes the digest and reads the attachments. What it
    cannot establish here is coverage — this fake writes no epoch closure, and
    an open range is honestly unknown, never a confirmation it has not earned.
    """
    session = harness.arrange(scenario(GRANTING))
    session.client.ask_decision(_ask())
    bundle = session.client.export_evidence("local", 1)
    assert isinstance(bundle, Answered), bundle
    verdict = verify_export(bundle.value)
    assert verdict.manifest_hash_recomputes is True, verdict
    assert verdict.chain is not None and verdict.chain.condition is ChainCondition.intact
    assert "policy_map_incomplete" not in verdict.issues, verdict
    assert verdict.coverage == "unknown", verdict


def test_a_read_over_a_scope_with_no_entries_is_unverifiable_and_not_empty(
    harness: _Harness,
) -> None:
    """Article 2: an absence is never a healthy state.

    An unbounded range over a chain with nothing in it establishes nothing,
    and the published verifier is what says so — the fake no longer writes
    that verdict by hand.
    """
    page = harness.arrange(scenario(GRANTING)).client.read_evidence("elsewhere", 1)
    assert isinstance(page, Answered), page
    assert page.value["entries"] == []
    assert page.value["verification"]["condition"] == "unverifiable"
    assert page.value["verification"]["covers_an_entry"] is False


def test_a_write_to_a_read_only_target_is_the_method_refusal_and_not_a_missing_route(
    harness: _Harness,
) -> None:
    """Articles 4 and 13: a path this binding publishes is a path this fake knows."""
    session = harness.arrange(scenario(GRANTING))
    for target in ("/policy/status", "/decisions/decision-1"):
        status, document = _over_the_socket(session, "POST", target)
        assert status == 405, (target, document)
        assert document["code"] == "operation_unknown", (target, document)
