# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
import inspect
import json
import socket
from dataclasses import replace
from datetime import UTC, datetime
from inspect import isfunction
from pathlib import Path

import jsonschema
import pytest
from handler_bytes import read_one_document
from sayfirst_contract.artifacts import domain_schema
from sayfirst_contract.binding.http_unix_socket.routes import (
    DOCUMENT_MEDIA_TYPE,
    ROUTES,
    STREAM_MEDIA_TYPE,
    selects_stream,
)
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_contract.policy import ProjectionStep
from sayfirst_contract.problems import Problem, ProblemCode
from sayfirst_control_plane.adapters.api.decision_routes import DecisionRoutes
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.application import decisions as decisions_application
from sayfirst_control_plane.application.decisions import DecisionAnswer
from sayfirst_control_plane.application.policy import PolicyStatus, ProjectionStatus
from sayfirst_control_plane.domain.grant import mint_grant
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal

NOW = datetime(2026, 9, 4, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64


def _decision() -> Decision:
    return Decision(
        "decision-1",
        "local",
        "mail.send",
        Outcome.ALLOW,
        Reason.POLICY_ALLOWS,
        "sha256:" + "a" * 64,
        None,
        "2026-09-04T00:00:00Z",
        None,
        1,
        {
            "principal": {"kind": "process", "uid": 1001, "name": "build"},
            "arguments_digest": DIGEST,
            "rule_id": "mail",
            "grant_id": None,
            "grant": None,
        },
    )


class Policy:
    def status(self) -> PolicyStatus:
        return PolicyStatus(
            "file",
            "sha256:" + "a" * 64,
            1,
            NOW,
            1,
            ProjectionStatus("memory", "sha256:" + "a" * 64, ProjectionStep.YES),
        )


class Decisions:
    def __init__(self, *, stream: bool = False) -> None:
        self.decisions = MemoryDecisionStore()
        self.decisions.append(_decision())
        self.policy = Policy()
        self.stream = stream

    def ask(self, question, *, grant_connection=False, signal_writer=None, deliver=None):  # type: ignore[no-untyped-def]
        decision = _decision()
        # The real service mints only on a connection that can carry signals.
        if not self.stream or not grant_connection:
            return DecisionAnswer(decision, None, None)
        grant = mint_grant(
            decision,
            NOW,
            lifetime_seconds=30,
            policy_version=decision.policy_version or "",
            heartbeat_seconds=5,
        )
        answer = DecisionAnswer(decision, grant, None)
        if deliver is not None:
            deliver(answer)
        return replace(answer, connection=object())  # type: ignore[arg-type]


def _exchange(call):  # type: ignore[no-untyped-def]
    """Run one route and read the one document it framed.

    Read to the length the answer declares rather than to the end of the
    connection: a document answer no longer ends its connection, so the end of
    the connection is not where the answer stops. That is the property the
    handler's own cases hold; here it is only how a complete answer is read,
    and it is read by the one framing reader this package keeps.
    """
    server, client = socket.socketpair(socket.AF_UNIX)
    client.settimeout(1)
    try:
        result = call(server)
        return result, read_one_document(client)
    finally:
        server.close()
        client.close()


def _body(response: bytes) -> tuple[bytes, dict[str, object]]:
    head, body = response.split(b"\r\n\r\n", 1)
    return head, json.loads(body)


def test_json_decision_response_is_http_over_the_socket() -> None:
    """Articles 6 and 13: a decision document uses the published HTTP binding."""
    routes = DecisionRoutes(Decisions())  # type: ignore[arg-type]
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", 1001, "build", (), ()),
    )
    _, response = _exchange(
        lambda connection: routes.ask_decision(
            question,
            connection,
            accept=DOCUMENT_MEDIA_TYPE,
        )
    )
    head, document = _body(response)
    assert head.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: application/json" in head
    jsonschema.validate(document, domain_schema("decision-result"))


def test_grant_decision_response_is_an_http_event_stream() -> None:
    """Articles 10 and 13: a grant begins a standards-framed event stream."""
    routes = DecisionRoutes(Decisions(stream=True))  # type: ignore[arg-type]
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", 1001, "build", (), ()),
    )
    server, client = socket.socketpair(socket.AF_UNIX)
    client.settimeout(1)
    try:
        routes.ask_decision(question, server, accept=STREAM_MEDIA_TYPE)
        response = client.recv(65536)
    finally:
        server.close()
        client.close()
    head, event = response.split(b"\r\n\r\n", 1)
    assert head.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: text/event-stream" in head
    assert event.startswith(b"event: decision\ndata: {")


def test_get_decision_requires_scope_and_answers_the_published_record() -> None:
    """Articles 3, 5 and 13: the read is scoped and uses the record schema."""
    routes = DecisionRoutes(Decisions())  # type: ignore[arg-type]
    _, response = _exchange(
        lambda connection: routes.read_decision("local", "decision-1", connection)
    )
    head, document = _body(response)
    assert head.startswith(b"HTTP/1.1 200 OK\r\n")
    assert "approval_ref" not in document
    jsonschema.validate(document, domain_schema("decision-record"))
    _, refused = _exchange(lambda connection: routes.read_decision("", "decision-1", connection))
    refused_head, problem = _body(refused)
    assert refused_head.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert problem["code"] == "scope_required"
    _, missing = _exchange(lambda connection: routes.read_decision("local", "missing", connection))
    missing_head, missing_problem = _body(missing)
    assert missing_head.startswith(b"HTTP/1.1 404 Not Found\r\n")
    assert missing_problem["code"] == "decision_not_found"


def test_get_policy_status_answers_the_published_projection_status() -> None:
    """Articles 3 and 13: status identifies its authority and projection."""
    routes = DecisionRoutes(Decisions())  # type: ignore[arg-type]
    _, response = _exchange(routes.read_policy_status)
    head, document = _body(response)
    assert head.startswith(b"HTTP/1.1 200 OK\r\n")
    jsonschema.validate(document, domain_schema("policy-status"))


def test_the_adapter_claims_exactly_the_block_23_binding_operations() -> None:
    """Article 13: method names and the published route operations stay aligned."""
    operations = {
        name
        for name, value in vars(DecisionRoutes).items()
        if isfunction(value) and not name.startswith("_")
    }
    assert operations == {"ask_decision", "read_decision", "read_policy_status"}


def _named_problem_codes(module) -> set[ProblemCode]:  # type: ignore[no-untyped-def]
    """Every `ProblemCode.X` a module names, read from its source."""
    tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
    return {
        ProblemCode[node.attr]
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "ProblemCode"
        and node.attr in ProblemCode.__members__
    }


def test_the_ask_route_answers_only_codes_its_published_binding_lists() -> None:
    """Article 13: a server never answers outside the shape it publishes."""
    route = next(item for item in ROUTES if item.operation == "ask_decision")
    codes = _named_problem_codes(decisions_application)
    assert {ProblemCode.POLICY_UNAVAILABLE, ProblemCode.REQUEST_MALFORMED} <= codes
    for code in codes:
        status = DecisionRoutes._problem_status(Problem(code, "", False, 1))
        assert status in route.problems, f"{code.value} answers unpublished status {status}"
        assert code.value in route.problems[status], f"{code.value} is unpublished at {status}"


def test_the_read_route_answers_only_codes_its_published_binding_lists() -> None:
    """Article 13: the record route publishes each refusal it can answer."""
    route = next(item for item in ROUTES if item.operation == "read_decision")
    for code, status in (
        (ProblemCode.SCOPE_REQUIRED, 400),
        (ProblemCode.DECISION_NOT_FOUND, 404),
    ):
        assert code.value in route.problems[status]


@pytest.mark.parametrize(
    "accept",
    [
        None,
        "",
        "application/json",
        "*/*",
        "text/event-stream",
        "application/json, text/event-stream",
    ],
)
def test_the_route_answers_the_media_type_the_published_selector_names(accept) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the server reads the published selector, not an out-of-band flag."""
    streaming = selects_stream(accept)
    routes = DecisionRoutes(Decisions(stream=True))  # type: ignore[arg-type]
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", 1001, "build", (), ()),
    )
    server, client = socket.socketpair(socket.AF_UNIX)
    client.settimeout(1)
    try:
        answer = routes.ask_decision(question, server, accept=accept)
        response = client.recv(65536)
    finally:
        server.close()
        client.close()
    head = response.split(b"\r\n\r\n", 1)[0]
    expected = STREAM_MEDIA_TYPE if streaming else DOCUMENT_MEDIA_TYPE
    assert f"Content-Type: {expected}".encode() in head
    assert isinstance(answer, DecisionAnswer)
    assert (answer.grant is not None) is streaming
