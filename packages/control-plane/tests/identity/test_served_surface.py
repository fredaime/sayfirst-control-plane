# SPDX-License-Identifier: Apache-2.0
"""Article 13: the served surface is the published binding, exactly.

The one transport binding "is derived from the domain contract, adds no
vocabulary to it, and is published beside it". A path the daemon answers that
the binding does not publish is vocabulary the contract never carried; an
operation the binding publishes that the only server implementing it answers
`operation_unknown` is vocabulary the contract carries and nobody honours.
Both are drift, and this compares the two tables against each other rather than
against a second copy of either.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.binding.http_unix_socket.routes import ROUTES
from sayfirst_contract.problems import problem_retryable
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_control_plane.adapters import http_surface
from sayfirst_testing.doubles import StaticAccountDirectory
from sayfirst_testing.schemas import validate_document

pytestmark = pytest.mark.identity

_AT = "2026-09-04T00:00:00+00:00"
ME = os.geteuid()
MY_GID = os.getegid()
OPERATORS = 90000


def _credential() -> PeerCredential:
    return PeerCredential(uid=ME, gid=MY_GID, pid=4242, captured_at=_AT)


def alice_directory(**kwargs: object) -> StaticAccountDirectory:
    return StaticAccountDirectory(
        accounts={ME: ("alice", MY_GID)},
        memberships={"alice": (MY_GID, OPERATORS)},
        group_names={MY_GID: "alice", OPERATORS: "operators"},
        **kwargs,  # type: ignore[arg-type]
    )


SERVER_PACKAGE = Path(http_surface.__file__).resolve().parents[1]
CUT_NAME = "/health"
"""Block 2.1's rename table records `health` -> `read_status`. The old name is
not a path of this binding, so no server of this binding answers it."""


def published_operations() -> dict[str, tuple[str, str]]:
    """Every operation the binding document publishes, with its method and path."""
    document = load_json("binding", "http-unix-socket", "openapi.json")
    assert isinstance(document, dict)
    paths = document["paths"]
    assert isinstance(paths, dict)
    return {
        str(operation["operationId"]): (method.upper(), str(path))
        for path, methods in paths.items()
        for method, operation in methods.items()
    }


def test_the_binding_document_and_the_binding_route_table_agree() -> None:
    """Article 13: one binding, published once, read the same way twice."""
    from_routes = {route.operation: (route.method, route.path) for route in ROUTES}
    assert published_operations() == from_routes


def test_the_daemon_serves_exactly_the_operations_the_binding_publishes() -> None:
    """Article 13: what this block serves, and what it defers, are both named.

    The served set and the deferred set partition the published operations, so
    an operation cannot be quietly served under a name the binding does not
    carry, nor quietly dropped from the surface that carries it.
    """
    published = published_operations()
    served = set(http_surface.SERVED_OPERATIONS)
    deferred = set(http_surface.DEFERRED_OPERATIONS)
    assert served | deferred == set(published)
    assert not served & deferred
    assert served == {
        "read_status",
        "read_whoami",
        "ask_decision",
        "read_decision",
        "read_policy_status",
        "read_approval",
        "resolve_approval",
        "read_evidence",
        "export_evidence",
    }
    # Every published operation is answered, the approval pair included: a
    # suspension is kept in memory by the daemon, a rule member bounds its
    # wait, the person of a resolution is the connection's verified principal,
    # and the sweep that ends the grants ends the waits that ran out.
    assert deferred == set()
    # Six of the served operations answer out of a composition; a deployment
    # that composed none does not serve them, which is the next case.
    assert served >= http_surface.COMPOSED_OPERATIONS


def test_no_target_the_daemon_answers_is_outside_the_binding() -> None:
    """Article 13: the served route table is derived, never spelled a second time."""
    published = published_operations()
    for operation in http_surface.SERVED_OPERATIONS:
        method, path = published[operation]
        assert http_surface.SERVED[(method, path)] == operation
    assert set(http_surface.SERVED) == {
        published[operation] for operation in http_surface.SERVED_OPERATIONS
    }
    for source in SERVER_PACKAGE.rglob("*.py"):
        assert CUT_NAME not in source.read_text(encoding="utf-8"), source


def test_every_served_operation_is_answered_as_itself(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 13: a published operation this daemon composed is never `operation_unknown`."""
    published = published_operations()
    session = make_session(credential=_credential(), directory=alice_directory())
    for operation in set(http_surface.SERVED_OPERATIONS) - http_surface.COMPOSED_OPERATIONS:
        method, path = published[operation]
        body = (
            {"contract_generation": 1, "capability": "example.effect"} if method == "POST" else None
        )
        _, document = session.request(method, path, body)
        assert document.get("code") != "operation_unknown", operation


def test_an_operation_this_deployment_composed_nothing_for_is_not_answered(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2: an absent authority is not answered as an empty one.

    This daemon composes no policy authority, no decision store, no approval
    store and no evidence store, so the six operations that read one are not
    served by it. None of them publishes a code for "there is no authority
    here", and answering `decision_not_found`, `approval_unknown` or an empty
    page would claim a store was consulted, so the answer is the one this
    server spells for an operation it does not answer at all.
    `packages/control-plane/tests/e2e/test_composed_daemon.py` holds the other
    half: composed, every one of the six is served.

    The resolution is a POST, and it is refused here before its body is read.
    That is the order the rest of this surface keeps too: "this daemon does not
    serve that" is a fact about the daemon, and a complaint about the request
    would claim the request had reached something (article 2).
    """
    published = published_operations()
    session = make_session(credential=_credential(), directory=alice_directory())
    for operation in sorted(http_surface.COMPOSED_OPERATIONS):
        method, path = published[operation]
        target = (
            path.replace("{decision_ref}", "decision-1")
            .replace("{approval_ref}", "approval-1")
            .replace("{scope}", "local")
        )
        status, document = session.request(
            method, f"{target}?contract_generation=1&from_sequence=1&scope=local"
        )
        assert status == 404, operation
        assert document["code"] == "operation_unknown", operation


def test_the_status_operation_is_served_at_the_path_the_binding_publishes(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 13 and article 2: the status result carries no claim it cannot hold.

    Nothing composes an evidence store or a privacy provider into this
    operation, so the grade is `unverified` on the basis that access was not
    established, the store's authority is `unknown` and the provider is the
    schema's reserved `unknown` — the values the contract carries for exactly
    this. Block 2.4's emitter answers them for a caller that brings one; the
    change that composes it here replaces these with what it can prove.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    status, document = session.request("GET", "/status")
    assert status == 200, document
    validate_document(document, "status-result")
    assert document["contract_generation"] == 1
    assert document["supported_generations"] == [1]
    assert document["integrity_grade"]["grade"] == "unverified"
    assert document["integrity_grade"]["basis"] == "access_not_established"
    assert document["integrity_grade"]["store"] == "unknown"
    assert document["privacy_provider"] == "unknown"
    assert document["store"] == {"authority": "unknown", "kind": "unknown"}
    assert document["principal"] == {"kind": "user", "uid": ME, "name": "alice"}


def test_the_cut_name_is_not_served_at_an_unpublished_path(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 13: `/health` is the name block 2.1 cut; nothing answers it."""
    session = make_session(credential=_credential(), directory=alice_directory())
    status, document = session.request("GET", CUT_NAME)
    assert status == 404
    assert document["code"] == "operation_unknown"


def test_a_deferred_operation_is_answered_as_unknown_and_not_invented(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2: an operation no code here implements is not answered as if it were.

    Nothing is deferred now, and the case stays rather than being deleted: the
    rule it holds is about any operation this server might publish and not
    answer, and a deleted case would have to be rediscovered the next time one
    appears. It iterates an empty tuple, which the case above is what makes
    meaningful — the two sets partition what the binding publishes, so an
    operation cannot leave both.
    """
    published = published_operations()
    session = make_session(credential=_credential(), directory=alice_directory())
    for operation in http_surface.DEFERRED_OPERATIONS:
        method, path = published[operation]
        target = path.replace("{approval_ref}", "ap_0000000000000000")
        body = {"contract_generation": 1} if method == "POST" else None
        status, document = session.request(method, target, body)
        assert status == 404, operation
        assert document["code"] == "operation_unknown", operation


def test_a_status_request_on_an_unknown_connection_is_refused_retryably(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 3: the status result names a principal, so it needs one resolved.

    `read_status` publishes `principal_groups_unavailable` at 503 for exactly
    this; inventing a kind and a name for a directory that could not be
    consulted would be the negative fact article 2 refuses. `whoami` remains
    served on an `unknown` connection, and it is where the state is read.
    """
    session = make_session(credential=_credential(), directory=alice_directory(outage=True))
    connection = session.connect()
    status, document = session.request("GET", "/status", connection=connection)
    assert status == 503
    assert document["code"] == "principal_groups_unavailable"
    assert document["retryable"] is True
    status, seen = session.request("GET", "/whoami", connection=connection)
    connection.close()
    assert status == 200
    assert seen["status"] == "unknown"


# -- rule G5: the attempt is repeated on the next request ---------------------


def test_the_first_request_after_an_accept_time_outage_repeats_the_lookup(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule G5: the next request repeats the attempt — the *next* one.

    An outage at accept happens inside no request at all, so the request that
    follows it is the first one, and it is the one that must ask again. Costing
    a whole request to every connection accepted during a name-service blip is
    fail-closed but it is not what `refresh_due_at` promises the caller.
    """
    directory = alice_directory(outage=True)
    session = make_session(credential=_credential(), directory=directory)
    connection = session.connect()
    for _ in range(500):
        if directory.calls:
            break
        time.sleep(0.01)
    assert directory.calls, "the daemon never consulted the directory at accept"
    directory.outage = False
    directory.calls.clear()
    status, document = session.request("GET", "/whoami", connection=connection)
    connection.close()
    assert status == 200
    assert directory.calls, "the first request did not repeat the lookup"
    assert document["status"] == "established"
    assert document["principal"]["name"] == "alice"


def test_a_decision_is_served_on_the_first_request_after_the_outage_ends(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule G5: and the recovered lookup is what the request is served on."""
    directory = alice_directory(outage=True)
    session = make_session(credential=_credential(), directory=directory)
    connection = session.connect()
    for _ in range(500):
        if directory.calls:
            break
        time.sleep(0.01)
    directory.outage = False
    status, document = session.request(
        "POST",
        "/decisions",
        {"contract_generation": 1, "capability": "example.effect"},
        connection=connection,
    )
    connection.close()
    # No policy authority exists in this block, so the honest answer is
    # `policy_unavailable`. What matters here is that it is not
    # `principal_groups_unavailable`: the principal was resolved for this
    # request rather than a request later.
    assert status == 503
    assert document["code"] == "policy_unavailable", document


def test_an_outage_at_accept_is_not_carried_into_the_request_that_follows(tmp_path: Path) -> None:
    """Article 6, rule G5, at the domain: the outage belongs to no request.

    `unknown_since_request` records which request the outage was noted in.
    Recording the *served* count made an accept-time outage indistinguishable
    from one noted inside request 1, and the counter only overtook it at
    request 2.
    """
    from datetime import timedelta

    from sayfirst_contract.whoami import ConnectionStatus
    from sayfirst_control_plane.adapters.socket_server import Daemon
    from sayfirst_control_plane.domain.evidence import RecordCollector
    from sayfirst_control_plane.settings import read_settings
    from sayfirst_testing.doubles import FixedClock, StaticPeerIdentity

    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    clock = FixedClock()
    directory = alice_directory(outage=True)
    daemon = Daemon(
        read_settings(
            {"socket": {"mode": "per_user", "path": str(root / "daemon.sock")}, "identity": {}},
            platform="linux",
        ),
        platform="linux",
        directory=directory,
        peer_identity=StaticPeerIdentity(_credential()),
        clock=clock,
        evidence=RecordCollector(),
        daemon_uid=ME,
        socket_gid=None,
        overflow_ids=(65534, 65534),
    )
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    assert identity.status == ConnectionStatus.UNKNOWN
    directory.outage = False
    directory.calls.clear()

    # Request 1 begins: it is the next request after the outage, so it asks.
    identity.begin_request()
    assert daemon.refresh_if_due(identity) is None
    assert directory.calls, "the first request after the outage never asked again"
    assert identity.status == ConnectionStatus.ESTABLISHED
    assert identity.requests_begun == 1

    # And the same request does not ask twice.
    directory.calls.clear()
    assert daemon.refresh_if_due(identity) is None
    assert directory.calls == []
    assert identity.refresh_due_at == clock.now() + timedelta(
        seconds=daemon.settings.group_lifetime_seconds
    )


# -- the body the request framed, and the framing this daemon reads -----------

_ASK = {"contract_generation": 1, "capability": "example.effect"}


def test_a_chunked_body_is_refused_by_name_and_never_read_as_a_request(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2 and article 13: no fact about a body nobody read, and no desync.

    `protocol_version` is HTTP/1.1, so a conforming caller may frame its
    request with `Transfer-Encoding: chunked`. The daemon read `Content-Length`
    only: it answered `generation_missing` — a claim about a body it had not
    read — and then parsed the chunk-size line as the next request line, so the
    caller received the base handler's HTML 400 on a broken connection. The
    binding's own purpose is third-party implementability; this is the guard.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    connection = session.connect()
    connection.request(
        "POST",
        "/decisions",
        body=iter([json.dumps(_ASK).encode()]),
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    document = json.loads(response.read() or b"{}")
    assert response.status == 400, document
    assert response.getheader("Content-Type") == "application/json"
    assert document["code"] == "request_malformed", document
    assert "chunked" in document["message"]
    # And the connection is still a connection: the framing was skipped, so
    # what follows is read as a request rather than as a chunk-size line.
    connection.request("GET", "/whoami")
    following = connection.getresponse()
    seen = json.loads(following.read() or b"{}")
    connection.close()
    assert following.status == 200, seen
    assert seen["status"] == "established"


def test_a_body_a_route_does_not_read_is_not_read_as_the_next_request(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 13: every route consumes the body its request framed.

    `GET /whoami` never looked at the body, so a caller that sent one had its
    bytes read as the request line of its next request on the same connection
    — answered `operation_unknown`, for an operation it never named.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    for method, target in (("GET", "/whoami"), ("GET", "/status"), ("POST", "/nowhere")):
        connection = session.connect()
        connection.request(
            method, target, body=json.dumps(_ASK), headers={"Content-Type": "application/json"}
        )
        first = connection.getresponse()
        first.read()
        status, document = session.request("GET", "/whoami", connection=connection)
        connection.close()
        assert status == 200, (method, target, document)
        assert document["status"] == "established", (method, target, document)


def _raw(session, request: bytes) -> tuple[bytes, bool]:  # type: ignore[no-untyped-def]
    """One request written by hand: what the daemon wrote back, and whether it closed."""
    connection = session.connect()
    stream = connection.sock
    assert stream is not None
    stream.settimeout(2)
    stream.sendall(request)
    answered, closed = b"", False
    try:
        while True:
            block = stream.recv(65536)
            if not block:
                closed = True
                break
            answered += block
    except TimeoutError:
        pass
    stream.close()
    return answered, closed


def test_a_length_that_is_not_a_length_is_refused_rather_than_ignored(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2: a `Content-Length` the daemon cannot read frames no body.

    `int(...)` on it raised, the body was left unread, and the request was
    answered as though it carried none — the same false fact, and the same
    desync, as the chunked case.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    answered, closed = _raw(
        session,
        b"POST /decisions HTTP/1.1\r\nHost: sayfirst\r\n"
        b"Content-Type: application/json\r\nContent-Length: seven\r\n\r\n",
    )
    head, _, body = answered.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 400 "), answered
    assert b"application/json" in head, answered
    document = json.loads(body or b"{}")
    assert document["code"] == "request_malformed", document
    # There is no telling where the next request begins on a stream whose
    # framing was not read, so the connection ends rather than desyncs.
    assert closed, "the connection was left open on a body the daemon could not frame"


# -- one registry, one binding, no second copy of either ----------------------


def codes_the_surface_answers() -> set[str]:
    """Every problem code the server package hands to `_send_problem`, by AST."""
    import ast

    found: set[str] = set()
    for source in SERVER_PACKAGE.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_send_problem"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                found.add(node.args[0].value)
    assert len(found) >= 8, found
    return found


def test_the_daemon_answers_the_retryability_the_registry_publishes(  # type: ignore[no-untyped-def]
    make_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 13: one registry answers whether a problem may be retried.

    The client reads `problem_retryable`; the stub reads it; the daemon — the
    only server implementing this binding — kept a hand-written set beside it.
    The two agreed on the day they were written and nothing held them there, so
    the change that shipped the drift would be a later block editing the
    registry and nobody editing the daemon. This moves the registry's answer
    and requires the daemon's answer to move with it.
    """
    from sayfirst_contract.problems import ProblemCode

    published = {code: problem_retryable(ProblemCode(code)) for code in codes_the_surface_answers()}
    monkeypatch.setattr(
        http_surface,
        "problem_retryable",
        lambda code: None if published[code.value] is False else not published[code.value],
    )
    session = make_session(credential=_credential(), directory=alice_directory())
    status, document = session.request(
        "POST", "/decisions", {"contract_generation": 1, "capability": "example.effect"}
    )
    assert status == 503
    assert document["code"] == "policy_unavailable"
    assert document["retryable"] is False, "the daemon answered from a second copy"
    status, document = session.request("GET", "/nowhere")
    assert document["code"] == "operation_unknown"
    assert document["retryable"] is None, "the daemon answered from a second copy"


def test_no_problem_the_daemon_answers_carries_a_second_retryability() -> None:
    """Article 13: every code it can emit takes its retryability from the registry."""
    from sayfirst_contract.problems import ProblemCode

    for code in codes_the_surface_answers():
        published = problem_retryable(ProblemCode(code))
        assert http_surface._problem(code, "why").retryable is published, code


def test_the_status_of_a_problem_is_the_status_the_binding_publishes() -> None:
    """Article 13: the binding adds no vocabulary, and the server adds no second copy.

    `SERVED` is already derived from `ROUTES` so no path is spelled twice; the
    status each problem carries is the other thing the binding publishes about
    it, and it is derived the same way. The one code no route publishes is the
    one a request that names no route receives, and it is named apart.
    """
    published: dict[str, int] = {}
    for route in ROUTES:
        for status, codes in route.problems.items():
            for code in codes:
                assert published.setdefault(code, status) == status, code
                assert http_surface._STATUS_BY_CODE[code] == status, code
    assert set(http_surface._STATUS_OFF_THE_ROUTES) == {"operation_unknown"}
    assert not set(http_surface._STATUS_OFF_THE_ROUTES) & set(published)
    for code in codes_the_surface_answers():
        assert code in http_surface._STATUS_BY_CODE, code


# -- every reachable answer, walked against the binding ------------------------

UNREADABLE_REQUESTS: dict[str, bytes] = {
    "an over-long request line": b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: x\r\n\r\n",
    "a version this daemon does not speak": b"GET /whoami HTTP/9.9\r\nHost: x\r\n\r\n",
    "a request line that is not a request line": b"!!!! !!!! !!!! !!!!\r\n\r\n",
    "a version that carries no status line": b"GET /whoami\r\n\r\n",
    "more headers than the reader accepts": (
        b"GET /whoami HTTP/1.1\r\nHost: x\r\n"
        + b"".join(b"X-%d: 1\r\n" % index for index in range(200))
        + b"\r\n"
    ),
    "a method the binding does not define": b"BREW /whoami HTTP/1.1\r\nHost: x\r\n\r\n",
    "a path the binding does not publish": b"GET /nowhere HTTP/1.1\r\nHost: x\r\n\r\n",
}
"""Requests that reach an answer before any `do_*` method or `_guard` does."""


def _answer_of(answered: bytes) -> tuple[int, bytes, dict]:
    head, _, body = answered.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 "), answered[:200]
    return int(head.split()[1]), head, json.loads(body or b"{}")


def test_every_answer_the_served_surface_writes_is_one_the_binding_publishes(  # type: ignore[no-untyped-def]
    make_session,
) -> None:
    """Article 13: a status no route publishes is vocabulary the contract never carried.

    `BaseHTTPRequestHandler.send_error` answers before any `do_*` method and
    before `_guard`, with an HTML page at 414, 505, 400 or 431. None of those
    bodies is a problem document and none of those statuses is published by
    `binding/http_unix_socket/routes.py`, so a caller of the contract cannot
    read any of them, and cannot tell one from "could not ask" (article 2).
    This walks the surface an admitted peer can reach and holds every answer
    against the binding's own table.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    for what, request in UNREADABLE_REQUESTS.items():
        answered, _ = _raw(session, request)
        assert answered, f"{what}: the daemon answered nothing at all"
        status, head, document = _answer_of(answered)
        assert b"application/json" in head, (what, head)
        assert b"text/html" not in head, (what, head)
        validate_document(document, "problem-document")
        assert http_surface._STATUS_BY_CODE[document["code"]] == status, (what, document)


def test_a_refused_peer_whose_request_is_unreadable_still_reads_a_problem(  # type: ignore[no-untyped-def]
    make_session,
) -> None:
    """Article 2: "never a bare EOF", including before the refusal is consulted.

    `send_error` runs before `setup`'s refusal is ever read, so a refused peer
    whose first request is malformed used to receive an HTML page. The daemon
    answers about the thing it could not do first — it never read a request, so
    it never reached admission — and it answers it as a published problem.
    """
    refused = PeerCredential(uid=ME + 1, gid=MY_GID, pid=11, captured_at=_AT)
    session = make_session(credential=refused, directory=alice_directory())
    for what, request in UNREADABLE_REQUESTS.items():
        answered, closed = _raw(session, request)
        assert answered, f"{what}: a refused peer read a bare EOF"
        status, head, document = _answer_of(answered)
        validate_document(document, "problem-document")
        assert http_surface._STATUS_BY_CODE[document["code"]] == status, (what, document)
        assert closed, what


def test_the_daemon_writes_no_answer_its_base_class_composed() -> None:
    """Article 13: the HTML error page of `http.server` is not an answer of this binding.

    Every path on which `BaseHTTPRequestHandler` answers by itself goes through
    `send_error`; overriding it is what keeps the surface's answers to the ones
    the binding publishes, whichever new path a later standard library adds.
    """
    from http.server import BaseHTTPRequestHandler

    assert http_surface.RequestHandler.send_error is not BaseHTTPRequestHandler.send_error
    assert http_surface.RequestHandler.parse_request is not BaseHTTPRequestHandler.parse_request
    for source in SERVER_PACKAGE.rglob("*.py"):
        assert "text/html" not in source.read_text(encoding="utf-8"), source


# -- a defect in this daemon, answered as a defect ----------------------------


def _breaks(*_: object, **__: object) -> None:
    raise ZeroDivisionError("a defect in this daemon, not a fact about the world")


def test_a_defect_in_a_handler_is_answered_internal_and_recorded(  # type: ignore[no-untyped-def]
    make_session, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Article 2: an exception the daemon discarded is not evidence of unreachability.

    `handle_error` was `pass` and `log_message` was `pass`, and there was no
    other logging call in the server package, so an exception anywhere in
    `do_GET`, `do_POST`, `whoami` or `read_status` closed the connection with
    zero bytes written. `VerifiedConnection._request` reads zero bytes as
    `unreachable`, retryable — so the project's own client told its caller "the
    daemon could not be reached, try again" about a deterministic defect on a
    socket that answered every other request. The evidence held is an exception
    this daemon caught; "unreachable" is a stronger claim than that evidence.
    Rule P1 already names the answer: `internal`, "and logged".
    """
    import logging

    from sayfirst_contract.problems import ProblemCode

    session = make_session(credential=_credential(), directory=alice_directory())
    monkeypatch.setattr(http_surface, "whoami", _breaks)
    with caplog.at_level(logging.ERROR):
        status, document = session.request("GET", "/whoami")
    assert status == 500, document
    assert document["code"] == "internal", document
    assert document["retryable"] is problem_retryable(ProblemCode("internal")), document
    validate_document(document, "problem-document")
    assert http_surface._STATUS_BY_CODE["internal"] == 500
    recorded = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert recorded, "the defect was answered and then discarded"
    assert any("ZeroDivisionError" in (record.exc_text or "") for record in recorded), [
        record.getMessage() for record in recorded
    ]


def test_a_defect_leaves_the_connection_answering_rather_than_silent(  # type: ignore[no-untyped-def]
    make_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 1: "could not ask" is never written for an answer that exists.

    The bytes on the wire, not the client's reading of them: a defect used to
    produce a bare EOF, which is exactly what a daemon that died looks like.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    monkeypatch.setattr(http_surface, "whoami", _breaks)
    answered, closed = _raw(session, b"GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n")
    assert answered, "the caller read a bare EOF for a defect the daemon caught"
    status, head, document = _answer_of(answered)
    assert status == 500, answered
    assert b"application/json" in head, head
    assert document["code"] == "internal", document
    assert closed


def test_a_defect_before_the_first_request_is_answered_and_not_a_bare_eof(  # type: ignore[no-untyped-def]
    make_session, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Rule P1: no reachable path leaves a caller reading zero bytes.

    `setup` runs admission and the directory lookup, so it is a place a defect
    can reach; an exception there left `handle()` unentered and the connection
    closed with nothing written.
    """
    import logging

    session = make_session(credential=_credential(), directory=alice_directory())
    monkeypatch.setattr(type(session.daemon), "on_connection", _breaks)
    with caplog.at_level(logging.ERROR):
        answered, _ = _raw(session, b"GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n")
    assert answered, "the caller read a bare EOF for a defect in the connection's set-up"
    status, _, document = _answer_of(answered)
    assert status == 500, answered
    assert document["code"] == "internal", document
    assert caplog.records, "the defect was answered and then discarded"


def test_a_defect_after_the_answer_is_recorded_even_though_nobody_can_be_told(  # type: ignore[no-untyped-def]
    make_session, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Article 2: `_Server.handle_error` was `pass`, so the operator held no record.

    The caller already has its answer, so there is nothing to tell it; what was
    missing is any trace at all that the daemon failed.
    """
    import logging

    session = make_session(credential=_credential(), directory=alice_directory())
    monkeypatch.setattr(type(session.daemon), "on_close", _breaks)
    with caplog.at_level(logging.ERROR):
        status, document = session.request("GET", "/whoami")
        assert status == 200, document
        # The record is written on the connection's own thread, after the
        # answer the caller already read.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not caplog.records:
            time.sleep(0.01)
    assert any("ZeroDivisionError" in (record.exc_text or "") for record in caplog.records), [
        record.getMessage() for record in caplog.records
    ]
