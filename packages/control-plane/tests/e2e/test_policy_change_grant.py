# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import socket
import time
from datetime import UTC, datetime, timedelta

import jsonschema
from composed_daemon import policy_document
from sayfirst_contract.artifacts import domain_schema
from sayfirst_contract.binding.http_unix_socket.routes import STREAM_MEDIA_TYPE
from sayfirst_contract.decisions import DecisionAsk, Outcome
from sayfirst_contract.problems import ProblemCode
from sayfirst_control_plane.adapters.api.decision_routes import DecisionRoutes
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.sqlite.policy_projection import SqlitePolicyProjection
from sayfirst_control_plane.application.decisions import (
    DecisionAnswer,
    DecisionProblem,
    DecisionService,
    GrantSettings,
)
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.grant import GrantState, grant_matches, grant_state
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal
from sayfirst_control_plane.ports.policy_store import (
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

DIGEST = "sha256:" + "1" * 64


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 4, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


class ProtectedFilePolicyStore(FilePolicyStore):
    """The access guard is exercised separately; this scenario isolates live invalidation."""

    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


def _event(connection: socket.socket, *, first: bool = False) -> tuple[str, dict[str, object]]:
    data = b""
    if first:
        while b"\r\n\r\n" not in data:
            data += connection.recv(65536)
        headers, data = data.split(b"\r\n\r\n", 1)
        assert headers.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"Content-Type: text/event-stream" in headers
    while b"\n\n" not in data:
        data += connection.recv(65536)
    event, payload, _ = data.split(b"\n", 2)
    return event.removeprefix(b"event: ").decode(), json.loads(payload.removeprefix(b"data: "))


def _stream(connection: socket.socket) -> tuple[bytes, list[tuple[str, dict[str, object]]]]:
    """Read an event stream to its close and return its headers and every frame."""
    data = b""
    while True:
        part = connection.recv(65536)
        if not part:
            break
        data += part
    headers, body = data.split(b"\r\n\r\n", 1)
    frames = []
    for frame in body.split(b"\n\n"):
        if not frame:
            continue
        name, payload = frame.split(b"\n", 1)
        frames.append(
            (
                name.removeprefix(b"event: ").decode(),
                json.loads(payload.removeprefix(b"data: ")),
            )
        )
    return headers, frames


def _policy(outcome: str, revision: str) -> bytes:
    lifetime = "grant_lifetime_seconds = 30\n" if outcome == "allow" else ""
    return (
        "format = 1\n"
        "[revision]\n"
        f'reason = "{revision}"\n'
        "[[rule]]\n"
        'id = "mail"\n'
        'capability = "mail.send"\n'
        'principals = ["user:build"]\n'
        f'outcome = "{outcome}"\n'
        'reason = "host rule"\n'
        f"{lifetime}"
        f'arguments_digest = "{DIGEST}"\n'
    ).encode()


def test_a_policy_change_under_a_live_grant_makes_the_next_operation_miss(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 10: a signalled version change invalidates the very next hit."""
    policy_path = tmp_path / "policy.toml"
    policy_path.write_bytes(_policy("allow", "initial permission"))
    os.chmod(policy_path, 0o600)
    clock = Clock()
    events = MemoryEvents()
    authority = ProtectedFilePolicyStore(policy_path, clock=clock)
    projection = SqlitePolicyProjection(tmp_path / "projection.db")
    policy = PolicyService(
        authority,
        (projection,),
        events=events,
        reload_seconds=1,
        clock=clock,
    )
    grants = GrantConnections(events=events, clock=clock)
    policy.start(ProtectionExpectation.per_user(os.getuid()))
    records = MemoryDecisionStore()
    decisions = DecisionService(
        policy,
        authority,
        records,
        grants,
        settings=GrantSettings(default_lifetime_seconds=30),
        events=events,
        clock=clock,
    )

    class CountingDecisions:
        def __init__(self, service):  # type: ignore[no-untyped-def]
            self.service = service
            self.ask_calls = 0
            self.decisions = service.decisions
            self.policy = service.policy

        def ask(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            self.ask_calls += 1
            return self.service.ask(*args, **kwargs)

    counted = CountingDecisions(decisions)
    routes = DecisionRoutes(counted)  # type: ignore[arg-type]
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", os.getuid(), "build", tuple(os.getgroups()), ("users",)),
    )
    server_connection, boundary_connection = socket.socketpair(socket.AF_UNIX)
    boundary_connection.settimeout(1)
    try:
        first = routes.ask_decision(question, server_connection, accept=STREAM_MEDIA_TYPE)
        event_name, first_document = _event(boundary_connection, first=True)
        assert event_name == "decision"
        assert first_document["outcome"] == "allow"
        assert isinstance(first, DecisionAnswer)
        assert first.decision.outcome is Outcome.ALLOW
        assert first.grant is not None and first.connection is not None

        # The second operation is an exact, live hit and never reaches the service.
        assert grant_matches(first.grant, question)
        assert (
            grant_state(
                first.grant,
                clock.now,
                current_policy_version=policy.current_version,
                connection_live=first.connection.live,
                last_heard_at=clock.now,
            )
            is GrantState.LIVE
        )
        assert counted.ask_calls == 1

        policy_path.write_bytes(_policy("deny", "permission withdrawn"))
        clock.now += timedelta(seconds=1)
        assert policy.reload_if_due()
        event_name, ended_document = _event(boundary_connection)
        assert event_name == "grant_ended"
        assert ended_document["reason"] == "policy_version_changed"
        jsonschema.validate(ended_document, domain_schema("grant-signal"))
        assert boundary_connection.recv(1) == b""

        # The ended issuing connection makes the third operation miss and ask anew.
        third_server, third_boundary = socket.socketpair(socket.AF_UNIX)
        try:
            third = routes.ask_decision(question, third_server, accept=STREAM_MEDIA_TYPE)
            # The request selected the stream, so the deny is a frame on it and
            # the stream closes at once, carrying no grant (article 13).
            third_headers, third_frames = _stream(third_boundary)
            assert b"Content-Type: text/event-stream" in third_headers
            assert [name for name, _ in third_frames] == ["decision"]
            third_document = third_frames[0][1]
        finally:
            third_server.close()
            third_boundary.close()
        assert isinstance(third, DecisionAnswer)
        assert third_document["outcome"] == "deny"
        assert third.decision.outcome is Outcome.DENY
        assert third.decision.reason.value == "policy_denies"
        assert third.decision.policy_version == policy.current_version
        assert counted.ask_calls == 2
        assert records.get("local", first.decision.decision_ref) is not None
        assert records.get("local", third.decision.decision_ref) is not None

        ordered = [
            event.kind
            for event in events.entries
            if event.kind
            in {
                "decision.recorded",
                "grant.issued",
                "policy.version_changed",
                "grant.ended",
            }
        ]
        assert ordered == [
            "decision.recorded",
            "grant.issued",
            "policy.version_changed",
            "grant.ended",
            "decision.recorded",
        ]
    finally:
        server_connection.close()
        boundary_connection.close()


def test_a_version_change_while_the_grant_is_registered_reaches_the_boundary(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 10: no window registers a grant the boundary cannot be signalled about."""
    policy_path = tmp_path / "policy.toml"
    policy_path.write_bytes(_policy("allow", "initial permission"))
    os.chmod(policy_path, 0o600)
    clock = Clock()
    authority = ProtectedFilePolicyStore(policy_path, clock=clock)
    policy = PolicyService(
        authority,
        (SqlitePolicyProjection(tmp_path / "projection.db"),),
        reload_seconds=1,
        clock=clock,
    )

    class ChangeOnIssue(MemoryEvents):
        """Rewrite and reload the authority in the instant the grant is registered."""

        def record(self, kind, details, *, at=None):  # type: ignore[no-untyped-def]
            super().record(kind, details, at=at)
            if kind == "grant.issued":
                policy_path.write_bytes(_policy("deny", "permission withdrawn"))
                clock.now += timedelta(seconds=1)
                assert policy.reload_if_due()

    events = ChangeOnIssue()
    policy.events = events
    grants = GrantConnections(events=events, clock=clock)
    policy.start(ProtectionExpectation.per_user(os.getuid()))
    routes = DecisionRoutes(
        DecisionService(
            policy,
            authority,
            MemoryDecisionStore(),
            grants,
            settings=GrantSettings(default_lifetime_seconds=30),
            events=events,
            clock=clock,
        )
    )
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", os.getuid(), "build", tuple(os.getgroups()), ("users",)),
    )
    server_connection, boundary_connection = socket.socketpair(socket.AF_UNIX)
    boundary_connection.settimeout(1)
    try:
        answer = routes.ask_decision(question, server_connection, accept=STREAM_MEDIA_TYPE)
        assert isinstance(answer, DecisionAnswer)
        assert answer.grant is not None
        headers, frames = _stream(boundary_connection)
        assert headers.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"Content-Type: text/event-stream" in headers
        # The boundary is told the grant has ended on the very connection that
        # issued it, rather than being left holding a grant the server retired.
        assert [name for name, _ in frames] == ["decision", "grant_ended"]
        assert frames[0][1]["outcome"] == "allow"
        assert frames[1][1]["reason"] == "policy_version_changed"
        jsonschema.validate(frames[1][1], domain_schema("grant-signal"))
        assert answer.connection is not None and not answer.connection.live
    finally:
        server_connection.close()
        boundary_connection.close()


def test_composing_the_service_ends_a_grant_of_another_connection_on_a_change(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 10: the composed package, not its caller, connects version change to grants.

    Two boundaries hold grants on their own connections. Only the second one
    asks again; the first is signalled and ended because composing
    `DecisionService` over a `PolicyService` and a `GrantConnections` is what
    wires the change, exactly as this package's README claims.
    """
    policy_path = tmp_path / "policy.toml"
    policy_path.write_bytes(_policy("allow", "initial permission"))
    os.chmod(policy_path, 0o600)
    clock = Clock()
    events = MemoryEvents()
    authority = ProtectedFilePolicyStore(policy_path, clock=clock)
    policy = PolicyService(
        authority,
        (SqlitePolicyProjection(tmp_path / "projection.db"),),
        events=events,
        reload_seconds=1,
        clock=clock,
    )
    grants = GrantConnections(events=events, clock=clock)
    policy.start(ProtectionExpectation.per_user(os.getuid()))
    # No caller wires the two collaborators together; the service composes them.
    routes = DecisionRoutes(
        DecisionService(
            policy,
            authority,
            MemoryDecisionStore(),
            grants,
            settings=GrantSettings(default_lifetime_seconds=30),
            events=events,
            clock=clock,
        )
    )
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", os.getuid(), "build", tuple(os.getgroups()), ("users",)),
    )
    first_server, first_boundary = socket.socketpair(socket.AF_UNIX)
    second_server, second_boundary = socket.socketpair(socket.AF_UNIX)
    first_boundary.settimeout(1)
    second_boundary.settimeout(1)
    try:
        first = routes.ask_decision(question, first_server, accept=STREAM_MEDIA_TYPE)
        assert _event(first_boundary, first=True)[0] == "decision"
        second = routes.ask_decision(question, second_server, accept=STREAM_MEDIA_TYPE)
        assert _event(second_boundary, first=True)[0] == "decision"
        assert isinstance(first, DecisionAnswer) and isinstance(second, DecisionAnswer)
        assert first.connection is not None and first.connection.live
        assert second.connection is not None and second.connection.live

        policy_path.write_bytes(_policy("deny", "permission withdrawn"))
        clock.now += timedelta(seconds=1)
        assert policy.reload_if_due()

        # The boundary that never asked again is told on its own connection.
        name, ended = _event(first_boundary)
        assert name == "grant_ended"
        assert ended["reason"] == "policy_version_changed"
        jsonschema.validate(ended, domain_schema("grant-signal"))
        assert not first.connection.live
        assert not second.connection.live
        assert grants.connection_count == 0
    finally:
        for peer in (first_server, first_boundary, second_server, second_boundary):
            peer.close()


def test_the_sweep_of_a_later_request_heartbeats_a_live_grant_and_ends_a_spent_one(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 10: the decision path ticks the registry, so a boundary hears and is expired.

    The grant document tells a boundary its `heartbeat_seconds`, and article
    10 lets a boundary "that has not heard from it within the grant's lifetime"
    treat its grants as expired. Nothing ticked the registry, so no heartbeat
    was ever written and no grant ever ended as `expired`: the promise was in
    the document and nowhere in the daemon. Here the tick runs on the decision
    path, and the boundary that is not asking receives both.
    """
    policy_path = tmp_path / "policy.toml"
    policy_path.write_bytes(_policy("allow", "initial permission"))
    os.chmod(policy_path, 0o600)
    clock = Clock()
    events = MemoryEvents()
    authority = ProtectedFilePolicyStore(policy_path, clock=clock)
    policy = PolicyService(
        authority,
        (SqlitePolicyProjection(tmp_path / "projection.db"),),
        events=events,
        reload_seconds=1,
        clock=clock,
    )
    grants = GrantConnections(events=events, clock=clock)
    policy.start(ProtectionExpectation.per_user(os.getuid()))
    routes = DecisionRoutes(
        DecisionService(
            policy,
            authority,
            MemoryDecisionStore(),
            grants,
            settings=GrantSettings(default_lifetime_seconds=30, heartbeat_seconds=5),
            events=events,
            clock=clock,
        )
    )
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", os.getuid(), "build", tuple(os.getgroups()), ("users",)),
    )
    held_server, held_boundary = socket.socketpair(socket.AF_UNIX)
    held_boundary.settimeout(1)
    try:
        held = routes.ask_decision(question, held_server, accept=STREAM_MEDIA_TYPE)
        assert _event(held_boundary, first=True)[0] == "decision"
        assert isinstance(held, DecisionAnswer)
        assert held.grant is not None and held.connection is not None
        assert held.grant.heartbeat_seconds == 5

        # Past the heartbeat, inside the lifetime: another boundary asks, and
        # the sweep that request runs writes the heartbeat on this connection.
        clock.now += timedelta(seconds=6)
        other_server, other_boundary = socket.socketpair(socket.AF_UNIX)
        other_boundary.settimeout(1)
        try:
            routes.ask_decision(question, other_server, accept=STREAM_MEDIA_TYPE)
            assert _event(other_boundary, first=True)[0] == "decision"
            name, beat = _event(held_boundary)
            assert name == "heartbeat"
            assert beat["policy_version"] == policy.current_version
            assert beat["grant_id"] == held.grant.grant_id
            jsonschema.validate(beat, domain_schema("grant-signal"))
            assert held.connection.live

            # Past its lifetime: the next request's sweep ends it as expired,
            # with the reason it happened for, on the connection that holds it.
            clock.now += timedelta(seconds=25)
            third_server, third_boundary = socket.socketpair(socket.AF_UNIX)
            third_boundary.settimeout(1)
            try:
                routes.ask_decision(question, third_server, accept=STREAM_MEDIA_TYPE)
                name, ended = _event(held_boundary)
                assert name == "grant_ended"
                assert ended["reason"] == "expired"
                assert ended["grant_id"] == held.grant.grant_id
                jsonschema.validate(ended, domain_schema("grant-signal"))
                assert not held.connection.live
            finally:
                third_server.close()
                third_boundary.close()
        finally:
            other_server.close()
            other_boundary.close()
    finally:
        held_server.close()
        held_boundary.close()


def test_a_request_this_service_refuses_still_carries_the_change_to_a_held_grant(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 10: the reload is consulted before the answer, refusal included.

    A malformed ask never reaches the policy load that used to be the only
    thing noticing a version change, so a boundary holding a grant under the
    old version learned nothing from it. The consultation is at the top of
    `ask`, before the request can be refused over anything, so the boundary is
    signalled and its next operation misses — and the refused request is still
    refused, on its own connection, as the request it was.
    """
    policy_path = tmp_path / "policy.toml"
    policy_path.write_bytes(_policy("allow", "initial permission"))
    os.chmod(policy_path, 0o600)
    clock = Clock()
    events = MemoryEvents()
    authority = ProtectedFilePolicyStore(policy_path, clock=clock)
    policy = PolicyService(
        authority,
        (SqlitePolicyProjection(tmp_path / "projection.db"),),
        events=events,
        reload_seconds=1,
        clock=clock,
    )
    grants = GrantConnections(events=events, clock=clock)
    policy.start(ProtectionExpectation.per_user(os.getuid()))
    records = MemoryDecisionStore()
    routes = DecisionRoutes(
        DecisionService(
            policy,
            authority,
            records,
            grants,
            settings=GrantSettings(default_lifetime_seconds=30),
            events=events,
            clock=clock,
        )
    )
    principal = Principal("process", os.getuid(), "build", tuple(os.getgroups()), ("users",))
    question = DecisionQuestion(DecisionAsk("mail.send", arguments_digest=DIGEST), principal)
    held_server, held_boundary = socket.socketpair(socket.AF_UNIX)
    held_boundary.settimeout(1)
    try:
        held = routes.ask_decision(question, held_server, accept=STREAM_MEDIA_TYPE)
        assert _event(held_boundary, first=True)[0] == "decision"
        assert isinstance(held, DecisionAnswer)
        assert held.grant is not None and held.connection is not None
        version_granted_under = held.grant.policy_version

        policy_path.write_bytes(_policy("deny", "permission withdrawn"))
        clock.now += timedelta(seconds=1)

        # A malformed ask: refused by the published schema, before any policy
        # is loaded for it. Nothing else asks this daemon anything.
        malformed_server, malformed_boundary = socket.socketpair(socket.AF_UNIX)
        malformed_boundary.settimeout(1)
        try:
            refused = routes.ask_decision(
                DecisionQuestion(
                    DecisionAsk("mail.send", arguments_digest="not-a-digest"), principal
                ),
                malformed_server,
                accept=STREAM_MEDIA_TYPE,
            )
            assert isinstance(refused, DecisionProblem)
            assert refused.problem.code is ProblemCode.REQUEST_MALFORMED
        finally:
            malformed_server.close()
            malformed_boundary.close()

        name, ended = _event(held_boundary)
        assert name == "grant_ended"
        assert ended["reason"] == "policy_version_changed"
        assert ended["policy_version"] != version_granted_under
        jsonschema.validate(ended, domain_schema("grant-signal"))
        assert not held.connection.live

        # The boundary's next operation therefore misses and is decided anew.
        next_server, next_boundary = socket.socketpair(socket.AF_UNIX)
        try:
            answer = routes.ask_decision(question, next_server, accept=STREAM_MEDIA_TYPE)
            _, frames = _stream(next_boundary)
        finally:
            next_server.close()
            next_boundary.close()
        assert isinstance(answer, DecisionAnswer)
        assert answer.decision.outcome is Outcome.DENY
        assert [name for name, _ in frames] == ["decision"]
        assert frames[0][1]["outcome"] == "deny"
    finally:
        held_server.close()
        held_boundary.close()


def test_a_policy_change_reaches_a_held_connection_that_asks_nothing_more(
    composed,  # type: ignore[no-untyped-def]
) -> None:
    """Article 10, over a real daemon: the boundary that asks nothing is still signalled.

    The gap this closes, in the words of the article's own Guard: "a connection
    that asks nothing more does not learn of a policy change until it does".
    Nothing in this case asks the daemon a second thing, and nothing in it
    calls `PolicyService.reload_if_due` — which is what the three cases above
    had to do, and what made them proofs of the domain object rather than of
    the daemon. The boundary holds the connection its grant was delivered on,
    the policy file changes under it, and the daemon consults the reload age on
    the wake it already takes to watch that connection.
    """
    session = composed(rules=[("allow", "example.effect")])
    boundary = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    boundary.settimeout(20)
    boundary.connect(session.daemon.settings.socket_path)
    body = json.dumps({"contract_generation": 1, "capability": "example.effect", "scope": "local"})
    boundary.sendall(
        (
            "POST /decisions HTTP/1.1\r\nHost: sayfirst\r\nAccept: text/event-stream\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
        ).encode()
    )
    try:
        frames = b""
        while b"event: decision" not in frames or not frames.endswith(b"\n\n"):
            chunk = boundary.recv(65536)
            assert chunk, frames
            frames += chunk
        decision = json.loads(frames.split(b"event: decision\ndata: ", 1)[1].split(b"\n\n", 1)[0])
        assert decision["outcome"] == "allow"
        assert decision["grant"] is not None
        granted_under = decision["grant"]["policy_version"]

        # The answer is written before the grant is registered (article 10), so
        # the hold this case is about starts a scheduling later.
        grants = session.services.decisions.grants
        deadline = time.monotonic() + 5.0
        while grants.connection_count != 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert grants.connection_count == 1

        # The policy changes under the live grant. Nothing asks this daemon
        # anything after this line, and nothing in this file schedules a reload.
        session.policy_path.write_text(
            policy_document([("deny", "example.effect")], reason="permission withdrawn"),
            encoding="utf-8",
        )

        ended = frames
        while b"event: grant_ended" not in ended:
            chunk = boundary.recv(65536)
            assert chunk, ended
            ended += chunk
        signal = json.loads(ended.split(b"event: grant_ended\ndata: ", 1)[1].split(b"\n\n")[0])
        assert signal["reason"] == "policy_version_changed"
        assert signal["grant_id"] == decision["grant"]["grant_id"]
        assert signal["policy_version"] != granted_under
        jsonschema.validate(signal, domain_schema("grant-signal"))
    finally:
        boundary.close()

    # The boundary's next operation misses and is decided against the new file.
    status, answered = session.ask()
    assert status == 200, answered
    assert answered["outcome"] == "deny"
    assert answered["policy_version"] != granted_under
