# SPDX-License-Identifier: Apache-2.0
"""A grant's issuing connection stays live, and a closed one releases what it held.

Article 10 makes the issuing connection part of what a grant *is*: "the control
plane signals a change of version to every connected boundary over the
connection that issued the grant, and a boundary that has lost that connection
... treats its grants as expired — a hit is honoured only while the version is
current on a live connection."

Two facts contradicted that, and each is a defect on its own.

The first: after any adapter-written answer the handler set `close_connection`
unconditionally, so the daemon closed the very connection it had just made a
grant's channel. A grant issued that way is dead on arrival — the boundary
cannot be signalled on it, and the published `grant_ended` reason
`connection_lost` had no code anywhere that could produce it.

That unconditional close reached the DOCUMENT answers too, and cost every
caller a connect and a re-verification for its second read while rule C4
forbade the client re-opening silently. Only a stream ends its connection, and
both halves of that rule are held below: a document answer leaves a connection
the next request is answered on, and a stream still ends the one it was
delivered on.

The second: closing that connection released nothing. The `GrantConnection`
stayed in the registry, holding one of the sixty-four slots the default
per-principal bound gives. Sixty-four ordinary asks therefore exhausted the
bound and the sixty-fifth was answered `allow` with no grant at all — a
correct answer, at a cost the boundary pays on every operation, arrived at by
leaking rather than by any rule anybody wrote.

The reproduction is `handler_demos.py` from the first outside read, turned into
a case here: the same production handler, the same ordinary asks, and the two
numbers it printed — `close_connection: true` on the issuing connection, and
`registry connections: 64` after sixty-five requests.
"""

from __future__ import annotations

import json
import socket
import time

import pytest
from handler_bytes import (
    GRANT_LIFETIME_SECONDS,
    HandlerHost,
    answer,
    read_one_document,
    request_bytes,
    running,
)
from sayfirst_contract.artifacts import load_json
from sayfirst_control_plane.application.events import MemoryEvents


@pytest.fixture
def host():  # type: ignore[no-untyped-def]
    made = HandlerHost()
    try:
        yield made
    finally:
        made.close()


def _registered(host, count: int, *, within: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    """Wait for the registry to hold `count` connections.

    The grant is delivered before it is registered — deliberately, so that a
    version change can never end a grant on a channel that does not yet exist
    (`application/decisions.py`) — so reading the frame can beat the entry into
    the registry by a scheduling quantum. That order is the property; this only
    declines to race it.
    """
    deadline = time.monotonic() + within
    while host.grants.connection_count != count and time.monotonic() < deadline:
        time.sleep(0.005)
    assert host.grants.connection_count == count


def _next_event(peer: socket.socket) -> tuple[str, dict]:
    """The next server-sent event on a stream, read to the end of its frame."""
    data = b""
    while b"\n\n" not in data:
        part = peer.recv(65536)
        assert part, f"the stream ended instead of carrying an event: {data!r}"
        data += part
    name, payload = data.split(b"\n\n", 1)[0].split(b"\ndata: ", 1)
    return name.removeprefix(b"event: ").decode(), json.loads(payload)


def test_the_connection_that_issued_a_grant_is_not_closed_under_it(host) -> None:  # type: ignore[no-untyped-def]
    """Article 10: the channel a grant is signalled on is the connection it came on."""
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        assert run.frame()["grant"] is not None, run.frame()
        _registered(host, 1)

        # The daemon has answered and has not let go: a boundary reading this
        # stream is waiting for the next signal, not at the end of it.
        run.peer.settimeout(0.5)
        with pytest.raises(TimeoutError):
            run.peer.recv(65536)
        assert host.grants.connection_count == 1


def test_a_version_change_reaches_the_boundary_over_the_issuing_connection(host) -> None:  # type: ignore[no-untyped-def]
    """Article 10, the whole sentence: signalled over the connection that issued it."""
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        grant = run.frame()["grant"]
        assert grant is not None
        _registered(host, 1)

        host.grants.policy_version_changed("sha256:" + "b" * 64)

        name, signal = _next_event(run.peer)
        assert (name, signal["reason"]) == ("grant_ended", "policy_version_changed")
        assert signal["grant_id"] == grant["grant_id"]
        # And then the connection goes: the grant it existed for has ended.
        assert run.peer.recv(65536) == b""
        assert host.grants.connection_count == 0


def test_a_closed_connection_releases_the_grant_it_carried(host) -> None:  # type: ignore[no-untyped-def]
    """Article 10: a boundary that has gone away holds nothing here either."""
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        assert run.frame()["grant"] is not None
        _registered(host, 1)
    # Leaving the context closed the peer, which is a boundary going away.
    assert host.grants.connection_count == 0


def test_sixty_five_ordinary_asks_do_not_exhaust_the_per_principal_bound(host) -> None:  # type: ignore[no-untyped-def]
    """Article 10: grant reuse survives ordinary use, because nothing accumulates."""
    granted = 0
    for _ in range(65):
        run = answer(host, request_bytes(stream=True), until_frame=True)
        frame = run.frame()
        assert frame["outcome"] == "allow", frame
        granted += frame["grant"] is not None
    assert granted == 65, f"only {granted} of 65 ordinary asks were given a grant"
    assert host.grants.connection_count == 0


def test_the_bound_still_binds_when_the_connections_are_really_held() -> None:
    """The registry is not made unbounded by releasing: a held slot is still a slot."""
    bounded = HandlerHost(max_connections_per_principal=2)
    try:
        with running(bounded, request_bytes(stream=True), until_frame=True) as first:
            assert first.frame()["grant"] is not None
            with running(bounded, request_bytes(stream=True), until_frame=True) as second:
                assert second.frame()["grant"] is not None
                _registered(bounded, 2)
                third = answer(bounded, request_bytes(stream=True), until_frame=True)
                assert third.frame()["outcome"] == "allow"
                assert third.frame()["grant"] is None, "the bound stopped binding"
    finally:
        bounded.close()


def _answered(peer: socket.socket, raw: bytes) -> dict:
    """Write one more request on a connection already used, and read its document."""
    peer.sendall(raw)
    return json.loads(read_one_document(peer).partition(b"\r\n\r\n")[2])


def _unanswered(peer: socket.socket, raw: bytes) -> bool:
    """Whether asking again on this connection gets no answer at all.

    Two ways one fact reaches a caller, and which of them it is, is a race this
    has no business pinning: the daemon may still hold the read side, in which
    case the request goes out and the read after it is the end of the
    connection; or it may already be gone, in which case the write itself
    fails. Both are the bare end of file the project's transport reports as
    `unreachable`, and neither is an answer.
    """
    try:
        peer.sendall(raw)
    except OSError:
        return True
    return peer.recv(65536) == b""


def _get(target: str) -> bytes:
    """One read request, framed the way a conforming client frames it."""
    return f"GET {target} HTTP/1.1\r\nHost: sayfirst\r\n\r\n".encode()


def test_a_document_answer_leaves_the_connection_open_for_the_next_read(host) -> None:  # type: ignore[no-untyped-def]
    """Rule C4 and article 10: only a stream ends its connection.

    The handler closed after ANY answer an adapter wrote, reads included, so a
    caller that read a decision and then its policy status paid a connect and a
    re-verification for the second — and rule C4 forbids a client re-opening
    silently, so the cost was visible in every caller. Three requests on one
    connection here: the ask that took the decision, the read that reads it
    back, and the policy status beside it.
    """
    with running(host, request_bytes()) as run:
        decision = run.document()
        assert decision["outcome"] == "allow", decision
        read_back = _answered(
            run.peer,
            _get(f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local"),
        )
        assert read_back["decision_ref"] == decision["decision_ref"], read_back
        status = _answered(run.peer, _get("/policy/status?contract_generation=1"))
        assert status["policy_version"] == decision["policy_version"], status


def test_a_decision_stream_still_ends_the_connection_it_was_delivered_on() -> None:
    """Article 10 binds the grant to the channel; the adapter shut the write side.

    The other half of the rule the case above holds, and it is held the same
    way — by asking again on the same connection and reading what comes back,
    never by reading `close_connection`. A repair that kept every connection
    open would break the grant's own end, and the two together pin the rule
    from both sides.

    A deny is the shortest stream this daemon serves: the request selected the
    stream, so the answer is a frame on it, and the adapter shuts the write
    side down at once because a stream is the one answer that ends its
    connection. What a caller that asks again then reads is the bare end of
    file its transport reports as `unreachable`, which rule C4 makes the
    caller's own `reconnect()` answer for.

    Not vacuous: the case above puts two further requests on a document
    answer's connection and is answered on both, so `_unanswered` is a
    distinction this surface really draws and not a fact about socket pairs.
    """
    from handler_bytes import policy_bytes

    denying = HandlerHost(raw=policy_bytes("deny"))
    try:
        with running(denying, request_bytes(stream=True), until_frame=True) as run:
            assert run.frame()["outcome"] == "deny", run.frame()
            assert run.frame()["grant"] is None, run.frame()
            # Said on the wire as well as done to the socket: the stream is the
            # one answer of this binding that publishes the close.
            assert b"Connection: close" in run.head, run.head
            assert _unanswered(run.peer, _get("/policy/status?contract_generation=1")), (
                "a stream's connection answered a second request"
            )
        assert denying.grants.connection_count == 0
    finally:
        denying.close()


def test_an_answer_with_no_grant_closes_its_connection_as_before() -> None:
    """Nothing but a grant holds a connection: a deny is answered and the socket closes."""
    from handler_bytes import policy_bytes

    denying = HandlerHost(raw=policy_bytes("deny"))
    try:
        run = answer(denying, request_bytes(stream=True), until_frame=True)
        assert run.frame()["outcome"] == "deny"
        assert run.frame()["grant"] is None
        assert run.handler.close_connection is True
        assert denying.grants.connection_count == 0
    finally:
        denying.close()


def test_a_grant_that_ends_lets_its_connection_go(host) -> None:  # type: ignore[no-untyped-def]
    """The hold is the grant's, not the handler's: the daemon stopping ends both."""
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        assert run.frame()["grant"] is not None
        _registered(host, 1)
        host.grants.shutdown()
        deadline = time.monotonic() + GRANT_LIFETIME_SECONDS
        name, signal = _next_event(run.peer)
        assert (name, signal["reason"]) == ("grant_ended", "daemon_stopping")
        assert run.peer.recv(65536) == b""
        assert time.monotonic() < deadline, "the connection outlived its grant"
        assert host.grants.connection_count == 0


def test_a_peer_that_writes_on_a_held_stream_is_not_recorded_as_one_that_went_away(host) -> None:  # type: ignore[no-untyped-def]
    """Article 2: the record names what happened, and here the daemon closed it.

    The stream answer published `Connection: close` and the binding defines no
    second operation on it, so anything the peer writes ends the hold — that is
    the design. What the registry recorded was `connection_lost`, which is the
    boundary going away, and the peer had not gone anywhere: it was still there
    and read a reset. `select` says only that a read would not block, and both
    a peer that closed and a peer that wrote make it say so; one peek tells the
    two apart, and the two get two records.
    """
    events = MemoryEvents()
    host.grants.events = events
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        assert run.frame()["grant"] is not None
        _registered(host, 1)
        run.peer.sendall(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
        _registered(host, 0)

    ended = [entry for entry in events.entries if entry.kind == "grant.ended"]
    assert [entry.details["reason"] for entry in ended] == ["peer_wrote_on_the_stream"], ended


def test_a_peer_that_closes_a_held_stream_is_still_a_connection_lost(host) -> None:  # type: ignore[no-untyped-def]
    """Anti-vacuity: the reason that was always right is still the one recorded."""
    events = MemoryEvents()
    host.grants.events = events
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        assert run.frame()["grant"] is not None
        _registered(host, 1)
    _registered(host, 0)

    ended = [entry for entry in events.entries if entry.kind == "grant.ended"]
    assert [entry.details["reason"] for entry in ended] == ["connection_lost"], ended


def test_a_peer_that_half_closes_a_held_stream_is_a_boundary_that_went_away(host) -> None:  # type: ignore[no-untyped-def]
    """Article 2 and article 13: the record is true because the binding says so.

    `shutdown(SHUT_WR)` and `close` are one event on the daemon's read side —
    end of file, and no peek can tell them apart, because there is nothing left
    to peek at. So the record cannot be made finer by the mechanism, and the
    binding is what makes it true: `x-stream-hold` on the operation that
    publishes this stream says a boundary holding it keeps its write side open
    for as long as it holds the grant. A boundary that half-closes has said, in
    the only word this transport has for it, that it is gone, and
    `connection_lost` is what happened.
    """
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    hold = binding["paths"]["/decisions"]["post"]["x-stream-hold"]
    assert hold["half-close"] == "forbidden"
    assert hold["reason-at-end-of-file"] == "connection_lost"

    events = MemoryEvents()
    host.grants.events = events
    with running(host, request_bytes(stream=True), until_frame=True) as run:
        assert run.frame()["grant"] is not None
        _registered(host, 1)
        run.peer.shutdown(socket.SHUT_WR)
        # Still reading, and there is nothing more to read: the hold is over.
        _registered(host, 0)
        assert run.peer.recv(65536) == b""

    ended = [entry for entry in events.entries if entry.kind == "grant.ended"]
    assert [entry.details["reason"] for entry in ended] == ["connection_lost"], ended
