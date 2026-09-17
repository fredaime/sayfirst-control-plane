# SPDX-License-Identifier: Apache-2.0
"""A client that HOLDS a decision reads the grant and the signals after it.

The daemon already serves a grant, and this client already asks for it:
`DECISION_ACCEPT` names the stream media type first, and the answer's first
frame carries the grant document, which `Decision.from_document` keeps in
`extra`. What was missing is the only thing that makes a grant usable —
**keeping the connection**. `_request` closes in its `finally`, and article 10
binds a grant to the channel that delivered it, so every grant this client has
ever received was ended by the client itself, in the same call that obtained it.

`_first_frame` says as much in its own docstring: "a replay observes the answer;
it does not hold what the connection would go on carrying". That is the right
behaviour for a conformance replay and the wrong one for a holder, so the holder
gets its own method rather than a flag on that one.

The server here is a scripted socket, not the composed daemon. What is under
test is the client's reading, and a script lets the frames be exactly the bytes
`decision_routes.py` writes — including the `event:` line before each `data:`
line, and the `\\n\\n` terminator rather than `\\r\\n\\r\\n`.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.decisions import DecisionAsk, Outcome
from sayfirst_contract.grants import GrantEndReason, GrantSignal, GrantSignalKind

DIGEST = "sha256:" + "1" * 64
VERSION = "sha256:" + "a" * 64
LATER = "sha256:" + "b" * 64

GRANT = {
    "grant_id": "g-1",
    "decision_ref": "dec-1",
    "policy_version": VERSION,
    "issued_at": "2026-09-14T12:00:00+00:00",
    "lifetime_seconds": 300,
    "expires_at": "2026-09-14T12:05:00+00:00",
    "heartbeat_seconds": 10,
    "conditions": {
        "scope": "local",
        "capability": "example.effect",
        "principal_reference": "user:build",
        "arguments_digest": DIGEST,
    },
}


def _decision(*, outcome: str = "allow", grant: dict[str, object] | None = None) -> dict:
    document: dict[str, object] = {
        "contract_generation": 1,
        "authority": "control-plane",
        "decision_ref": "dec-1",
        "scope": "local",
        "capability": "example.effect",
        "outcome": outcome,
        "reason": "policy_allows" if outcome == "allow" else "policy_denies",
        "policy_version": VERSION,
        "approval_ref": None,
        "decided_at": "2026-09-14T12:00:00+00:00",
        "correlation": None,
    }
    if grant is not None:
        document["grant"] = grant
    return document


def _signal(kind: str, at: str, reason: str | None = None) -> dict:
    document: dict[str, object] = {
        "contract_generation": 1,
        "kind": kind,
        "grant_id": "g-1",
        "policy_version": VERSION if reason is None else LATER,
        "at": at,
    }
    if reason is not None:
        document["reason"] = reason
    return document


def _frame(name: str, document: dict) -> bytes:
    """Exactly what `_StreamWriter.event` puts on the wire."""
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return b"event: " + name.encode() + b"\ndata: " + payload + b"\n\n"


def _read_request(connection: socket.socket) -> bytes:
    """Read one request WHOLE: the headers to the blank line, then the declared body.

    One `recv` is not a request. `http.client` puts the headers and the body on
    the wire in two sends, so a read that takes whatever has arrived can stop
    between them — and then the read below that is meant to hold this socket
    open is satisfied by a byte of the body instead of by the client's close.
    This side then leaves its scope and closes with request bytes still unread
    in its receive queue, which resets the connection on this family, under a
    client that was still reading its frames. That is where the
    `ConnectionResetError` in `signals()` came from, roughly once in four runs
    of this module: proven deterministically 2026-09-15 by bounding this read
    to the header bytes alone, which reproduces it every time.
    """
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = connection.recv(65536)
        if not chunk:
            return buffer
        buffer += chunk
    head, body = buffer.split(b"\r\n\r\n", 1)
    declared = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            declared = int(value.strip())
    while len(body) < declared:
        chunk = connection.recv(declared - len(body))
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def _await_the_clients_close(connection: socket.socket) -> None:
    """Block until the client closes, which is the only thing this can now read.

    The request was drained, so no leftover request byte can satisfy this read
    and end it early; this side's write half is already shut down, so `b""`
    here is the client's own close. A client that wrote something unexpected
    would keep this waiting rather than let a close race the reader, which is
    the invariant that matters: this socket is never torn down under a client
    that has frames left to read.
    """
    while connection.recv(65536):
        pass


def _read_the_head_and_leave_the_body(connection: socket.socket) -> None:
    """Consume the request's headers and leave its body where it arrived.

    The counterpart to `_read_request`, and the mechanism of `ending="reset"`:
    on this socket family, a side that closes with bytes still unread in its
    receive queue leaves the peer's next read with `ECONNRESET`, while the bytes
    it already wrote are delivered first. So the frames below arrive, and the
    read after them is a reset rather than an end of file — which is what a
    holder sees when a daemon dies mid-stream.

    The headers are peeked before they are consumed so that exactly they are
    taken; the single peek after them waits for the body to arrive without
    taking it, which is what makes the close a reset every time rather than one
    run in four.
    """
    head = b""
    while b"\r\n\r\n" not in head:
        peeked = connection.recv(65536, socket.MSG_PEEK)
        if not peeked:
            return
        head = peeked
    boundary = head.index(b"\r\n\r\n") + 4
    taken = 0
    while taken < boundary:
        chunk = connection.recv(boundary - taken)
        if not chunk:
            return
        taken += len(chunk)
    declared = 0
    for line in head[:boundary].split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            declared = int(value.strip())
    if declared:
        connection.recv(1, socket.MSG_PEEK)


#: How the scripted far end leaves the stream. `close` is an orderly end of
#: file the client reads as the end of the grant; `reset` is a peer that is
#: gone, which article 10 makes the same fact and which used to reach the
#: holder as an exception it had to classify for itself.
ENDINGS: tuple[str, ...] = ("close", "reset")


def _serve(path: Path, frames: list[bytes], *, ending: str = "close") -> threading.Thread:
    """Script one answer on one socket, ending it the way a real peer ends it.

    `close` shuts the write side down and then waits for the client's own
    close, which is what the daemon does and what keeps this socket from being
    torn down under a client that still has frames to read. `reset` leaves the
    request unread and closes, which is what a peer that went away looks like,
    and is the input `GrantChannel.signals()` must read as the end of the
    stream (article 10).

    Both endings have a case; the parameter is asserted against the two so that
    a typo is a failure and not a silently different double.
    """
    assert ending in ENDINGS, ending
    listening = threading.Event()

    def run() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            listening.set()
            connection, _ = server.accept()
            with connection:
                if ending == "reset":
                    _read_the_head_and_leave_the_body(connection)
                else:
                    _read_request(connection)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/event-stream\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"Connection: close\r\n\r\n"
                )
                for frame in frames:
                    connection.sendall(frame)
                if ending == "close":
                    connection.shutdown(socket.SHUT_WR)
                    _await_the_clients_close(connection)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    # Wait for the listener rather than for a duration: a sleep here would be a
    # race that passes on this machine and fails on a slower one.
    assert listening.wait(timeout=5.0), "the scripted listener never bound its socket"
    return thread


@pytest.fixture
def socket_path(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "sayfirst.sock"
    yield path
    path.unlink(missing_ok=True)


def _client(path: Path) -> SocketClient:
    return SocketClient(socket_path=path, expected_uid=os.getuid(), timeout=5.0)


def _ask() -> DecisionAsk:
    return DecisionAsk(capability="example.effect", scope="local", arguments_digest=DIGEST)


def test_a_held_decision_carries_its_grant(socket_path: Path) -> None:
    _serve(socket_path, [_frame("decision", _decision(grant=GRANT))])
    result, channel = _client(socket_path).hold_decision(_ask())
    assert result.is_ok
    assert result.value.outcome is Outcome.ALLOW
    assert channel is not None
    assert channel.grant is not None
    assert channel.grant.grant_id == "g-1"
    assert channel.grant.conditions.arguments_digest == DIGEST
    channel.close()


def test_the_signals_after_the_answer_are_readable(socket_path: Path) -> None:
    """The whole point: `ask_decision` cannot see these, because it has closed."""
    _serve(
        socket_path,
        [
            _frame("decision", _decision(grant=GRANT)),
            _frame("heartbeat", _signal("heartbeat", "2026-09-14T12:00:10+00:00")),
            _frame(
                "grant_ended",
                _signal("grant_ended", "2026-09-14T12:00:20+00:00", "policy_version_changed"),
            ),
        ],
    )
    _, channel = _client(socket_path).hold_decision(_ask())
    assert channel is not None
    signals = list(channel.signals())
    assert [signal.kind for signal in signals] == [
        GrantSignalKind.HEARTBEAT,
        GrantSignalKind.GRANT_ENDED,
    ]
    assert signals[0].reason is None
    assert signals[-1].reason is GrantEndReason.POLICY_VERSION_CHANGED
    assert signals[-1].policy_version == LATER
    channel.close()


def test_an_answer_that_minted_no_grant_still_reads(socket_path: Path) -> None:
    _serve(socket_path, [_frame("decision", _decision(outcome="deny"))])
    result, channel = _client(socket_path).hold_decision(_ask())
    assert result.is_ok
    assert result.value.outcome is Outcome.DENY
    assert channel is not None
    assert channel.grant is None
    assert list(channel.signals()) == []
    channel.close()


def test_a_peer_that_reset_the_stream_is_the_end_of_the_stream(socket_path: Path) -> None:
    """Article 10: a peer that reset is gone, and a grant ends when its channel does.

    A `ConnectionResetError` out of `readline` is not a signal this generation
    cannot read; it is no signal at all. Raising it out of `signals()` made a
    holder's iteration a failure it had to classify for itself, and made this
    module's own double flake roughly one run in four before the double was
    fixed.

    On a platform whose close of this socket family is always orderly, the
    stream reaches its end by the other route and the assertion below is the
    same one — this case can be vacuous there, never false.
    """
    _serve(socket_path, [_frame("decision", _decision(grant=GRANT))], ending="reset")
    _, channel = _client(socket_path).hold_decision(_ask())
    assert channel is not None
    assert list(channel.signals()) == []
    channel.close()


def test_the_channel_closes_without_having_read_its_signals(socket_path: Path) -> None:
    """Closing is how a holder gives up a grant, so it must not require draining."""
    _serve(socket_path, [_frame("decision", _decision(grant=GRANT))])
    _, channel = _client(socket_path).hold_decision(_ask())
    assert channel is not None
    channel.close()
    channel.close()  # idempotent: a holder may close a channel it already gave up


def test_a_signal_document_round_trips(socket_path: Path) -> None:
    """`GrantSignal` could be written and not read; the pair is now symmetric.

    That asymmetry is the shape of the gap: a contract that can serialise a
    signal but not parse one was written for a side that only ever sends them.
    """
    original = GrantSignal(
        kind=GrantSignalKind.GRANT_ENDED,
        grant_id="g-1",
        policy_version=VERSION,
        at="2026-09-14T12:00:20+00:00",
        reason=GrantEndReason.EXPIRED,
        contract_generation=1,
    )
    assert GrantSignal.from_document(original.to_document()) == original


def test_reading_a_signal_of_an_unknown_kind_is_refused_not_guessed(socket_path: Path) -> None:
    """Article 3: an unreadable input never takes the more permissive reading."""
    with pytest.raises(ValueError):
        GrantSignal.from_document(
            {
                "contract_generation": 1,
                "kind": "invented_kind",
                "grant_id": "g-1",
                "policy_version": VERSION,
                "at": "2026-09-14T12:00:20+00:00",
            }
        )


def test_the_existing_ask_still_closes_its_connection(socket_path: Path) -> None:
    """The regression that matters: `ask_decision` is unchanged.

    It answers from the same first frame and gives the connection up, so it
    yields no channel and no way to reach a signal. If this ever returns
    something holdable, `hold_decision` has leaked into it.
    """
    _serve(socket_path, [_frame("decision", _decision(grant=GRANT))])
    result = _client(socket_path).ask_decision(_ask())
    assert result.is_ok
    assert result.value.outcome is Outcome.ALLOW
    # The grant document still arrives in `extra` — it always did — and is
    # unusable, because the channel it is bound to is gone.
    assert "grant" in result.value.extra
