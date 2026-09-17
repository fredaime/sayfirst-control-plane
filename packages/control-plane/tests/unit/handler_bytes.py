# SPDX-License-Identifier: Apache-2.0
"""The production request handler, driven over a real socket pair.

`tests/e2e/composed_daemon.py` starts the whole daemon on an address of its
own; `tests/identity/conftest.py` starts the socket surface with nothing
composed behind it. Neither reaches the question these cases ask, which is what
the *handler* does with the connection it was given after it has answered on
it: the composed session opens a connection per request and closes it at once,
so a connection the daemon should have kept and a connection it closed look the
same from outside.

So this drives `RequestHandler` itself, on one half of a `socketpair`, with the
identity and the composed services as explicit fixtures. It is a real socket —
the handler's reads and writes, the peer's close, and everything the handler
does with the connection behave as they do in the daemon — and it is not a
daemon: nothing is bound, no privilege is dropped, and no peer credential is
read from the kernel. What it therefore cannot hold is the start sequence, the
admission checks, and anything that depends on a credential the kernel
delivered; `tests/identity` holds those.
"""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Final

from sayfirst_contract.binding.http_unix_socket.routes import STREAM_MEDIA_TYPE
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import Delegation, GroupsStatus, Principal
from sayfirst_control_plane.adapters.api.decision_routes import DecisionRoutes
from sayfirst_control_plane.adapters.http_surface import RequestHandler
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.decisions import DecisionService, GrantSettings
from sayfirst_control_plane.application.evidence_emitter import EvidenceEmitter
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.connection import ConnectionIdentity
from sayfirst_control_plane.domain.policy import parse_policy, policy_version
from sayfirst_control_plane.ports.policy_store import (
    LoadedPolicy,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

_AT = "2026-09-04T00:00:00+00:00"
MAX_LIFETIME_SECONDS = 3600
GRANT_LIFETIME_SECONDS = 30


def policy_bytes(outcome: str = "allow", *, capability: str = "storage.write") -> bytes:
    """A format-1 policy with one rule, and a grant lifetime when it allows."""
    lifetime = f"grant_lifetime_seconds = {GRANT_LIFETIME_SECONDS}\n" if outcome == "allow" else ""
    return (
        "format = 1\n"
        "[revision]\n"
        'reason = "handler-level counterexample"\n'
        "[[rule]]\n"
        'id = "r"\n'
        f'capability = "{capability}"\n'
        'principals = ["user:alice"]\n'
        'reason = "test"\n'
        f'outcome = "{outcome}"\n'
        f"{lifetime}"
    ).encode()


class _Authority:
    """A policy authority whose protection is granted; the checks are held elsewhere."""

    max_lifetime_seconds = MAX_LIFETIME_SECONDS

    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def load(self) -> LoadedPolicy:
        parsed = parse_policy(self.raw, max_lifetime_seconds=self.max_lifetime_seconds)
        return LoadedPolicy(parsed, policy_version(self.raw), datetime.now(UTC), len(self.raw))

    def protection_at_start(self, expectation: ProtectionExpectation) -> ProtectionVerdict:
        return ProtectionVerdict(ProtectionState.PROTECTED)


class _Recording(RequestHandler):
    """The production handler, recording the instance before it serves anything.

    A handler that keeps its connection has not returned from its constructor
    while the case is still looking at it, so the instance cannot be read from
    the constructor's value. Nothing else is changed.
    """

    def __init__(self, *args: Any, seen: list[RequestHandler], **kwargs: Any) -> None:
        seen.append(self)
        super().__init__(*args, **kwargs)


class HandlerHost:
    """A composed decision surface, and the connections handlers ran on."""

    def __init__(
        self,
        raw: bytes | None = None,
        *,
        uid: int = 1001,
        gid: int = 1001,
        max_connections_per_principal: int = 64,
    ) -> None:
        self.authority = _Authority(policy_bytes() if raw is None else raw)
        self.policy = PolicyService(self.authority, (MemoryPolicyProjection(),))
        self.policy.start(ProtectionExpectation.per_user(uid))
        self.grants = GrantConnections(max_connections_per_principal=max_connections_per_principal)
        self.decisions = DecisionService(
            self.policy,
            self.authority,
            MemoryDecisionStore(),
            self.grants,
            settings=GrantSettings(
                default_lifetime_seconds=GRANT_LIFETIME_SECONDS,
                max_lifetime_seconds=MAX_LIFETIME_SECONDS,
            ),
        )
        self.store = InMemoryEvidenceStore()
        self.emitter = EvidenceEmitter(self.store)
        self.uid = uid
        self.gid = gid
        self.closed: list[str] = []
        self._connections = 0
        services = SimpleNamespace(
            decisions=self.decisions,
            decision_routes=DecisionRoutes(self.decisions),
            emitter=self.emitter,
            evidence_routes=None,
        )
        self.daemon = SimpleNamespace(
            services=services,
            settings=SimpleNamespace(resolution_timeout_seconds=5, group_lifetime_seconds=300),
            on_connection=lambda identity: None,
            on_close=lambda identity: self.closed.append(identity.connection_id),
            refresh_if_due=lambda identity: None,
            touch=lambda identity, scope: None,
            read_delegation=lambda document: Delegation.from_request_member(
                document.get("delegation")
            ),
        )

    def identity(self) -> ConnectionIdentity:
        self._connections += 1
        identity = ConnectionIdentity(
            connection_id=f"connection-{self._connections}",
            accepted_at=_AT,
            socket_path="/no/address/is/bound/here",
            mode="per_user",
            peer=PeerCredential(self.uid, self.gid, 0, _AT),
        )
        identity.bind(
            Principal(
                kind="user",
                uid=self.uid,
                gid=self.gid,
                name="alice",
                groups=("alice",),
                groups_status=GroupsStatus.RESOLVED,
                unnamed_group_ids=(),
                established_by="peer_credential",
                established_at=_AT,
            ),
            datetime.now(UTC),
            300,
        )
        return identity

    def close(self) -> None:
        self.grants.shutdown()
        self.emitter.close()


def request_bytes(
    *,
    stream: bool = False,
    generation: object = 1,
    capability: str = "storage.write",
    members: dict[str, object] | None = None,
) -> bytes:
    """One `POST /decisions` request, framed the way a conforming client frames it."""
    document: dict[str, object] = {"capability": capability, "scope": "local"}
    if generation is not _ABSENT:
        document["contract_generation"] = generation
    document.update(members or {})
    body = json.dumps(document).encode()
    lines = [
        b"POST /decisions HTTP/1.1",
        b"Host: sayfirst",
        b"Content-Type: application/json",
        b"Content-Length: " + str(len(body)).encode(),
    ]
    if stream:
        lines.append(b"Accept: " + STREAM_MEDIA_TYPE.encode())
    return b"\r\n".join((*lines, b"", body))


class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - a marker, never rendered
        return "<absent>"


_ABSENT = _Absent()
ABSENT = _ABSENT


class Run:
    """One handler run: the bytes it wrote, and the handler that wrote them."""

    def __init__(self, seen: list[RequestHandler], peer: socket.socket) -> None:
        self._seen = seen
        self.peer = peer
        self.head = b""
        self.body = b""

    @property
    def handler(self) -> RequestHandler:
        assert self._seen, "the handler was not constructed"
        return self._seen[0]

    def frame(self) -> dict[str, object]:
        """The first event of a stream answer."""
        name, _, payload = self.body.partition(b"\ndata: ")
        assert name == b"event: decision", (self.head, self.body)
        return json.loads(payload.split(b"\n\n", 1)[0])

    def document(self) -> dict[str, object]:
        return json.loads(self.body)

    def status(self) -> int:
        return int(self.head.split(b" ", 2)[1])


#: The header every document answer of this binding frames its body with.
LENGTH_HEADER: Final = b"Content-Length: "


def declared_length(head: bytes) -> int:
    """The body length this answer's head declares.

    The one place this parse is written. It stood in three places at once — in
    this module, and in the two cases that had to read a whole document once the
    daemon stopped closing its connections — and a framing change spread over
    three edits is a framing change one of which gets missed.

    An answer that declares no length is a failure of the case rather than of
    the parse, so it is an assertion that shows what arrived: the `IndexError`
    a split used to raise says nothing about the answer it could not read.
    """
    assert LENGTH_HEADER in head, f"the answer declares no length: {head!r}"
    return int(head.split(LENGTH_HEADER, 1)[1].split(b"\r\n", 1)[0])


def read_one_document(peer: socket.socket) -> bytes:
    """One whole document answer, head and body, off a connection that stays open.

    Read to the length the head declares rather than to the end of the
    connection: only a stream ends its connection now, so the end of the
    connection is no longer where a document answer stops. An end of file
    before the body is complete is what a caller reads as « could not ask »,
    and it is named here rather than returned as a short answer.
    """
    data = b""
    while True:
        head, separator, body = data.partition(b"\r\n\r\n")
        if separator:
            length = declared_length(head)
            if len(body) >= length:
                return head + separator + body[:length]
        part = peer.recv(65536)
        assert part, f"the connection ended instead of answering: {data!r}"
        data += part


def _read_answer(peer: socket.socket, *, until_frame: bool) -> tuple[bytes, bytes]:
    """Head and body, read to the first stream frame or to the end of a document."""
    data = b""
    while True:
        if b"\r\n\r\n" in data:
            head, body = data.split(b"\r\n\r\n", 1)
            if until_frame and b"\n\n" in body:
                return head, body
            if not until_frame and LENGTH_HEADER in head:
                length = declared_length(head)
                if len(body) >= length:
                    return head, body[:length]
        part = peer.recv(65536)
        if not part:
            head, _, body = data.partition(b"\r\n\r\n")
            return head, body
        data += part


@contextmanager
def running(
    host: HandlerHost, raw: bytes, *, until_frame: bool = False, timeout: float = 10.0
) -> Iterator[Run]:
    """Run one request through the handler, on a thread, and hold the peer open.

    The handler runs where the daemon runs it — on a thread of its own with the
    connection to itself — because that is the only place a connection it
    decides to keep can be observed still open. Leaving the context closes the
    peer end, which is what a boundary going away does.
    """
    server, peer = socket.socketpair(socket.AF_UNIX)
    peer.settimeout(timeout)
    identity = host.identity()
    seen: list[RequestHandler] = []
    run = Run(seen, peer)

    def serve() -> None:
        try:
            _Recording(
                server, "", SimpleNamespace(daemon=host.daemon), identity=identity, seen=seen
            )
        finally:
            # What `socketserver` does the moment a handler returns
            # (`shutdown_request`). A harness that left the socket open would
            # make every connection look kept and the case unobservable.
            with suppress(OSError):
                server.shutdown(socket.SHUT_RDWR)
            server.close()

    peer.sendall(raw)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        run.head, run.body = _read_answer(peer, until_frame=until_frame)
        yield run
    finally:
        peer.close()
        thread.join(timeout=timeout)
        assert not thread.is_alive(), "the handler did not finish after the peer closed"
        server.close()


def answer(host: HandlerHost, raw: bytes, *, until_frame: bool = False) -> Run:
    """One request, run to its end with the connection closed behind it."""
    with running(host, raw, until_frame=until_frame) as run:
        pass
    return run


def answer_inline(host: HandlerHost, raw: bytes) -> Run:
    """One request whose answer holds no connection, run without a thread.

    Only a grant makes the handler hold a connection open with nothing left to
    read on it, so an answer that mints none returns from the handler once the
    peer has said there is no second request — which the write-side shutdown
    below is. Running it inline is what makes driving a generated corpus of
    thousands of requests through the whole surface cost seconds rather than
    minutes.
    """
    server, peer = socket.socketpair(socket.AF_UNIX)
    seen: list[RequestHandler] = []
    run = Run(seen, peer)
    try:
        peer.sendall(raw)
        # One request and no more, said the way a client says it: the read side
        # of the handler reaches the end of the stream instead of waiting out
        # the keep-alive bound for a second request nobody is going to send.
        peer.shutdown(socket.SHUT_WR)
        try:
            _Recording(
                server, "", SimpleNamespace(daemon=host.daemon), identity=host.identity(), seen=seen
            )
        finally:
            with suppress(OSError):
                server.shutdown(socket.SHUT_RDWR)
            server.close()
        peer.settimeout(5.0)
        data = b""
        while True:
            part = peer.recv(65536)
            if not part:
                break
            data += part
        run.head, _, run.body = data.partition(b"\r\n\r\n")
    finally:
        peer.close()
    return run
