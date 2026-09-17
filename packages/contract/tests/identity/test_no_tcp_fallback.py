# SPDX-License-Identifier: Apache-2.0
"""Article 6: no TCP anywhere, not even as the fallback of a dropped connection."""

from __future__ import annotations

import ast
import http.client
import os
import socket
from pathlib import Path

import pytest
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.transport import socket_client
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.transport.socket_client import (
    SocketClientProblem,
    SocketProfile,
    connect,
)
from sayfirst_testing.doubles import StaticPeerIdentity
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms

_AT = "2026-09-04T00:00:00+00:00"
TRANSPORT = Path(socket_client.__file__).parent


def _credential(uid: int) -> PeerCredential:
    return PeerCredential(uid=uid, gid=0, pid=1, captured_at=_AT)


def test_a_dropped_connection_never_reaches_for_a_network(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule C4: a reconnection is a local one or it is a refusal."""
    reached: list[object] = []
    monkeypatch.setattr(
        http.client.socket,
        "create_connection",
        lambda *arguments, **keywords: reached.append(arguments)
        or (_ for _ in ()).throw(AssertionError("the client opened a network connection")),
    )
    opened: list[object] = []

    def factory() -> object:
        stream = _ScriptedStream()
        opened.append(stream)
        return stream

    connection = connect(
        SocketProfile("/run/d.sock"),
        peer_identity=StaticPeerIdentity(_credential(os.geteuid())),
        socket_factory=factory,  # type: ignore[arg-type]
    )
    # The far end closed the keep-alive; the stock HTTP class would now dial
    # its host and port over TCP.
    connection.http.sock = None
    with pytest.raises(SocketClientProblem) as refusal:
        connection.read_whoami()
    assert refusal.value.problem.code is ProblemCode.UNREACHABLE
    assert reached == []
    assert len(opened) == 1


def test_a_reconnection_is_verified_again(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule C4: there is no "verified once per profile"."""
    adapter = StaticPeerIdentity(_credential(os.geteuid()))
    streams: list[_ScriptedStream] = []

    def factory() -> object:
        stream = _ScriptedStream()
        streams.append(stream)
        return stream

    profile = SocketProfile("/run/d.sock")
    connection = connect(profile, peer_identity=adapter, socket_factory=factory)  # type: ignore[arg-type]
    assert adapter.calls == 1
    connection.http.sock = None
    connection.reconnect()
    assert adapter.calls == 2
    assert len(streams) == 2
    assert streams[1].calls[0] == "connect"

    # An impostor arriving at the address between two requests is refused.
    adapter.credential = _credential(os.geteuid() + 1)
    connection.http.sock = None
    with pytest.raises(SocketClientProblem) as refusal:
        connection.reconnect()
    assert refusal.value.problem.code is ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL
    assert streams[2].calls[-1] == "close"
    assert bytes(streams[2].written) == b""


def test_the_transport_constructs_no_socket_of_another_family() -> None:
    """Article 6, rule L3 on the client side: one family, and no other."""
    constructions = 0
    for source in TRANSPORT.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            if name.startswith("socket.") and name != "socket.socket":
                raise AssertionError(f"{source.name}: {name}")
            if name == "socket.socket":
                arguments = [ast.unparse(item) for item in node.args]
                arguments += [ast.unparse(item.value) for item in node.keywords]
                assert "socket.AF_UNIX" in arguments, f"{source.name}: {ast.unparse(node)}"
                constructions += 1
    assert constructions >= 1


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_connection_class_has_no_network_connect(tmp_path: Path) -> None:
    """Article 6: the HTTP wrapper cannot dial a host and a port, by construction."""
    address = tmp_path / "daemon.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with listener:
        listener.bind(str(address))
        listener.listen(1)
        connection = connect(SocketProfile(str(address)))
        try:
            wrapper = type(connection.http)
            assert wrapper is not http.client.HTTPConnection
            assert wrapper.auto_open == 0
            assert wrapper.connect is not http.client.HTTPConnection.connect
            assert connection.http.host == socket_client.PLACEHOLDER_HOST
        finally:
            connection.close()
    address.unlink(missing_ok=True)


class _ScriptedStream:
    """A local stream that records what was asked of it and answers nothing."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.written = bytearray()

    def connect(self, address: str) -> None:
        self.calls.append("connect")

    def getsockopt(self, *_: object) -> bytes:
        self.calls.append("getsockopt")
        return b""

    def sendall(self, data: bytes) -> None:
        self.calls.append("sendall")
        self.written.extend(data)

    send = sendall

    def close(self) -> None:
        self.calls.append("close")

    def makefile(self, *_: object, **__: object):  # type: ignore[no-untyped-def]
        import io

        return io.BytesIO(b"")

    def settimeout(self, value: object) -> None:
        pass
