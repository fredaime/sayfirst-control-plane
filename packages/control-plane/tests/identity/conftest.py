# SPDX-License-Identifier: Apache-2.0
"""A daemon a test can start on a temporary local address and script entirely."""

from __future__ import annotations

import errno
import http.client
import json
import os
import socket
import threading
from pathlib import Path

import pytest
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.domain.evidence import RecordCollector
from sayfirst_control_plane.settings import read_settings
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory, StaticPeerIdentity

# The Linux value (rule L8): every fixture and helper in this tree that
# simulates Linux on `platform="linux"` passes this rather than let
# `Daemon.__init__` read the real host (article 2).
_LINUX_OVERFLOW_IDS = (65534, 65534)


@pytest.fixture(autouse=True)
def _fake_the_next_host_read_a_linux_simulation_would_make(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake `os.getxattr` where the host has none, so a simulation stops at the fixture.

    Every daemon this directory builds simulates Linux with `platform="linux"`,
    so `Daemon.start()` reaches `has_access_acl(path, "linux")`, which reads
    `system.posix_acl_access` through `os.getxattr` — a binding CPython exposes
    on Linux only (`adapters/posix/path_access.py` guards the same absence).
    On a host without it that is an `AttributeError`, not the `OSError`
    `has_access_acl` already handles, so the macOS job would fail one layer
    past the overflow ids. Faked only where the reader is actually absent, so
    a real Linux host keeps reading its own filesystem exactly as before.
    """
    if hasattr(os, "getxattr"):
        return

    def _no_extended_attributes(*_args: object, **_kwargs: object) -> bytes:
        raise OSError(errno.ENODATA, "extended attributes are not supported here")

    monkeypatch.setattr(os, "getxattr", _no_extended_attributes, raising=False)


class Session:
    """A running daemon and a client that speaks to it over its own address."""

    def __init__(self, daemon: Daemon) -> None:
        self.daemon = daemon
        self.evidence: RecordCollector = daemon.evidence  # type: ignore[assignment]
        self._thread = threading.Thread(target=daemon.serve_forever, daemon=True)
        self._thread.start()

    def connect(self) -> http.client.HTTPConnection:
        connection = http.client.HTTPConnection("sayfirst")
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(5)
        connection.sock.connect(self.daemon.settings.socket_path)
        return connection

    def request(
        self,
        method: str,
        target: str,
        document: object | None = None,
        connection: http.client.HTTPConnection | None = None,
    ) -> tuple[int, dict]:
        own = connection is None
        connection = connection or self.connect()
        body = None if document is None else json.dumps(document)
        headers = {} if body is None else {"Content-Type": "application/json"}
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        parsed = json.loads(response.read() or b"{}")
        if own:
            connection.close()
        return response.status, parsed

    def close(self) -> None:
        self.daemon.stop()
        self._thread.join(timeout=5)


@pytest.fixture
def make_session(tmp_path: Path):  # type: ignore[no-untyped-def]
    sessions: list[Session] = []

    def factory(
        *,
        credential: PeerCredential | None = None,
        directory: StaticAccountDirectory | None = None,
        clock: FixedClock | None = None,
        unavailable: bool = False,
        overrides: dict | None = None,
        socket_gid: int | None = None,
        daemon_uid: int | None = None,
    ) -> Session:
        root = tmp_path / f"run{len(sessions)}"
        root.mkdir(mode=0o700)
        document = {
            "socket": {"mode": "per_user", "path": str(root / "daemon.sock")},
            "identity": {},
        }
        for section, members in (overrides or {}).items():
            document.setdefault(section, {}).update(members)
        settings = read_settings(document, platform="linux")
        daemon = Daemon(
            settings,
            platform="linux",
            directory=directory or StaticAccountDirectory(),
            peer_identity=StaticPeerIdentity(credential, unavailable=unavailable),
            clock=clock or FixedClock(),
            evidence=RecordCollector(),
            daemon_uid=os.geteuid() if daemon_uid is None else daemon_uid,
            socket_gid=socket_gid,
            overflow_ids=_LINUX_OVERFLOW_IDS,
        )
        daemon.start()
        session = Session(daemon)
        sessions.append(session)
        return session

    yield factory
    for session in sessions:
        session.close()


@pytest.fixture
def credential() -> PeerCredential:
    return PeerCredential(uid=1000, gid=1000, pid=4242, captured_at="2026-09-04T00:00:00+00:00")
