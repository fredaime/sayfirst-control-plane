# SPDX-License-Identifier: Apache-2.0
"""A daemon composed from every block, on a temporary local address.

`tests/identity/conftest.py` starts the socket surface of block 2.2 with
nothing composed behind it. This one starts the same surface over the policy
authority, the evidence store and the plugin composition the other blocks
publish, because the seam between them is what these cases are about.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.bootstrap import ComposedServices, compose
from sayfirst_control_plane.domain.evidence import RecordCollector
from sayfirst_control_plane.settings import read_settings
from sayfirst_testing.doubles import StaticAccountDirectory, StaticPeerIdentity

ME = os.geteuid()
MY_GID = os.getegid()
_AT = "2026-09-04T00:00:00+00:00"


def policy_document(rules: Sequence[tuple[str, str]], *, reason: str = "composition") -> str:
    """A format-1 policy file naming one rule per (outcome, capability) pair."""
    lines = ["format = 1", "[revision]", f'reason = "{reason}"']
    for index, (outcome, capability) in enumerate(rules):
        lines.extend(
            (
                "[[rule]]",
                f'id = "rule-{index}"',
                f'capability = "{capability}"',
                'scope = "local"',
                'principals = ["user:alice"]',
                f'outcome = "{outcome}"',
                f'reason = "the {outcome} rule"',
            )
        )
    return "\n".join(lines) + "\n"


class ComposedSession:
    """A running composed daemon and a client that speaks to its address."""

    def __init__(self, daemon: Daemon, services: ComposedServices, policy_path: Path) -> None:
        self.daemon = daemon
        self.services = services
        self.policy_path = policy_path
        self._thread = threading.Thread(target=daemon.serve_forever, daemon=True)
        self._thread.start()

    def connect(self) -> http.client.HTTPConnection:
        connection = http.client.HTTPConnection("sayfirst")
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(10)
        connection.sock.connect(self.daemon.settings.socket_path)
        return connection

    def request(
        self,
        method: str,
        target: str,
        document: object | None = None,
        connection: http.client.HTTPConnection | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        own = connection is None
        connection = connection or self.connect()
        body = None if document is None else json.dumps(document)
        sent = dict(headers or {})
        if body is not None:
            sent.setdefault("Content-Type", "application/json")
        connection.request(method, target, body=body, headers=sent)
        response = connection.getresponse()
        parsed = json.loads(response.read() or b"{}")
        if own:
            connection.close()
        return response.status, parsed

    def ask(self, capability: str = "example.effect", **members: object) -> tuple[int, dict]:
        return self.request(
            "POST",
            "/decisions",
            {"contract_generation": 1, "capability": capability, "scope": "local", **members},
        )

    def flush(self) -> None:
        assert self.services.emitter.flush("local", timeout=10)

    @property
    def root(self) -> Path:
        return self.policy_path.parent

    def close(self) -> None:
        self.daemon.stop()
        self._thread.join(timeout=10)


@contextmanager
def make_composed_daemon(tmp_path: Path) -> Iterator[object]:
    """A factory for composed daemons, each closed when the caller is done."""
    sessions: list[ComposedSession] = []

    def factory(
        rules: Sequence[tuple[str, str]] = (("allow", "example.effect"),),
        *,
        remove_policy: bool = False,
        plugins: dict | None = None,
        root: Path | None = None,
        rewrite_policy: bool = True,
    ) -> ComposedSession:
        """A composed daemon, on a fresh root or — for a restart — on the root a stopped one used.

        `root` names an existing root to compose over again, the way a restart
        does: the decision file, the archive and the chain are the ones the
        previous daemon left. `rewrite_policy=False` leaves the policy file as
        the case wrote it between the two lives.
        """
        if root is None:
            root = tmp_path / f"run{len(sessions)}"
            root.mkdir(mode=0o700)
        policy_path = root / "policy.toml"
        if rewrite_policy or not policy_path.exists():
            policy_path.write_text(policy_document(rules), encoding="utf-8")
            os.chmod(policy_path, 0o600)
        document: dict[str, object] = {
            "socket": {"mode": "per_user", "path": str(root / "daemon.sock")},
            "identity": {},
            "policy": {"path": str(policy_path)},
            "evidence": {"path": str(root / "evidence")},
        }
        if plugins is not None:
            document["plugins"] = plugins
        settings = read_settings(document, platform="linux")
        services = compose(settings, daemon_uid=ME)
        assert services is not None
        if remove_policy:
            policy_path.unlink()
        daemon = Daemon(
            settings,
            platform="linux",
            directory=StaticAccountDirectory(
                accounts={ME: ("alice", MY_GID)},
                memberships={"alice": (MY_GID,)},
                group_names={MY_GID: "alice"},
            ),
            peer_identity=StaticPeerIdentity(
                PeerCredential(uid=ME, gid=MY_GID, pid=os.getpid(), captured_at=_AT)
            ),
            evidence=RecordCollector(),
            daemon_uid=ME,
            services=services,
        )
        daemon.overflow_uid, daemon.overflow_gid = 65534, 65534
        daemon.start()
        session = ComposedSession(daemon, services, policy_path)
        sessions.append(session)
        return session

    try:
        yield factory
    finally:
        for session in sessions:
            session.close()
