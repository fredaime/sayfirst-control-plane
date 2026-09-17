# SPDX-License-Identifier: Apache-2.0
"""Article 6, rules L6 and C5: without an adapter there is no identity to offer."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.transport.peer import PeerIdentityUnsupported, select_peer_identity
from sayfirst_contract.transport.socket_client import (
    SocketClientProblem,
    SocketProfile,
    connect,
)
from sayfirst_control_plane import cli
from sayfirst_control_plane.settings import EX_CONFIG


def test_an_unsupported_platform_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Article 3: fail-closed on every side of the boundary at once.

    The selector has no generic adapter, the daemon refuses to start rather
    than run "without identity", and the client refuses to connect rather than
    fall back to a connection it cannot verify.
    """
    for platform in ("win32", "freebsd14", "sunos5", ""):
        with pytest.raises(PeerIdentityUnsupported):
            select_peer_identity(platform)

    config = tmp_path / "daemon.toml"
    config.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        f'[socket]\nmode = "per_user"\npath = "{tmp_path / "daemon.sock"}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(cli.sys, "platform", "win32")
    assert cli.main(["serve", "--config", str(config)]) == EX_CONFIG
    assert EX_CONFIG == 78
    assert capsys.readouterr().err.startswith("peer_identity_unsupported")
    assert not (tmp_path / "daemon.sock").exists(), "the daemon bound before it refused"

    opened: list[object] = []
    with pytest.raises(SocketClientProblem) as refusal:
        connect(
            SocketProfile(str(tmp_path / "daemon.sock")),
            platform="win32",
            socket_factory=lambda: opened.append(None),  # type: ignore[arg-type,return-value]
        )
    assert refusal.value.problem.code is ProblemCode.PEER_IDENTITY_UNSUPPORTED
    assert refusal.value.classification == "could_not_ask"
    assert opened == [], "the client opened something on a platform it cannot verify"


def test_the_command_reports_the_same_refusal_to_its_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 1: it is a could-not-ask, so no effect starts."""
    from sayfirst_contract.transport import cli as client_cli

    monkeypatch.setattr("sys.platform", "win32")
    out, err = io.StringIO(), io.StringIO()
    code = client_cli.main(
        ["whoami", "--socket", str(tmp_path / "daemon.sock"), "--json"], out=out, err=err
    )
    assert code == client_cli.EXIT_COULD_NOT_ASK
    assert "peer_identity_unsupported" in err.getvalue()
