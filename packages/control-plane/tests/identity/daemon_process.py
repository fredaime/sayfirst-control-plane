# SPDX-License-Identifier: Apache-2.0
"""Starting the daemon in its own process, for the guards that need a kernel."""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[4]
SOURCES = (
    REPOSITORY / "packages" / "contract" / "src",
    REPOSITORY / "packages" / "control-plane" / "src",
)
SERVER_PACKAGE = REPOSITORY / "packages" / "control-plane" / "src" / "sayfirst_control_plane"


def _environment(home: Path | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    # As in `e2e/test_daemon_process_decides.py`: the sources come first, and
    # whatever the run already put on the path is kept behind them so that a
    # hook installed by path reaches this daemon too (article 17).
    environment["PYTHONPATH"] = os.pathsep.join(
        [*(str(item) for item in SOURCES), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    environment.pop("XDG_RUNTIME_DIR", None)
    if home is not None:
        environment["HOME"] = str(home)
    return environment


def write_config(root: Path, **socket_members: object) -> Path:
    """A configuration file; a member given as `None` is left out of it.

    `path=None` is how a guard asks for the documented default address rather
    than one the test picked (rule L2).
    """
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    members = {"mode": "per_user", "path": str(root / "daemon.sock"), **socket_members}
    body = (
        "[socket]\n"
        + "\n".join(f'{key} = "{value}"' for key, value in members.items() if value is not None)
        + "\n"
    )
    config = root / "daemon.toml"
    config.write_text("# SPDX-License-Identifier: Apache-2.0\n" + body, encoding="utf-8")
    return config


def start_daemon(
    config: Path, *, umask: int | None = None, home: Path | None = None
) -> subprocess.Popen[str]:
    def preexec() -> None:  # pragma: no cover - runs in the child
        if umask is not None:
            os.umask(umask)

    return subprocess.Popen(
        [sys.executable, "-m", "sayfirst_control_plane.cli", "serve", "--config", str(config)],
        env=_environment(home),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=preexec if umask is not None else None,
    )


@contextmanager
def serving(
    config: Path, *, umask: int | None = None, home: Path | None = None
) -> Iterator[subprocess.Popen[str]]:
    process = start_daemon(config, umask=umask, home=home)
    try:
        assert process.stdout is not None
        ready = process.stdout.readline()
        assert ready.startswith("serving "), (
            ready,
            process.stderr.read() if process.stderr else "",
        )
        yield process
    finally:
        process.terminate()
        process.wait(timeout=10)


def refuse(config: Path, *, home: Path | None = None) -> tuple[int, str]:
    process = start_daemon(config, home=home)
    _, errors = process.communicate(timeout=20)
    return process.returncode, errors.strip()


def ask(socket_path: Path, target: str = "/whoami") -> tuple[int, dict]:
    connection = http.client.HTTPConnection("sayfirst")
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(10)
    connection.sock.connect(str(socket_path))
    connection.request("GET", target)
    response = connection.getresponse()
    document = json.loads(response.read() or b"{}")
    connection.close()
    return response.status, document
