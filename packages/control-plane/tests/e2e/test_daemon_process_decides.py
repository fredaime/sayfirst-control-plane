# SPDX-License-Identifier: Apache-2.0
"""The skeleton walking: a real process, a real socket, a real decision.

Everything else in this suite starts the daemon inside the test process, which
proves the composition but not the command that performs it. This starts the
published command with a configuration file, asks it for a decision over its
own address, and reads the record it wrote — so `assemble` composing at start,
the readiness line, the socket's permissions and the evidence root are all
exercised by the thing an operator actually runs.
"""

from __future__ import annotations

import http.client
import json
import os
import pwd
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[4]
SOURCES = (
    REPOSITORY / "packages" / "contract" / "src",
    REPOSITORY / "packages" / "control-plane" / "src",
)
ME = os.geteuid()
MY_NAME = pwd.getpwuid(ME).pw_name

_POLICY = f"""format = 1

[revision]
reason = "the walking skeleton"

[[rule]]
id = "walk"
capability = "example.effect"
scope = "local"
principals = ["user:{MY_NAME}"]
outcome = "allow"
reason = "the composed daemon decides"
"""


def _ask(socket_path: Path, method: str, target: str, document: object | None = None):  # type: ignore[no-untyped-def]
    connection = http.client.HTTPConnection("sayfirst")
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(10)
    connection.sock.connect(str(socket_path))
    body = None if document is None else json.dumps(document)
    connection.request(
        method,
        target,
        body=body,
        headers={} if body is None else {"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    parsed = json.loads(response.read() or b"{}")
    connection.close()
    return response.status, parsed


@pytest.fixture
def serving_daemon(tmp_path: Path):  # type: ignore[no-untyped-def]
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    policy = run / "policy.toml"
    policy.write_text(_POLICY, encoding="utf-8")
    os.chmod(policy, 0o600)
    socket_path = run / "daemon.sock"
    config = run / "daemon.toml"
    config.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "[socket]\n"
        'mode = "per_user"\n'
        f'path = "{socket_path}"\n'
        "[policy]\n"
        f'path = "{policy}"\n'
        "[evidence]\n"
        f'path = "{run / "evidence"}"\n',
        encoding="utf-8",
    )
    environment = dict(os.environ)
    # The sources this daemon imports come first; whatever the run already put
    # on the path is kept behind them, so a hook the run installed by path — the
    # one `tests/test_no_outbound_network.py` uses to hold article 17 over this
    # subprocess — is inherited rather than dropped.
    environment["PYTHONPATH"] = os.pathsep.join(
        [*(str(item) for item in SOURCES), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "sayfirst_control_plane.cli", "serve", "--config", str(config)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        ready = process.stdout.readline()
        assert ready.startswith("serving "), (
            ready,
            process.stderr.read() if process.stderr else "",
        )
        yield socket_path, run
    finally:
        process.terminate()
        process.wait(timeout=20)


def test_the_published_command_composes_a_daemon_that_decides(serving_daemon) -> None:  # type: ignore[no-untyped-def]
    """Articles 1, 6, 10 and 13: one port, one capability, one decision, one record."""
    socket_path, run = serving_daemon

    status, decision = _ask(
        socket_path,
        "POST",
        "/decisions",
        {"contract_generation": 1, "capability": "example.effect", "scope": "local"},
    )

    assert status == 200, decision
    assert (decision["outcome"], decision["reason"]) == ("allow", "policy_allows")
    assert decision["rule_id"] == "walk"

    chain = run / "evidence" / "local.jsonl"
    deadline = time.monotonic() + 10
    kinds: list[str] = []
    while "effect" not in kinds and time.monotonic() < deadline:
        time.sleep(0.05)
        lines = chain.read_text(encoding="utf-8").splitlines() if chain.exists() else []
        kinds = [json.loads(line)["kind"] for line in lines if line]
    assert kinds[0] == "composition"
    assert "effect" in kinds

    status, page = _ask(
        socket_path, "GET", "/scopes/local/evidence?contract_generation=1&from_sequence=1"
    )
    assert status == 200, page
    assert page["verification"]["condition"] == "intact"
    assert any(
        entry["body"].get("decision_id") == decision["decision_ref"] for entry in page["entries"]
    )
