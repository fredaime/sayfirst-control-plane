# SPDX-License-Identifier: Apache-2.0
"""The published replay command, against eleven daemons started by the published command.

The in-process harness beside this module composes each daemon and moves its clock;
a deployment has neither. This is the run a deployment makes: every server-bound
scenario has a `serve` process of its own, arranged as the contract's README says,
the policy change is the deployment's command, the expiry is a real wait, and the
whole run must be proven through `sayfirst-conformance replay` — and through the
operator surface's spelling of the same replay.
"""

from __future__ import annotations

import io
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from _daemon import _launch
from sayfirst_contract.cli import main as operator_main
from sayfirst_contract.golden import Regime, load_scenarios
from scenario_daemon import MY_NAME, REVIEW_DEADLINE_SECONDS, scenario_policy

#: The published reload age of a policy file is two seconds; wait past it.
RELOAD_SECONDS = 3
#: The wait a `review_expire` daemon is given, and the replayer waits longer than it.
EXPIRY_SECONDS = 2

HOOK = (
    """\
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text(
    'format = 1\\n[revision]\\nreason = "changed by the deployment"\\n'
    '[[rule]]\\nid = "changed"\\ncapability = "example.effect"\\nscope = "local"\\n'
    f'principals = ["user:{sys.argv[2]}"]\\noutcome = "deny"\\nreason = "changed"\\n'
)
"""
    + f"import time; time.sleep({RELOAD_SECONDS})\n"
)


def _arrange(root: Path, index: int, name: str) -> tuple[Path, Path, subprocess.Popen]:
    scenario = load_scenarios()[name]
    run = root / f"d{index}"
    run.mkdir(mode=0o700)
    policy = run / "policy.toml"
    text = scenario_policy(
        scenario.given.policy or {},
        arrangement=scenario.given.applying_outcomes,
        arranged_capability=scenario.ask.capability,
    )
    if name == "review_expire":
        text = text.replace(
            f"review_deadline_seconds = {REVIEW_DEADLINE_SECONDS}".encode(),
            f"review_deadline_seconds = {EXPIRY_SECONDS}".encode(),
        )
    if name == "policy_unavailable_is_could_not_ask":
        text = scenario_policy({scenario.ask.capability: Regime.AUTO})
    policy.write_bytes(text)
    os.chmod(policy, 0o600)
    config = run / "daemon.toml"
    config.write_text(
        f'[socket]\nmode = "per_user"\npath = "{run / "daemon.sock"}"\n'
        f'[policy]\npath = "{policy}"\n[evidence]\npath = "{run / "evidence"}"\n'
    )
    os.chmod(config, 0o600)
    return run / "daemon.sock", policy, _launch(config)


@pytest.fixture
def deployment():
    root = Path(tempfile.mkdtemp(prefix="sfr", dir="/tmp"))
    os.chmod(root, 0o700)
    processes: list[subprocess.Popen] = []
    try:
        names = [name for name, s in load_scenarios().items() if s.binds_server()]
        sockets: dict[str, Path] = {}
        policies: dict[str, Path] = {}
        for index, name in enumerate(names):
            socket_path, policy, process = _arrange(root, index, name)
            processes.append(process)
            sockets[name], policies[name] = socket_path, policy
        # The README's arrangement: the file is broken AFTER the start.
        policies["policy_unavailable_is_could_not_ask"].unlink()
        time.sleep(RELOAD_SECONDS)
        hook = root / "change_policy.py"
        hook.write_text(HOOK)
        command = " ".join(
            shlex.quote(part)
            for part in (
                sys.executable,
                str(hook),
                str(policies["grant_miss_after_policy_version_change"]),
                MY_NAME,
            )
        )
        yield sockets, command
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=30)
        shutil.rmtree(root, ignore_errors=True)


def _arguments(sockets: dict[str, Path], command: str) -> list[str]:
    arguments = ["replay"]
    for name, path in sockets.items():
        arguments += ["--socket", f"{name}={path}"]
    return [
        *arguments,
        "--change-policy-command",
        command,
        "--deadline-wait-seconds",
        str(EXPIRY_SECONDS + 2),
    ]


def test_the_published_command_proves_every_server_scenario(deployment) -> None:
    sockets, command = deployment
    finished = subprocess.run(
        [sys.executable, "-m", "sayfirst_conformance.main", *_arguments(sockets, command)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert finished.returncode == 0, finished.stdout + finished.stderr
    assert finished.stdout.splitlines()[-1].startswith(f"run\tproven\t{len(sockets)} scenarios"), (
        finished.stdout
    )


def test_the_operator_surface_proves_the_same_run(deployment) -> None:
    sockets, command = deployment
    output = io.StringIO()
    code = operator_main(["conformance", *_arguments(sockets, command)], stdout=output)
    assert code == 0, output.getvalue()
    assert output.getvalue().splitlines()[-1] == f"run\tproven\t{len(sockets)} scenarios proven", (
        output.getvalue()
    )
