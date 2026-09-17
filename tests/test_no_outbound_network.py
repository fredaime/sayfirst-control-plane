# SPDX-License-Identifier: Apache-2.0
"""Article 17: the integration suite makes no outbound connection, and is watched.

One rule per file (`CONTRIBUTING.md`, article 16). The rule here is the first
of the two tests article 17's Guard names: the integration suite runs with
outbound network disabled and every attempted connection is counted through a
hook below the socket, so an attempt fails this test whether or not the code
that made it swallowed the error.

Two properties distinguish this from a test that watches a listener and finds
nothing. The first is that the hook records *before* it refuses, so a
`try: ... except OSError: pass` around a connection is counted, not hidden; the
positive control below plants exactly that and asserts the count. The second is
that the hook is installed by `site` in every process that inherits the path,
so the daemons the suite starts as subprocesses are subject to the same rule as
the process that started them — asserted here by requiring more than one
process to have installed it, which fails if a later change stops passing the
path down.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
HOOK = REPOSITORY / "tests" / "outbound_audit"

#: The suite article 17 names. These trees stand a real daemon up — in this
#: process and in subprocesses — and speak to it over its socket; a unit test
#: that never opens one cannot hold this rule.
INTEGRATION_TREES = (
    "packages/control-plane/tests/integration",
    "packages/control-plane/tests/e2e",
    "packages/control-plane/tests/identity",
    "packages/contract/tests/identity",
)


def _short_root(leaf: str) -> Path:
    """A protected, short-enough base for a nested run's socket addresses.

    The nested run may not share the outer run's `--basetemp`: pytest clears
    the directory it is given, and clearing it under a run that is using it is
    a failure with nothing to do with article 17 (`conftest.py`).
    """
    root = Path(tempfile.gettempdir()) / leaf
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(mode=0o700)
    return root


def _environment(log: Path) -> dict[str, str]:
    inherited = os.environ.get("PYTHONPATH")
    path = os.pathsep.join([str(HOOK), *([inherited] if inherited else [])])
    return {**os.environ, "PYTHONPATH": path, "SAYFIRST_OUTBOUND_LOG": str(log)}


def _lines(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_the_integration_suite_attempts_no_outbound_connection() -> None:
    """Article 17: nothing under the integration trees reaches for the network."""
    root = _short_root(f"sf-o{os.getpid()}")
    log = root / "outbound.log"
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--basetemp",
                str(root / "b"),
                *INTEGRATION_TREES,
            ],
            cwd=REPOSITORY,
            env=_environment(log),
            capture_output=True,
            text=True,
        )
    finally:
        recorded = _lines(log)
        shutil.rmtree(root, ignore_errors=True)
    installed = [line for line in recorded if line.startswith("hook-installed")]
    attempts = [line for line in recorded if not line.startswith("hook-installed")]
    assert attempts == [], attempts
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    # Anti-vacuity, twice over: a run that never installed the hook proves
    # nothing, and a hook the daemon subprocesses do not inherit proves less
    # than this file claims.
    assert installed, result.stdout[-2000:] + result.stderr[-2000:]
    assert len({line.rsplit("pid=", 1)[1] for line in installed}) > 1, installed


def test_a_swallowed_outbound_attempt_is_still_counted() -> None:
    """Article 17: the count survives the code that hid the error from itself."""
    root = _short_root(f"sf-p{os.getpid()}")
    log = root / "outbound.log"
    program = (
        "import socket\n"
        "try:\n"
        "    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(('127.0.0.1', 9))\n"
        "except BaseException:\n"
        "    pass\n"
        "print('the caller noticed nothing')\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", program],
            cwd=REPOSITORY,
            env=_environment(log),
            capture_output=True,
            text=True,
        )
        recorded = _lines(log)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert result.returncode == 0, result.stderr
    assert "the caller noticed nothing" in result.stdout
    attempts = [line for line in recorded if not line.startswith("hook-installed")]
    assert len(attempts) == 1, recorded
    assert "socket.connect" in attempts[0] and "AF_INET" in attempts[0]
