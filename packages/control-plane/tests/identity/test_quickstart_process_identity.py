# SPDX-License-Identifier: Apache-2.0
"""The quickstart proves the process it started on both platforms the identity job runs on.

`down` signals a process only when the instant the system reports for its id equals the
one recorded at its start, on the same boot. That proof used to be read from `/proc`
alone, so on macOS no instant was ever recorded: `down` could never stop the daemon `up`
had started, and a second `up` wrote over its record. macOS keeps a start time and a
boot-session identifier of its own, and the launcher reads them through `sysctl`.

These run on Linux and macOS alike — nothing here is gated to one — so the macOS runner
of the identity job is what proves the Darwin half, against real processes and a real
daemon.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

import pytest
from sayfirst_control_plane.settings import read_settings
from sayfirst_quickstart import launcher as quickstart
from sayfirst_quickstart.launcher import Started
from sayfirst_testing.privileges import requires_unprivileged


def _sleeping() -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def test_a_living_process_has_a_start_instant_scoped_to_this_boot() -> None:
    child = _sleeping()
    try:
        token = quickstart.process_began(child.pid)
        assert token is not None, "this platform keeps no start instant the launcher can read"
        assert token == quickstart.process_began(child.pid), "the instant moved during a life"
        boot = quickstart._boot_identity()
        assert boot is not None, "this platform names no boot the launcher can read"
        assert token.startswith(f"{boot}:")
        assert quickstart._identity(Started(child.pid, token, "unused")) == "ours"
    finally:
        child.kill()
        child.wait(timeout=10)


def test_a_process_that_has_ended_is_gone() -> None:
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait(timeout=10)
    assert quickstart._identity(Started(child.pid, "any-boot:1", "unused")) == "gone"


def test_an_unreaped_process_is_gone_although_the_kernel_still_lists_it() -> None:
    pid = os.fork()
    if pid == 0:  # the child: exit at once, and stay unreaped until the parent waits
        os._exit(0)
    try:
        deadline = time.monotonic() + 5
        state = quickstart._process_state(pid)
        while (state is None or state[0] != "Z") and time.monotonic() < deadline:
            time.sleep(0.01)
            state = quickstart._process_state(pid)
        assert state is not None and state[0] == "Z", state
        assert quickstart._identity(Started(pid, quickstart.process_began(pid), "unused")) == "gone"
    finally:
        os.waitpid(pid, 0)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Path:  # type: ignore[misc]
    """A home directory whose default socket address fits the platform's limit.

    macOS allows a hundred and four bytes for a socket's address, and pytest's own
    temporary directories there are long enough to spend all of them; `/tmp` does not.
    """
    directory = Path(tempfile.mkdtemp(prefix="q", dir="/tmp"))
    monkeypatch.setenv("HOME", str(directory))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    try:
        yield directory
    finally:
        record = quickstart.read_record(quickstart.layout(str(directory)))
        if record is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(record.pid, signal.SIGTERM)
        shutil.rmtree(directory, ignore_errors=True)


@requires_unprivileged()
def test_down_stops_the_daemon_up_started_on_this_platform(home: Path) -> None:
    def read(path: Path):  # type: ignore[no-untyped-def]
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        return read_settings(document, platform=sys.platform, environ={}, home=str(home))

    out, err = io.StringIO(), io.StringIO()
    assert quickstart.up(home=str(home), read_settings_from=read, out=out, err=err) == 0, (
        err.getvalue()
    )
    pid = int(next(line for line in out.getvalue().splitlines() if line.startswith("pid: "))[5:])
    record = quickstart.read_record(quickstart.layout(str(home)))
    assert record is not None and record.pid == pid
    assert record.began is not None, "no start instant was recorded, so down could never prove it"

    out, err = io.StringIO(), io.StringIO()
    assert quickstart.down(home=str(home), read_settings_from=read, out=out, err=err) == 0, (
        err.getvalue()
    )
    assert out.getvalue().splitlines()[0] == f"SayFirst Control Plane stopped (pid {pid})"
    assert quickstart.read_record(quickstart.layout(str(home))) is None
