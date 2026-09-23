# SPDX-License-Identifier: Apache-2.0
"""`sayfirst-daemon up --quickstart` and `down`, against the real daemon they start.

Nothing here is a double. The command is run as a process, under a home
directory of its own with no runtime directory, so the address it serves is the
fallback of the binding's default rule; what it started is then asked a question
over that socket through the published transport, because « ready » is a claim
about a daemon that answers and the only evidence for it is an answer
(article 2).

The cases that matter most are the ones about what the command must NOT do:
write over a file a person edited, call a daemon ready that refused to start,
or send a signal to a process it cannot prove it started.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from _daemon import SOURCES
from sayfirst_contract.client import Answered
from sayfirst_contract.transport.socket_client import SocketProfile, connect
from sayfirst_quickstart import launcher as quickstart

#: How long a process has to be gone, or an address to be answered at.
PATIENCE_SECONDS = 15


class _Home:
    """One account's home directory, and the commands run under it."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.names = quickstart.layout(str(home))
        self.address = home / ".sayfirst" / "run" / "daemon.sock"
        self.environment = {
            **{name: value for name, value in os.environ.items() if name != "XDG_RUNTIME_DIR"},
            "HOME": str(home),
            "PYTHONPATH": os.pathsep.join(
                [*(str(item) for item in SOURCES), *filter(None, [os.environ.get("PYTHONPATH")])]
            ),
        }

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "sayfirst_quickstart.command", *arguments],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def answering_pid(self) -> int | None:
        """The process the kernel says is listening, asked through the transport."""
        try:
            connection = connect(SocketProfile(str(self.address)))
        except Exception:
            return None
        with closing(connection):
            assert isinstance(connection.read_status(), Answered)
            return connection.server_credential.pid

    def recorded_pid(self) -> int | None:
        try:
            return int(json.loads(self.names.record.read_text(encoding="utf-8"))["pid"])
        except (OSError, ValueError, KeyError):
            return None


def _gone(pid: int) -> bool:
    deadline = time.monotonic() + PATIENCE_SECONDS
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def home(tmp_path: Path) -> Iterator[_Home]:
    directory = tmp_path / "home"
    directory.mkdir(mode=0o700)
    account = _Home(directory)
    started: set[int] = set()
    account.started = started  # type: ignore[attr-defined]
    try:
        yield account
    finally:
        for pid in {*started, *filter(None, [account.recorded_pid(), account.answering_pid()])}:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            _gone(pid)


def _pid_said(result: subprocess.CompletedProcess[str]) -> int:
    line = next(line for line in result.stdout.splitlines() if line.startswith("pid: "))
    return int(line.removeprefix("pid: "))


def test_up_says_ready_only_about_a_daemon_that_answers(home: _Home) -> None:
    result = home.run("up", "--quickstart")
    assert result.returncode == 0, result.stderr
    said = result.stdout.splitlines()
    assert said[0] == "SayFirst Control Plane ready"
    assert "mode: per_user" in said
    assert f"socket: {home.address}" in said
    assert f"policy: {home.names.policy}" in said
    assert f"evidence: {home.names.evidence}" in said
    assert "stop: sayfirst-daemon down" in said
    # The grade is the daemon's own sentence about itself, not this command's:
    # a per-user caller can write the store it is asking about, and the
    # quickstart does not get to say anything better than that (article 7).
    assert any(line.startswith("integrity grade: observability (") for line in said), said
    assert home.answering_pid() == _pid_said(result) == home.recorded_pid()


def test_up_writes_private_files_a_person_can_read(home: _Home) -> None:
    assert home.run("up", "--quickstart").returncode == 0
    assert home.names.policy.read_text(encoding="utf-8").startswith("# SayFirst quickstart policy")
    for path, mode in (
        (home.names.root, 0o700),
        (home.names.evidence, 0o700),
        (home.names.policy, 0o600),
        (home.names.configuration, 0o600),
        (home.names.log, 0o600),
        (home.names.record, 0o600),
        (home.names.lock, 0o600),
    ):
        assert path.lstat().st_mode & 0o777 == mode, path
    # …and nothing else. This is the whole of what the launcher persists, held
    # here because it is deliberately outside the server's information contract
    # (`sayfirst_quickstart` says why): a file added later fails this line. The
    # lock orders two lifecycle commands and is empty; it is the launcher's, not
    # the daemon's information.
    assert sorted(entry.name for entry in home.names.root.iterdir()) == [
        "daemon.lock",
        "daemon.log",
        "daemon.run.json",
        "daemon.toml",
        "evidence",
        "policy.toml",
    ]


def test_a_second_up_starts_nothing_and_writes_over_nothing(home: _Home) -> None:
    first = home.run("up", "--quickstart")
    assert first.returncode == 0, first.stderr
    edited = home.names.policy.read_text(encoding="utf-8") + "\n# a note of my own\n"
    home.names.policy.write_text(edited, encoding="utf-8")
    second = home.run("up", "--quickstart")
    assert second.returncode == 0, second.stderr
    assert second.stdout.splitlines()[0] == "SayFirst Control Plane already running"
    assert _pid_said(second) == _pid_said(first) == home.answering_pid()
    assert home.names.policy.read_text(encoding="utf-8") == edited


def test_down_stops_what_up_started_and_leaves_the_address_empty(home: _Home) -> None:
    started = _pid_said(home.run("up", "--quickstart"))
    result = home.run("down")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[0] == f"SayFirst Control Plane stopped (pid {started})"
    assert _gone(started)
    assert not home.address.exists()
    assert not home.names.record.exists()
    # The files a person may have edited, and the evidence, outlive the daemon.
    assert home.names.policy.is_file() and home.names.evidence.is_dir()
    again = home.run("down")
    assert again.returncode == 0
    assert again.stdout.splitlines()[0] == "SayFirst Control Plane not running"


def test_up_after_a_crash_clears_the_stale_address_and_the_stale_record(home: _Home) -> None:
    crashed = _pid_said(home.run("up", "--quickstart"))
    os.kill(crashed, signal.SIGKILL)
    assert _gone(crashed)
    assert home.address.exists(), "a killed daemon leaves its address behind"
    assert home.recorded_pid() == crashed
    result = home.run("up", "--quickstart")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[0] == "SayFirst Control Plane ready"
    assert home.answering_pid() == _pid_said(result) != crashed


def test_down_never_signals_a_process_it_cannot_prove_it_started(home: _Home) -> None:
    """A record naming a live process that is not the daemon: the number was reused."""
    assert home.run("up", "--quickstart").returncode == 0
    assert home.run("down").returncode == 0
    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        home.names.record.write_text(
            json.dumps({"pid": bystander.pid, "began": "1", "socket": str(home.address)}),
            encoding="utf-8",
        )
        result = home.run("down")
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines()[0] == "SayFirst Control Plane not running"
        assert "stale" in result.stdout
        assert bystander.poll() is None, "down signalled a process it had not started"
        assert not home.names.record.exists()
    finally:
        bystander.kill()
        bystander.wait(timeout=20)


def test_up_does_not_start_a_second_daemon_over_one_it_started_that_is_not_answering(
    home: _Home,
) -> None:
    """The recorded process is alive — the system says it began when the record says —
    and nothing answers at its address. Starting another would write over the only
    record of the first, and `down` could then never stop it."""
    assert home.run("up", "--quickstart").returncode == 0
    assert home.run("down").returncode == 0
    silent = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        record = {
            "pid": silent.pid,
            "began": quickstart.process_began(silent.pid),
            "socket": str(home.address),
        }
        if record["began"] is None:
            pytest.skip("this platform keeps no record of when a process began")
        home.names.record.write_text(json.dumps(record), encoding="utf-8")
        result = home.run("up", "--quickstart")
        assert result.returncode == 1, result.stdout
        assert f"pid {silent.pid}" in result.stderr and "not answering" in result.stderr
        assert "ready" not in result.stdout
        assert json.loads(home.names.record.read_text(encoding="utf-8")) == record
        assert home.answering_pid() is None
    finally:
        silent.kill()
        silent.wait(timeout=20)


def test_a_daemon_somebody_else_started_is_neither_adopted_nor_stopped(home: _Home) -> None:
    assert home.run("up", "--quickstart").returncode == 0
    assert home.run("down").returncode == 0
    foreign = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "sayfirst_control_plane.cli",
            "serve",
            "--config",
            str(home.names.configuration),
        ],
        env=home.environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    home.started.add(foreign.pid)  # type: ignore[attr-defined]
    try:
        assert foreign.stdout is not None
        assert foreign.stdout.readline().startswith("serving ")
        up = home.run("up", "--quickstart")
        assert up.returncode == 78, up.stdout
        assert "socket_in_use" in up.stderr
        assert not home.names.record.exists()
        down = home.run("down")
        assert down.returncode == 1
        assert "did not start" in down.stderr
        assert home.answering_pid() == foreign.pid
    finally:
        foreign.terminate()
        foreign.wait(timeout=20)


def test_a_policy_the_daemon_refuses_is_said_in_its_words_and_left_as_it_is(home: _Home) -> None:
    assert home.run("up", "--quickstart").returncode == 0
    assert home.run("down").returncode == 0
    home.names.policy.write_text("format = 1\nthis is not a policy\n", encoding="utf-8")
    result = home.run("up", "--quickstart")
    assert result.returncode == 78, result.stdout
    assert "policy_unavailable_at_start" in result.stderr
    assert "ready" not in result.stdout
    assert home.names.policy.read_text(encoding="utf-8") == "format = 1\nthis is not a policy\n"
    assert home.answering_pid() is None
    assert not home.names.record.exists()


def test_a_stale_address_nobody_listens_at_does_not_stop_a_start(home: _Home) -> None:
    # Every level private, as the daemon itself would have made them: `parents=True`
    # would give the level above the umask's permissions, and the daemon refuses
    # an address below a directory a group can write.
    for level in (home.address.parent.parent, home.address.parent):
        level.mkdir(mode=0o700)
        level.chmod(0o700)
    with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as leftover:
        leftover.bind(str(home.address))
    assert home.address.exists()
    result = home.run("up", "--quickstart")
    assert result.returncode == 0, result.stderr
    assert home.answering_pid() == _pid_said(result)


def test_up_is_the_quickstart_and_says_so_when_it_is_not_asked_for(home: _Home) -> None:
    result = home.run("up")
    assert result.returncode == 2
    assert "--quickstart" in result.stderr
    assert not home.names.root.exists()


def test_serve_is_still_what_the_command_does_when_it_is_given_no_verb(home: _Home) -> None:
    """`sayfirst-daemon --config FILE` started a daemon before there were verbs."""
    from sayfirst_quickstart.command import build_parser

    assert build_parser().parse_args(["--config", "daemon.toml"]).command == "serve"
    assert build_parser().parse_args(["serve", "--config", "daemon.toml"]).command == "serve"
