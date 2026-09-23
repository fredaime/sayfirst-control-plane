# SPDX-License-Identifier: Apache-2.0
"""The lifecycle a quickstart `up`/`down` must get right about a process it does not hold.

`up` starts the daemon detached and returns; `down`, a separate command later,
must re-identify that exact process before it signals it, and never signal, adopt
or bury a process it cannot prove is the one it started. The system reuses the
number that names a process, so a number is not an identity: these cases pin the
places where treating it as one would signal the wrong process, call a dead one
« running », or call a running one « stopped ».

Nothing here is a real daemon. Where a real process or a real socket is needed to
exercise the actual kernel behaviour — a start instant read from `/proc`, a
`pidfd`-pinned signal, a listener that accepts but never answers, an unreaped
zombie — one is created inside the test and cleaned up; the rest drive `up` and
`down` with doubles so a single decision can be put under a microscope.
"""

from __future__ import annotations

import io
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

import pytest
from sayfirst_control_plane.settings import read_settings
from sayfirst_quickstart import launcher as quickstart
from sayfirst_quickstart.launcher import Listener, Started

ACCOUNT = "example"


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return home


def _prepared(home: Path) -> quickstart.Layout:
    names = quickstart.layout(str(home))
    quickstart.prepare(names, account=ACCOUNT)
    return names


def _reader(home: Path):
    def read(path: Path):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        return read_settings(document, platform="linux", environ={}, home=str(home))

    return read


def _record(names: quickstart.Layout, *, pid: int, began: str | None, socket: str) -> None:
    names.record.write_text(
        json.dumps({"pid": pid, "began": began, "socket": socket}), encoding="utf-8"
    )


class _FakeChild:
    """A `subprocess.Popen` stand-in whose exit and stop behaviour the test chooses."""

    def __init__(self, *, pid: int, exits: int | None, stops: bool) -> None:
        self.pid = pid
        self._exits = exits
        self._stops = stops
        self.terminated = False
        self.returncode = exits

    def poll(self) -> int | None:
        return self._exits

    def wait(self, timeout: float | None = None) -> int:
        if self._stops:
            self._exits = 0
            self.returncode = 0
            return 0
        raise subprocess.TimeoutExpired("daemon", timeout or 0)

    def terminate(self) -> None:
        self.terminated = True


# -- F3: a probe of an unresponsive listener must be bounded ------------------------


def test_answering_gives_up_on_a_listener_that_accepts_and_never_replies(tmp_path: Path) -> None:
    """A listener that never answers must not hang the command that asks it."""
    run = tmp_path / ".sayfirst" / "run"
    run.mkdir(mode=0o700, parents=True)
    address = run / "daemon.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(address))
        server.listen(1)  # accepts the connection into the backlog, never reads it
        start = time.monotonic()
        answered = quickstart.answering(str(address))
        elapsed = time.monotonic() - start
    assert answered is None
    assert elapsed < quickstart.PROBE_SECONDS + 3.0, f"the probe hung for {elapsed:.1f}s"


# -- F10: the start token carries the boot it was measured against ------------------


def test_the_start_token_is_scoped_to_the_boot_it_was_read_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(quickstart, "_process_state", lambda pid: ("R", "998877"))
    monkeypatch.setattr(quickstart, "_boot_identity", lambda: "boot-alpha")
    first = quickstart.process_began(1234)
    monkeypatch.setattr(quickstart, "_boot_identity", lambda: "boot-beta")
    second = quickstart.process_began(1234)
    assert first == "boot-alpha:998877"
    assert second == "boot-beta:998877"
    assert first != second, "the same id and tick on two boots read as the same process"


# -- F2: the stop signal is pinned to the recorded process -------------------------


def test_a_stop_signal_reaches_the_recorded_process(tmp_path: Path) -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        began = quickstart.process_began(child.pid)
        assert began is not None
        quickstart._request_stop(Started(child.pid, began, "unused"))
        assert child.wait(timeout=10) == -signal.SIGTERM
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)


def test_a_stop_signal_is_withheld_when_the_start_instant_no_longer_matches(
    tmp_path: Path,
) -> None:
    """A record whose start instant does not match the live id is a reused number:
    the process this command started is gone, and nothing is signalled."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        quickstart._request_stop(Started(child.pid, "a-token-that-is-not-this-process", "unused"))
        time.sleep(0.3)
        assert child.poll() is None, "a process was signalled whose start instant did not match"
    finally:
        child.kill()
        child.wait(timeout=10)


# -- F1: a listener whose id was reused is not the daemon we started ----------------


def test_down_leaves_a_reused_id_listener_running_and_signals_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Something answers at our address with our recorded id — but it began at a
    different instant, so the number was reused and the answerer is not ours."""
    home = _home(tmp_path)
    names = _prepared(home)
    _record(names, pid=4321, began="the-instant-we-recorded", socket="the-address")
    monkeypatch.setattr(quickstart, "answering", lambda address: Listener(4321, {}))
    monkeypatch.setattr(quickstart, "process_began", lambda pid: "a-different-instant")
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)  # the id is held — by another
    signalled: list[int] = []
    # Signal 0 is a liveness probe and delivers nothing; only a real signal counts.
    monkeypatch.setattr(
        quickstart.os, "kill", lambda pid, sig: signalled.append(pid) if sig else None
    )
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.down(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EXIT_NOT_DONE
    assert "did not start it" in err.getvalue() or "left running" in err.getvalue()
    assert signalled == [], "down signalled a process it could not prove it started"
    assert not names.record.exists(), "the stale record naming a gone process was kept"


# -- F8: an unprovable but living process is neither signalled nor declared gone ----


def test_down_keeps_the_record_when_a_living_process_cannot_be_proved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    names = _prepared(home)
    _record(names, pid=5555, began="recorded", socket="the-address")
    monkeypatch.setattr(quickstart, "answering", lambda address: None)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: None)  # token unreadable
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)  # but it is alive
    signalled: list[int] = []
    monkeypatch.setattr(quickstart.os, "kill", lambda pid, sig: signalled.append(pid))
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.down(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EXIT_NOT_DONE
    assert signalled == []
    assert names.record.exists(), "the record of a process that may still live was discarded"
    assert "not running" not in out.getvalue(), "a living, unprovable process was called gone"


def test_down_removes_the_record_when_the_process_is_truly_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    names = _prepared(home)
    _record(names, pid=6666, began="recorded", socket="the-address")
    monkeypatch.setattr(quickstart, "answering", lambda address: None)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: None)
    monkeypatch.setattr(quickstart, "_running", lambda pid: False)  # and it is gone
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.down(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == 0
    assert "SayFirst Control Plane not running" in out.getvalue()
    assert "stale" in out.getvalue()
    assert not names.record.exists()


# -- F7: a zombie with the recorded id is not a running daemon ----------------------


def test_an_unreaped_earlier_daemon_does_not_block_a_new_start(tmp_path: Path) -> None:
    """A recorded process that exited but was not reaped keeps its start instant in
    `/proc`; the restart guard must read its state, not only its instant."""
    pid = os.fork()
    if pid == 0:  # the child: exit at once, becoming a zombie its parent has not reaped
        os._exit(0)
    try:
        # Give the child a moment to exit and settle into Z.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and quickstart._process_state(pid)[0] != "Z":
            time.sleep(0.01)
        state = quickstart._process_state(pid)
        assert state is not None and state[0] == "Z", f"expected a zombie, saw {state}"
        began = quickstart.process_began(pid)
        assert began is not None, "a zombie still has a start instant in /proc"
        record = Started(pid, began, "the-address")
        assert quickstart._earlier_daemon_running(record) is False
    finally:
        os.waitpid(pid, 0)


def test_a_living_earlier_daemon_does_block_a_new_start(tmp_path: Path) -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        began = quickstart.process_began(child.pid)
        assert began is not None
        assert quickstart._earlier_daemon_running(Started(child.pid, began, "the-address")) is True
    finally:
        child.kill()
        child.wait(timeout=10)


# -- F5: up must not claim a daemon stopped when it did not stop --------------------


def test_up_keeps_the_record_when_the_started_child_will_not_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    names = quickstart.layout(str(home))
    monkeypatch.setattr(quickstart, "answering", lambda address: None)  # never becomes ready
    monkeypatch.setattr(quickstart, "READY_SECONDS", 0.1)
    monkeypatch.setattr(quickstart, "STOP_SECONDS", 0.1)
    child = _FakeChild(pid=777001, exits=None, stops=False)  # ignores the stop it is asked for
    monkeypatch.setattr(quickstart.subprocess, "Popen", lambda *a, **k: child)
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EXIT_NOT_DONE
    assert child.terminated, "the unready daemon was never asked to stop"
    assert "still running" in err.getvalue()
    assert "stopped" not in err.getvalue().replace("stops it", "")
    assert names.record.exists(), "the record of a daemon still running was discarded"


# -- F6: a record that cannot be written must not leave the child orphaned ----------


def test_up_stops_the_child_when_its_record_cannot_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    names = quickstart.layout(str(home))
    child = _FakeChild(pid=777002, exits=None, stops=True)
    monkeypatch.setattr(quickstart.subprocess, "Popen", lambda *a, **k: child)

    def no_space(names_arg, started):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(quickstart, "write_record", no_space)
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EXIT_NOT_DONE
    assert child.terminated, "the started child was left running with no record"
    assert not names.record.exists()
    assert "record" in err.getvalue()


# -- F4: two lifecycle commands do not race the one shared record ------------------


def test_up_waits_for_a_lifecycle_lock_another_command_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    names = _prepared(home)
    # Make `up` take the fast « already running » path once it holds the lock, so
    # the test observes the lock alone and starts no real daemon.
    _record(names, pid=8888, began="recorded", socket="the-address")
    monkeypatch.setattr(quickstart, "answering", lambda address: Listener(8888, {}))
    monkeypatch.setattr(quickstart, "process_began", lambda pid: "recorded")
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)
    proceeded = threading.Event()
    started = threading.Event()
    out = io.StringIO()

    def run_up() -> None:
        started.set()
        quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=io.StringIO())
        proceeded.set()

    with quickstart._exclusive(names):
        worker = threading.Thread(target=run_up)
        worker.start()
        started.wait(timeout=5)
        assert not proceeded.wait(timeout=0.5), "up did not wait for the lock another command held"
    assert proceeded.wait(timeout=5), "up did not proceed once the lock was released"
    worker.join(timeout=5)
    assert "already running" in out.getvalue()


# -- F11: chmod is tied to the directory that was created, following no link --------


def test_a_directory_swapped_for_a_link_after_creation_is_not_chmodded_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the just-created directory is replaced by a symlink before its mode is
    set, the mode change must refuse the link rather than follow it to its target."""
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    assert quickstart.stat_module.S_IMODE(victim.lstat().st_mode) == 0o755
    target = tmp_path / "root"
    real_mkdir = os.mkdir

    def racing_mkdir(path, mode=0o777):
        real_mkdir(path, mode)  # create the directory as normal…
        os.rmdir(path)  # …then a racer removes it…
        os.symlink(victim, path)  # …and points a link at somebody else's directory

    monkeypatch.setattr(quickstart.os, "mkdir", racing_mkdir)
    with pytest.raises(OSError):
        quickstart._private_directory(target, create_only=False)
    assert quickstart.stat_module.S_IMODE(victim.lstat().st_mode) == 0o755, "the link was followed"


# -- identity has three answers: ours, gone, and unknown -----------------------------


def test_identity_reads_the_recorded_instant_in_the_format_it_was_written_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A record without the boot is compared on the instant alone, and only that far."""
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: "boot-a:500")
    cases = {
        "boot-a:500": "ours",  # the same process
        "boot-b:500": "gone",  # the same instant on another boot: another process
        "boot-a:499": "gone",  # another instant: the number was reused
        "499": "gone",  # written without the boot, and still another instant
        "500": "unknown",  # the same instant, and the record does not say which boot
    }
    for began, expected in cases.items():
        assert quickstart._identity(Started(4242, began, "a")) == expected, began
    assert quickstart._identity(Started(4242, None, "a")) == "unknown"


def test_identity_of_an_id_nothing_holds_is_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(quickstart, "_running", lambda pid: False)
    assert quickstart._identity(Started(4242, "boot-a:500", "a")) == "gone"


def test_identity_of_a_living_id_whose_instant_cannot_be_read_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: None)
    assert quickstart._identity(Started(4242, "boot-a:500", "a")) == "unknown"


def test_up_starts_nothing_over_a_living_process_it_cannot_prove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`down` would refuse to stop it; so `up` must not bury its record under a new one."""
    home = _home(tmp_path)
    names = _prepared(home)
    _record(names, pid=5151, began="boot-a:500", socket="the-address")
    monkeypatch.setattr(quickstart, "answering", lambda address: None)
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: None)
    monkeypatch.setattr(
        quickstart.subprocess, "Popen", lambda *a, **k: pytest.fail("a daemon was started")
    )
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EXIT_NOT_DONE
    assert "cannot prove" in err.getvalue()
    assert json.loads(names.record.read_text(encoding="utf-8"))["pid"] == 5151


def test_down_keeps_a_record_that_carries_no_instant_while_its_id_lives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    names = _prepared(home)
    _record(names, pid=5252, began=None, socket="the-address")
    monkeypatch.setattr(quickstart, "answering", lambda address: None)
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: "boot-a:700")
    signalled: list[int] = []
    monkeypatch.setattr(quickstart.os, "kill", lambda pid, sig: signalled.append(pid))
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.down(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EXIT_NOT_DONE
    assert signalled == []
    assert names.record.exists()
    assert "not running" not in out.getvalue()


# -- `up` reports the daemon it started, not a configuration edited since --------------


def test_already_running_reports_the_address_and_paths_the_daemon_was_started_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Edit daemon.toml under a running daemon: it still reads what it started on."""
    home = _home(tmp_path)
    names = _prepared(home)
    started_on = {
        "pid": 6161,
        "began": "boot-a:900",
        "socket": "/run/started-on.sock",
        "policy": "/srv/started-on/policy.toml",
        "evidence": "/srv/started-on/evidence",
    }
    names.record.write_text(json.dumps(started_on), encoding="utf-8")
    asked: list[str] = []

    def answering(address: str) -> Listener | None:
        asked.append(address)
        return Listener(6161, {}) if address == "/run/started-on.sock" else None

    monkeypatch.setattr(quickstart, "answering", answering)
    monkeypatch.setattr(quickstart, "_running", lambda pid: True)
    monkeypatch.setattr(quickstart, "process_began", lambda pid: "boot-a:900")
    monkeypatch.setattr(quickstart, "render_status", lambda status: "(status)")
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    said = out.getvalue()
    assert code == 0, err.getvalue()
    assert said.splitlines()[0] == "SayFirst Control Plane already running"
    assert "socket: /run/started-on.sock" in said
    assert "policy: /srv/started-on/policy.toml" in said
    assert "evidence: /srv/started-on/evidence" in said
    assert "/run/started-on.sock" in asked
    # The configuration now names other paths, and the report says so rather than
    # printing them as if the running daemon read them.
    assert str(names.policy) in said and "restart" in said


def test_a_record_that_cannot_be_written_and_a_child_that_will_not_stop_is_said_plainly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(tmp_path)
    child = _FakeChild(pid=777003, exits=None, stops=False)
    monkeypatch.setattr(quickstart.subprocess, "Popen", lambda *a, **k: child)
    monkeypatch.setattr(quickstart, "STOP_SECONDS", 0.1)

    def no_space(names_arg, started):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(quickstart, "write_record", no_space)
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    said = err.getvalue()
    assert code == quickstart.EXIT_NOT_DONE
    assert "777003" in said and "still running" in said
    assert "nothing runs unmanaged" not in said
