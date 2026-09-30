# SPDX-License-Identifier: Apache-2.0
"""`down` signals a process only on a record this account's private layout vouches for.

A record another account could write, one reached through a link, or one a
privileged `down` read on another's behalf named any pid with a matching
start instant, and `down` sent it SIGTERM.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tomllib
from pathlib import Path

import pytest
from sayfirst_control_plane.settings import read_settings
from sayfirst_quickstart import launcher as quickstart
from sayfirst_testing.privileges import requires_unprivileged


def _reader(home: Path):  # type: ignore[no-untyped-def]
    def read(path: Path):  # type: ignore[no-untyped-def]
        return read_settings(
            tomllib.loads(path.read_text()), platform="linux", environ={}, home=str(home)
        )

    return read


def _forge(root: Path, pid: int) -> None:
    (root / "daemon.run.json").write_text(
        json.dumps(
            {"pid": pid, "began": quickstart.process_began(pid), "socket": str(root / "none.sock")}
        )
    )


@pytest.fixture
def sacrificial():  # type: ignore[no-untyped-def]
    child = subprocess.Popen(["sleep", "300"])
    yield child
    child.kill()
    child.wait()


def _down(home: Path) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.down(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    return code, err.getvalue()


@requires_unprivileged()
def test_down_refuses_a_quickstart_directory_other_accounts_can_write(
    tmp_path, sacrificial
) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "home" / ".sayfirst" / "quickstart"
    root.mkdir(parents=True)
    os.chmod(root, 0o777)
    _forge(root, sacrificial.pid)
    code, err = _down(tmp_path / "home")
    assert code == quickstart.EX_CONFIG and "other accounts" in err
    assert sacrificial.poll() is None, "a process was signalled"


def test_down_refuses_a_quickstart_directory_that_is_a_link(tmp_path, sacrificial) -> None:  # type: ignore[no-untyped-def]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (tmp_path / "home" / ".sayfirst").mkdir(parents=True)
    (tmp_path / "home" / ".sayfirst" / "quickstart").symlink_to(elsewhere)
    _forge(elsewhere, sacrificial.pid)
    code, _ = _down(tmp_path / "home")
    assert code == quickstart.EX_CONFIG
    assert sacrificial.poll() is None


@requires_unprivileged()
def test_down_does_not_chmod_through_a_lock_that_is_a_link(tmp_path, sacrificial) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "home" / ".sayfirst" / "quickstart"
    root.mkdir(parents=True, mode=0o700)
    _forge(root, sacrificial.pid)
    os.chmod(root / "daemon.run.json", 0o600)
    target = tmp_path / "victim"
    target.write_text("x")
    os.chmod(target, 0o644)
    (root / "daemon.lock").symlink_to(target)
    code, err = _down(tmp_path / "home")
    assert code == quickstart.EX_CONFIG
    assert "daemon.lock is a link" in err and "nothing was signalled" in err
    assert target.stat().st_mode & 0o777 == 0o644
    assert sacrificial.poll() is None, "a process was signalled"


@requires_unprivileged()
def test_up_refuses_a_lock_that_is_a_link_by_name(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    names = quickstart.layout(str(home))
    quickstart.prepare(names, account="example")
    target = tmp_path / "victim"
    target.write_text("x")
    os.chmod(target, 0o644)
    names.lock.unlink(missing_ok=True)
    names.lock.symlink_to(target)

    def no_start(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("a daemon was started")

    monkeypatch.setattr(quickstart.subprocess, "Popen", no_start)
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(home=str(home), read_settings_from=_reader(home), out=out, err=err)
    assert code == quickstart.EX_CONFIG
    assert err.getvalue().startswith("quickstart: ") and "daemon.lock is a link" in err.getvalue()
    assert target.stat().st_mode & 0o777 == 0o644
    assert not names.record.exists()


def test_a_record_another_account_owns_is_not_a_record(tmp_path, sacrificial, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "home" / ".sayfirst" / "quickstart"
    root.mkdir(parents=True, mode=0o700)
    _forge(root, sacrificial.pid)
    real = os.geteuid()
    monkeypatch.setattr(quickstart.os, "geteuid", lambda: real + 1)
    assert quickstart.read_record(quickstart.layout(str(tmp_path / "home"))) is None


def test_a_record_that_is_a_link_is_not_followed(tmp_path, sacrificial) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "home" / ".sayfirst" / "quickstart"
    root.mkdir(parents=True, mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    _forge(elsewhere, sacrificial.pid)
    (root / "daemon.run.json").symlink_to(elsewhere / "daemon.run.json")
    assert quickstart.read_record(quickstart.layout(str(tmp_path / "home"))) is None


def test_down_refuses_root(tmp_path, monkeypatch, sacrificial) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "home" / ".sayfirst" / "quickstart"
    root.mkdir(parents=True, mode=0o700)
    _forge(root, sacrificial.pid)
    monkeypatch.setattr(quickstart.os, "geteuid", lambda: 0)
    code, err = _down(tmp_path / "home")
    assert code == quickstart.EX_CONFIG and "being run as root" in err
    assert sacrificial.poll() is None


@requires_unprivileged()
def test_down_still_stops_the_daemon_of_a_private_layout(tmp_path, sacrificial) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "home" / ".sayfirst" / "quickstart"
    root.mkdir(parents=True, mode=0o700)
    _forge(root, sacrificial.pid)
    os.chmod(root / "daemon.run.json", 0o600)
    code, _ = _down(tmp_path / "home")
    assert code == 0 and sacrificial.wait(timeout=5) == -15
