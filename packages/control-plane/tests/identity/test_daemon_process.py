# SPDX-License-Identifier: Apache-2.0
"""Guards that exercise the kernel: the daemon runs, in its own process."""

from __future__ import annotations

import ast
import contextlib
import http.client
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import ClassVar

import pytest
from daemon_process import SERVER_PACKAGE, ask, refuse, serving, write_config
from sayfirst_testing.platforms import (
    OS_REAL_PLATFORMS,
    requires_platform,
    requires_platforms,
)
from sayfirst_testing.privileges import requires_unprivileged

# -- the guards article 6 names ---------------------------------------------


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_daemon_listens_only_on_the_socket(tmp_path: Path) -> None:
    """Article 6: a Unix domain socket, and only there. Loopback is not an exception."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    with serving(config) as process:
        ask(address)
        listening = (
            _linux_listeners(process.pid)
            if sys.platform == "linux"
            else _darwin_listeners(process.pid)
        )
    assert listening == [str(address)]


def _linux_listeners(pid: int) -> list[str]:
    """Every socket the daemon holds, matched against the kernel's own tables."""
    inodes = set()
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        # A descriptor may close between listing and reading; that one was
        # not a listener, so it is not this guard's business.
        with contextlib.suppress(FileNotFoundError):
            match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(entry))
            if match:
                inodes.add(match.group(1))
    assert inodes, "the daemon holds no socket at all"
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in Path(table).read_text().splitlines()[1:]:
            columns = line.split()
            if columns[3] == "0A" and columns[9] in inodes:
                raise AssertionError(f"the daemon has a listener in {table}: {line}")
    listening = []
    for line in Path("/proc/net/unix").read_text().splitlines()[1:]:
        columns = line.split()
        if columns[6] in inodes and int(columns[3], 16) & 0x10000:
            listening.append(columns[7] if len(columns) > 7 else "")
    return listening


def _darwin_listeners(pid: int) -> list[str]:
    """The same enumeration with the tool that platform has.

    `lsof -p <pid> -a -i -P -n` lists every internet endpoint the process
    holds and must list nothing at all; `lsof -p <pid> -a -U` lists its local
    ones and must list exactly the address the daemon was configured with.
    """
    internet = subprocess.run(
        ["lsof", "-p", str(pid), "-a", "-i", "-P", "-n"],
        capture_output=True,
        text=True,
        check=False,
    )
    endpoints = [
        line for line in internet.stdout.splitlines() if line and not line.startswith("COMMAND")
    ]
    assert endpoints == [], f"the daemon has a network endpoint: {endpoints}"
    local = subprocess.run(
        ["lsof", "-p", str(pid), "-a", "-U"], capture_output=True, text=True, check=False
    )
    listening = []
    for line in local.stdout.splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        name = line.split()[-1]
        if name.startswith("/"):
            listening.append(name)
    assert listening, "the daemon holds no local socket at all"
    return sorted(set(listening))


def test_the_daemon_has_no_tcp_listener_to_configure() -> None:
    """Article 6, rule L3: nothing in the server constructs any other family."""
    constructions = 0
    for source in SERVER_PACKAGE.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            if name in {"socket.socket", "socket.create_server", "socket.create_connection"}:
                assert name == "socket.socket", f"{source}: {name}"
                arguments = [ast.unparse(item) for item in node.args]
                arguments += [ast.unparse(item.value) for item in node.keywords]
                assert "socket.AF_UNIX" in arguments, f"{source}: {ast.unparse(node)}"
                constructions += 1
    assert constructions >= 1
    from sayfirst_control_plane.cli import build_parser
    from sayfirst_control_plane.settings import Settings

    options = {option for action in build_parser()._actions for option in action.option_strings}
    names = options | set(Settings.__dataclass_fields__)
    assert not any("host" in name or "port" in name for name in names), names


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_daemon_refuses_to_start_on_a_socket_directory_writable_by_anyone_else(
    tmp_path: Path,
) -> None:
    """Article 6, rule S3: whoever can write it can bind an impostor in its place."""
    root = tmp_path / "run"
    config = write_config(root)
    for mode in (0o777, 0o770):
        root.chmod(mode)
        code, errors = refuse(config)
        assert code == 78, (oct(mode), errors)
        assert errors.startswith("socket_directory_unprotected"), oct(mode)
    root.chmod(0o700)
    with serving(config):
        pass


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_socket_is_created_at_its_final_mode(tmp_path: Path) -> None:
    """Article 6, rule S2: never briefly more permissive than its final mode."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    with serving(config, umask=0o000):
        assert stat.S_IMODE(os.stat(address).st_mode) == 0o700
        assert os.stat(address).st_uid == os.geteuid()


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_stale_socket_is_replaced_and_a_live_one_is_not(tmp_path: Path) -> None:
    """Article 6, rule L7: nothing but a local address is ever unlinked."""
    root = tmp_path / "run"
    config = write_config(root)
    address = root / "daemon.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(address))
    stale.close()
    assert address.exists()
    with serving(config):
        assert address.exists()
    live = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        live.bind(str(address))
        live.listen(1)
        code, errors = refuse(config)
        assert code == 78
        assert errors.startswith("socket_in_use")
    finally:
        live.close()
        address.unlink(missing_ok=True)
    address.write_text("not a local address", encoding="utf-8")
    code, errors = refuse(config)
    assert code == 78
    assert errors.startswith("socket_in_use")
    assert address.read_text(encoding="utf-8") == "not a local address"


@requires_platform("linux")
def test_an_abstract_or_unnamed_socket_is_refused() -> None:
    """Article 6, rule L4: a name with no file has no permissions and no admission list."""
    from sayfirst_control_plane.adapters.socket_server import verify_bound_name
    from sayfirst_control_plane.settings import StartRefused

    bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with bound:
        bound.bind("\0sayfirst-guard")
        with pytest.raises(StartRefused) as refusal:
            verify_bound_name(bound.getsockname())
        assert refusal.value.reason == "socket_abstract_or_unnamed"
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with left, right, pytest.raises(StartRefused) as refusal:
        verify_bound_name(left.getsockname())
    assert refusal.value.reason == "socket_abstract_or_unnamed"


@requires_platform("linux")
def test_the_overflow_ids_are_read_at_start_or_the_daemon_does_not_start(tmp_path: Path) -> None:
    """Article 6, rule L8: without them the daemon cannot tell an identity apart."""
    from sayfirst_control_plane.adapters.socket_server import read_overflow_ids
    from sayfirst_control_plane.settings import StartRefused

    assert read_overflow_ids("linux") == (65534, 65534)
    with pytest.raises(StartRefused) as refusal:
        read_overflow_ids("linux", root=tmp_path)
    assert refusal.value.reason == "overflow_id_unreadable"
    assert read_overflow_ids("darwin") == (None, None)


def test_the_daemon_is_not_built_on_a_platform_with_no_adapter(tmp_path: Path) -> None:
    """Article 6, rule L6: a daemon that cannot read a credential does not run."""
    from sayfirst_control_plane.adapters.socket_server import Daemon
    from sayfirst_control_plane.settings import StartRefused, read_settings
    from sayfirst_testing.doubles import StaticAccountDirectory

    settings = read_settings(
        {"socket": {"mode": "per_user", "path": str(tmp_path / "daemon.sock")}},
        platform="linux",
    )
    with pytest.raises(StartRefused) as refusal:
        Daemon(settings, platform="win32", directory=StaticAccountDirectory())
    assert refusal.value.reason == "peer_identity_unsupported"


@requires_platforms(*OS_REAL_PLATFORMS)
def test_whoami_reports_the_principal_as_the_socket_saw_it(tmp_path: Path) -> None:
    """Article 6: the guard the article names, end to end, against the real kernel."""
    import grp

    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    with serving(config):
        status, document = ask(address)
    assert status == 200
    assert document["peer"]["uid"] == os.geteuid()
    assert document["peer"]["gid"] == os.getegid()
    assert document["peer"]["pid"] == os.getpid()
    assert document["status"] == "established"
    assert document["mode"] == "per_user"
    assert document["socket_path"] == str(address)
    import pwd

    expected_name = pwd.getpwuid(os.geteuid()).pw_name
    assert document["principal"]["name"] == expected_name
    expected_groups = [
        grp.getgrgid(gid).gr_name for gid in os.getgrouplist(expected_name, os.getegid())
    ]
    assert document["principal"]["groups"] == expected_groups
    assert document["principal"]["groups_status"] == "resolved"
    assert document["principal"]["established_by"] == "peer_credential"


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_second_request_on_one_connection_keeps_the_credential(tmp_path: Path) -> None:
    """Article 6, rule P2: keep-alive reuses the connection and its credential."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    with serving(config):
        connection = http.client.HTTPConnection("sayfirst")
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(10)
        connection.sock.connect(str(address))
        seen = []
        for _ in range(2):
            connection.request("GET", "/whoami")
            response = connection.getresponse()
            seen.append(json.loads(response.read())["connection_id"])
        connection.close()
    assert seen[0] == seen[1]


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_daemon_creates_its_per_user_directory_protected(tmp_path: Path) -> None:
    """Article 6, rule L2: a per-user daemon makes its own place, and makes it 0700."""
    root = tmp_path / "made-by-the-daemon"
    config_root = tmp_path / "conf"
    config_root.mkdir(mode=0o700)
    config = config_root / "daemon.toml"
    config.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        f'[socket]\nmode = "per_user"\npath = "{root / "daemon.sock"}"\n',
        encoding="utf-8",
    )
    with serving(config):
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
    assert time.monotonic() > 0


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_documented_default_address_starts_a_daemon_on_a_clean_machine() -> None:
    """Article 6, rules L2 and S4: the place the daemon makes is one it accepts.

    The default address of a per-user daemon is two levels below a home that
    has neither of them yet, and `mkdir(parents=True)` applies its mode to the
    leaf alone: under a permissive umask the level above arrived at `0777`,
    which is the exact condition rule S4 refuses. The daemon then refused to
    start on the directory it had itself created, and went on refusing, because
    nothing removes it. So this runs the documented default end to end on a
    clean machine state and requires a daemon that serves — twice, since the
    ancestor the first start leaves behind is what the second start checks.
    """
    # A short root: the default address is 30 bytes below the home, and
    # `sun_path` holds 104 on macOS, where a temporary directory is long.
    with tempfile.TemporaryDirectory(dir="/tmp") as base:
        home = Path(base) / "h"
        home.mkdir(mode=0o700)
        config = write_config(Path(base) / "c", path=None)
        address = home / ".sayfirst" / "run" / "daemon.sock"
        with serving(config, umask=0o000, home=home):
            status, document = ask(address)
        assert status == 200, document
        modes = {
            str(level): stat.S_IMODE(os.stat(level).st_mode)
            for level in (home / ".sayfirst", address.parent)
        }
        assert set(modes.values()) == {0o700}, modes
        with serving(config, umask=0o022, home=home) as second:
            assert second.poll() is None
            assert ask(address)[0] == 200


ROOT_OWNED_DIRECTORY = Path("/usr/lib")
"""A directory rule S3 accepts — owner uid 0, neither `S_IWGRP` nor `S_IWOTH` —
and that an unprivileged daemon cannot bind in. Both operating systems have it
at this path and with these permissions."""


@requires_platforms(*OS_REAL_PLATFORMS)
@requires_unprivileged()
def test_a_start_the_host_refuses_exits_with_the_documented_code_and_reason(
    tmp_path: Path,
) -> None:
    """Article 2: `docs/deployment.md` promises one reason and 78, on every path.

    An `OSError` from `bind`, from reading the configuration file, or from any
    other call of the start sequence used to reach `main()` unconverted: exit 1
    and a stack trace, where the document publishes 78 and one sentence. A
    supervisor keyed on `EX_CONFIG` reads exit 1 as an ordinary crash and
    restarts the daemon forever, and an operator reads a traceback instead of
    the sentence that names what to fix.

    Not runnable as root: every refusal it drives is the host denying the
    tester something, and the host denies root nothing.
    """
    root = tmp_path / "run"
    denied = write_config(root, path=str(ROOT_OWNED_DIRECTORY / "sayfirst-start-refused.sock"))
    unreadable = root / "absent.toml"
    malformed = root / "malformed.toml"
    malformed.write_text("# SPDX-License-Identifier: Apache-2.0\n[socket\n", encoding="utf-8")
    documented = {
        denied: "socket_address_denied",
        unreadable: "configuration_unreadable",
        malformed: "configuration_unreadable",
    }
    for config, reason in documented.items():
        code, errors = refuse(config)
        assert code == 78, (config.name, code, errors)
        assert errors.startswith(f"{reason}: "), (config.name, errors)
        assert "Traceback" not in errors, (config.name, errors)
        assert "\n" not in errors, (config.name, errors)


def test_a_stop_signal_during_shutdown_does_not_end_the_daemon_in_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 2: a clean stop that writes a stack trace reads as a crash.

    `stop_serving` stays installed while the daemon shuts down, so a second
    `SIGTERM` — the one a supervisor sends when the first did not free the
    address fast enough — raises `KeyboardInterrupt` inside the shutdown path
    and the interpreter writes a traceback on standard error at exit 0.
    Observed on a real daemon: "Exception ignored on threading shutdown".
    A daemon that stopped as asked says nothing that reads as a failure.
    """
    import signal as signal_module

    from sayfirst_control_plane import cli

    seen: dict[str, object] = {}

    class _Daemon:
        acl_note = "acl: checked"
        start_notes: ClassVar[list[str]] = []

        def start(self) -> None:
            return None

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def stop(self) -> None:
            seen["handler"] = signal_module.getsignal(signal_module.SIGTERM)

    monkeypatch.setattr(cli, "assemble", lambda settings, platform: _Daemon())
    config = write_config(tmp_path / "run")
    installed = signal_module.getsignal(signal_module.SIGTERM)
    try:
        assert cli.main(["serve", "--config", str(config)]) == 0
    finally:
        signal_module.signal(signal_module.SIGTERM, installed)
    assert seen["handler"] is signal_module.SIG_IGN, seen
