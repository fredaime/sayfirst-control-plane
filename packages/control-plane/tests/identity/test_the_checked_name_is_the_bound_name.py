# SPDX-License-Identifier: Apache-2.0
"""Article 6: the name the daemon proved protected is the name it binds, chowns, chmods and removes.

The check resolved the configured path; bind, chown, chmod, stat and the
unlink at stop re-followed the configured name. A link swapped between the
two moved the daemon's chmod (and, as root in system mode, its chown) onto a
file of the swapper's choosing, and the closing stat — following the same
link — agreed with it.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_control_plane.adapters import socket_server
from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.settings import (
    PER_USER,
    StartRefused,
    final_file_mode,
    read_settings,
    sun_path_limit,
)
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory, StaticPeerIdentity
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms

ME, GID = os.geteuid(), os.getegid()


def _daemon(path: Path) -> Daemon:
    settings = read_settings({"socket": {"mode": PER_USER, "path": str(path)}}, platform="linux")
    return Daemon(
        settings,
        platform="linux",
        directory=StaticAccountDirectory(
            accounts={ME: ("alice", GID)}, memberships={"alice": (GID,)}, group_names={GID: "alice"}
        ),
        peer_identity=StaticPeerIdentity(
            PeerCredential(uid=ME, gid=GID, pid=1, captured_at="2026-09-04T00:00:00+00:00")
        ),
        clock=FixedClock(),
        daemon_uid=ME,
        overflow_ids=(65534, 65534),
    )


@requires_platforms(*OS_REAL_PLATFORMS)
def test_permissions_are_set_on_the_name_that_was_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "base"
    base.mkdir(mode=0o700)
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("unrelated\n")
    victim.chmod(0o644)
    (elsewhere / "d.sock").symlink_to(victim)
    link = base / "link"
    link.symlink_to(protected)

    bind = socket_server._Server.server_bind

    def racing_bind(self):  # type: ignore[no-untyped-def]
        bind(self)
        swapped = base / "link.new"
        swapped.symlink_to(elsewhere)
        os.replace(swapped, link)

    monkeypatch.setattr(socket_server._Server, "server_bind", racing_bind)
    daemon = _daemon(link / "d.sock")
    daemon.start()
    try:
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644, "the chmod followed the swapped link"
        bound = os.lstat(protected / "d.sock")
        assert stat.S_ISSOCK(bound.st_mode)
        assert stat.S_IMODE(bound.st_mode) == final_file_mode(PER_USER)
    finally:
        daemon.stop()
    assert not os.path.lexists(protected / "d.sock"), "stop left the socket it created"
    assert victim.exists() and os.path.lexists(elsewhere / "d.sock"), (
        "stop removed what it did not create"
    )


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_resolved_address_longer_than_the_kernel_holds_is_refused_by_name(
    tmp_path: Path,
) -> None:
    """Article 6: the length that counts is the one of the name bound, not the one configured.

    The configured path passes the settings check; the daemon binds the
    resolved one, which a short link into a deep directory makes longer than
    the kernel's address holds. That is the same refusal, by the same name.
    """
    deep = tmp_path
    for _ in range(4):
        deep = deep / ("d" * 40)
        deep.mkdir(mode=0o700)
    link = tmp_path / "l"
    link.symlink_to(deep)
    configured = link / "d.sock"
    limit = sun_path_limit("linux")
    assert len(str(configured).encode()) + 1 <= limit
    assert len(str(deep.resolve() / "d.sock").encode()) + 1 > limit
    daemon = _daemon(configured)
    with pytest.raises(StartRefused) as refused:
        daemon.start()
    assert refused.value.reason == "socket_path_too_long", refused.value.detail
    assert not os.path.lexists(deep / "d.sock")
