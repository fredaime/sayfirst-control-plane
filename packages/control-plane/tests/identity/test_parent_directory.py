# SPDX-License-Identifier: Apache-2.0
"""The directory the daemon makes for itself, and the ambient mask it makes it under.

Article 6: "the socket's parent directory is writable by the daemon's principal
and root only, since whoever can write it can unlink the path and bind an
impostor". Rule S4 extends that to every ancestor. A daemon that creates an
ancestor a stranger can write has created the condition it refuses, so these
guards check the levels the daemon makes, not only the one it binds in.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.domain.evidence import RecordCollector
from sayfirst_control_plane.settings import read_settings
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory, StaticPeerIdentity

ME = os.geteuid()


def _daemon(address: Path) -> Daemon:
    settings = read_settings(
        {"socket": {"mode": "per_user", "path": str(address)}, "identity": {}},
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=StaticAccountDirectory(),
        peer_identity=StaticPeerIdentity(None, unavailable=True),
        clock=FixedClock(),
        evidence=RecordCollector(),
        daemon_uid=ME,
        overflow_ids=(65534, 65534),
    )
    return daemon


def test_every_level_the_daemon_creates_arrives_at_0700(tmp_path: Path) -> None:
    """Article 6, rule S4: the daemon does not create the condition it refuses.

    `Path.mkdir(parents=True)` applies its mode to the leaf only; every level
    above it arrives at `0o777 & ~umask`. Under a permissive umask that is a
    world-writable ancestor of the local address — and the daemon refuses to
    start on one of those, so it refused on its own work, permanently.
    """
    address = tmp_path / "home" / ".sayfirst" / "run" / "daemon.sock"
    daemon = _daemon(address)
    previous = os.umask(0o000)
    try:
        daemon.start()
    finally:
        os.umask(previous)
        daemon.stop()
    modes = {
        str(level): stat.S_IMODE(os.stat(level).st_mode)
        for level in (address.parent.parent.parent, address.parent.parent, address.parent)
    }
    assert set(modes.values()) == {0o700}, modes


def test_a_second_start_is_served_by_the_directory_the_first_one_made(tmp_path: Path) -> None:
    """Article 6, rule S4: what the daemon leaves behind is what it starts on next.

    Nothing removes the directory when the daemon exits, so a first start that
    leaves a level the check refuses has made every later start impossible by
    hand-repair only.
    """
    address = tmp_path / "home" / ".sayfirst" / "run" / "daemon.sock"
    previous = os.umask(0o000)
    try:
        first = _daemon(address)
        first.start()
        first.stop()
    finally:
        os.umask(previous)
    second = _daemon(address)
    second.start()
    second.stop()
