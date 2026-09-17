# SPDX-License-Identifier: Apache-2.0
"""Article 6, rule K3: an account name absent from the directory at start is logged.

"Logged, not refused" is two claims. The daemon must look the configured
names up — otherwise there is nothing to log — and it must go on serving when
one of them is not there: a mapping that names an account this host does not
have yet changes evidence vocabulary and nothing else (rule K3), so it is not
a reason to keep the host without a control plane.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from sayfirst_control_plane.adapters.socket_server import Daemon, account_kind_notes
from sayfirst_control_plane.cli import start_report
from sayfirst_control_plane.settings import read_settings
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory, StaticPeerIdentity


def test_the_notes_name_every_configured_account_and_the_absent_ones() -> None:
    """Rule K3: the mapping is read against the directory, name by name."""
    asked: list[str] = []

    def lookup(name: str) -> int | None:
        asked.append(name)
        return None if name == "svc-absent" else 4242

    notes = account_kind_notes({"svc-absent": "service", "svc-present": "workload"}, lookup=lookup)
    assert asked == ["svc-absent", "svc-present"]
    assert len(notes) == 2
    absent, present = notes
    assert "svc-absent" in absent and "service" in absent and "absent" in absent
    assert "svc-present" in present and "workload" in present and "absent" not in present


def test_a_configured_account_absent_from_the_directory_is_logged_not_refused(
    tmp_path: Path,
) -> None:
    """Rule K3: the daemon starts, and its start log says which name is not there."""
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    read = read_settings(
        {"socket": {"mode": "per_user", "path": str(root / "daemon.sock")}, "identity": {}},
        platform="linux",
    )
    settings = replace(read, account_kinds={"svc-absent": "service", "svc-present": "workload"})
    daemon = Daemon(
        settings,
        platform="linux",
        directory=StaticAccountDirectory(),
        peer_identity=StaticPeerIdentity(),
        clock=FixedClock(),
        account_uid=lambda name: None if name == "svc-absent" else 4242,
        overflow_ids=(65534, 65534),
    )
    daemon.start()
    try:
        assert Path(settings.socket_path).exists()
        joined = "\n".join(daemon.start_notes)
        assert "svc-absent" in joined
        assert "absent" in joined
        assert "svc-present" in joined
        # The start log the command prints: the readiness line first, then
        # what the start checks noticed.
        report = start_report(settings, daemon)
        assert report[0].startswith("serving ")
        assert report[1:] == daemon.start_notes
    finally:
        daemon.stop()
