# SPDX-License-Identifier: Apache-2.0
"""Rule L7 on the way out: a clean stop removes its address, or says it could not.

In system mode the daemon has dropped to its own account and the directory the
packager lays out is root's, so the unlink is refused; it used to be swallowed, and a
comment claimed the next start would find nothing at the name. The next start does
clear a name nobody listens at — the stop now says the name is there and why.
Reproduced here without root by taking write away from the socket's directory.
"""

from __future__ import annotations

import os
import shutil
import signal
import tempfile
from pathlib import Path

import pytest
from _daemon import _launch

POLICY = 'format = 1\n[revision]\nreason = "stop"\n'


@pytest.fixture
def deployment():
    root = Path(tempfile.mkdtemp(prefix="sfs", dir="/tmp"))
    os.chmod(root, 0o700)
    sockets = root / "s"
    sockets.mkdir(mode=0o700)
    policy = root / "policy.toml"
    policy.write_text(POLICY)
    os.chmod(policy, 0o600)
    config = root / "daemon.toml"
    config.write_text(
        f'[socket]\nmode = "per_user"\npath = "{sockets / "daemon.sock"}"\n'
        f'[policy]\npath = "{policy}"\n[evidence]\npath = "{root / "evidence"}"\n'
    )
    os.chmod(config, 0o600)
    try:
        yield config, sockets
    finally:
        os.chmod(sockets, 0o700)
        shutil.rmtree(root, ignore_errors=True)


def _stop(process) -> tuple[int, str]:
    process.send_signal(signal.SIGTERM)
    _, err = process.communicate(timeout=30)
    return process.returncode, err


def test_a_clean_stop_removes_its_socket_and_says_nothing_more(deployment) -> None:
    config, sockets = deployment
    code, err = _stop(_launch(config))
    assert code == 0, err
    assert not (sockets / "daemon.sock").exists()
    assert "socket_left_behind" not in err


def test_a_stop_that_cannot_remove_its_socket_says_so_and_the_next_start_serves(
    deployment,
) -> None:
    config, sockets = deployment
    process = _launch(config)
    os.chmod(sockets, 0o500)
    code, err = _stop(process)
    os.chmod(sockets, 0o700)
    assert code == 0, err
    assert (sockets / "daemon.sock").exists()
    assert f"socket_left_behind: {sockets / 'daemon.sock'}: " in err, err
    assert err.rstrip().endswith(
        "nobody is listening at it; the next start clears it, or refuses naming why"
    ), err
    again = _launch(config)  # raises unless it prints its serving line
    code, err = _stop(again)
    assert code == 0, err
