# SPDX-License-Identifier: Apache-2.0
"""A connection that can be told how long to wait, and a socket that cannot be made.

`connect()` built a blocking socket with no bound. A process that accepted the
connection and then never answered held the caller for ever: a command asking a
question, or reading what was decided, simply stopped. A timeout the caller names
now bounds every step of a connection — the connect, the credential, each read —
and a step that runs past it is the unreachable problem the transport already has
for every other way of not being answered.

The socket itself was made outside the handling that turns a failure into that
problem, so a process out of descriptors got the operating system's own error
instead of an answer it could classify.
"""

from __future__ import annotations

import errno
import socket
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.transport.socket_client import (
    SocketClientProblem,
    SocketProfile,
    connect,
)


@pytest.fixture
def silent(tmp_path: Path) -> Iterator[Path]:
    """This account listening at an address, accepting, and never saying a word."""
    address = tmp_path / "daemon.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(address))
        server.listen(4)
        yield address


def test_a_named_timeout_bounds_a_peer_that_never_answers(silent: Path) -> None:
    started = time.monotonic()
    connection = connect(SocketProfile(str(silent)), timeout=0.3)
    try:
        with pytest.raises(SocketClientProblem) as failed:
            connection.read_status()
    finally:
        connection.close()
    assert failed.value.problem.code is ProblemCode.UNREACHABLE
    assert time.monotonic() - started < 5.0


def test_a_socket_the_system_cannot_make_is_unreachable_not_an_exception(tmp_path: Path) -> None:
    def exhausted() -> socket.socket:
        raise OSError(errno.EMFILE, "Too many open files")

    with pytest.raises(SocketClientProblem) as failed:
        connect(SocketProfile(str(tmp_path / "daemon.sock")), socket_factory=exhausted)
    assert failed.value.problem.code is ProblemCode.UNREACHABLE
