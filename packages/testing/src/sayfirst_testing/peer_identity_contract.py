# SPDX-License-Identifier: Apache-2.0
"""The contract of the PeerIdentity port, run against every adapter.

It covers `establish(connection)`: what the kernel recorded for the process at
the other end, read on both sides of a local stream.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

from sayfirst_contract.transport.peer import (
    PeerCredential,
    PeerCredentialUnavailable,
    PeerIdentity,
)


def _assert_is_this_process(credential: PeerCredential) -> None:
    assert credential.uid == os.geteuid()
    assert credential.gid == os.getegid()
    assert credential.pid == os.getpid()
    assert credential.captured_at


def assert_own_credential_over_a_socketpair(adapter: PeerIdentity) -> None:
    """Both ends of a socketpair belong to this process, so both report it."""
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with left, right:
        _assert_is_this_process(adapter.establish(left))
        _assert_is_this_process(adapter.establish(right))


def assert_both_sides_of_a_listener_are_read(adapter: PeerIdentity, bound_at: Path) -> None:
    """The connecting side reads the listener's record and the reverse."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with listener:
        listener.bind(str(bound_at))
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with client:
            client.connect(str(bound_at))
            accepted, _ = listener.accept()
            with accepted:
                _assert_is_this_process(adapter.establish(accepted))
                _assert_is_this_process(adapter.establish(client))
    bound_at.unlink(missing_ok=True)


def assert_no_identity_is_unavailable(adapter: PeerIdentity) -> None:
    """A record the adapter cannot read is unavailable, never an identity."""

    class _Refusing:
        def getsockopt(self, *_: object) -> bytes:
            raise OSError(22, "Invalid argument")

    try:
        adapter.establish(_Refusing())  # type: ignore[arg-type]
    except PeerCredentialUnavailable:
        return
    raise AssertionError("an unreadable credential must be unavailable")


def run_the_peer_identity_contract(adapter: PeerIdentity, *, bound_at: Path) -> None:
    """Every promise of the port, against one adapter (article 8)."""
    assert isinstance(adapter.VERSION, int) and not isinstance(adapter.VERSION, bool)
    assert adapter.VERSION >= 1
    assert_own_credential_over_a_socketpair(adapter)
    assert_both_sides_of_a_listener_are_read(adapter, bound_at)
    assert_no_identity_is_unavailable(adapter)
