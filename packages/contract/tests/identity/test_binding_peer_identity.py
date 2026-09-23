# SPDX-License-Identifier: Apache-2.0
"""The binding's own client reads a peer's identity the way the rest of the contract does.

The contract ships two clients of one daemon: the transport client the reads and the
command-line interface use, and the binding client a boundary holds its grants through.
Each used to read the far end's identity for itself, and the binding's reading knew one
platform — it asked the kernel on Linux, then reached for a `getpeereid` the standard
library does not have, and raised. So on macOS, where the transport client verified
peers, every governed effect ended in an exception that is none of the boundary's four
outcomes. One reading now serves both: the adapters of `transport.peer`.

These cases run on every platform the identity job covers, so the macOS runner is what
proves the Darwin half; here the half that must never be an exception is proved with a
platform that has no adapter at all.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from sayfirst_contract.binding.http_unix_socket import client as binding
from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.client import CouldNotAsk
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.transport.peer import PeerCredentialUnavailable


@pytest.fixture
def listening(tmp_path: Path) -> Iterator[Path]:
    """An address something of this account listens at, and never answers."""
    address = tmp_path / "daemon.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(address))
        server.listen(4)
        yield address


def test_the_binding_reads_a_peers_identity_on_this_platform() -> None:
    """The same uid the kernel reports to the transport client, on Linux and on macOS."""
    here, there = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with here, there:
        assert binding._peer_uid(here) == os.geteuid()


def test_a_governed_ask_on_a_platform_with_no_adapter_is_an_answer(
    listening: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Could not ask, said as the contract says it — never an exception the boundary
    does not know, which a governed program written against its four outcomes would
    not catch."""
    monkeypatch.setattr(binding.sys, "platform", "plan9")
    client = SocketClient(listening, expected_uid=os.geteuid(), timeout=2.0)
    result, channel = client.hold_decision(DecisionAsk("process.spawn"))
    assert channel is None
    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.PEER_IDENTITY_UNSUPPORTED


def test_a_credential_the_kernel_cannot_give_is_an_answer(
    listening: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter's own refusal to read a credential is the contract's problem code."""

    class Withholding:
        def establish(self, connection: socket.socket) -> object:
            raise PeerCredentialUnavailable("the kernel reported no identity for the peer")

    monkeypatch.setattr(binding, "select_peer_identity", lambda platform: Withholding())
    client = SocketClient(listening, expected_uid=os.geteuid(), timeout=2.0)
    result, channel = client.hold_decision(DecisionAsk("process.spawn"))
    assert channel is None
    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.PEER_CREDENTIAL_UNAVAILABLE
