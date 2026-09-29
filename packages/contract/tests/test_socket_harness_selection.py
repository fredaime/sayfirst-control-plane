# SPDX-License-Identifier: Apache-2.0
"""Article 13: the published harness asks the question each scenario scripts.

`no_grant_without_signal_channel` scripts a request that does NOT select the event
stream. A harness that always selected the stream made every conforming daemon fail
that scenario through the published command — the run could never be proven.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sayfirst_contract.binding.http_unix_socket.replay as replay_transport
from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.binding.http_unix_socket.replay import SocketHarness
from sayfirst_contract.golden import load_scenarios


@pytest.fixture
def inner_clients(monkeypatch: pytest.MonkeyPatch):
    """Keep the client the harness builds, instead of negotiating over a socket."""
    monkeypatch.setattr(replay_transport, "NegotiatedClient", lambda inner: inner)


def _arranged(name: str, tmp_path: Path) -> SocketClient:
    harness = SocketHarness({name: tmp_path / "unused.sock"}, expected_uid=0)
    return harness.arrange(load_scenarios()[name]).client  # type: ignore[return-value]


def test_a_scenario_without_a_signal_channel_selects_the_document(
    tmp_path: Path, inner_clients: None
) -> None:
    client = _arranged("no_grant_without_signal_channel", tmp_path)
    assert client.DECISION_ACCEPT == SocketClient.DOCUMENT_ACCEPT


@pytest.mark.parametrize(
    "name",
    [
        name
        for name, scenario in load_scenarios().items()
        if scenario.binds_server() and scenario.given.signal_channel is not False
    ],
)
def test_every_other_server_scenario_still_selects_the_stream(
    name: str, tmp_path: Path, inner_clients: None
) -> None:
    client = _arranged(name, tmp_path)
    assert client.DECISION_ACCEPT == SocketClient.DECISION_ACCEPT
