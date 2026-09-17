# SPDX-License-Identifier: Apache-2.0
"""Arrange contract scenario replay through HTTP over Unix sockets."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from ...decisions import DecisionAsk
from ...generation import NegotiatedClient
from ...golden import Scenario
from ...grants import Grant, grant_use
from .client import SocketClient


@dataclass
class _SocketSession:
    scenario: Scenario
    client: NegotiatedClient
    deadline_callback: Callable[[Scenario], None]
    policy_callback: Callable[[Scenario, Mapping[str, object]], None]

    def pass_deadline(self) -> None:
        """Put the arranged daemon past the wait of the suspension it just opened.

        A scenario that scripts `resolve: "expire"` needs the wait to run out
        and asserts the state a read renders afterwards; it does not script how
        long the wait is, because that is the deployment's own rule. So a
        daemon arranged for it must suspend with a wait shorter than the
        seconds this session will spend here, and must render `expired` as of
        the instant a read is taken rather than only after a sweep it schedules
        itself.

        By default that is a real wait, because a daemon this harness did not
        build has no clock it can be asked to move. A harness that composed the
        daemon passes `pass_deadline` and moves the instant instead, which is
        what the server's own acceptance run does.
        """
        self.deadline_callback(self.scenario)

    def use_grant(self, grant: Mapping[str, object], ask: DecisionAsk) -> str:
        """Apply the published holder rule under the arrangement the scenario scripts.

        Two members of `given` are that arrangement and are read here and
        nowhere else: `connection_live` places the holder after the loss of
        the connection its grant is bound to, and `grant_lifetime_seconds`
        places it at the end of the lifetime the scenario buys. A scenario
        that scripts neither has its holder act at once (articles 3 and 10).
        """
        held = Grant.from_document(grant)
        issued_at = datetime.fromisoformat(held.issued_at)
        lifetime = self.scenario.given.grant_lifetime_seconds
        at = issued_at + timedelta(seconds=lifetime if lifetime is not None else 0)
        return grant_use(
            held,
            ask,
            held.conditions.principal_reference,
            now=at,
            connection_live=self.scenario.given.connection_live is not False,
        ).value

    def change_policy(self, policy: Mapping[str, object]) -> None:
        self.policy_callback(self.scenario, policy)

    def close(self) -> None:
        pass


class SocketHarness:
    """Arrange each scenario against its explicitly configured daemon socket.

    A daemon replayed here answers the whole published binding, and the three
    scenarios that end a wait are the ones that say so most plainly: they ask,
    read where the suspension stands, act on it or let it run out, and read
    again. So a daemon arranged for one of them serves `read_approval` and
    `resolve_approval`, keeps the suspension its own answer named, and renders
    its state as of the instant it is read. What the scenario does not say is
    how long a wait lasts or who the person is — the first is the deployment's
    rule and the second is the connection's principal — and neither is a member
    of any fixture.
    """

    def __init__(
        self,
        socket_paths: Mapping[str, str | Path],
        *,
        expected_uid: int | None = None,
        timeout: float = 5.0,
        deadline_wait_seconds: float = 61.0,
        pass_deadline: Callable[[Scenario], None] | None = None,
        change_policy: Callable[[Scenario, Mapping[str, object]], None] | None = None,
    ) -> None:
        self.socket_paths = {name: Path(path) for name, path in socket_paths.items()}
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.timeout = timeout
        self.deadline_callback = pass_deadline or (
            lambda scenario: time.sleep(deadline_wait_seconds)
        )
        self.policy_callback = change_policy or (lambda scenario, policy: None)

    def arrange(self, scenario: Scenario) -> _SocketSession:
        try:
            socket_path = self.socket_paths[scenario.name]
        except KeyError as exc:
            raise LookupError(f"no daemon socket configured for {scenario.name!r}") from exc
        client = NegotiatedClient(
            SocketClient(socket_path, expected_uid=self.expected_uid, timeout=self.timeout)
        )
        return _SocketSession(scenario, client, self.deadline_callback, self.policy_callback)


__all__ = ["SocketHarness"]
