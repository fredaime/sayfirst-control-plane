# SPDX-License-Identifier: Apache-2.0
"""Arrange one composed daemon per authoritative scenario, on its own socket.

Block 2.6 gave the replay a side-neutral runner and a `Session` protocol; this
implements that protocol over a real daemon rather than over the published
fake. Nothing here reaches into the runner: the client is the published socket
client, the session is the published protocol, and the daemon is the one
`bootstrap.compose` builds.
"""

from __future__ import annotations

import os
import pwd
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.generation import NegotiatedClient
from sayfirst_contract.golden import Regime, Scenario
from sayfirst_control_plane.adapters.nss_directory import NssAccountDirectory
from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.bootstrap import compose
from sayfirst_control_plane.settings import read_settings

ME = os.geteuid()
MY_NAME = pwd.getpwuid(ME).pw_name
_OUTCOME_OF = {Regime.AUTO: "allow", Regime.REVIEW: "suspend", Regime.DENY: "deny"}

#: How long a suspension arranged here waits. The scenarios script a review
#: regime and say nothing about a bound, so the bound is this harness's: it is
#: written onto every suspend rule below and it is the number `pass_deadline`
#: steps over. One number, because a harness that wrote one bound and advanced
#: past a different one would report a lapse it never reached (articles 9, 13).
REVIEW_DEADLINE_SECONDS = 60


class DocumentSocketClient(SocketClient):
    """The published client, asking for the answer that carries no grant channel.

    The binding publishes one selector over two media types, and a scenario
    that scripts `signal_channel: false` scripts the request that selects the
    document. The published client always selects the stream, so the selection
    is made here — by the class member the client itself reads, not by a second
    request written beside it (article 13).
    """

    DECISION_ACCEPT = SocketClient.DOCUMENT_ACCEPT


def scenario_policy(
    policy: Mapping[str, Regime],
    *,
    arrangement: tuple[str, ...] | None = None,
    arranged_capability: str | None = None,
) -> bytes:
    """The scenario's policy as a format-1 file, one rule per arranged entry.

    A scenario that scripts `applying_outcomes` scripts an arrangement of
    several applying rules, and their file order is part of what it proves.
    """
    lines = ["format = 1", "[revision]", 'reason = "scenario arrangement"']
    index = 0
    for capability, regime in policy.items():
        outcomes = (
            arrangement
            if arrangement is not None and capability == arranged_capability
            else (_OUTCOME_OF[regime],)
        )
        for outcome in outcomes:
            lines.extend(
                (
                    "[[rule]]",
                    f'id = "scenario-{index}"',
                    f'capability = "{capability}"',
                    'scope = "local"',
                    f'principals = ["user:{MY_NAME}"]',
                    f'outcome = "{outcome}"',
                    'reason = "scenario rule"',
                )
            )
            if outcome == "suspend":
                # Only a suspension waits, and the loader refuses the member
                # anywhere else, so it is written here and nowhere else.
                lines.append(f"review_deadline_seconds = {REVIEW_DEADLINE_SECONDS}")
            index += 1
    return ("\n".join(lines) + "\n").encode()


class Clock:
    """The wall clock, plus whatever `pass_deadline` has put on top of it.

    A wait's deadline is set by the decision that opened it and judged by the
    read that renders it, so both must be measured by one clock; this is that
    clock, handed to `compose`, and `pass_deadline` is the only caller that
    shifts it. It is the real clock shifted rather than a frozen instant, so a
    daemon arranged here still ages as a deployment does — a scenario that
    scripts no expiry runs at an offset of zero and sees exactly the clock this
    harness always gave it. The offset is read from the serving thread: one
    attribute, replaced whole, never partially observed.
    """

    def __init__(self) -> None:
        self.offset = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset

    def advance(self, seconds: int) -> None:
        self.offset = self.offset + timedelta(seconds=seconds)


class DaemonSession:
    """The runner's session protocol, answered by a daemon on a real socket."""

    def __init__(self, scenario: Scenario, daemon: Daemon, policy_path: Path, clock: Clock) -> None:
        self.scenario = scenario
        self.daemon = daemon
        self.policy_path = policy_path
        self.clock = clock
        self._thread = threading.Thread(target=daemon.serve_forever, daemon=True)
        self._thread.start()
        client = DocumentSocketClient if not scenario.given.signal_channel else SocketClient
        self.client = NegotiatedClient(
            client(Path(daemon.settings.socket_path), expected_uid=ME, timeout=10.0)
        )

    def pass_deadline(self) -> None:
        """Put this daemon's clock past the wait its own policy arranged.

        The clock rather than a real wait: this harness composes the daemon, so
        it owns the instant every part of it reads, and a lapse proven by
        moving that instant is proven rather than raced against a loaded
        machine. The number stepped over is the number written into the rule.
        A third-party daemon this harness did not compose has no such clock,
        which is why the published harness waits instead.
        """
        self.clock.advance(REVIEW_DEADLINE_SECONDS + 1)

    def use_grant(self, grant: Mapping[str, object], ask: DecisionAsk) -> str:
        raise AssertionError("no scenario replayed here asserts what a held grant covers")

    def change_policy(self, policy: Mapping[str, object]) -> None:
        """Replace the authority the daemon reads, as the scenario scripts it."""
        typed = {name: Regime(value) for name, value in policy.items()}
        self.policy_path.write_bytes(scenario_policy(typed))
        os.chmod(self.policy_path, 0o600)

    def close(self) -> None:
        # The runner closes a session when its scenario ends; the harness closes
        # every session when the run ends. Both are right, so this is once.
        self.daemon.stop()
        self._thread.join(timeout=10)


class DaemonHarness:
    """One composed daemon per scenario, each on its own address and authority."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.sessions: list[DaemonSession] = []

    def arrange(self, scenario: Scenario) -> DaemonSession:
        # The address is numbered rather than named: the kernel's address
        # structure holds 108 bytes, and a scenario name under a temporary
        # root spends them (rule L2). Which daemon is which is the order below.
        run = self.root / f"d{len(self.sessions)}"
        run.mkdir(mode=0o700, parents=True)
        policy_path = run / "policy.toml"
        policy_path.write_bytes(
            scenario_policy(
                scenario.given.policy or {},
                arrangement=scenario.given.applying_outcomes,
                arranged_capability=scenario.ask.capability,
            )
        )
        os.chmod(policy_path, 0o600)
        settings = read_settings(
            {
                "socket": {"mode": "per_user", "path": str(run / "daemon.sock")},
                "policy": {"path": str(policy_path)},
                "evidence": {"path": str(run / "evidence")},
            },
            platform="linux",
        )
        clock = Clock()
        services = compose(settings, daemon_uid=ME, clock=clock)
        assert services is not None
        if scenario.given.policy_unavailable:
            # The authority was read at start and is gone by the time the ask
            # arrives, which is the state this scenario is about.
            policy_path.unlink()
        daemon = Daemon(
            settings,
            platform="linux",
            directory=NssAccountDirectory(),
            services=services,
        )
        daemon.start()
        session = DaemonSession(scenario, daemon, policy_path, clock)
        self.sessions.append(session)
        return session

    def close(self) -> None:
        for session in self.sessions:
            session.close()
