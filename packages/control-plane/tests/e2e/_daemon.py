# SPDX-License-Identifier: Apache-2.0
"""The shared harness for a boundary and readers meeting the published daemon."""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_boundary import Boundary, OutcomeLog, Record
from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.decisions import DecisionAsk

REPOSITORY = Path(__file__).resolve().parents[4]
SOURCES = (
    REPOSITORY / "packages" / "contract" / "src",
    REPOSITORY / "packages" / "control-plane" / "src",
)
ME = pwd.getpwuid(os.geteuid()).pw_name
PRINCIPAL = f"user:{ME}"
ARGUMENTS = {"to": "someone@example.test"}


def _rule(
    identifier: str,
    capability: str,
    outcome: str,
    *,
    lifetime: int | None = 300,
    digest: str | None = None,
    review: int | None = None,
) -> str:
    lines = [
        "[[rule]]",
        f'id = "{identifier}"',
        f'capability = "{capability}"',
        'scope = "local"',
        f'principals = ["{PRINCIPAL}"]',
        f'outcome = "{outcome}"',
        f'reason = "the walk says {outcome}"',
    ]
    if lifetime is not None and outcome == "allow":
        lines.append(f"grant_lifetime_seconds = {lifetime}")
    if digest is not None:
        lines.append(f'arguments_digest = "{digest}"')
    if review is not None and outcome == "suspend":
        # How long the person has. The loader defaults it to five minutes, so a
        # rule names it only where the case is about the wait running out.
        lines.append(f"review_deadline_seconds = {review}")
    return "\n".join(lines) + "\n"


def _policy(rules: str, *, reason: str = "the boundary walk") -> str:
    return f'format = 1\n\n[revision]\nreason = "{reason}"\n\n{rules}'


class _Counting:
    """The published client, plus a count of how often it actually asked.

    The whole point of a grant is that a holder acts again WITHOUT asking, so
    "did it ask" is the property, and the only honest way to measure it is at
    the client. Reading the daemon's record would count decisions, which is a
    different number the moment anything is cached.
    """

    def __init__(self, inner: SocketClient) -> None:
        self._inner = inner
        #: Attempts: incremented before the call, so an attempt the daemon
        #: never answered (a socket that was not there) is counted too.
        self.asks = 0
        #: Answers: incremented only when the call returned. The two differ by
        #: exactly the number of attempts that raised, which is what a restart
        #: case must account for rather than assume away.
        self.answered = 0
        #: Per capability, because a total is not a measurement when the test
        #: asks about more than one thing. The first draft of the policy-change
        #: case below asserted on the total and would have passed with the
        #: grant never ending at all: the denial it used to drive the daemon's
        #: reload incremented the same counter it was reading.
        self.by_capability: dict[str, int] = {}
        #: Per (scope, capability): scope is a condition of the question, so
        #: the same capability in two scopes is two questions.
        self.by_question: dict[tuple[str, str], int] = {}
        # An unsynchronised read-modify-write is not an oracle for a case that
        # asks from two threads at once.
        self._lock = threading.Lock()

    def hold_decision(self, ask: DecisionAsk):  # type: ignore[no-untyped-def]
        with self._lock:
            self.asks += 1
            self.by_capability[ask.capability] = self.by_capability.get(ask.capability, 0) + 1
            question = (ask.scope, ask.capability)
            self.by_question[question] = self.by_question.get(question, 0) + 1
        answer = self._inner.hold_decision(ask)
        with self._lock:
            self.answered += 1
        return answer


#: How long a daemon has to announce its socket before the wait gives up.
ANNOUNCE_SECONDS = 15


def _launch(config: Path) -> subprocess.Popen:
    """Start the published command on a written config, and wait for its socket.

    The wait is bounded. A daemon that neither announces itself nor exits would
    otherwise hang every module that shares this harness, and every restart
    inside one, with nothing said about why — so on expiry the process is
    killed and what it wrote is the failure.
    """
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [*(str(item) for item in SOURCES), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "sayfirst_control_plane.cli", "serve", "--config", str(config)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    announced: list[str] = []
    reader = threading.Thread(target=lambda: announced.append(_first_line(process)), daemon=True)
    reader.start()
    reader.join(ANNOUNCE_SECONDS)
    ready = announced[0] if announced else ""
    if not ready.startswith("serving "):
        process.kill()
        process.wait(timeout=20)
        raise AssertionError(
            f"the daemon did not announce a socket within {ANNOUNCE_SECONDS} s: "
            f"said {ready!r}, wrote {_written(process)!r}"
        )
    return process


def _first_line(process: subprocess.Popen) -> str:
    assert process.stdout is not None
    return process.stdout.readline()


def _written(process: subprocess.Popen) -> str:
    """What the process wrote to its error stream, once it has stopped writing."""
    try:
        return process.stderr.read() if process.stderr else ""
    except (OSError, ValueError):  # the stream was already given up
        return ""


class _Daemon:
    def __init__(self, run: Path, process: subprocess.Popen, socket_path: Path) -> None:
        self.run = run
        self.process = process
        self.socket_path = socket_path
        self.policy = run / "policy.toml"
        self.config = run / "daemon.toml"
        #: Whether this process was stopped on purpose. A case that stops the
        #: daemon to prove what a caller sees then stops it again at teardown,
        #: and that is not the same event as a daemon that exited by itself.
        self.stopped = False

    def rewrite_policy(self, rules: str, *, reason: str) -> None:
        self.policy.write_text(_policy(rules, reason=reason), encoding="utf-8")
        os.chmod(self.policy, 0o600)

    def stop(self) -> None:
        """Stop the process, and say so if it had already stopped itself.

        A daemon that exited on its own leaves nothing at the socket path, so
        the next dial in the test reads as « No such file or directory » — a
        client problem standing in for a server that died, measured
        2026-09-15. Its exit status and what it wrote are the only evidence of
        what happened, so they are what this raises. A daemon a case stopped
        itself is a different event, and stopping it again is idempotent.
        """
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=20)
            self.stopped = True
            return
        if self.stopped:
            return
        raise AssertionError(
            f"the daemon exited on its own with status {self.process.returncode}: "
            f"{_written(self.process)!r}"
        )

    def restart(self) -> None:
        """Stop, and start a new process on the SAME config and socket path."""
        self.stop()
        self.process = _launch(self.config)
        self.stopped = False

    def client(self) -> SocketClient:
        """The published client, raw: for a case that holds channels itself."""
        return SocketClient(socket_path=self.socket_path, expected_uid=os.geteuid(), timeout=10.0)

    def boundary(self, *, capacity: int = 64) -> tuple[Boundary, _Counting, list[Record]]:
        written: list[Record] = []
        client = _Counting(self.client())
        log = OutcomeLog(capacity=capacity, sink=written.append, clock=lambda: datetime.now(UTC))
        return (
            Boundary(client=client, principal_reference=PRINCIPAL, log=log),  # type: ignore[arg-type]
            client,
            written,
        )


@pytest.fixture
def daemon(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Start the published command, and stop it however the test ends."""
    started: list[_Daemon] = []

    def start(rules: str) -> _Daemon:
        run = tmp_path / f"run{len(started)}"
        run.mkdir(mode=0o700)
        policy = run / "policy.toml"
        policy.write_text(_policy(rules), encoding="utf-8")
        os.chmod(policy, 0o600)
        socket_path = run / "daemon.sock"
        config = run / "daemon.toml"
        config.write_text(
            "# SPDX-License-Identifier: Apache-2.0\n"
            "[socket]\n"
            'mode = "per_user"\n'
            f'path = "{socket_path}"\n'
            "[policy]\n"
            f'path = "{policy}"\n'
            "[evidence]\n"
            f'path = "{run / "evidence"}"\n',
            encoding="utf-8",
        )
        running = _Daemon(run, _launch(config), socket_path)
        started.append(running)
        return running

    yield start
    # Every daemon is stopped even when one of them reports having exited on
    # its own; the first such report is what the test fails with.
    exited: list[AssertionError] = []
    for running in started:
        try:
            running.stop()
        except AssertionError as report:
            exited.append(report)
    if exited:
        raise exited[0]


ALLOW = _rule("allow-one", "example.effect", "allow")
DENY = _rule("deny-one", "example.refused", "deny")
SUSPEND = _rule("suspend-one", "example.waits", "suspend")
#: A suspension whose wait runs out inside a test run. Its own capability, so
#: that the walk a person completes is never racing a two-second deadline it
#: was not written to test.
LAPSES = _rule("suspend-lapses", "example.lapses", "suspend", review=2)
#: The wait that bounds `LAPSES`, so a case counts it from one place.
LAPSE_SECONDS = 2
