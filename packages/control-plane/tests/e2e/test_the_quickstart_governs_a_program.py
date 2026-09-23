# SPDX-License-Identifier: Apache-2.0
"""The three commands of a first run, against the real daemon they start.

    sayfirst-daemon up --quickstart
    sayfirst instrument run --pack subprocess --scope local -- python my_agent.py
    sayfirst-daemon down

Nothing between those lines is told where anything is: the daemon serves at the
default address of its mode, the client given no `--socket` looks at the same
rule's answer, and the pack is designated by the name it ships under. This
module is the evidence that the two distributions really meet there — each
repository's own tests can only hold its own half (article 13 keeps the client
off the server, so the client's suite answers a double).

What is read is what a person would read: the program's own output and exit
status, whether the effect HAPPENED (a file the program creates by spawning
`touch`, because an exit status alone cannot tell a refusal from a spawn that
was let through), and the chain the daemon kept, read back over the same socket.

The policy is the starter the quickstart wrote, edited the way its own comments
say to edit it — one word — so that those comments are held to be true.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing
from pathlib import Path

import pytest
from _daemon import CLIENT_REPO, REPOSITORY, SOURCES
from sayfirst_contract.client import Answered
from sayfirst_contract.transport.socket_client import SocketProfile, connect
from sayfirst_quickstart import launcher as quickstart

#: How long the daemon's asynchronous write of an effect has to appear, and a
#: stopped process to be gone. A deadline written in each module that waits,
#: for the reason the sibling modules give beside theirs.
POLL_SECONDS = 15

BOUNDARY_SOURCE = REPOSITORY / "packages" / "boundary" / "src"
OPERATOR_SOURCE = REPOSITORY / "packages" / "cli" / "src"

#: The client has to be the one that reads a pack by name and finds the default
#: address for itself; a checkout from before that is a different client.
CLIENT_PRESENT = (CLIENT_REPO / "src" / "sayfirst_cli" / "instrument" / "designation.py").is_file()

pytestmark = pytest.mark.skipif(
    not CLIENT_PRESENT,
    reason=(
        "the open command-line client is not checked out beside this repository, or is a "
        "checkout from before it designated a shipped pack by name"
    ),
)

ALLOWED_LINE = 'outcome = "allow"\nreason = "starting a local process is allowed on this machine"'


class _FirstRun:
    """One account's home directory, with the two distributions' commands run under it."""

    def __init__(self, root: Path) -> None:
        self.home = root / "home"
        self.home.mkdir(mode=0o700)
        self.work = root / "work"
        self.work.mkdir()
        self.marker = self.work / "the-effect-happened"
        (self.work / "my_agent.py").write_text(
            "import subprocess\n\n"
            f'subprocess.run(["touch", {str(self.marker)!r}], check=True)\n'
            'print("hello from my_agent")\n',
            encoding="utf-8",
        )
        self.names = quickstart.layout(str(self.home))
        self.address = self.home / ".sayfirst" / "run" / "daemon.sock"
        # `python` has to be found the way a shell finds it, and found to be the
        # interpreter these tests run in: the client here is imported from its
        # source tree, which is not an installation it could lend to another.
        self.environment = {
            **{name: value for name, value in os.environ.items() if name != "XDG_RUNTIME_DIR"},
            "HOME": str(self.home),
            "PATH": os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")]),
            "PYTHONPATH": os.pathsep.join(
                [
                    str(CLIENT_REPO / "src"),
                    *(str(item) for item in SOURCES),
                    str(BOUNDARY_SOURCE),
                    str(OPERATOR_SOURCE),
                    *filter(None, [os.environ.get("PYTHONPATH")]),
                ]
            ),
        }

    def _run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(argv),
            cwd=self.work,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def daemon(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self._run(sys.executable, "-m", "sayfirst_quickstart.command", *arguments)

    def sayfirst(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        """The client, started the way its console script starts it."""
        return self._run(
            sys.executable, "-c", "from sayfirst_cli.main import run; run()", *arguments
        )

    def operator(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        """`sayfirstd`, started the way its console script starts it."""
        return self._run(sys.executable, "-c", "from sayfirstd.main import run; run()", *arguments)

    def governed(self, verb: str = "run") -> subprocess.CompletedProcess[str]:
        """The line of the quickstart, word for word: no socket, a pack by name, `python`."""
        return self.sayfirst(
            "instrument", verb, "--pack", "subprocess", "--scope", "local",
            "--", "python", "my_agent.py",
        )  # fmt: skip

    def the_policy_says(self, outcome: str) -> None:
        """Edit the starter exactly as its own comment says: one word of one rule."""
        text = self.names.policy.read_text(encoding="utf-8")
        assert text.count(ALLOWED_LINE) == 1, "the starter's first rule is not the one edited here"
        self.names.policy.write_text(
            text.replace(ALLOWED_LINE, ALLOWED_LINE.replace('"allow"', f'"{outcome}"', 1)),
            encoding="utf-8",
        )

    def effects(self) -> list[Mapping[str, object]]:
        """Every `effect` entry of the chain, read back over the socket."""
        with closing(connect(SocketProfile(str(self.address)))) as connection:
            result = connection.read_evidence("local", 1)
            assert isinstance(result, Answered), result
            return [entry for entry in result.value["entries"] if entry["kind"] == "effect"]


def _until[T](probe: Callable[[], T | None], describe: Callable[[], object]) -> T:
    deadline = time.monotonic() + POLL_SECONDS
    while True:
        answer = probe()
        if answer:
            return answer
        assert time.monotonic() < deadline, describe()
        time.sleep(0.05)


def _recorded(first: _FirstRun, outcome: str, *, count: int = 1) -> list[Mapping[str, object]]:
    """Wait for the chain to hold `count` effects of this outcome for spawning."""

    def matched() -> list[Mapping[str, object]] | None:
        found = [
            entry
            for entry in first.effects()
            if entry["body"]["capability"] == "process.spawn"
            and entry["body"]["outcome"] == outcome
        ]
        return found if len(found) >= count else None

    return _until(matched, first.effects)


@pytest.fixture
def first(tmp_path: Path) -> Iterator[_FirstRun]:
    run = _FirstRun(tmp_path)
    started = run.daemon("up", "--quickstart")
    assert started.returncode == 0, started.stderr
    assert started.stdout.splitlines()[0] == "SayFirst Control Plane ready"
    try:
        yield run
    finally:
        run.daemon("down")
        record = quickstart.read_record(run.names)
        if record is not None:  # pragma: no cover - only when `down` itself failed
            os.kill(record.pid, signal.SIGTERM)


def test_an_allowed_effect_runs_and_the_real_control_plane_recorded_the_decision(
    first: _FirstRun,
) -> None:
    finished = first.governed()
    assert finished.returncode == 0, finished.stderr
    assert finished.stdout == "hello from my_agent\n"
    assert first.marker.exists()
    (effect,) = _recorded(first, "allow")
    assert effect["body"]["reason"] == "policy_allows"


def test_a_denied_effect_does_not_happen_and_the_denial_is_recorded(first: _FirstRun) -> None:
    first.the_policy_says("deny")
    finished = first.governed()
    assert not first.marker.exists()
    assert finished.returncode == 1
    assert "sayfirst_boundary.errors.Denied" in finished.stderr
    assert "hello" not in finished.stdout
    (effect,) = _recorded(first, "deny")
    assert effect["body"]["reason"] == "policy_denies"


def test_a_suspended_effect_waits_for_a_person_and_runs_once_they_approve(
    first: _FirstRun,
) -> None:
    first.the_policy_says("suspend")
    waiting = first.governed()
    assert not first.marker.exists(), "the effect ran before anybody approved it"
    assert waiting.returncode == 5, waiting.stderr  # the published « suspend »
    said = re.search(r"Suspended: suspended: process\.spawn awaits approval (\S+)", waiting.stderr)
    assert said is not None, waiting.stderr
    approval = said[1]

    shown = first.sayfirst("approvals", "show", "--approval", approval, "--scope", "local")
    assert shown.returncode == 0, shown.stderr
    assert "state: pending" in shown.stdout

    # Asking again while the wait is open is the same wait, and still no effect.
    again = first.governed()
    assert approval in again.stderr and not first.marker.exists()

    approved = first.sayfirst(
        "approvals", "approve", "--approval", approval, "--scope", "local",
        "--reason", "checked by hand",
    )  # fmt: skip
    assert approved.returncode == 0, approved.stderr
    assert "state: approved" in approved.stdout

    finished = first.governed()
    assert finished.returncode == 0, finished.stderr
    assert first.marker.exists()
    (effect,) = _recorded(first, "allow")
    assert effect["body"]["reason"] == "approval_granted"

    # One approval is one execution: the same question, asked again, waits again.
    first.marker.unlink()
    once_more = first.governed()
    assert once_more.returncode == 5 and not first.marker.exists()
    assert "awaits approval" in once_more.stderr and approval not in once_more.stderr


def test_a_verification_proves_the_effect_was_decided_and_claims_nothing_more(
    first: _FirstRun,
) -> None:
    finished = first.governed("verify")
    assert finished.returncode == 0, (finished.stdout, finished.stderr)
    assert finished.stdout.splitlines() == [
        "governed subprocess subprocess.Popen process.spawn events=1",
        "inspected: subprocess",
        "target exit: 0",
    ]
    # The program's own output is on the diagnostic stream, never in the report.
    assert "hello from my_agent" in finished.stderr


def test_a_verification_of_two_different_effects_is_clean(first: _FirstRun) -> None:
    """The multi-connection run. Two spawns with different arguments are two asks,
    so the shipped boundary opens two connections and the plane writes two
    records — one per grant. Both are this run's, told so by the correlation this
    run stamped on every ask, not by a connection identity that differs between
    them. Before that, the second record read as another execution's and the run
    exited 7 with a spurious `unjudged`; the every-shipped-pack gate is the same
    defect across three capabilities.
    """
    program = first.work / "two.py"
    program.write_text(
        "import subprocess\n"
        'subprocess.run(["echo", "one"], check=True)\n'
        'subprocess.run(["echo", "two"], check=True)\n',
        encoding="utf-8",
    )
    finished = first.sayfirst(
        "instrument", "verify", "--pack", "subprocess", "--scope", "local",
        "--", "python", "two.py",
    )  # fmt: skip
    assert finished.returncode == 0, (finished.stdout, finished.stderr)
    assert finished.stdout.splitlines() == [
        "governed subprocess subprocess.Popen process.spawn events=2",
        "inspected: subprocess",
        "target exit: 0",
    ]
    assert "unjudged" not in finished.stdout
    effects = _recorded(first, "allow", count=2)
    assert len({str(e["body"].get("correlation")) for e in effects}) == 1
    assert all(e["body"]["correlation_source"] == "boundary_supplied" for e in effects)


def test_a_verification_of_one_effect_repeated_is_clean(first: _FirstRun) -> None:
    """The same spawn twice, within one grant's lifetime.

    Under `run` the second is a grant hit: answered by the grant the first
    minted, with nothing asked and so nothing recorded — article 10's cache. The
    verifier's proof is one recorded decision per effect it saw, so it used to
    find the second effect without a record, stop it, and report `ungoverned`
    with status 6. A verifying run asks for every effect instead, and the plane
    records each.
    """
    program = first.work / "twice.py"
    program.write_text(
        "import subprocess\n"
        'subprocess.run(["echo", "again"], check=True)\n'
        'subprocess.run(["echo", "again"], check=True)\n',
        encoding="utf-8",
    )
    finished = first.sayfirst(
        "instrument", "verify", "--pack", "subprocess", "--scope", "local",
        "--", "python", "twice.py",
    )  # fmt: skip
    assert finished.returncode == 0, (finished.stdout, finished.stderr)
    assert finished.stdout.splitlines() == [
        "governed subprocess subprocess.Popen process.spawn events=2",
        "inspected: subprocess",
        "target exit: 0",
    ]
    _recorded(first, "allow", count=2)


@pytest.mark.parametrize(
    "spawn",
    [
        pytest.param("close_fds=False", id="through-posix-spawn"),
        pytest.param("cwd='/'", id="through-fork-exec"),
    ],
)
def test_a_spawn_popen_makes_itself_is_one_effect(first: _FirstRun, spawn: str) -> None:
    """`Popen` creates its process through `os.posix_spawn` when it can and through
    `_posixsubprocess.fork_exec` otherwise, and the subprocess pack names both as paths
    it does not interpose. One governed spawn raised two events, and the run reported
    an unjudged effect and status 7 for a program that did nothing around the pack.
    The pack now names them as its point's own `inner_events`, and the verifier pairs
    one with the call it judged when it is that thread's very next event.

    An executable named with a directory and `close_fds=False` takes the first path on
    every interpreter this project supports; a working directory takes the second,
    which raises its own event from Python 3.14 and none before.
    """
    program = first.work / "inner.py"
    program.write_text(
        f'import subprocess\nsubprocess.run(["/bin/true"], check=True, {spawn})\n',
        encoding="utf-8",
    )
    finished = first.sayfirst(
        "instrument", "verify", "--pack", "subprocess", "--scope", "local",
        "--", "python", "inner.py",
    )  # fmt: skip
    assert finished.returncode == 0, (finished.stdout, finished.stderr)
    assert finished.stdout.splitlines() == [
        "governed subprocess subprocess.Popen process.spawn events=1",
        "inspected: subprocess",
        "target exit: 0",
    ]
    assert "unjudged" not in finished.stdout
    assert "not judged" not in finished.stderr


def test_a_verification_of_a_denied_program_is_not_a_pass(first: _FirstRun) -> None:
    """The proof is about what was decided, and a path nobody walked proves nothing."""
    first.the_policy_says("deny")
    finished = first.governed("verify")
    assert finished.returncode == 7, (finished.stdout, finished.stderr)
    assert finished.stdout.splitlines()[0].startswith("not-exercised subprocess ")
    assert not first.marker.exists()


def test_status_finds_the_quickstart_without_being_told_where_it_is(first: _FirstRun) -> None:
    status = first.operator("status")
    assert status.returncode == 0, status.stderr
    assert f"verified: true (server_uid {os.geteuid()}, expected {os.geteuid()})" in status.stdout
    # Per-user, so the caller can write the store it asks about: the grade says
    # so, and the quickstart did not get to say anything kinder (article 7).
    assert "integrity grade: observability (" in status.stdout


def test_with_the_control_plane_down_the_effect_fails_closed_and_is_not_a_denial(
    first: _FirstRun,
) -> None:
    assert first.daemon("down").returncode == 0
    finished = first.governed()
    assert not first.marker.exists()
    assert "sayfirst_boundary.errors.CouldNotAsk" in finished.stderr
    assert "Denied" not in finished.stderr
    assert f"socket: {first.address} (the per-user default" in finished.stderr
    asked = first.sayfirst("ask", "--capability", "process.spawn")
    assert asked.returncode == 4, asked.stderr
    assert "could not ask: unreachable" in asked.stderr
