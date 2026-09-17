# SPDX-License-Identifier: Apache-2.0
"""`sayfirst instrument run`, against a real daemon: a program governed end to end.

Article 9's guard for the open project's packs is anti-vacuity: it refuses to
pass by finding nothing to check, and the day a pack, the engine and
`instrument run` exist is the day something has to actually govern a program
and be watched doing it. This module is that watching. It starts a real
daemon (`_daemon.py`, shared with the rest of this directory), runs the
published client's `instrument run` as a SUBPROCESS with the shipped
`subprocess` pack installed, and reads the chain the daemon wrote back through
the transport — the same three-sided proof
`test_the_reads_answer_from_a_real_daemon.py` runs for the four reads, run
here for the fifth verb.

Three cases, because they are the three shapes an ask takes once a program is
governed rather than a test harness driving the boundary directly: a grant
answers the second of two identical spawns without asking again, a denial
never lets the spawn happen, and a daemon that cannot be reached fails the
same way — closed, not open. Each is read off the two places a person reading
a shell would: the process's own exit code and streams, and — for the allow
and deny cases — the chain the daemon kept, polled to a deadline because the
write that proves it is asynchronous (`_daemon.py`'s own `_until`, copied here
for the reason its docstring gives beside the first copy: a deadline written
twice is not written once).

## Where a failure crosses from this client's to the program's

`instrument/launch.py`'s own docstring draws the line at the hand-off: every
failure BEFORE it is the invocation's own mistake, raised as `LaunchMisuse`
and reported exit 64; every failure AFTER it is the program's, and nothing
translates it. A denial or an unreachable daemon is raised inside the
GOVERNED PROGRAM's own `subprocess.run` call, after the hand-off, as
`sayfirst_boundary.errors.Denied` or `...CouldNotAsk` — the program's own
exception to catch, which the two-line apps below do not. So what a shell
sees for either is not a code this client chose for "denied": it is a plain
`Traceback` and CPython's own exit status for an exception nothing caught,
which is 1. The exception's class name and message are legible in that
traceback and are what the two failing cases below assert on, empirically
confirmed by hand against this daemon and this client before this module was
written.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from pathlib import Path

import pytest
from _daemon import REPOSITORY, SOURCES, _Daemon, _rule
from sayfirst_contract.client import Answered
from sayfirst_contract.transport.socket_client import SocketProfile, VerifiedConnection, connect

#: How long the daemon's asynchronous write of an effect has to appear.
#: Shared with `test_the_reads_answer_from_a_real_daemon.py`'s own constant of
#: the same name and the same reason: the chain is written after the answer is
#: on the wire, and a read that arrives first is "not yet" and not "never".
POLL_SECONDS = 15

#: The open command-line client, run as a SUBPROCESS for the reason given
#: beside the same constant in `test_the_reads_answer_from_a_real_daemon.py`:
#: article 13 keeps the client depending on the contract and never on the
#: server, and a process boundary is the honest way to exercise it from here.
CLIENT_REPO = REPOSITORY.parent / "sf-cli-lt"

#: The instrumentation chain's own module, present only once the sibling
#: checkout ships `sayfirst instrument`. Checked apart from `CLIENT_PRESENT`
#: (the reads module's own guard) because a checkout can ship `ask` — and so
#: pass that guard — while still being the branch from before `instrument`
#: landed.
INSTRUMENT_COMMANDS = CLIENT_REPO / "src" / "sayfirst_cli" / "instrument" / "commands.py"
SUBPROCESS_PACK = CLIENT_REPO / "src" / "sayfirst_cli" / "packs" / "subprocess"
CLIENT_PRESENT = (CLIENT_REPO / "src" / "sayfirst_cli" / "ask.py").is_file()
INSTRUMENT_PRESENT = INSTRUMENT_COMMANDS.is_file()

pytestmark = [
    pytest.mark.skipif(
        not CLIENT_PRESENT,
        reason="the open command-line client is not checked out beside this repository",
    ),
    pytest.mark.skipif(
        not INSTRUMENT_PRESENT,
        reason="the sibling client checkout does not ship the instrumentation chain",
    ),
]

#: The boundary's own sources, added to what the reads module's `SOURCES`
#: composes: the GOVERNED PROGRAM's process imports `sayfirst_boundary`
#: directly — `instrument/launch.py` installs it in front of the program, in
#: that same process — which none of the four read commands ever do.
BOUNDARY_SOURCE = REPOSITORY / "packages" / "boundary" / "src"

#: One rule each, built with `_daemon.py`'s own `_rule` — scope `local`,
#: principal `user:<ME>` (the module's global, baked into `_rule` itself), no
#: digest pinned — the way `test_the_boundary_holds_a_real_grant.py` already
#: builds one-off rules rather than this module adding a second `ALLOW`/`DENY`
#: pair naming a capability `_daemon.py` itself never uses.
ALLOW_SPAWN = _rule("allow-spawn", "process.spawn", "allow")
DENY_SPAWN = _rule("deny-spawn", "process.spawn", "deny")

#: A program that asks for the same effect twice: the second `subprocess.run`
#: is a grant hit, and the chain proves that by holding one `effect` entry and
#: not two. It catches nothing — a refusal is its own exception to propagate —
#: exactly like `governed_programs.py`'s `SPAWNING_APP` on the sibling side.
ASKS_TWICE = """\
import subprocess

subprocess.run(["true"], check=True)
subprocess.run(["true"], check=True)
print("done")
"""


def _marker_app(marker: Path) -> str:
    """A program that spawns a marker file instead of `true`.

    A refusal that still let the process spawn would be invisible to an exit
    code or a chain entry alone — the boundary only records what a wrapper
    tells it to. Only the marker's own absence proves the spawn never
    happened, which is why the deny and unreachable cases below use this
    instead of `ASKS_TWICE`.
    """
    return f"""\
import subprocess

subprocess.run(["touch", {str(marker)!r}], check=True)
print("done")
"""


def _profile(running: _Daemon) -> SocketProfile:
    """This daemon's address, as the transport's profile names it."""
    return SocketProfile(str(running.socket_path), mode="per_user", daemon_user=None, scope="local")


def _until[T](probe: Callable[[], T | None], describe: Callable[[], object]) -> T:
    """Poll until `probe` answers, or fail at the deadline with what `describe` says.

    Copied from `test_the_reads_answer_from_a_real_daemon.py` rather than
    imported — that module's own note beside its copy is why: it was written
    twice, identically, before, and the second copy is where a deadline gets
    dropped, so each module keeps its own.
    """
    deadline = time.monotonic() + POLL_SECONDS
    while True:
        answer = probe()
        if answer is not None:
            return answer
        assert time.monotonic() < deadline, describe()
        time.sleep(0.05)


def _wait_for_one_effect(
    connection: VerifiedConnection, *, capability: str
) -> Mapping[str, object]:
    """Poll until exactly one `effect` entry of `capability` is on the chain.

    Bounded at exactly one on purpose: `ASKS_TWICE` asks twice and the whole
    claim under test is that the SECOND ask never reaches the daemon, so a
    second matching entry appearing before the deadline is the failure this is
    written to catch, not a race to tolerate.
    """
    seen: list[Mapping[str, object]] = []

    def matched() -> Mapping[str, object] | None:
        result = connection.read_evidence("local", 1)
        assert isinstance(result, Answered), result
        page = result.value
        seen.append(page)
        effects = [
            entry
            for entry in page["entries"]
            if entry["kind"] == "effect" and entry["body"]["capability"] == capability
        ]
        assert len(effects) <= 1, (capability, page)
        return effects[0] if effects else None

    return _until(matched, lambda: seen[-1:])


def _client_environment() -> dict[str, str]:
    """The client's sources first, this repository's next, the boundary's too.

    `_daemon.py`'s `SOURCES` gives the contract and the control plane, exactly
    as `test_the_reads_answer_from_a_real_daemon.py` composes it; this adds
    `BOUNDARY_SOURCE`, which that module never needed because none of the four
    reads import `sayfirst_boundary` — only a GOVERNED PROGRAM's process does
    (article 13: the client's environment is what its own process needs, and a
    program running inside it needs more than the client alone does).
    """
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(CLIENT_REPO / "src"),
            *(str(item) for item in SOURCES),
            str(BOUNDARY_SOURCE),
            *filter(None, [os.environ.get("PYTHONPATH")]),
        ]
    )
    return environment


def _instrument_run(*args: str) -> subprocess.CompletedProcess[str]:
    """`sayfirst instrument run ...`, exactly as the console script would run it.

    Invoked the way `test_the_reads_answer_from_a_real_daemon.py` invokes
    every read — `-c "from sayfirst_cli.main import run; run()"`, never
    `-m sayfirst_cli.main` — for the reason given beside that module's own
    `_client`: the `-m` form puts the working directory on the import path as
    a side effect of how the interpreter starts, which is exactly the thing
    `instrument run`'s own launcher is under test for supplying itself.
    """
    argv = [
        sys.executable,
        "-c",
        "from sayfirst_cli.main import run; run()",
        "instrument",
        "run",
        *args,
    ]
    return subprocess.run(
        argv, env=_client_environment(), capture_output=True, text=True, timeout=60
    )


def test_a_governed_program_asks_once_and_the_chain_records_it(daemon, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Two identical spawns, one ask: the second is a grant hit and asks nothing.

    `ALLOW_SPAWN` pins no digest and gives the grant its ordinary 300-second
    lifetime, so the second `subprocess.run(["true"], ...)` in `ASKS_TWICE` is
    answered from the boundary's own cache and the daemon is never asked about
    it — which is the property `_wait_for_one_effect`'s "exactly one" bound
    exists to catch a violation of.
    """
    running = daemon(ALLOW_SPAWN)
    app = tmp_path / "app.py"
    app.write_text(ASKS_TWICE, encoding="utf-8")
    # Taken after the daemon fixture's own `run0` directory and `app.py` exist,
    # so it names what the GOVERNED RUN below may not add to `tmp_path`.
    before = {entry.name for entry in tmp_path.iterdir()}

    finished = _instrument_run(
        "--pack",
        str(SUBPROCESS_PACK),
        "--socket",
        str(running.socket_path),
        "--scope",
        "local",
        "--",
        str(app),
    )
    assert finished.returncode == 0, (finished.returncode, finished.stdout, finished.stderr)
    assert "done" in finished.stdout, (finished.stdout, finished.stderr)
    assert finished.stderr == "", finished.stderr

    after = {entry.name for entry in tmp_path.iterdir()}
    assert after == before, (before, after)

    with closing(connect(_profile(running))) as connection:
        effect = _wait_for_one_effect(connection, capability="process.spawn")
    assert effect["body"]["outcome"] == "allow", effect


def test_a_denied_program_does_not_spawn(daemon, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A `deny` answer is the program's own exception, and the spawn never runs.

    `instrument/launch.py`'s docstring draws the this-client/program line at
    the hand-off: the denial happens after it, inside `app.py`'s own
    `subprocess.run`, so what a shell sees is `app.py`'s uncaught
    `sayfirst_boundary.errors.Denied` propagating out of the interpreter —
    CPython's own traceback and exit status (1) for an exception nothing
    caught, not a code this client chose. The number happens to match what a
    reader might expect of a deliberately chosen "denied" exit status, which
    is exactly why this docstring states the mechanism rather than only the
    number: the two are not the same claim.
    """
    running = daemon(DENY_SPAWN)
    marker = tmp_path / "spawned"
    app = tmp_path / "app.py"
    app.write_text(_marker_app(marker), encoding="utf-8")

    finished = _instrument_run(
        "--pack",
        str(SUBPROCESS_PACK),
        "--socket",
        str(running.socket_path),
        "--scope",
        "local",
        "--",
        str(app),
    )
    assert finished.returncode == 1, (finished.returncode, finished.stdout, finished.stderr)
    assert "Denied" in finished.stderr, (finished.stdout, finished.stderr)
    assert "process.spawn" in finished.stderr, (finished.stdout, finished.stderr)
    assert "done" not in finished.stdout, (finished.stdout, finished.stderr)
    assert not marker.exists(), (marker, finished.stdout, finished.stderr)

    with closing(connect(_profile(running))) as connection:
        effect = _wait_for_one_effect(connection, capability="process.spawn")
    assert effect["body"]["outcome"] == "deny", effect


def test_an_unreachable_daemon_fails_closed(tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """No daemon at the address: the program's own `CouldNotAsk`, and no spawn.

    Doctrine D4, named in `sayfirst_boundary.errors.CouldNotAsk`'s own
    docstring: the absence of a refusal is not permission. No `daemon` fixture
    runs for this case — nothing is listening at this socket path at all — so
    the first `subprocess.run` in `_marker_app` raises before a `Popen` is
    ever created, the same way `test_a_denied_program_does_not_spawn` asserts
    for a `deny`: exit 1, CPython's own traceback for the boundary's uncaught
    exception, no marker.
    """
    marker = tmp_path / "spawned"
    app = tmp_path / "app.py"
    app.write_text(_marker_app(marker), encoding="utf-8")
    absent_socket = tmp_path / "no-daemon-here.sock"

    finished = _instrument_run(
        "--pack",
        str(SUBPROCESS_PACK),
        "--socket",
        str(absent_socket),
        "--scope",
        "local",
        "--",
        str(app),
    )
    assert finished.returncode == 1, (finished.returncode, finished.stdout, finished.stderr)
    assert "CouldNotAsk" in finished.stderr, (finished.stdout, finished.stderr)
    assert "done" not in finished.stdout, (finished.stdout, finished.stderr)
    assert not marker.exists(), (marker, finished.stdout, finished.stderr)
