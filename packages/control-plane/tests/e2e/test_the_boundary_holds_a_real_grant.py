# SPDX-License-Identifier: Apache-2.0
"""The boundary against a real daemon: a real socket, real grants, real signals.

Layer 0 was built against doubles. Doubles are where its two worst defects hid —
a test double that returned a list where the real channel blocks, and one that
ended a stream where the real one keeps it open — so a suite that never meets
the daemon proves the boundary agrees with the author's idea of the daemon.

This is the other half. Each case starts the published `serve` command with a
written policy, drives `sayfirst_boundary.Boundary` over the socket it opens,
and asserts on what the daemon actually did. What is under test is the SEAM:
the grant arriving on a held channel, the signals that end it, and the refusals
that must never become permission.

The daemon reloads its policy every two seconds, which is what makes the
version-change case reachable from a test rather than only from a diagram.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from _daemon import ALLOW, ARGUMENTS, DENY, REPOSITORY, SOURCES, SUSPEND, _Daemon, _rule
from sayfirst_boundary import CouldNotAsk, Denied, Suspended
from sayfirst_boundary.errors import AskRefused
from sayfirst_contract.binding.http_unix_socket.client import SocketClient, _UnixConnection
from sayfirst_contract.binding.http_unix_socket.routes import DOCUMENT_MEDIA_TYPE
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.grants import GrantEndReason, GrantSignal, GrantSignalKind


def test_an_allow_runs_the_body_and_is_recorded(daemon) -> None:  # type: ignore[no-untyped-def]
    running = daemon(ALLOW)
    boundary, client, written = running.boundary()
    ran = False
    with boundary.request("example.effect", ARGUMENTS) as grant:
        ran = True
        grant.record_outcome("sha256:" + "5" * 64)
    boundary.flush()
    boundary.close()

    assert ran is True
    assert client.asks == 1
    assert [record.outcome_digest for record in written] == ["sha256:" + "5" * 64]
    assert written[0].dropped_before == 0


def test_the_same_act_again_does_not_ask_the_daemon(daemon) -> None:  # type: ignore[no-untyped-def]
    """The grant doing its job: acting again without asking (article 10)."""
    running = daemon(ALLOW)
    boundary, client, _ = running.boundary()
    for _ in range(3):
        with boundary.request("example.effect", ARGUMENTS):
            pass
    boundary.close()
    assert client.asks == 1, "a held grant must cover the acts it was minted for"


def test_different_arguments_are_a_different_question(daemon) -> None:  # type: ignore[no-untyped-def]
    running = daemon(ALLOW)
    boundary, client, _ = running.boundary()
    with boundary.request("example.effect", ARGUMENTS):
        pass
    with boundary.request("example.effect", {"to": "other@example.test"}):
        pass
    boundary.close()
    assert client.asks == 2, "a pinned arguments digest does not cover a different call"


def test_a_deny_does_not_run_the_body_and_is_never_cached(daemon) -> None:  # type: ignore[no-untyped-def]
    running = daemon(ALLOW + "\n" + DENY)
    boundary, client, _ = running.boundary()
    for _ in range(2):
        ran = False
        with pytest.raises(Denied), boundary.request("example.refused", ARGUMENTS):
            ran = True
        assert ran is False
    boundary.close()
    assert client.asks == 2, "a denial must be asked again, never remembered as an answer"


def test_a_suspend_raises_and_does_not_run_the_body(daemon) -> None:  # type: ignore[no-untyped-def]
    running = daemon(ALLOW + "\n" + SUSPEND)
    boundary, client, _ = running.boundary()
    ran = False
    with pytest.raises(Suspended) as raised, boundary.request("example.waits", ARGUMENTS):
        ran = True
    boundary.close()
    assert ran is False
    assert raised.value.capability == "example.waits"
    assert client.asks == 1


def test_a_capability_no_rule_covers_is_refused_not_allowed(daemon) -> None:  # type: ignore[no-untyped-def]
    """Absence is not permission. The daemon has no rule for this at all."""
    running = daemon(ALLOW)
    boundary, _, _ = running.boundary()
    ran = False
    with pytest.raises((Denied, CouldNotAsk)), boundary.request("example.unknown", ARGUMENTS):
        ran = True
    boundary.close()
    assert ran is False


def test_a_daemon_that_is_gone_fails_closed(daemon) -> None:  # type: ignore[no-untyped-def]
    """The fourth thing that is not an outcome. It must not become permission."""
    running = daemon(ALLOW)
    boundary, _, _ = running.boundary()
    running.stop()
    ran = False
    with pytest.raises(CouldNotAsk) as raised, boundary.request("example.effect", ARGUMENTS):
        ran = True
    boundary.close()
    assert ran is False
    assert raised.value.retryable is True, "an unreachable daemon is worth asking again"


def test_a_policy_change_ends_a_held_grant(daemon) -> None:  # type: ignore[no-untyped-def]
    """Article 10's headline: a grant is bound to the version it was issued under.

    What this proves, exactly: after the policy version changes, the next act
    ASKS AGAIN rather than being covered by the grant issued under the old one.

    What it does NOT prove, and the distinction was measured rather than
    assumed: that the `grant_ended` SIGNAL is what ended it. The daemon closes
    the stream in the same act as sending that signal, so the reader reaches
    end-of-stream too, and `ending()` tests a lost connection before it tests a
    read signal. Mutating the signal branch away leaves this test green.

    The signal path is held by `test_the_ending_signal_names_its_reason` below,
    which reads the frames itself, and by the unit tests in
    `packages/boundary/tests/test_signals.py`. This case is about the outcome a
    caller sees; that one is about the reason the plane gave.
    """
    running = daemon(ALLOW)
    boundary, client, _ = running.boundary()
    with boundary.request("example.effect", ARGUMENTS):
        pass
    assert client.by_capability["example.effect"] == 1

    running.rewrite_policy(
        _rule("allow-one", "example.effect", "allow") + "\n" + DENY,
        reason="a second revision, which changes the version",
    )
    # The daemon consults its reload age when something asks, so give it both:
    # more than the two-second age, and a request to consult it on. That
    # request uses a DIFFERENT capability, and the assertion below counts only
    # the original one — otherwise the prodding would drive the number it is
    # being read for.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        time.sleep(0.5)
        with pytest.raises(Denied), boundary.request("example.refused", ARGUMENTS):
            pass
        with boundary.request("example.effect", ARGUMENTS):
            pass
        if client.by_capability["example.effect"] > 1:
            break
    boundary.close()
    assert client.by_capability["example.effect"] > 1, (
        "the grant survived a policy version change: it was issued under one "
        "version and honoured under another"
    )


def test_a_daemon_that_stops_while_a_grant_is_held_ends_it(daemon) -> None:  # type: ignore[no-untyped-def]
    """A lost channel ends its grants whatever their lifetime says.

    The dangerous shape is the opposite: a boundary that keeps honouring a
    three-hundred-second grant after the authority that issued it went away.
    """
    running = daemon(ALLOW)
    boundary, _, _ = running.boundary()
    with boundary.request("example.effect", ARGUMENTS):
        pass
    running.stop()

    ran = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with boundary.request("example.effect", ARGUMENTS):
                ran = True
        except CouldNotAsk:
            break
        time.sleep(0.25)
    boundary.close()
    assert ran is False, "the grant outlived the authority that issued it"


def test_the_records_carry_a_sequence_and_declare_no_gap(daemon) -> None:  # type: ignore[no-untyped-def]
    running = daemon(ALLOW)
    boundary, _, written = running.boundary()
    for index in range(4):
        with boundary.request("example.effect", ARGUMENTS) as grant:
            grant.record_outcome(f"sha256:{index}" + "0" * 63)
    boundary.flush()
    boundary.close()
    assert [record.sequence for record in written] == [1, 2, 3, 4]
    assert {record.dropped_before for record in written} == {0}


def test_the_ending_signal_names_its_reason(daemon) -> None:  # type: ignore[no-untyped-def]
    """The signal path itself, read off the wire from the real daemon.

    The case above cannot see this: the daemon ends the stream in the same act
    as ending the grant, so a boundary that ignored signals entirely would
    still stop honouring the grant, and the test would still pass. Measured —
    mutating the signal branch away left it green.

    So this one skips the boundary and reads the channel. It asserts the plane
    actually SAYS why, with the reason the constitution names, which is what a
    third-party holder is entitled to act on.
    """
    from sayfirst_contract.grants import GrantEndReason, GrantSignalKind

    running = daemon(ALLOW)
    client = SocketClient(socket_path=running.socket_path, expected_uid=os.geteuid(), timeout=10.0)
    result, channel = client.hold_decision(
        DecisionAsk(
            capability="example.effect",
            scope="local",
            arguments_digest="sha256:" + "1" * 64,
        )
    )
    assert result.is_ok, result
    assert channel is not None and channel.grant is not None, "the allow minted no grant"
    try:
        running.rewrite_policy(
            _rule("allow-one", "example.effect", "allow") + "\n" + DENY,
            reason="a revision that ends the grant above",
        )
        # Prod the daemon so it consults its reload age, on a second connection
        # so this one carries nothing but signals.
        prod = SocketClient(
            socket_path=running.socket_path, expected_uid=os.geteuid(), timeout=10.0
        )
        deadline = time.monotonic() + 30
        signals = []
        while time.monotonic() < deadline and not signals:
            time.sleep(0.5)
            _, spare = prod.hold_decision(DecisionAsk(capability="example.refused", scope="local"))
            if spare is not None:
                spare.close()
            for signal in channel.signals():
                signals.append(signal)
                if signal.kind is GrantSignalKind.GRANT_ENDED:
                    break
        endings = [s for s in signals if s.kind is GrantSignalKind.GRANT_ENDED]
        assert endings, f"the plane ended the grant without saying so: {signals}"
        assert endings[-1].reason is GrantEndReason.POLICY_VERSION_CHANGED
        assert endings[-1].grant_id == channel.grant.grant_id
    finally:
        channel.close()


#: The open command-line client lives in its own repository, beside this one.
#: It is invoked as a SUBPROCESS rather than imported: the client depends on the
#: contract and never on the server (article 13), and a process boundary is the
#: honest way to exercise it from here without pretending otherwise.
CLIENT_REPO = REPOSITORY.parent / "sf-cli-lt"


@pytest.mark.skipif(
    not (CLIENT_REPO / "src" / "sayfirst_cli" / "ask.py").is_file(),
    reason=(
        "the open command-line client is not checked out beside this repository; "
        "its own gate covers `ask` against a canned daemon, and this case adds "
        "only the real one"
    ),
)
@pytest.mark.parametrize(
    ("capability", "code", "word"),
    [("example.effect", 0, "allow"), ("example.refused", 1, "deny")],
)
def test_the_published_client_asks_the_real_daemon(daemon, capability, code, word) -> None:  # type: ignore[no-untyped-def]
    """`sayfirst ask` against a daemon that is actually deciding.

    Its own suite drives a canned daemon, which proves the rendering and the
    exit codes. This proves the two agree about the wire — the place where a
    client and a server that were only ever tested apart tend to differ.
    """
    running = daemon(ALLOW + "\n" + DENY)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(CLIENT_REPO / "src"),
            *(str(item) for item in SOURCES),
            *filter(None, [os.environ.get("PYTHONPATH")]),
        ]
    )
    finished = subprocess.run(
        [
            sys.executable,
            # The published entry point is the console script, which resolves to
            # `main:run`. `-m sayfirst_cli.main` imports the module and exits 0
            # in silence — there is no `__main__` guard — so invoking it that way
            # would test nothing while looking like a pass.
            "-c",
            "from sayfirst_cli.main import run; run()",
            "ask",
            "--capability",
            capability,
            "--scope",
            "local",
            "--socket",
            str(running.socket_path),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert finished.returncode == code, (finished.stdout, finished.stderr)
    assert word in finished.stdout.lower(), finished.stdout


# ---------------------------------------------------------------------------
# The second walk. Each case below names, in its docstring, the change to the
# PRODUCT that would make it fail; a case that survives its own mutation is a
# case that measures nothing, and every one of these was mutated once before
# it was trusted. The plan behind them was reviewed twice before a line was
# written, and every finding was checked against the source before adoption.
# ---------------------------------------------------------------------------

#: The absolute value `packages/boundary/tests/test_digest.py` pins for this
#: document. Copied, not computed: an oracle that called the function under
#: test would agree with any canonicalisation at all.
FRENCH_DIGEST = "sha256:ccf5583b48d3244bb20029567f98f14609067138766ce70944eb54bbead90801"


def _grant_threads() -> list[threading.Thread]:
    """Every live reader thread, which is one per channel a boundary still holds."""
    return [item for item in threading.enumerate() if item.name.startswith("sayfirst-grant-")]


def _until(predicate: Callable[[], object], *, timeout: float, every: float = 0.1) -> bool:
    """Condition-based waiting with a deadline; a sleep is never the assertion."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(every)
    return bool(predicate())


class _Frames:
    """Read a held channel's frames on a thread, because `signals()` blocks."""

    def __init__(self, channel) -> None:  # type: ignore[no-untyped-def]
        self._seen: list[GrantSignal] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._read, args=(channel,), daemon=True)
        self._thread.start()

    def _read(self, channel) -> None:  # type: ignore[no-untyped-def]
        try:
            for signal in channel.signals():
                with self._lock:
                    self._seen.append(signal)
        except Exception:
            pass

    def snapshot(self) -> list[GrantSignal]:
        with self._lock:
            return list(self._seen)

    def endings(self) -> list[GrantSignal]:
        return [s for s in self.snapshot() if s.kind is GrantSignalKind.GRANT_ENDED]

    def heartbeats(self) -> list[GrantSignal]:
        return [s for s in self.snapshot() if s.kind is GrantSignalKind.HEARTBEAT]


def _raw(  # type: ignore[no-untyped-def]
    running: _Daemon,
    method: str,
    target: str,
    document: object | None = None,
    *,
    accept: str = SocketClient.DOCUMENT_ACCEPT,
) -> tuple[int, dict]:
    """One request the published client cannot be made to send, over its own connection."""
    connection = _UnixConnection(running.socket_path, os.geteuid(), 10.0)
    try:
        headers = {"Accept": accept}
        body = None
        if document is not None:
            body = json.dumps(document)
            headers["Content-Type"] = DOCUMENT_MEDIA_TYPE
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def _problem_code(document: dict) -> object:
    problem = document.get("problem", document)
    return problem.get("code") if isinstance(problem, dict) else None


def _effect_decision_ids(running: _Daemon, scope: str) -> set[str]:
    """The decisions one scope's chain records, read raw: `SocketClient` has no reader."""
    status, document = _raw(
        running, "GET", f"/scopes/{scope}/evidence?contract_generation=1&from_sequence=1"
    )
    if status != 200:
        return set()
    entries = document.get("entries", [])
    return {
        str(entry["body"]["decision_id"])
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("body"), dict)
        and "decision_id" in entry["body"]
    }


def _hold(running: _Daemon, client: SocketClient, digest: str):  # type: ignore[no-untyped-def]
    """Hold one grant on the allow rule over a raw channel; the caller closes it."""
    result, channel = client.hold_decision(
        DecisionAsk(capability="example.effect", scope="local", arguments_digest=digest)
    )
    assert result.is_ok, result
    assert channel is not None and channel.grant is not None, "the allow minted no grant"
    return channel


# -- O1 ---------------------------------------------------------------------


def test_a_grants_own_lifetime_ends_it_and_the_daemon_says_so(daemon) -> None:  # type: ignore[no-untyped-def]
    """A one-second lifetime, and the frame that says `expired`.

    The boundary half proves the grant stops being honoured: an act, an
    immediate second act that HITS (without which a never-caching boundary
    would pass), then an act after the lifetime that asks again. It cannot
    tell whether local arithmetic or the daemon's `grant_ended(expired)` did
    the ending — the daemon closes the stream in the same act, so the
    connection-lost path fires first. The raw half is the discriminating
    observation: on a second channel, the ending arrives with `EXPIRED`
    before the stream ends.

    Mutation: at `decision_routes.py:108`, publish the `grant_ended` frame
    with `reason=None` while still closing the stream. Every boundary
    assertion here still holds; only the reason assertion reddens. Stopping
    `tick()` is NOT a mutation of this case: the issuing connection's own
    watcher (`http_surface.py:840`) ends the grant with `EXPIRED` regardless.
    """
    running = daemon(_rule("allow-short", "example.effect", "allow", lifetime=1))
    boundary, client, _ = running.boundary()
    with boundary.request("example.effect", ARGUMENTS):
        pass
    with boundary.request("example.effect", ARGUMENTS):
        pass
    assert client.answered == 1, "the grant was not honoured even before its lifetime"

    channel = _hold(running, running.client(), "sha256:" + "2" * 64)
    frames = _Frames(channel)
    try:
        time.sleep(1.5)
        with boundary.request("example.effect", ARGUMENTS):
            pass
        assert client.answered == 2, "a grant was honoured past its lifetime"
        assert _until(frames.endings, timeout=10), f"no ending arrived: {frames.snapshot()}"
        ending = frames.endings()[-1]
        assert ending.reason is GrantEndReason.EXPIRED, ending
        assert ending.grant_id == channel.grant.grant_id
    finally:
        channel.close()
        boundary.close()


# -- O2 ---------------------------------------------------------------------


class _PausingMapping(dict):  # type: ignore[type-arg]
    """The store's own mapping, with the first lookup `put` makes held open.

    It computes the answer FIRST and pauses after — a stale read, which is the
    race: the caller has seen `None` and is about to act on it while another
    put completes. The pause ends when any store happens or after `hold_for`
    seconds, so a `put` that serialises under a lock (the fix) is never
    deadlocked: the second put blocks on the lock, the wait times out, the
    first stores, and the second then displaces it.

    Nothing of the production `put` is reproduced here. A subclass that
    re-implemented `put` would be testing the subclass.
    """

    def __init__(self, hold_for: float) -> None:
        super().__init__()
        self._stored = threading.Event()
        self._hold_for = hold_for
        self._armed = True
        self.paused = False

    def get(self, key, default=None):  # type: ignore[no-untyped-def, override]
        value = super().get(key, default)
        if self._armed and sys._getframe(1).f_code.co_name == "put":
            self._armed = False
            self.paused = True
            self._stored.wait(self._hold_for)
        return value

    def __setitem__(self, key, value) -> None:  # type: ignore[no-untyped-def, override]
        super().__setitem__(key, value)
        self._stored.set()


def test_racing_puts_do_not_orphan_a_reader(daemon) -> None:  # type: ignore[no-untyped-def]
    """Two threads, one question, both missing the cache at once.

    Each asks — concurrent misses are two asks, and this case does not claim
    otherwise — and each gets a grant. Only ONE may be held afterwards, and
    the other's channel must have been CLOSED: a reader that was displaced
    and not closed keeps a channel and a thread alive for the daemon's whole
    grant lifetime, invisible to the store and to `close()`.

    Mutation: this case is the regression test for the lock in `GrantStore`.
    Removing the lock (or the close-under-lock of the displaced reader)
    restores the interleaving the mapping above forces, and one reader thread
    survives that the store does not hold.
    """
    running = daemon(ALLOW)
    boundary, client, _ = running.boundary()
    baseline = len(_grant_threads())
    mapping = _PausingMapping(hold_for=2.0)
    boundary._store._held = mapping  # beneath the unchanged production put
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []

    def act() -> None:
        try:
            barrier.wait(5)
            with boundary.request("example.effect", ARGUMENTS):
                pass
        except BaseException as error:  # re-raised by the assertion below
            failures.append(error)

    workers = [threading.Thread(target=act) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
    assert not failures, failures
    assert not any(worker.is_alive() for worker in workers)
    assert mapping.paused, "the interleaving was not forced; this case measured nothing"
    assert client.answered == 2, "two concurrent misses each ask; coalescing is not claimed"

    held = len(mapping)
    assert held == 1
    assert _until(lambda: len(_grant_threads()) - baseline == held, timeout=5), (
        f"{len(_grant_threads()) - baseline} live reader thread(s) for {held} held grant: "
        "a displaced reader was never closed"
    )
    boundary.close()
    assert _until(lambda: len(_grant_threads()) == baseline, timeout=5)


# -- O3 ---------------------------------------------------------------------


def test_a_pinned_digest_is_honoured_exactly_from_an_independent_oracle(daemon) -> None:  # type: ignore[no-untyped-def]
    """The rule pins a LITERAL digest; the boundary must compute that one.

    Mutation: `ensure_ascii=True` in `digest.py` escapes the `é`, the digest
    changes, the literal no longer matches, and the allow becomes a denial.
    Daemon side: drop the digest comparison from `Rule.applies` and the
    mismatching act is allowed.
    """
    running = daemon(_rule("allow-pinned", "example.effect", "allow", digest=FRENCH_DIGEST))
    boundary, client, _ = running.boundary()
    with boundary.request("example.effect", {"nom": "Frédéric"}):
        pass
    with pytest.raises(Denied) as raised, boundary.request("example.effect", {"nom": "Frederic"}):
        pass
    boundary.close()
    assert raised.value.reason == "policy_absent"
    assert client.answered == 2


# -- O5 ---------------------------------------------------------------------


def test_the_bounded_log_declares_its_gaps_under_a_real_run(daemon) -> None:  # type: ignore[no-untyped-def]
    """Capacity two, five acts: the two survivors each declare three lost.

    Mutation: stamp `dropped_before` at record time instead of at flush and
    the survivors read `[2, 3]`.
    """
    running = daemon(ALLOW)
    boundary, _, written = running.boundary(capacity=2)
    for index in range(1, 6):
        with boundary.request("example.effect", ARGUMENTS) as grant:
            grant.record_outcome(f"sha256:{index}" + "0" * 63)
    boundary.flush()
    boundary.close()
    assert [record.sequence for record in written] == [4, 5]
    assert [record.dropped_before for record in written] == [3, 3]


# -- O6 ---------------------------------------------------------------------


def test_a_restart_on_the_same_socket_is_recovered_from_and_cleaned_up(daemon) -> None:  # type: ignore[no-untyped-def]
    """The daemon comes back on the same path; the boundary asks again, once.

    `CouldNotAsk` is tolerated any number of times while the socket is absent
    — there is no basis for "at most one". Attempts and answers are counted
    apart: the counter increments before every call, raised or not.

    Mutation: make `Boundary.close()` skip `store.close()` and the final
    thread count stays at one.
    """
    running = daemon(ALLOW)
    boundary, client, _ = running.boundary()
    baseline = len(_grant_threads())
    with boundary.request("example.effect", ARGUMENTS) as first:
        pass
    with boundary.request("example.effect", ARGUMENTS):
        pass
    assert client.answered == 1

    running.restart()
    failures = 0
    recovered: str | None = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and recovered is None:
        try:
            with boundary.request("example.effect", ARGUMENTS) as grant:
                recovered = grant.decision_ref
        except CouldNotAsk:
            failures += 1
            time.sleep(0.25)
    assert recovered is not None, "the boundary never recovered after the restart"
    assert recovered != first.decision_ref, "a decision from the old process was reused"
    assert client.answered == 2
    assert client.asks == 2 + failures
    assert _until(lambda: len(_grant_threads()) - baseline == 1, timeout=5), (
        "the reader of the stopped daemon's channel is still alive"
    )
    boundary.close()
    assert _until(lambda: len(_grant_threads()) == baseline, timeout=5)


# -- O7 ---------------------------------------------------------------------


def test_scope_is_a_condition_not_a_label(daemon) -> None:  # type: ignore[no-untyped-def]
    """The same capability and arguments in another scope is another question.

    Mutation: drop `scope` from the store's key and the `other` lookup finds
    the `local` reader, `grant_use` rejects it on scope, `take` deletes it,
    and the THIRD act asks again — the final hit assertion is what reddens.
    """
    running = daemon(ALLOW)
    boundary, client, _ = running.boundary()
    with boundary.request("example.effect", ARGUMENTS, scope="local"):
        pass
    with (
        pytest.raises(Denied) as raised,
        boundary.request("example.effect", ARGUMENTS, scope="other"),
    ):
        pass
    assert raised.value.reason == "policy_absent"
    with boundary.request("example.effect", ARGUMENTS, scope="local"):
        pass
    boundary.close()
    assert client.by_question == {
        ("local", "example.effect"): 1,
        ("other", "example.effect"): 1,
    }, client.by_question


# -- O9 ---------------------------------------------------------------------


def test_the_daemons_chains_name_every_decision_the_boundary_was_answered(daemon) -> None:  # type: ignore[no-untyped-def]
    """Every decision the client was given is on a chain — the right scope's.

    Chains are per scope (`http_surface.py:769`), so both are read and their
    union compared. Cached acts reuse a reference and add no entry: the
    assertion is on the SET.

    Mutation: stop `_record_effect` writing and the set is short.
    """
    running = daemon(ALLOW)
    boundary, _, _ = running.boundary()
    answered: set[str] = set()
    with boundary.request("example.effect", ARGUMENTS, scope="local") as grant:
        answered.add(grant.decision_ref)
    with (
        pytest.raises(Denied) as raised,
        boundary.request("example.effect", ARGUMENTS, scope="other"),
    ):
        pass
    answered.add(raised.value.decision_ref)
    with boundary.request("example.effect", ARGUMENTS, scope="local") as grant:
        answered.add(grant.decision_ref)
    assert len(answered) == 2, answered

    def recorded() -> set[str]:
        return _effect_decision_ids(running, "local") | _effect_decision_ids(running, "other")

    assert _until(lambda: recorded() == answered, timeout=15), (recorded(), answered)
    boundary.close()


# -- O8 ---------------------------------------------------------------------


@pytest.mark.skipif(
    not (CLIENT_REPO / "src" / "sayfirst_cli" / "ask.py").is_file(),
    reason="the open command-line client is not checked out beside this repository",
)
@pytest.mark.parametrize(
    ("capability", "socket", "code", "stream", "words"),
    [
        ("example.effect", "real", 0, "stdout", ("allow",)),
        ("example.refused", "real", 1, "stdout", ("deny",)),
        ("example.unknown", "real", 1, "stdout", ("deny", "policy_absent")),
        ("example.waits", "real", 5, "stdout", ("suspend",)),
        ("example.effect", "absent", 4, "stderr", ()),
    ],
)
def test_the_published_client_renders_every_answer_on_the_right_stream(  # type: ignore[no-untyped-def]
    daemon, tmp_path: Path, capability, socket, code, stream, words
) -> None:
    """Five things can come back; each has a stream and a LITERAL code.

    No rule at all is a denial (`policy_absent`, exit 1), never a refusal.
    Could-not-ask goes to stderr with exit 4 and writes nothing to stdout.
    The codes are literals here, not read from `exit_codes.py`.

    Mutation: swap `EXIT_SUSPEND` and `EXIT_COULD_NOT_ASK` and two rows fail.
    """
    running = daemon(ALLOW + "\n" + DENY + "\n" + SUSPEND)
    path = running.socket_path if socket == "real" else tmp_path / "nobody-listens.sock"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(CLIENT_REPO / "src"),
            *(str(item) for item in SOURCES),
            *filter(None, [os.environ.get("PYTHONPATH")]),
        ]
    )
    finished = subprocess.run(
        [
            sys.executable,
            "-c",
            "from sayfirst_cli.main import run; run()",
            "ask",
            "--capability",
            capability,
            "--scope",
            "local",
            "--socket",
            str(path),
            "--json",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert finished.returncode == code, (finished.stdout, finished.stderr)
    spoken = finished.stdout if stream == "stdout" else finished.stderr
    silent = finished.stderr if stream == "stdout" else finished.stdout
    assert spoken.strip(), (finished.stdout, finished.stderr)
    assert not silent.strip(), f"{stream} was not the only stream written: {silent!r}"
    for word in words:
        assert word in spoken.lower(), (word, spoken)


# -- M1 ---------------------------------------------------------------------


def test_an_allow_without_a_grant_still_runs_and_is_never_cached(daemon) -> None:  # type: ignore[no-untyped-def]
    """At the daemon's per-principal cap, an allow arrives with no grant.

    `decisions.py:288`: with no reservation the answer is returned and no
    channel is opened. The body runs — it is an allow — and nothing is cached,
    so the next act asks again.

    Mutation: remove the `grant is not None` guard in `Boundary._ask` so a
    grantless stream is handed to `SignalReader`; it raises `ValueError` and
    the valid allow fails.
    """
    running = daemon(ALLOW)
    raw = running.client()
    channels = []
    try:
        for index in range(64):
            channels.append(_hold(running, raw, f"sha256:{index:064x}"))
        boundary, client, _ = running.boundary()
        for _ in range(2):
            ran = False
            with boundary.request("example.effect", ARGUMENTS):
                ran = True
            assert ran is True, "an allow without a grant is still an allow"
        boundary.close()
        assert client.answered == 2, "an allow served without a grant was cached"
    finally:
        for channel in channels:
            channel.close()


# -- M2 ---------------------------------------------------------------------


def test_an_idle_held_connection_is_heartbeat_and_invalidated_unasked(daemon) -> None:  # type: ignore[no-untyped-def]
    """The daemon sweeps while it holds; nothing else needs to ask.

    Two raw channels, no further request on either: a heartbeat arrives on
    each; after a policy rewrite, `grant_ended(policy_version_changed)`
    arrives on each, still unprompted.

    Mutation: make the holding sweep (`http_surface.py:867`) a no-op and no
    frame ever arrives on an idle channel.
    """
    running = daemon(ALLOW)
    raw = running.client()
    held = []
    try:
        for index in range(2):
            channel = _hold(running, raw, f"sha256:{index:064x}")
            held.append((channel, _Frames(channel)))
        assert _until(lambda: all(frames.heartbeats() for _, frames in held), timeout=15), [
            frames.snapshot() for _, frames in held
        ]
        running.rewrite_policy(
            _rule("allow-one", "example.effect", "allow") + "\n" + DENY,
            reason="a revision nobody asked about",
        )
        assert _until(lambda: all(frames.endings() for _, frames in held), timeout=15), [
            frames.snapshot() for _, frames in held
        ]
        for channel, frames in held:
            ending = frames.endings()[-1]
            assert ending.reason is GrantEndReason.POLICY_VERSION_CHANGED, ending
            assert ending.grant_id == channel.grant.grant_id
    finally:
        for channel, _ in held:
            channel.close()


# -- M3 ---------------------------------------------------------------------


def test_a_malformed_question_is_refused_distinctly(daemon) -> None:  # type: ignore[no-untyped-def]
    """Two malformations, two codes, neither ever a body.

    Raw arm: an unknown member is `member_unknown` at 400, before the scope is
    touched. Boundary arm: a capability that is not a string is what the
    published schema refuses, `request_malformed`, surfaced as `AskRefused`;
    a refusal is never cached, so the second act asks again.

    Mutation: map contract `Refused` to `CouldNotAsk` in `Boundary._ask` and
    the exception assertion fails.
    """
    running = daemon(ALLOW)
    status, document = _raw(
        running,
        "POST",
        "/decisions",
        {"contract_generation": 1, "capability": "example.effect", "scope": "local", "extra": 1},
        accept=SocketClient.DECISION_ACCEPT,
    )
    assert status == 400, document
    assert _problem_code(document) == "member_unknown", document

    boundary, client, _ = running.boundary()
    for _ in range(2):
        ran = False
        with pytest.raises(AskRefused) as raised, boundary.request(123, ARGUMENTS):  # type: ignore[arg-type]
            ran = True
        assert ran is False
        assert raised.value.problem_code == "request_malformed", raised.value
    boundary.close()
    assert client.answered == 2, "a refusal was remembered as an answer"
