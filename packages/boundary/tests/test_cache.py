# SPDX-License-Identifier: Apache-2.0
"""The store answers with a usable grant or with nothing.

Keyed on the grant's own conditions, which are exactly the question it answers:
scope, capability, principal and the pinned arguments digest. A near miss is a
miss — article 3 gives an unknown input no more permissive reading — and an
ended grant is discarded on the way out rather than returned for the caller to
re-test.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_boundary.cache import GrantStore
from sayfirst_boundary.signals import SignalReader
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.grants import (
    Grant,
    GrantConditions,
    GrantEndReason,
    GrantSignal,
    GrantSignalKind,
)

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
VERSION = "sha256:" + "a" * 64
DIGEST = "sha256:" + "1" * 64
PRINCIPAL = "user:build"
#: Real seconds a wait may take before it is a failure. Sized for a shared
#: runner under load, where two reader threads can take whole seconds to be
#: scheduled; a wait still ends the instant its condition holds.
DEADLINE = 30.0


def _grant(*, capability: str = "example.effect", digest: str | None = DIGEST) -> Grant:
    return Grant(
        grant_id="g-1",
        decision_ref="dec-1",
        policy_version=VERSION,
        issued_at=NOW.isoformat(),
        lifetime_seconds=300,
        expires_at=(NOW + timedelta(seconds=300)).isoformat(),
        heartbeat_seconds=10,
        conditions=GrantConditions("local", capability, PRINCIPAL, digest),
    )


class _Stream:
    def __init__(self, grant: Grant, signals: list[GrantSignal] | None = None) -> None:
        self.grant = grant
        self._signals = signals or []
        self.closed = False
        self._arrived = threading.Condition()
        self._finished = False

    def deliver(self, signal: GrantSignal) -> None:
        with self._arrived:
            self._signals.append(signal)
            self._arrived.notify_all()

    def finish(self) -> None:
        with self._arrived:
            self._finished = True
            self._arrived.notify_all()

    def signals(self) -> Iterator[GrantSignal]:
        while True:
            with self._arrived:
                while not self._signals and not self._finished:
                    self._arrived.wait()
                if self._signals:
                    yield self._signals.pop(0)
                    continue
                return

    def close(self) -> None:
        self.closed = True
        self.finish()


def _reader(grant: Grant, signals: list[GrantSignal] | None = None) -> SignalReader:
    return SignalReader(_Stream(grant, signals), clock=lambda: NOW)


def _until(predicate, what: str) -> None:
    """Wait for a condition, never for a duration.

    The bound is measured on the clock, not counted in ticks: a tick of the
    event's wait takes ten milliseconds on an idle host and far longer on a
    loaded one, and counting ticks read a slow runner as a timeout while the
    condition was still on its way (measured on a shared runner, 2026-09-16).
    """
    pause = threading.Event()
    started = time.monotonic()
    while not predicate():
        assert pause.wait(0.01) is False
        assert time.monotonic() - started < DEADLINE, f"timed out waiting until {what}"


def _ask(*, capability: str = "example.effect", digest: str | None = DIGEST) -> DecisionAsk:
    return DecisionAsk(capability=capability, scope="local", arguments_digest=digest)


@pytest.fixture
def store() -> Iterator[GrantStore]:
    """A store that is always given up.

    Each held grant runs a reader thread that parks on its channel, so a test
    that walks away from a store leaves a thread waiting until the process
    exits. Four of these tests did. The leak is harmless at this scale and is
    exactly the kind of thing that stops being harmless quietly, so the fixture
    closes rather than each test remembering to.
    """
    held = GrantStore()
    try:
        yield held
    finally:
        held.close()


def test_a_stored_grant_answers_the_question_it_was_minted_for(store: GrantStore) -> None:
    store.put(_reader(_grant()))
    assert store.take(_ask(), PRINCIPAL, now=NOW + timedelta(seconds=1)) is not None


def test_a_different_capability_finds_nothing(store: GrantStore) -> None:
    store.put(_reader(_grant()))
    assert store.take(_ask(capability="other.effect"), PRINCIPAL, now=NOW) is None


def test_different_arguments_find_nothing(store: GrantStore) -> None:
    store.put(_reader(_grant()))
    assert store.take(_ask(digest="sha256:" + "2" * 64), PRINCIPAL, now=NOW) is None


def test_a_different_principal_finds_nothing(store: GrantStore) -> None:
    store.put(_reader(_grant()))
    assert store.take(_ask(), "user:someone-else", now=NOW) is None


def test_an_expired_grant_is_discarded_rather_than_returned(store: GrantStore) -> None:
    store.put(_reader(_grant()))
    assert store.take(_ask(), PRINCIPAL, now=NOW + timedelta(seconds=300)) is None
    # and it is gone, not merely refused once
    assert store.take(_ask(), PRINCIPAL, now=NOW + timedelta(seconds=1)) is None


def test_an_ended_grant_is_discarded_and_its_stream_closed(store: GrantStore) -> None:
    ended = GrantSignal(
        kind=GrantSignalKind.GRANT_ENDED,
        grant_id="g-1",
        policy_version=VERSION,
        at=(NOW + timedelta(seconds=5)).isoformat(),
        reason=GrantEndReason.POLICY_VERSION_CHANGED,
        contract_generation=1,
    )
    stream = _Stream(_grant())
    reader = SignalReader(stream, clock=lambda: NOW)
    store.put(reader)
    stream.deliver(ended)
    _until(lambda: reader.held().ended_by is not None, "the ending is applied")
    assert store.take(_ask(), PRINCIPAL, now=NOW + timedelta(seconds=6)) is None
    assert stream.closed is True


def test_closing_the_store_closes_every_stream_it_holds(store: GrantStore) -> None:
    first, second = _Stream(_grant()), _Stream(_grant(capability="other.effect"))
    store.put(SignalReader(first, clock=lambda: NOW))
    store.put(SignalReader(second, clock=lambda: NOW))
    store.close()
    assert (first.closed, second.closed) == (True, True)


def test_closing_the_store_ends_the_threads_its_grants_were_running() -> None:
    """The resource property, pinned rather than assumed.

    Each held grant parks a reader thread on its channel. If `close` did not
    reach them, a long-lived process would accumulate one per distinct question
    it had ever asked — and would do so silently, which is how this kind of leak
    is normally discovered much later.
    """
    # Counted by name, never as a delta over the process: a reader another
    # test left running ends on its own schedule, and a target computed before
    # it did so is one this test could wait for forever (seen once, 30 s).
    first, second = _grant(), _grant(capability="other.effect")
    names = {f"sayfirst-grant-{first.grant_id}", f"sayfirst-grant-{second.grant_id}"}
    held = GrantStore()
    held.put(_reader(first))
    held.put(_reader(second))
    _until(lambda: names <= _reader_thread_names(), "both readers are running")
    held.close()
    _until(lambda: not (names & _reader_thread_names()), "both reader threads have ended")


def _reader_thread_names() -> set[str]:
    return {
        thread.name for thread in threading.enumerate() if thread.name.startswith("sayfirst-grant-")
    }
