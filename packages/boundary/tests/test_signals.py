# SPDX-License-Identifier: Apache-2.0
"""What the channel tells a holder, and what it must never be read as.

Two defects shaped this file, and both were invisible to the version of it that
used a list-backed double:

* **A stream that ends after saying something still ends the grant.** The first
  implementation only noticed the end of the stream when the stream had said
  nothing at all, so a heartbeat followed by the daemon dying left the grant
  reading as live. That is the fail-open direction, which is the one that
  matters.
* **The real channel blocks.** `GrantChannel.signals()` waits for a frame or a
  close, so pulling it to exhaustion on the hot path waits for the daemon to
  hang up. A double that returns a list and stops cannot show that; the doubles
  here block exactly where the real one does, which is why `_Blocking` exists.

Waiting is condition-based throughout. A sleep long enough to be reliable here
would be a sleep long enough to hide a regression, and a short one is a race that
passes on this machine and fails on a busier one.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_boundary.signals import SignalReader
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
DEADLINE = 5.0


def _grant() -> Grant:
    return Grant(
        grant_id="g-1",
        decision_ref="dec-1",
        policy_version=VERSION,
        issued_at=NOW.isoformat(),
        lifetime_seconds=300,
        expires_at=(NOW + timedelta(seconds=300)).isoformat(),
        heartbeat_seconds=10,
        conditions=GrantConditions("local", "example.effect", "user:build", DIGEST),
    )


def _signal(kind: GrantSignalKind, reason: GrantEndReason | None, at: datetime) -> GrantSignal:
    return GrantSignal(
        kind=kind,
        grant_id="g-1",
        policy_version=VERSION,
        at=at.isoformat(),
        reason=reason,
        contract_generation=1,
    )


class _Blocking:
    """A channel that blocks for a frame exactly as the real one does.

    `deliver` hands one signal to the reader; `finish` ends the stream. Until one
    of those happens, `signals()` is parked — which is the whole property the
    list-backed double could not express.
    """

    def __init__(self) -> None:
        self.grant = _grant()
        self.closed = False
        self._queue: list[GrantSignal] = []
        self._arrived = threading.Condition()
        self._finished = False

    def deliver(self, signal: GrantSignal) -> None:
        with self._arrived:
            self._queue.append(signal)
            self._arrived.notify_all()

    def finish(self) -> None:
        with self._arrived:
            self._finished = True
            self._arrived.notify_all()

    def signals(self) -> Iterator[GrantSignal]:
        while True:
            with self._arrived:
                while not self._queue and not self._finished:
                    self._arrived.wait()
                if self._queue:
                    yield self._queue.pop(0)
                    continue
                return

    def close(self) -> None:
        self.closed = True
        self.finish()


def _reader(channel: _Blocking) -> SignalReader:
    return SignalReader(channel, clock=lambda: NOW)


def _until(predicate, what: str) -> None:
    """Wait for a condition, never for a duration."""
    deadline = threading.Event()
    waited = 0.0
    while not predicate():
        assert deadline.wait(0.01) is False
        waited += 0.01
        assert waited < DEADLINE, f"timed out waiting until {what}"


def test_a_new_reader_holds_a_live_grant_heard_from_at_issue() -> None:
    channel = _Blocking()
    reader = _reader(channel)
    held = reader.held()
    assert held.connection_live is True
    assert held.ended_by is None
    assert held.last_heard_at == datetime.fromisoformat(held.grant.issued_at)
    reader.close()


def test_asking_what_is_held_never_waits_for_the_network() -> None:
    """The deadlock the first implementation had. This test would have hung.

    The channel is parked with nothing to say — the normal state of a live grant
    between heartbeats — and the reader must answer anyway.
    """
    channel = _Blocking()
    reader = _reader(channel)
    for _ in range(3):
        assert reader.held().connection_live is True
    reader.close()


def test_a_heartbeat_moves_the_last_time_we_heard_anything() -> None:
    beat_at = NOW + timedelta(seconds=10)
    channel = _Blocking()
    reader = _reader(channel)
    channel.deliver(_signal(GrantSignalKind.HEARTBEAT, None, beat_at))
    _until(lambda: reader.held().last_heard_at == beat_at, "the heartbeat is applied")
    assert reader.held().ended_by is None
    assert reader.held().connection_live is True
    reader.close()


def test_an_ending_is_recorded_and_is_final() -> None:
    ended_at = NOW + timedelta(seconds=20)
    channel = _Blocking()
    reader = _reader(channel)
    channel.deliver(
        _signal(GrantSignalKind.GRANT_ENDED, GrantEndReason.POLICY_VERSION_CHANGED, ended_at)
    )
    _until(lambda: reader.held().ended_by is not None, "the ending is applied")
    assert reader.held().ended_by is GrantEndReason.POLICY_VERSION_CHANGED
    reader.close()


def test_a_heartbeat_after_an_ending_does_not_revive_the_grant() -> None:
    ended_at = NOW + timedelta(seconds=20)
    channel = _Blocking()
    reader = _reader(channel)
    channel.deliver(_signal(GrantSignalKind.GRANT_ENDED, GrantEndReason.EXPIRED, ended_at))
    _until(lambda: reader.held().ended_by is not None, "the ending is applied")
    channel.deliver(_signal(GrantSignalKind.HEARTBEAT, None, ended_at + timedelta(seconds=1)))
    # Nothing to wait for — the point is that nothing changes — so drive the
    # reader past the second signal by ending the stream and then checking.
    channel.finish()
    _until(lambda: reader.held().connection_live is False, "the stream ends")
    assert reader.held().ended_by is GrantEndReason.EXPIRED
    assert reader.held().last_heard_at == ended_at
    reader.close()


def test_the_end_of_the_stream_ends_the_grant() -> None:
    channel = _Blocking()
    reader = _reader(channel)
    channel.finish()
    _until(lambda: reader.held().connection_live is False, "the stream ends")
    reader.close()


def test_the_end_of_the_stream_ends_the_grant_EVEN_AFTER_a_heartbeat() -> None:
    """The fail-open defect, pinned.

    The first implementation noticed the end of a stream only when the stream had
    said nothing at all. A daemon that heartbeats and then dies is the ordinary
    way this happens, and it left the grant honourable on a dead connection.
    """
    channel = _Blocking()
    reader = _reader(channel)
    channel.deliver(_signal(GrantSignalKind.HEARTBEAT, None, NOW + timedelta(seconds=10)))
    _until(lambda: reader.held().last_heard_at != NOW, "the heartbeat is applied")
    assert reader.held().connection_live is True
    channel.finish()
    _until(lambda: reader.held().connection_live is False, "the stream ends after a heartbeat")
    assert reader.held().ended_by is None, "no signal ended it; the channel did"
    reader.close()


def test_a_channel_that_fails_ends_the_grant_rather_than_holding_it() -> None:
    """A raising channel is a channel that is over, not one that is quiet."""

    class _Failing(_Blocking):
        def signals(self) -> Iterator[GrantSignal]:
            raise OSError("the connection was reset")
            yield  # pragma: no cover - unreachable, makes this a generator

    channel = _Failing()
    reader = _reader(channel)
    _until(lambda: reader.held().connection_live is False, "the failure ends the grant")
    reader.close()


def test_closing_the_reader_closes_the_channel_and_ends_the_grant_at_once() -> None:
    """Set by `close` itself, not left to the thread: a caller must never see a
    live grant on a channel it has just given up."""
    channel = _Blocking()
    reader = _reader(channel)
    reader.close()
    assert reader.held().connection_live is False
    assert channel.closed is True


def test_closing_is_idempotent() -> None:
    channel = _Blocking()
    reader = _reader(channel)
    reader.close()
    reader.close()
    assert reader.held().connection_live is False


def test_a_channel_that_minted_no_grant_is_refused() -> None:
    class _Empty(_Blocking):
        def __init__(self) -> None:
            super().__init__()
            self.grant = None

    with pytest.raises(ValueError):
        _reader(_Empty())
