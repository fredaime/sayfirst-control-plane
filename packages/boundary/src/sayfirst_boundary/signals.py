# SPDX-License-Identifier: Apache-2.0
"""What the grant's own connection has said since the grant was issued.

Article 10 gives the channel two things to say — a heartbeat and an ending — and
this reader turns them into the two fields the freshness rule consults. It says
nothing else: a reader that inferred a policy version, or a remaining lifetime,
would be deriving an answer the control plane did not give (article 1).

The end of the stream is the third thing, and it is the one worth being explicit
about: it is **not** the absence of news. The grant is bound to this connection,
so a stream that has ended is a grant that has ended, and `connection_live` goes
false rather than staying true for want of a signal saying otherwise.

## Why this reads on a thread

`GrantChannel.signals()` blocks until a frame arrives or the peer closes — it has
to, because a heartbeat is a push and there is nothing to poll. The first version
of this module pulled that iterator to exhaustion inside a `drain()` the hot path
called, which against the real channel means *blocking until the daemon hangs up*:
a governed program would stop at its first cached act and never resume. The tests
passed because the test double's `signals()` returned a list and stopped, so the
double hid a deadlock rather than exposing one.

So the blocking read lives on its own daemon thread, and the state it maintains is
read under a lock. The cost is one thread per held grant, which is bounded by the
daemon's own admission limits — it issues at most sixty-four connections per
principal — and is the honest price of a push channel. The alternative, polling
the socket with a zero timeout, is wrong in a way that is hard to see: the frame
may already sit in the response's buffer while the socket reports nothing
readable, so the poll would report silence on a channel that had already spoken.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime
from threading import Lock, Thread
from typing import Protocol

from sayfirst_contract.grants import Grant, GrantEndReason, GrantSignal, GrantSignalKind

from .freshness import Held


class _Channel(Protocol):
    """The part of `GrantChannel` this reader uses, and no more."""

    grant: Grant | None

    def signals(self) -> Iterator[GrantSignal]: ...

    def close(self) -> None: ...


class SignalReader:
    """Keep one `Held` current from the signals its channel delivers."""

    def __init__(self, channel: _Channel, *, clock: Callable[[], datetime]) -> None:
        grant = channel.grant
        if grant is None:
            raise ValueError("a signal reader needs the grant its channel delivered")
        self._channel = channel
        self._clock = clock
        self._grant = grant
        self._lock = Lock()
        self._last_heard_at = datetime.fromisoformat(grant.issued_at)
        self._connection_live = True
        self._ended_by: GrantEndReason | None = None
        self._reader = Thread(
            target=self._read_until_the_channel_ends,
            name=f"sayfirst-grant-{grant.grant_id}",
            daemon=True,
        )
        self._reader.start()

    def _read_until_the_channel_ends(self) -> None:
        """Apply signals as they arrive, and end the grant when the channel does.

        Every way out of this loop is the end of the channel: exhaustion is the
        peer's close, and an exception is a channel that has failed. Neither is a
        state in which a grant may still be honoured, so the `finally` is the
        whole point of the method and not its tidying-up.

        The lock is taken per signal, never held across the blocking read, so a
        caller asking what it holds is never waiting on the network.
        """
        try:
            for signal in self._channel.signals():
                with self._lock:
                    self._apply(signal)
        except Exception:
            pass
        finally:
            with self._lock:
                self._connection_live = False

    def _apply(self, signal: GrantSignal) -> None:
        """Record one signal. Called with the lock held."""
        if self._ended_by is not None:
            # An ending is final: a heartbeat arriving after it cannot revive a
            # grant the control plane has already ended.
            return
        self._last_heard_at = datetime.fromisoformat(signal.at)
        if signal.kind is GrantSignalKind.GRANT_ENDED:
            self._ended_by = signal.reason

    def held(self) -> Held:
        """A snapshot of what this reader knows. Never blocks on the network."""
        with self._lock:
            return Held(
                grant=self._grant,
                last_heard_at=self._last_heard_at,
                connection_live=self._connection_live,
                ended_by=self._ended_by,
            )

    def close(self) -> None:
        """Give up the channel, which gives up the grant bound to it.

        Idempotent, because a holder may well abandon a grant it has already
        abandoned. `connection_live` is set here rather than left to the reader
        thread: the caller must not be able to observe a live grant on a channel
        it has just closed, and the thread may not have woken yet.
        """
        with self._lock:
            self._connection_live = False
        self._channel.close()
