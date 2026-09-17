# SPDX-License-Identifier: Apache-2.0
"""The held grants, keyed on exactly the questions they answer.

A grant's conditions ARE its key: scope, capability, principal and the pinned
arguments digest are what the control plane minted it for, and asking anything
else is asking a different question. So there is no matching to write here — the
conditions are compared as a whole, and a near miss is a miss.

`take` returns a grant that may be used, or nothing. It never returns one for
the caller to test: a store that handed out stale grants would be relying on
every caller to apply the freshness rule, which is as many chances to forget as
there are callers. An ended grant is discarded and its channel closed on the way
out, because the channel is what was holding it.

## Why there is a lock

A boundary is used from more than one thread, and two threads missing the cache
on the same question at the same moment each come back with a grant. That is
correct: two asks, two grants, and the daemon admits both. What must not happen
is what the first version of `put` allowed — read `None`, be overtaken by the
other thread's store, then store over it: the overtaken reader was never closed,
so its channel and its thread stayed alive for the daemon's whole grant lifetime,
invisible to the store and to `close()`. The e2e case
`test_racing_puts_do_not_orphan_a_reader` forces that interleaving and is the
regression test for this lock. Nothing under the lock touches the network: a
reader's `close` is a socket close, and `ending` is arithmetic.
"""

from __future__ import annotations

from datetime import datetime
from threading import Lock

from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.grants import GrantConditions

from .freshness import Ending, ending
from .signals import SignalReader


class GrantStore:
    """Every grant this boundary holds, at most one per question."""

    def __init__(self) -> None:
        self._held: dict[GrantConditions, SignalReader] = {}
        self._lock = Lock()

    def put(self, reader: SignalReader) -> None:
        """Hold this reader for its question, closing whichever one it displaces."""
        conditions = reader.held().grant.conditions
        with self._lock:
            existing = self._held.get(conditions)
            if existing is not None and existing is not reader:
                existing.close()
            self._held[conditions] = reader

    def take(
        self,
        ask: DecisionAsk,
        principal_reference: str,
        *,
        now: datetime,
    ) -> SignalReader | None:
        """A reader whose grant covers this ask, or nothing at all."""
        key = GrantConditions(
            scope=ask.scope,
            capability=ask.capability,
            principal_reference=principal_reference,
            arguments_digest=ask.arguments_digest,
        )
        with self._lock:
            reader = self._held.get(key)
            if reader is None:
                return None
            if ending(reader.held(), ask, principal_reference, now=now) is Ending.LIVE:
                return reader
            del self._held[key]
            reader.close()
            return None

    def close(self) -> None:
        """Give up every channel, and with it every grant."""
        with self._lock:
            readers = tuple(self._held.values())
            self._held.clear()
        for reader in readers:
            reader.close()
