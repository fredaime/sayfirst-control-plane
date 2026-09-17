# SPDX-License-Identifier: Apache-2.0
"""The narrow evidence seam used until block 2.4 supplies its store, and the sink a daemon composes.

Nothing here is evidence. The evidence chain is the authority for what the
daemon decided and it is kept per scope, on disk, verifiable; this seam carries
what the daemon *did* — a version reloaded, a grant ended, a person's act
applied or refused — for a reader who wants to see the machine work. Article 3
calls that an observation, and the classes below are held to it: they are
rebuildable from nothing, they may be absent or stale, and no decision is taken
from them.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Final, Protocol

#: How many events the sink a daemon composes keeps. One number, in one place:
#: `docs/deployment.md` publishes it so an operator can tell how much history a
#: live daemon holds, and
#: `packages/control-plane/tests/identity/test_approval_documentation.py` reads
#: it from here and holds the document to it, so a bound changed in the code
#: and not in the document is a failure rather than a drift.
DEFAULT_EVENT_CAPACITY: Final[int] = 1024


@dataclass(frozen=True)
class Event:
    kind: str
    at: datetime
    details: Mapping[str, object]


class Events(Protocol):
    def record(self, kind: str, details: Mapping[str, object], *, at: datetime) -> None: ...


class NullEvents:
    def record(self, kind: str, details: Mapping[str, object], *, at: datetime) -> None:
        pass


class MemoryEvents:
    def __init__(self) -> None:
        self.entries: list[Event] = []

    def record(
        self,
        kind: str,
        details: Mapping[str, object],
        *,
        at: datetime | None = None,
    ) -> None:
        self.entries.append(Event(kind, at or datetime.now(UTC), dict(details)))

    def of_kind(self, kind: str) -> tuple[Event, ...]:
        return tuple(event for event in self.entries if event.kind == kind)


class BoundedEvents:
    """The last `capacity` events, readable by an operator; an authority of nothing.

    An **observation** in the sense of article 3: rebuildable from nothing,
    allowed to be absent or stale, never consulted to decide anything, and gone
    at a restart. What survives an act is elsewhere — the decision records on
    the chain, and the approval record in its store — and a reader who takes
    this for either has taken an observation for an authority.

    Bounded with the discipline article 10 asks of the evidence pipeline. The
    bound is real: past `capacity` — `DEFAULT_EVENT_CAPACITY` entries, where the
    daemon composes it — the oldest entry goes when the newest arrives. What
    makes that honest rather than lossy is that the loss is declared: every
    entry keeps the sequence it was given, so the first sequence read back says
    where the gap is, `dropped()` says how wide it is, and `capacity` says what
    there was room for. A sink that quietly forgot would let a reader take
    silence for « nothing happened », which is the false all-clear article 2
    forbids.

    A lock, because the daemon serves more than one connection: two threads
    recording at once must not share a sequence, and a reader must not see the
    deque mid-append.
    """

    def __init__(self, *, capacity: int = DEFAULT_EVENT_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("a bounded sink keeps at least one event")
        self._lock = Lock()
        self._entries: deque[tuple[int, Event]] = deque(maxlen=capacity)
        #: Everything ever recorded, which is also the sequence of the last
        #: entry. `dropped` is derived from it rather than counted beside it,
        #: so the two cannot drift.
        self._recorded = 0

    @property
    def capacity(self) -> int:
        """The bound this sink was built with, read from the deque that holds it.

        Half of an operator's readout: `dropped()` says how much history is
        gone and this says how much there was room for, and a count of drops
        beside no bound cannot be judged (article 2).
        """
        return self._entries.maxlen or 0

    def record(
        self,
        kind: str,
        details: Mapping[str, object],
        *,
        at: datetime | None = None,
    ) -> None:
        """Keep one event, dropping the oldest when the bound is reached.

        The details are copied, because the caller built that mapping and this
        sink is not entitled to a later edit of it — and because an honest sink
        keeps what it was handed, not a view of what the caller does next.
        """
        with self._lock:
            self._recorded += 1
            self._entries.append(
                (self._recorded, Event(kind, at or datetime.now(UTC), dict(details)))
            )

    def since(self, sequence: int) -> tuple[tuple[int, Event], ...]:
        """Every kept entry after `sequence`, each with the sequence it was given.

        `since(0)` is everything still kept, which is not everything recorded
        when something was dropped; the sequences say which, and `dropped()`
        says how many.
        """
        with self._lock:
            return tuple(entry for entry in self._entries if entry[0] > sequence)

    def dropped(self) -> int:
        """How many entries the bound has discarded, declared rather than hidden."""
        with self._lock:
            return self._recorded - len(self._entries)
