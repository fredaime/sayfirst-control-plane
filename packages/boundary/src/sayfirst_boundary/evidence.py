# SPDX-License-Identifier: Apache-2.0
"""Outcome records, bounded, and honest about what the bound cost.

Article 10 requires asynchronous bounded emission with declared gaps: "sequence
numbers and an explicit dropped marker, so a store under pressure never produces
a clean record by losing part of one". Both halves matter. The bound is what
keeps a governed program from being held up by its own evidence; the marker is
what stops the resulting record from reading as complete.

The sequence counts every record the boundary MADE, not every record that got
out, so a gap is visible as a jump. A log that renumbered what survived would
produce an unbroken sequence describing an incomplete history.

## The marker is stamped when a record LEAVES, not when it is made

The first version stamped it at creation, and that is wrong in a way that only
shows under sustained pressure: a record can be made, survive, and then be
overtaken by later drops before it is ever emitted. With room for two and five
records made, the survivors are four and five, and four had been stamped while
only two were lost — so the first record a reader saw declared two gaps where
three had opened. Under-reporting a gap is the same failure as not declaring
one, just quieter.

Stamping on the way out fixes it because every dropped record is older than
every surviving one — the bound always sheds the oldest — so the count of drops
at the moment a record is emitted is exactly the number of lower-sequenced
records the reader will never see. A sink that refuses a record is counted the
same way, and the records behind it in the same flush carry the higher count.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Record:
    """One outcome, and how much was lost before it."""

    sequence: int
    capability: str
    decision_ref: str
    outcome_digest: str | None
    at: str
    dropped_before: int


@dataclass(frozen=True)
class _Pending:
    """A record that has been made but not yet emitted.

    It deliberately has no `dropped_before`: that number is not known until the
    record leaves, because a drop can happen after this one was made.
    """

    sequence: int
    capability: str
    decision_ref: str
    outcome_digest: str | None
    at: str


class OutcomeLog:
    """Hold at most `capacity` records, and say how many did not fit."""

    def __init__(
        self,
        *,
        capacity: int,
        sink: Callable[[Record], None],
        clock: Callable[[], datetime],
    ) -> None:
        if capacity < 1:
            raise ValueError("an outcome log holds at least one record")
        self._pending: deque[_Pending] = deque()
        self._capacity = capacity
        self._sink = sink
        self._clock = clock
        self._sequence = 0
        self._dropped = 0

    @property
    def dropped(self) -> int:
        """How many records this log has lost, to its bound or to its sink."""
        return self._dropped

    def record(self, *, capability: str, decision_ref: str, outcome_digest: str | None) -> None:
        """Make a record. Never blocks, never raises, never waits on the sink."""
        self._sequence += 1
        if len(self._pending) == self._capacity:
            self._pending.popleft()
            self._dropped += 1
        self._pending.append(
            _Pending(
                sequence=self._sequence,
                capability=capability,
                decision_ref=decision_ref,
                outcome_digest=outcome_digest,
                at=self._clock().isoformat(),
            )
        )

    def flush(self) -> None:
        """Hand what is held to the sink, counting whatever it refuses.

        The marker is read per record rather than once for the batch, so a sink
        that fails partway through is declared to the records behind it.
        """
        while self._pending:
            pending = self._pending.popleft()
            entry = Record(
                sequence=pending.sequence,
                capability=pending.capability,
                decision_ref=pending.decision_ref,
                outcome_digest=pending.outcome_digest,
                at=pending.at,
                dropped_before=self._dropped,
            )
            try:
                self._sink(entry)
            except Exception:
                self._dropped += 1
