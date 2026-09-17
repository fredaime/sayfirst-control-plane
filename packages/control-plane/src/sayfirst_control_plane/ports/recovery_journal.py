# SPDX-License-Identifier: Apache-2.0
"""The coordination journal: where the limits of evidence coverage are recorded (C3).

Evidence is emitted asynchronously (article 10), so a process that stops
uncleanly may have lost events nobody can inventory. The journal records, per
scope, when a producer epoch opened and, later, that it closed cleanly or was
reconciled after an unclean stop. It is authoritative for that bookkeeping
and for nothing else: it holds no event payload, reconstructs no decision,
and is never a second decision store. An epoch that is open at the next start
is unknown event coverage, whatever the decision inventory says.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .evidence_store import StoreLocation


class RecoveryJournalUnavailable(RuntimeError):
    """The journal of a scope cannot be read or appended; never an empty journal."""


@dataclass(frozen=True)
class JournalRecord:
    """One journal line: the record kind, the epoch it names, and what it says of it."""

    scope: str
    position: int
    record: str
    epoch_id: str
    store_id: str | None
    from_sequence: int | None
    marker_sequence: int | None
    marker_hash: str | None


class RecoveryJournal(Protocol):
    VERSION = 1

    def open_epoch(
        self, scope: str, epoch_id: str, *, store_id: str | None, from_sequence: int
    ) -> None: ...

    def epoch_clean(
        self, scope: str, epoch_id: str, *, marker_sequence: int | None, marker_hash: str | None
    ) -> None: ...

    def epoch_reconciled(
        self, scope: str, epoch_id: str, *, marker_sequence: int | None, marker_hash: str | None
    ) -> None: ...

    def open_epochs(self, scope: str) -> tuple[JournalRecord, ...]: ...

    def location(self) -> StoreLocation: ...
