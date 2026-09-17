# SPDX-License-Identifier: Apache-2.0
"""An in-memory evidence authority for the daemon's process lifetime."""

from __future__ import annotations

from threading import Lock

from sayfirst_control_plane.domain.evidence_chain import EvidenceEntry, EvidenceRecord, chained
from sayfirst_control_plane.domain.scope import validate_scope
from sayfirst_control_plane.ports.evidence_store import StoreLocation


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._chains: dict[str, list[EvidenceEntry]] = {}
        self._lock = Lock()

    def append(self, record: EvidenceRecord) -> EvidenceEntry:
        validate_scope(record.scope)
        with self._lock:
            chain = self._chains.setdefault(record.scope, [])
            entry = chained(record, chain[-1] if chain else None)
            chain.append(entry)
            return entry

    def read_range(
        self, scope: str, *, from_sequence: int, to_sequence: int | None = None
    ) -> tuple[EvidenceEntry, ...]:
        _validate_range(scope, from_sequence, to_sequence)
        with self._lock:
            return tuple(
                entry
                for entry in self._chains.get(scope, ())
                if entry.sequence >= from_sequence
                and (to_sequence is None or entry.sequence <= to_sequence)
            )

    def latest_sequence(self, scope: str) -> int | None:
        validate_scope(scope)
        with self._lock:
            chain = self._chains.get(scope, ())
            return chain[-1].sequence if chain else None

    def location(self) -> StoreLocation:
        return StoreLocation(
            kind="memory",
            root=None,
            retention=(
                "held in the daemon's memory for the life of the process; "
                "nothing survives a restart"
            ),
        )


def _validate_range(scope: str, start: int, end: int | None) -> None:
    validate_scope(scope)
    if start < 1 or (end is not None and end < start):
        raise ValueError("evidence range is invalid")
