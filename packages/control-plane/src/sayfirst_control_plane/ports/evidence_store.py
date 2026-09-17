# SPDX-License-Identifier: Apache-2.0
"""The authority that owns every scope's evidence-chain invariant."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sayfirst_control_plane.domain.evidence_chain import EvidenceEntry, EvidenceRecord


@dataclass(frozen=True)
class StoreLocation:
    kind: str
    root: Path | None
    retention: str

    def scope_path(self, scope: str) -> Path | None:
        if not scope:
            raise ValueError("scope is required")
        return None if self.root is None else self.root / f"{scope}.jsonl"


class EvidenceStore(Protocol):
    def append(self, record: EvidenceRecord) -> EvidenceEntry: ...

    def read_range(
        self, scope: str, *, from_sequence: int, to_sequence: int | None = None
    ) -> Sequence[EvidenceEntry]: ...

    def latest_sequence(self, scope: str) -> int | None: ...

    def location(self) -> StoreLocation: ...
