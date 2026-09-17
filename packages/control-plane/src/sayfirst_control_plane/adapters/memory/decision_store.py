# SPDX-License-Identifier: Apache-2.0
"""A process-local append-only decision authority, for tests and policy-less composition."""

from __future__ import annotations

from copy import deepcopy
from threading import RLock
from uuid import uuid4

from sayfirst_contract.decisions import Decision

from ...ports.decision_store import DecisionAlreadyExists, DecisionPosition, ScopeRequired
from ...ports.evidence_store import StoreLocation


class MemoryDecisionStore:
    VERSION = 1

    def __init__(self) -> None:
        self._lock = RLock()
        self._decisions: dict[tuple[str, str], Decision] = {}
        self._positions: dict[tuple[str, str], DecisionPosition] = {}
        self._store_ids: dict[str, str] = {}
        self._next: dict[str, int] = {}

    def append(self, decision: Decision) -> DecisionPosition:
        key = (decision.scope, decision.decision_ref)
        with self._lock:
            if key in self._decisions:
                raise DecisionAlreadyExists(key)
            store_id = self._store_ids.setdefault(decision.scope, f"memory:{uuid4()}")
            position = self._next.get(decision.scope, 0) + 1
            self._next[decision.scope] = position
            self._decisions[key] = deepcopy(decision)
            placed = DecisionPosition(store_id, position)
            self._positions[key] = placed
            return placed

    def get(self, scope: str, decision_ref: str) -> Decision | None:
        if not scope:
            raise ScopeRequired("a decision read must name a scope")
        with self._lock:
            decision = self._decisions.get((scope, decision_ref))
            return None if decision is None else deepcopy(decision)

    def position_of(self, scope: str, decision_ref: str) -> DecisionPosition | None:
        if not scope:
            raise ScopeRequired("a decision read must name a scope")
        with self._lock:
            return self._positions.get((scope, decision_ref))

    def location(self) -> StoreLocation:
        return StoreLocation(
            kind="memory",
            root=None,
            retention=(
                "held in the daemon's memory for the life of the process; "
                "nothing survives a restart, so no decision taken here can be "
                "explained after one"
            ),
        )
