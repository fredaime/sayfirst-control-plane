# SPDX-License-Identifier: Apache-2.0
"""The append-only decision authority port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sayfirst_contract.decisions import Decision

from ..domain.foreign import core_owned
from .evidence_store import StoreLocation


class DecisionAlreadyExists(ValueError):
    pass


class ScopeRequired(ValueError):
    pass


class DecisionStoreUnavailable(RuntimeError):
    """A known refusal before any byte was written, or a scope the store cannot serve.

    Nothing was committed by the operation that raised it. It is not an
    absence: a read that raises it consulted an authority that could not
    answer, and the route publishes `decision_store_unavailable` for exactly
    that, never `decision_not_found` (articles 2, 3).
    """


class DecisionAppendIndeterminate(RuntimeError):
    """A write that began and whose completion the store cannot establish (C2).

    A short write, a sync error or an exception after the first byte: the
    record may have committed. The caller answers no usable decision, cancels
    what it reserved, and never asserts that no decision occurred; recovery of
    the scope's tail decides what the bytes say, and a complete line found
    there is a committed decision the caller never received (R4).
    """


@dataclass(frozen=True)
class DecisionPosition:
    """Where a store committed a record: the store it names and its strictly increasing position.

    Opaque identifiers, never clocks; neither is recycled after recovery. An
    effect entry carries this so a recovery can pair every committed decision
    with its evidence by identity (C4).
    """

    store_id: str
    position: int


class DecisionStore(Protocol):
    VERSION = 1

    def append(self, decision: Decision) -> DecisionPosition: ...

    def get(self, scope: str, decision_ref: str) -> Decision | None: ...

    def location(self) -> StoreLocation: ...


def core_owned_decision(decision: object) -> Decision:
    """A decision a store answered with, read once and rebuilt as the core's own.

    The store is the authority for a decision already taken (article 3), so what
    it answers is the answer — but the object carrying it is memory the store
    owns, and a route renders it after reading it. One read, one value.
    """
    return core_owned(
        Decision,
        decision,
        decision_ref=str,
        scope=str,
        capability=str,
        decided_at=str,
        contract_generation=int,
        extra=dict,
    )


def core_owned_position(position: object) -> DecisionPosition:
    """The position a store answered an append with, as the core's own value."""
    return core_owned(DecisionPosition, position, store_id=str, position=int)
