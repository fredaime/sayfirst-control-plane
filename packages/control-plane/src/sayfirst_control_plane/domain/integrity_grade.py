# SPDX-License-Identifier: Apache-2.0
"""Integrity claims derived from a caller's effective store access."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sayfirst_control_plane.ports.path_access import PathFacts

from .write_reach import write_reaches_the_entry_below


class Grade(StrEnum):
    unverified = "unverified"
    observability = "observability"
    evidence = "evidence"


GRADE_RANK = {Grade.unverified: 0, Grade.observability: 1, Grade.evidence: 2}


@dataclass(frozen=True)
class CallerAccess:
    uid: int
    gids: frozenset[int]


@dataclass(frozen=True)
class GradeEvaluation:
    grade: Grade
    basis: str
    evaluated_at: datetime
    paths_inspected: int


def _class_bits(caller: CallerAccess, fact: PathFacts) -> int:
    assert fact.mode is not None
    if caller.uid == fact.owner_uid:
        return (fact.mode >> 6) & 0b111
    if fact.owner_gid in caller.gids:
        return (fact.mode >> 3) & 0b111
    return fact.mode & 0b111


def evaluate_grade(
    caller: CallerAccess, facts: Sequence[PathFacts], *, at: datetime
) -> GradeEvaluation:
    """Return only claims this version can establish from the inspected path."""
    if caller.uid == 0:
        return GradeEvaluation(Grade.observability, "caller_can_write", at, len(facts))
    if not facts or any(
        not fact.exists
        or fact.owner_uid is None
        or fact.owner_gid is None
        or fact.mode is None
        or fact.acl_present is not False
        for fact in facts
    ):
        return GradeEvaluation(Grade.unverified, "access_not_established", at, len(facts))

    reachable = True
    for index, fact in enumerate(facts):
        assert fact.mode is not None
        bits = _class_bits(caller, fact)
        owns = caller.uid == fact.owner_uid
        writable = owns or bool(bits & 0b010)
        if reachable and writable:
            child = facts[index + 1] if index + 1 < len(facts) else None
            # The last inspected path has nothing under it, so writing it is the
            # write; above it the question is the shared one
            # (`domain/write_reach.py`). A component with something under it is
            # a directory, or the walk could not have reached the child.
            reaches = (
                child is None
                or not child.exists
                or write_reaches_the_entry_below(
                    mode=fact.mode,
                    is_directory=True,
                    writer_owns_the_directory=owns,
                    writer_owns_the_entry=child.owner_uid == caller.uid,
                )
            )
            if reaches:
                return GradeEvaluation(Grade.observability, "caller_can_write", at, index + 1)
        if not bool(bits & 0b001):
            reachable = False

    return GradeEvaluation(Grade.unverified, "caller_cannot_write", at, len(facts))


def weakest(grades: Iterable[Grade]) -> Grade:
    values = tuple(grades)
    if not values:
        return Grade.unverified
    return min(values, key=GRADE_RANK.__getitem__)
