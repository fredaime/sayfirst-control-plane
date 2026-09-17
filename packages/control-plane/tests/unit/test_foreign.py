# SPDX-License-Identifier: Apache-2.0
"""The one rule for taking a value that crossed a port into the core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_control_plane.domain.foreign import (
    ForeignValueRefused,
    core_owned,
    core_owned_instant,
)


@dataclass(frozen=True)
class Value:
    name: str
    count: int
    tags: tuple[str, ...] = ()


class Counting:
    """A stand-in for a port's answer that counts every member it is asked for."""

    def __init__(self, **members: object) -> None:
        self._members = members
        self.reads: dict[str, int] = {}

    def __getattr__(self, name: str) -> object:
        if name.startswith("_") or name == "reads":
            raise AttributeError(name)
        self.reads[name] = self.reads.get(name, 0) + 1
        if name not in self._members:
            raise AttributeError(name)
        return self._members[name]


def test_every_member_is_read_exactly_once() -> None:
    """Articles 3 and 8: a member read twice is a member a port may answer twice."""
    answer = Counting(name="alice", count=2, tags=("a",))
    core_owned(Value, answer)
    assert answer.reads == {"name": 1, "count": 1, "tags": 1}


def test_the_value_is_the_core_s_own_type_not_one_the_answer_claims() -> None:
    """`type(value) is Kind`, which an object cannot answer about itself."""

    class Claiming:
        name = "alice"
        count = 2
        tags = ()

        @property  # type: ignore[misc]
        def __class__(self) -> type:  # type: ignore[override]
            return Value

    claiming = Claiming()
    assert isinstance(claiming, Value)
    assert type(claiming) is not Value
    assert type(core_owned(Value, claiming)) is Value


def test_a_member_that_carries_a_value_of_its_own_is_rebuilt_too() -> None:
    """A nested record is a second object the port still owns."""
    answer = Counting(name="alice", count=2, tags=["a", "b"])
    taken = core_owned(Value, answer, tags=tuple)
    assert taken.tags == ("a", "b")
    assert type(taken.tags) is tuple


def test_a_member_the_answer_does_not_have_is_refused() -> None:
    """Article 2: an object that answers no `count` is not this value."""
    with pytest.raises(ForeignValueRefused, match="no 'count'"):
        core_owned(Value, Counting(name="alice", tags=()))


def test_a_member_the_core_cannot_take_is_refused() -> None:
    """A rebuild that cannot be made is a refusal, never a half-built value."""
    with pytest.raises(ForeignValueRefused, match="'tags'"):
        core_owned(Value, Counting(name="alice", count=1, tags=4), tags=tuple)


def test_a_value_the_kind_itself_refuses_is_refused_here() -> None:
    """Whatever the core's own type will not accept does not become a core value."""

    @dataclass(frozen=True)
    class Bounded:
        size: int

        def __post_init__(self) -> None:
            if self.size < 0:
                raise ValueError("size is negative")

    with pytest.raises(ForeignValueRefused, match="not a Bounded"):
        core_owned(Bounded, Counting(size=-1))


def test_a_kind_that_is_not_a_value_is_a_programming_error_not_a_refusal() -> None:
    """The kind is the core's own; naming one that is not is this module's bug."""
    with pytest.raises(TypeError, match="not a value"):
        core_owned(int, Counting())  # type: ignore[type-var]

    with pytest.raises(TypeError, match="no member 'nothing'"):
        core_owned(Value, Counting(name="a", count=1, tags=()), nothing=str)


def test_a_member_named_kind_can_still_be_rebuilt() -> None:
    """Both parameters are positional-only, so a `kind` member is nameable."""

    @dataclass(frozen=True)
    class Record:
        kind: str

    assert core_owned(Record, Counting(kind=1), kind=str).kind == "1"


class LyingInstant(datetime):
    """A clock's answer that converts to a different instant the second time."""

    def astimezone(self, tz=None):  # type: ignore[no-untyped-def,override]
        return super().astimezone(tz) + timedelta(days=365)


def test_an_instant_becomes_a_plain_datetime_the_core_owns() -> None:
    """A clock is a port, and a `datetime` subclass answers its own arithmetic."""
    lying = LyingInstant(2026, 9, 4, 10, 0, tzinfo=UTC)
    assert type(lying) is not datetime
    taken = core_owned_instant(lying)
    assert type(taken) is datetime
    assert taken == datetime(2027, 9, 4, 10, 0, tzinfo=UTC)
    assert core_owned_instant(taken) == taken


def test_an_instant_without_an_offset_is_refused() -> None:
    """Article 2: an instant with no offset names no moment."""
    with pytest.raises(ForeignValueRefused, match="offset-aware"):
        core_owned_instant(datetime(2026, 9, 4, 10, 0))
    with pytest.raises(ForeignValueRefused, match="an instant"):
        core_owned_instant("2026-09-04T10:00:00Z")
