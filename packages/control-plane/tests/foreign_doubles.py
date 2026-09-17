# SPDX-License-Identifier: Apache-2.0
"""Two-faced doubles for every boundary a value crosses into the core.

Articles 3, 8, 11 and 12. A port is written outside the core — an adapter, or a
plugin the core loaded from an entry point — so the object it returns is memory
that code owns. Every read of that object after the core has checked it is a
fresh answer the port gets to choose, which is how one seam turned a recorded
rejection into a resumption on an approval nobody made.

The doubles here make the second read observable. `TwoFaced` counts every member
the core reads and rewrites the ones it is told to once the count passes its
grace, so a core module that copies the members into locals once and builds its
own value reads each member exactly once and never sees a lie, and a core module
that re-reads after judging sees one. `test_foreign_values.py` drives one of
these per boundary and holds every boundary to both halves of the rule: read
each member at most once, and never keep, record or hand on the object itself.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

NEVER = 1 << 30
"""A grace no drive reaches: the double counts its reads and never lies."""


class TwoFaced:
    """A value that answers honestly while it is read and lies once it is not.

    It is not the type it claims: `__class__` is a property, so `isinstance` —
    a question an object gets to answer about itself — says yes with no subclass
    and no monkeypatch, while `type(value) is Kind` still says no. Its members
    are answered by `__getattr__`, so what a check reads and what a recorder
    reads afterwards are two reads of memory the port owns.
    """

    def __init__(
        self,
        honest: object,
        *,
        grace: int = NEVER,
        lies: dict[str, object] | None = None,
    ) -> None:
        self.honest = honest
        self.grace = grace
        self.lies = dict(lies or {})
        self.reads: Counter[str] = Counter()

    @property  # type: ignore[misc]
    def __class__(self) -> type:  # type: ignore[override]
        return type(self.honest)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name in ("honest", "grace", "lies", "reads"):
            raise AttributeError(name)
        self.reads[name] += 1
        if name in self.lies and self.reads[name] > self.grace:
            return self.lies[name]
        return getattr(self.honest, name)

    def read_more_than_once(self) -> dict[str, int]:
        """The members this core path read a second time, and how often."""
        return {name: count for name, count in self.reads.items() if count > 1}


class TwoFacedInstant(datetime):
    """An instant that answers a different offset, text or zone on a second read.

    A clock is a port too, and `datetime` is the one value a port returns that
    the core cannot rebuild by naming its fields alone: it is a subclass here
    rather than a `TwoFaced`, because the arithmetic and comparison the core
    does with an instant live on the type, not on an attribute.
    """

    reads: Counter[str]
    grace: int

    def __new__(cls, *args: Any, grace: int = NEVER, **kwargs: Any) -> TwoFacedInstant:
        value = super().__new__(cls, *args, **kwargs)
        value.reads = Counter()
        value.grace = grace
        return value

    def _counted(self, name: str) -> bool:
        self.reads[name] += 1
        return self.reads[name] > self.grace

    def astimezone(self, tz: Any = None) -> datetime:  # type: ignore[override]
        lying = self._counted("astimezone")
        value = super().astimezone(tz)
        return value.replace(year=1999) if lying else value

    def isoformat(self, *args: Any, **kwargs: Any) -> str:
        lying = self._counted("isoformat")
        value = super().isoformat(*args, **kwargs)
        return value.replace(value[:4], "1999") if lying else value

    def strftime(self, format: str) -> str:
        lying = self._counted("strftime")
        value = super().strftime(format)
        return value.replace(value[:4], "1999") if lying else value

    def utcoffset(self):  # type: ignore[no-untyped-def]
        self._counted("utcoffset")
        return super().utcoffset()

    def read_more_than_once(self) -> dict[str, int]:
        """The members this core path read a second time, and how often.

        `utcoffset` is excluded: it is how the core asks whether an instant is
        offset-aware, and asking that of a value and then converting it is one
        read of one fact, not two reads of two.
        """
        return {
            name: count for name, count in self.reads.items() if count > 1 and name != "utcoffset"
        }


class TwoFacedSequence:
    """A membership list that yields different ids the second time it is walked.

    A port that answers a sequence answers an object, not a tuple: `__iter__` is
    a method it owns. A core module that walks it once into a value of its own
    reads one list; one that walks it again asks twice.
    """

    def __init__(self, honest: tuple[int, ...], *, grace: int = NEVER) -> None:
        self.honest = honest
        self.grace = grace
        self.reads: Counter[str] = Counter()

    def __iter__(self) -> Any:
        self.reads["__iter__"] += 1
        if self.reads["__iter__"] > self.grace:
            return iter(tuple(-gid for gid in self.honest))
        return iter(self.honest)

    def read_more_than_once(self) -> dict[str, int]:
        """The walks this core path made after the first one."""
        return {name: count for name, count in self.reads.items() if count > 1}


class TwoFacedText(str):
    """A name a port answered with: text of its own subclass, not the core's.

    Nothing here lies — a `str` is immutable and its members cannot be rewritten
    between two reads. What it demonstrates is the other half of the rule: a
    core value built out of it holds the port's object, with the port's `__eq__`
    and the port's `__hash__`, unless the core made its own copy.
    """

    def read_more_than_once(self) -> dict[str, int]:
        return {}
