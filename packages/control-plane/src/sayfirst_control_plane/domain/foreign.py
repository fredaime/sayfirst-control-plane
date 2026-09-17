# SPDX-License-Identifier: Apache-2.0
"""Taking a value that crossed a port into the core, once and for good.

Article 3 puts the authority for a decision in the core; article 8's Why says a
plugin port must not become a way to widen policy; article 11 says a record
claims only what was established. All three come down to one fact about memory:
a value a port answered with is memory that port owns, so every read of it
*after* the core has checked it is a fresh answer the port gets to choose. A
core module that checks an object and then records the object it checked has
checked nothing.

The rule is therefore mechanical: read every member exactly once, build the
core's own value out of what was read, and record and hand on that. `core_owned`
is that rule in one place, so a seam holds it in a line rather than in a habit.

Two properties of how it reads matter as much as what it builds. It names the
core's own type and constructs it, so the result satisfies `type(value) is Kind`
— not `isinstance`, which is a question an object answers about itself and which
an object defining `__class__` as a property answers however it likes. And it
reads each member exactly once, so what a later check compares and what a
recorder writes are one value rather than two reads of one name.

What it cannot do is stop a port lying on the *first* read. Nothing can: the
first read is the port's own claim, and the core refuses it only where the core
independently holds the fact — as `plugins/approval.py` holds the act put to the
provider, and as the capture seam holds the name of the redactor it composed.

The same fact about memory holds in the other direction, and that half was
missing. A value the core hands *to* a port is memory the port can write:
`frozen=True` refuses `setattr` and refuses nothing to `object.__setattr__`, so
an argument a provider is given and a fact the core is relying on must not be
one object. The approval seam kept the act it had put to the provider and
judged the provider's answer against it, and a provider rewrote that act in
place — no monkeypatch, no frame inspection, just the argument it was handed.
`core_owned_input` is the input side of the same rule: take the core's own copy
*before* the call, judge and record from the copy, and let the port do what it
likes with what it was given.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from typing import Any


class ForeignValueRefused(ValueError):
    """A value that crossed a port is not one the core can build its own from."""


def core_owned[T](kind: type[T], value: object, /, **rebuild: Callable[[Any], Any]) -> T:
    """The core's own `kind`, built from `value`'s members read exactly once.

    `rebuild` names the members that carry a value of their own across the
    boundary — a nested record, a mapping, a path — with the function that makes
    the core's own copy of it. A member with no entry is taken as it was read,
    which is right for the scalars a frozen value is otherwise made of.
    """
    if not is_dataclass(kind):
        raise TypeError(f"{kind.__name__} is not a value the core can rebuild")
    unknown = set(rebuild) - {member.name for member in fields(kind)}
    if unknown:
        raise TypeError(f"{kind.__name__} has no member {sorted(unknown)[0]!r}")
    members: dict[str, Any] = {}
    for member in fields(kind):
        if not member.init:
            continue
        try:
            read = getattr(value, member.name)
        except AttributeError as error:
            raise ForeignValueRefused(
                f"the value answered no {member.name!r}, so it is not a {kind.__name__}"
            ) from error
        convert = rebuild.get(member.name)
        try:
            members[member.name] = read if convert is None else convert(read)
        except Exception as error:
            raise ForeignValueRefused(
                f"the {member.name!r} of a {kind.__name__} could not be taken into the core"
            ) from error
    try:
        return kind(**members)  # type: ignore[call-arg]
    except Exception as error:
        raise ForeignValueRefused(f"the value is not a {kind.__name__}") from error


def core_owned_input[T](kind: type[T], value: object, /, **rebuild: Callable[[Any], Any]) -> T:
    """The core's own copy of a value it is about to hand across a port.

    The same construction as `core_owned` and the opposite reason. There the
    value came *from* a port and the danger was a second read; here it goes *to*
    one and the danger is a second write: `object.__setattr__` writes a frozen
    dataclass, so a fact the core holds and an argument a provider is given must
    not be one object.

    Which is the whole of the extra check. Every member is read once and the
    core's own `kind` is built from what was read — and the result is required
    to be a different object from the one it was built from, so a `kind` that
    hands back what it was given, by interning or by a `__new__` of its own,
    is refused rather than quietly making the copy an alias.
    """
    copy = core_owned(kind, value, **rebuild)
    if copy is value:
        raise ForeignValueRefused(
            f"a {kind.__name__} the core can hand across a port must not be the value it holds"
        )
    return copy


def core_owned_instant(value: object) -> datetime:
    """The core's own copy of an instant a port supplied, read exactly once.

    An instant is the one value a port answers that naming its fields cannot
    rebuild: the arithmetic and the ordering the core does with it live on the
    type, not on an attribute, so a `datetime` subclass answers them. This
    converts through the one text the contract already records instants in, and
    returns a plain `datetime` — `type(value) is datetime`.
    """
    if not isinstance(value, datetime):
        raise ForeignValueRefused("a clock answers an instant")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ForeignValueRefused("a clock answers an offset-aware instant")
    try:
        return datetime.fromisoformat(value.astimezone(UTC).isoformat())
    except Exception as error:
        raise ForeignValueRefused("the instant a clock answered cannot be read") from error
