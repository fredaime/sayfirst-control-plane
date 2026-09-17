# SPDX-License-Identifier: Apache-2.0
"""Forward-compatible readers for closed domain values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class Unknown:
    """A value this generation does not define, retained without interpretation."""

    raw: str


def read_enum[E: Enum](cls: type[E], raw: object) -> E | Unknown:
    """Read a known string member or retain the supplied value as unknown."""
    if not isinstance(raw, str):
        return Unknown(repr(raw))
    try:
        return cls(raw)
    except ValueError:
        return Unknown(raw)
