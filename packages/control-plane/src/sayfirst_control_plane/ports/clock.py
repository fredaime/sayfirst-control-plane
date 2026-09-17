# SPDX-License-Identifier: Apache-2.0
"""The port that supplies every instant this daemon records."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, Protocol, runtime_checkable

CLOCK_VERSION: Final[int] = 1


@runtime_checkable
class Clock(Protocol):
    """One offset-aware instant per call."""

    VERSION: int

    def now(self) -> datetime: ...


class SystemClock:
    """The host's clock, read once per call."""

    VERSION: Final[int] = CLOCK_VERSION

    def now(self) -> datetime:
        return datetime.now(UTC)
