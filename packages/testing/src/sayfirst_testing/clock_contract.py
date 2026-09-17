# SPDX-License-Identifier: Apache-2.0
"""The contract of the Clock port, run against every provider.

Article 8: a provider that does not pass this suite is not a provider. Every
instant this project records comes through here, and every one of them is
offset-aware — an instant without an offset is not a time anyone can compare
across hosts (article 2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class _Clock(Protocol):
    VERSION: int

    def now(self) -> datetime: ...


def assert_the_port_is_versioned(clock: _Clock) -> None:
    """Article 8: a port carries an integer version, and so does its provider."""
    assert isinstance(clock.VERSION, int)
    assert not isinstance(clock.VERSION, bool)
    assert clock.VERSION >= 1


def assert_every_instant_carries_its_offset(clock: _Clock) -> None:
    """An instant with no offset is one no other host can read."""
    instant = clock.now()
    assert isinstance(instant, datetime)
    assert instant.tzinfo is not None
    assert instant.utcoffset() is not None
    assert datetime.fromisoformat(instant.isoformat()) == instant


def assert_time_does_not_run_backwards(clock: _Clock) -> None:
    """Two readings in order are in order: a lifetime is computed from them."""
    first = clock.now()
    second = clock.now()
    assert second >= first


def run_the_clock_contract(clock: _Clock) -> None:
    """Every promise of the port, against one provider."""
    assert_the_port_is_versioned(clock)
    assert_every_instant_carries_its_offset(clock)
    assert_time_does_not_run_backwards(clock)
