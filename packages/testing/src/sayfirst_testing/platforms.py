# SPDX-License-Identifier: Apache-2.0
"""Platform gates whose skips are reported, never counted as passes."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from typing import TypeVar

import pytest

from .guard_gates import OS_REAL_PLATFORMS

F = TypeVar("F", bound=Callable[..., object])

__all__ = [
    "OS_REAL_PLATFORMS",
    "identity_summary",
    "requires_platform",
    "requires_platforms",
    "skip_reason",
    "skip_reason_for",
]


def skip_reason(platform: str) -> str:
    """The one sentence a host that cannot run a guard reports."""
    return f"not runnable on this host (requires {platform})"


def skip_reason_for(platforms: Sequence[str]) -> str:
    """The same sentence for a guard that either operating system can run."""
    return skip_reason(" or ".join(platforms))


def requires_platform(platform: str) -> Callable[[F], F]:
    """Skip a guard this host cannot run, saying which host runs it."""
    return pytest.mark.skipif(  # type: ignore[return-value]
        sys.platform != platform, reason=skip_reason(platform)
    )


def requires_platforms(*platforms: str) -> Callable[[F], F]:
    """Skip a guard no host of this kind can run, naming the hosts that can.

    A guard the host boundary defines runs on every operating system that has
    an adapter; one that reads a facility only one of them has names that one.
    """
    return pytest.mark.skipif(  # type: ignore[return-value]
        sys.platform not in platforms, reason=skip_reason_for(platforms)
    )


def identity_summary(*, passed: int, skipped: int, failed: int) -> str:
    """Render the identity summary; a skip is its own column, never a pass."""
    return f"identity: {passed} held, {skipped} not runnable on this host, {failed} broken"
