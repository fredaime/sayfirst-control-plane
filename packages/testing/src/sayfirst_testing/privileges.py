# SPDX-License-Identifier: Apache-2.0
"""Privilege gates: a guard that only a root container can hold says so.

A platform gate (`platforms.py`) answers "which operating system can hold this
guard". This answers the other question the identity guards raise: "which
privilege can". They are separate axes, and a guard can carry one of each — the
system-mode drop is Linux's and root's alike.

Two guards need this in opposite directions. One needs root, because system
mode refuses to start below it, so on an ordinary runner it has never executed
at all. The other needs *not* root: it drives an irreversible `setuid` in the
test process, or it reads uid 0 as a stranger, and either claim is false the
moment the tester is root. A guard whose premise is "the tester happened to
lack privilege" is a guard that was never held; article 2 asks that the claim
and the check be the same thing, so the premise is written into the gate where
`guard_gates` can read it and `scripts/require_platform_guards.py` can require
it of the runner that has it.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TypeVar

import pytest

F = TypeVar("F", bound=Callable[..., object])

__all__ = [
    "PRIVILEGES",
    "privilege_of_this_process",
    "requires_root",
    "requires_unprivileged",
    "skip_reason_for_privilege",
]

PRIVILEGES: tuple[str, ...] = ("root", "unprivileged")
"""The two privileges a runner can have, and the two gates that name them."""


def privilege_of_this_process() -> str:
    """`root` when this process can do what only uid 0 can, else `unprivileged`."""
    return "root" if os.geteuid() == 0 else "unprivileged"


def skip_reason_for_privilege(privilege: str) -> str:
    """The one sentence a runner that cannot hold a guard reports."""
    if privilege == "root":
        return "not runnable here (requires a throwaway root container)"
    return "not runnable as root (requires an unprivileged tester)"


def requires_root() -> Callable[[F], F]:
    """Skip a guard only a root container can hold, saying that is what it needs.

    System mode refuses to start when `geteuid()` is not 0, so every claim
    about what it does after that refusal is unexecuted on an ordinary runner.
    """
    return pytest.mark.skipif(  # type: ignore[return-value]
        os.geteuid() != 0, reason=skip_reason_for_privilege("root")
    )


def requires_unprivileged() -> Callable[[F], F]:
    """Skip a guard whose premise is that the tester is not root.

    Not a convenience: a guard that reads uid 0 as a stranger, or that relies
    on a call failing for want of privilege, states something false under root,
    and a false statement that passes is worse than one that is not made.
    """
    return pytest.mark.skipif(  # type: ignore[return-value]
        os.geteuid() == 0, reason=skip_reason_for_privilege("unprivileged")
    )
