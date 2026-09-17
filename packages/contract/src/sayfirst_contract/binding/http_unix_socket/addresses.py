# SPDX-License-Identifier: Apache-2.0
"""How long a local address may be, and how a replay run stays inside it.

The binding of article 13 names its transport, and this is the one fact of that
transport a caller cannot negotiate: `sockaddr_un.sun_path` is a fixed array,
so an address is not a name of unbounded length. A run that composes its
addresses out of a temporary root discovers the bound as `OSError: AF_UNIX path
too long` from `bind`, at the point where the fixture had already been arranged
and after the reason has been thrown away.

So the bound is stated here, once, and everything that binds an address for a
scenario asks for the address rather than composing one. Two numbers make the
statement usable rather than decorative:

* `ADDRESS_MARGIN_BYTES` is the room a run is required to leave. Zero headroom
  is not a passing suite; it is a suite that passes on the host it was measured
  on, and article 13 publishes this contract so that a third party can replay it
  on a host nobody here has seen.
* `FIXTURE_LEAF_BYTES` and `TEST_DIRECTORY_BYTES` are the budget the run root is
  chosen against: what a test may build below the root, and what the runner
  itself spends on the directory it gives each test.

The limits are the kernel's, not this project's: 108 bytes on Linux and 104 on
macOS, both including the terminating NUL. `sun_path_limit` is the one reading
of them; the daemon's own start-up refusal (`socket_path_too_long`) reads it
from here so that a bound checked in a fixture and a bound enforced at start
are the same number.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from hashlib import blake2s
from pathlib import Path
from typing import Final

SUN_PATH_LIMITS: Final[Mapping[str, int]] = {"linux": 108, "darwin": 104}
"""The size of `sun_path`, per platform, terminating NUL included."""

DEFAULT_SUN_PATH_LIMIT: Final[int] = 108
"""What an unrecognised platform is credited with: the more generous of the two.

A platform this table does not name is not thereby known to be stricter, and
inventing a stricter number for it would be a claim about a host nobody has
measured (article 2). The margin below is what protects the unmeasured case.
"""

STRICTEST_SUN_PATH_LIMIT: Final[int] = min(SUN_PATH_LIMITS.values())
"""The limit a run must satisfy to be portable to every platform named here."""

ADDRESS_MARGIN_BYTES: Final[int] = 16
"""The room every address this repository's fixtures bind is required to leave.

Sixteen bytes is one more directory level of a plausible name. It is chosen so
that the guard fails while the fix is still a small one — renaming a leaf —
rather than at the moment the kernel refuses, when the only fix left is to move
the whole run root.
"""

TEST_DIRECTORY_BYTES: Final[int] = 32
"""What the runner spends on the per-test directory below the run root.

`pytest` truncates a test's name to thirty characters and appends an index; with
the separator that is thirty-two bytes, and it is spent before a test has
written anything.
"""

FIXTURE_LEAF_BYTES: Final[int] = 40
"""What a test may spend below its own directory, separator included.

The longest one this repository builds today is a per-user daemon's
`/home/.sayfirst/run/daemon.sock` at thirty-one bytes.
"""


class AddressTooLong(ValueError):
    """An address that would not fit, refused where it was composed.

    Named for the reason the daemon publishes for the same condition
    (`socket_path_too_long`), because it is the same condition: the difference
    is only that the daemon is told an address and this is asked for one.
    """


def sun_path_limit(platform: str) -> int:
    """The size of `sun_path` on a platform, terminating NUL included."""
    return SUN_PATH_LIMITS.get(platform, DEFAULT_SUN_PATH_LIMIT)


def address_bytes(path: Path | str) -> int:
    """What a path costs in `sun_path`: its bytes and the NUL after them."""
    return len(os.fsencode(os.fspath(path))) + 1


def address_budget(root: Path | str) -> int:
    """The longest address a test below this run root is allowed to reach."""
    return address_bytes(root) + TEST_DIRECTORY_BYTES + FIXTURE_LEAF_BYTES


def root_leaves_the_margin(root: Path | str, *, platform: str) -> bool:
    """Whether a run root can hold the fixture budget and still leave the margin."""
    return address_budget(root) + ADDRESS_MARGIN_BYTES <= sun_path_limit(platform)


def refuse_a_long_address(path: Path | str, *, platform: str | None = None) -> None:
    """Refuse an address that leaves less than the margin, saying by how much.

    The kernel's own refusal names neither the limit nor the path; a fixture
    that trips this one is told both, and is told it while there is still room
    between the address and the limit (article 2).
    """
    limit = sun_path_limit(platform if platform is not None else sys.platform)
    size = address_bytes(path)
    if size + ADDRESS_MARGIN_BYTES > limit:
        raise AddressTooLong(
            f"socket_path_too_long: {path} is {size} bytes, the limit is {limit} "
            f"and this repository keeps {ADDRESS_MARGIN_BYTES} bytes of margin"
        )


def scenario_address(root: Path | str, name: str) -> Path:
    """The address one scenario is served at below a run root.

    The leaf is a digest of the scenario's name rather than the name itself.
    The name is what a reader wants, and it is also thirty-eight bytes of
    `sun_path` for `grant_miss_after_policy_version_change` alone — which is
    how a suite arrives at zero headroom without anyone deciding to spend it.
    A digest is short, stable across runs and selections, and derived from the
    one thing that identifies the scenario, so the same fixture is served at
    the same address every time; which scenario is which is the mapping the
    caller already holds.
    """
    leaf = blake2s(name.encode("utf-8"), digest_size=4).hexdigest()
    return Path(root) / f"{leaf}.sock"
