#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse a run in which a guard this runner owes was skipped instead of held.

`pytest -rs` reports a skip; it does not fail on one. A run of the identity
guards in which every guard gated to this operating system was skipped exits
`0`, so a step that only runs `-rs` and calls the result "required to run" makes
a claim its mechanism does not hold up (article 2). This is the mechanism: the
guards this runner owes are read from the gates in their own source, what the
run did is read from its JUnit report, and a required guard that was reported
as not runnable — or that never ran at all — fails the step by name.

    python scripts/require_platform_guards.py --junit=report.xml \\
        --platform=darwin --tree=packages/contract/tests/identity

A guard can be gated to a privilege as well as to an operating system. The
root-container guards of system mode are Linux's and root's alike, and an
ordinary Linux runner is right to skip them; `--privilege` says which runner
this is, so each guard is required of the runner that can actually hold it and
of no other. It defaults to what this process is, so the root container that
runs the suite owes the root guards without being told twice.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "packages" / "testing" / "src"))

from sayfirst_testing.guard_gates import (  # noqa: E402
    guards_not_held,
    guards_required_on,
    outcomes,
)
from sayfirst_testing.platforms import identity_summary  # noqa: E402
from sayfirst_testing.privileges import PRIVILEGES, privilege_of_this_process  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", required=True, type=Path, help="the run's JUnit report")
    parser.add_argument("--platform", default=sys.platform, help="the runner's `sys.platform`")
    parser.add_argument(
        "--tree", dest="trees", action="append", required=True, type=Path, help="a guard tree"
    )
    parser.add_argument(
        "--privilege",
        default=privilege_of_this_process(),
        choices=PRIVILEGES,
        help="the privilege this runner has; a guard gated to the other one is not owed here",
    )
    arguments = parser.parse_args(argv)

    read = outcomes(arguments.junit)
    counted = Counter(read.values())
    print(
        identity_summary(
            passed=counted["held"],
            skipped=counted["not runnable"],
            failed=counted["broken"],
        )
    )

    required = guards_required_on(
        arguments.platform, *arguments.trees, privilege=arguments.privilege
    )
    runner = f"{arguments.platform!r}/{arguments.privilege!r}"
    if not required:
        print(
            f"no guard is gated to {runner} in {[str(t) for t in arguments.trees]}: "
            "nothing was required of this runner"
        )
        return 0
    missing = guards_not_held(required, read)
    print(f"{len(required)} guard(s) gated to {runner} were required to run here")
    if not missing:
        return 0
    for name, outcome in missing.items():
        print(f"required on {runner}: {name} — {outcome}", file=sys.stderr)
    print(
        f"{len(missing)} guard(s) this runner owes were not held; "
        "a skip on the only runner that can hold a guard proves nothing about it",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover - the entry point CI calls
    raise SystemExit(main())
