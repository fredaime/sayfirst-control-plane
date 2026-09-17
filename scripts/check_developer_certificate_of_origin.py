#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse a change whose commits do not certify the Developer Certificate of Origin.

Article 15 asks that every contributor sign off each commit, and article 16's
Guard calls the check required. Nothing in this repository read the sign-offs
until now: the rule was written in `CONTRIBUTING.md` and held by whoever
happened to look.

    python scripts/check_developer_certificate_of_origin.py --base=<ref> --head=<ref>

Every commit in `base..head` that is not a merge must carry a `Signed-off-by:`
trailer naming a person and an address. A merge commit introduces no work of
its own, and its parents are checked where they were made, so it is passed over
— which is what the certificate itself asks for, and what refusing it would
turn into a rule about merge strategy.

The exit code is the point: `0` when every commit certifies, `1` naming each one
that does not, `2` when the range could not be read at all — a shallow checkout
has no range, and a check that cannot see the commits must not report that they
passed (article 2).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: `Signed-off-by: A Name <address@example.org>`, the form `git commit -s` writes.
SIGN_OFF = re.compile(
    r"^Signed-off-by:\s*(?P<name>[^<>]+?)\s*<(?P<address>[^<>@\s]+@[^<>@\s]+)>\s*$",
    re.MULTILINE,
)

#: What separates one commit's report from the next in `git log`'s output.
_RECORD = "\x1e"
_FIELD = "\x1f"


class RangeUnreadable(Exception):
    """The commits could not be listed, so nothing about them may be claimed."""


def commits(base: str, head: str, *, repository: Path | None = None) -> list[tuple[str, str, str]]:
    """Each non-merge commit in `base..head`, as identifier, subject and body."""
    result = subprocess.run(
        [
            "git",
            "log",
            "--no-merges",
            f"--format=%H{_FIELD}%s{_FIELD}%B{_RECORD}",
            f"{base}..{head}",
        ],
        cwd=repository or Path.cwd(),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RangeUnreadable(result.stderr.strip() or f"{base}..{head} could not be read")
    found = []
    for record in result.stdout.split(_RECORD):
        if not record.strip():
            continue
        identifier, subject, body = record.strip("\n").split(_FIELD, 2)
        found.append((identifier, subject, body))
    return found


def uncertified(base: str, head: str, *, repository: Path | None = None) -> list[str]:
    """Every commit in the range that carries no well-formed sign-off."""
    return [
        f"{identifier[:12]} {subject}"
        for identifier, subject, body in commits(base, head, repository=repository)
        if not SIGN_OFF.search(body)
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_developer_certificate_of_origin")
    parser.add_argument("--base", required=True, help="the ref the change starts from")
    parser.add_argument("--head", default="HEAD", help="the ref the change ends at")
    arguments = parser.parse_args(argv)
    try:
        missing = uncertified(arguments.base, arguments.head)
    except RangeUnreadable as error:
        print(f"the range could not be read: {error}", file=sys.stderr)
        return 2
    if missing:
        print(
            "these commits certify no Developer Certificate of Origin "
            "(article 15; `git commit -s`, or `git rebase --signoff` to repair them):",
            file=sys.stderr,
        )
        for line in missing:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"every commit in {arguments.base}..{arguments.head} is signed off")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
