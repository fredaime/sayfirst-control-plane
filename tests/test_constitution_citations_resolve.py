# SPDX-License-Identifier: Apache-2.0
"""Article 2: a file the constitution names is a file that exists.

One rule per file (`CONTRIBUTING.md`, article 16). A Guard paragraph that cites
a test or a script is making a claim about this repository, and the audit of
2026-09-06 found proof labels nobody resolved. A path that has been renamed,
moved or never written reads exactly like one that holds: this rule makes the
difference visible, by walking the constitution for every path it names and
opening each one.

Only tokens that carry a directory, and the documents the repository owns, are
treated as paths; `policy.toml` in a worked example names no file here.
"""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONSTITUTION = REPOSITORY / "CONSTITUTION.md"

#: The documents the repository owns, named without a directory (`CONTRIBUTING.md`).
OWN_DOCUMENTS = frozenset(
    {
        "CONSTITUTION.md",
        "GOVERNANCE.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "TRADEMARKS.md",
        "README.md",
        "CHANGELOG.md",
    }
)

_CITED = re.compile(r"`([A-Za-z0-9_./-]+\.(?:py|md|toml|json|yml|yaml|cfg|txt))`")


def cited() -> list[str]:
    """Every path the constitution names, in the order it names them."""
    found: list[str] = []
    for match in _CITED.finditer(CONSTITUTION.read_text(encoding="utf-8")):
        token = match.group(1)
        if token in found:
            continue
        if "/" in token or token in OWN_DOCUMENTS:
            found.append(token)
    return found


def _unresolved(tokens: list[str], root: Path) -> list[str]:
    """Every token that names no file at the given root."""
    return [token for token in tokens if not (root / token).exists()]


def test_every_file_the_constitution_names_is_a_file_this_branch_carries() -> None:
    """Article 2: a proof label pointing at nothing is a claim, not a proof."""
    missing = _unresolved(cited(), REPOSITORY)
    assert missing == [], missing
    # Anti-vacuity: a pattern that stopped matching would report no defect
    # because it read nothing, which is the failure it exists to prevent.
    assert len(cited()) >= 12, cited()


def test_this_guard_still_catches_a_planted_missing_citation() -> None:
    """Article 2: a checker that cannot fail cannot prove citations resolve."""
    planted = "tests/test_nobody_ever_wrote_this_guard.py"
    missing = _unresolved([planted], REPOSITORY)
    assert missing == [planted], (
        "FAIL the planted missing citation was not caught: this guard cannot fail."
    )
