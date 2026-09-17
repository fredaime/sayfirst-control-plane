# SPDX-License-Identifier: Apache-2.0
"""Article 8: what is discovered is joined to what is active, never by name alone.

A rule of the repository, not of one package: how a published surface joins two
records is a claim about the whole repository's honesty, and a name-only join
would publish an activation nobody performed. One rule per file, so a new rule
arrives as a new file and a new file never conflicts (`CONTRIBUTING.md`,
article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_the_readme_states_how_the_composed_column_is_joined() -> None:
    """Article 8's guard: discovered against active, with no name-only join."""
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "answers about a *selection*, never" in documentation
    assert "for that configured interface, at that configured interface" in documentation
    assert "this release refuses outright" in documentation
