# SPDX-License-Identifier: Apache-2.0
"""Articles 2 and 8: a rule this repository does not hold must not read as one it does.

A rule of the repository, not of one package: article 2 binds every claim this
repository publishes, and a deferred mechanism read as a shipped one is the
same defect wherever it is written. One rule per file, so a new rule arrives as
a new file and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_the_plugin_subcommand_of_article_8_is_deferred_in_writing() -> None:
    """Articles 2 and 8: a rule this block does not hold must not read as one it does."""
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "## A subcommand a plugin contributes (article 8)" in documentation
    assert "the parser is fixed" in documentation
    assert "nothing discovers, activates or composes a plugin subcommand" in documentation
