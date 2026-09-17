# SPDX-License-Identifier: Apache-2.0
"""Article 6: the host-identity guards run on both platforms in continuous integration.

A rule of the repository, not of one package: the workflow is the repository's
only statement of where its guards are proved. The Darwin adapter cannot be
exercised on the host this repository is developed on, so the matrix is the
only place the second adapter is proved; a workflow naming one platform would
leave that guard unheld everywhere. One rule per file, so a new rule arrives as
a new file and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def test_the_identity_guards_run_on_both_platforms_in_continuous_integration() -> None:
    """Article 6: CI runs the identity tests on Linux and on macOS."""
    workflow = (REPOSITORY / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "ubuntu-latest" in workflow
    assert "macos-latest" in workflow
    assert "tests/identity" in workflow
    assert "uv run --frozen --all-packages pytest" in workflow
    assert "ruff check" in workflow and "ruff format --check" in workflow
    matrix = workflow.partition("matrix:")[2]
    assert "ubuntu-latest" in matrix and "macos-latest" in matrix
    assert "-rs" in workflow, "a skipped identity guard must be reported, never silent"
