# SPDX-License-Identifier: Apache-2.0
"""Articles 15 and 16: the sign-off is read, not remembered.

One rule per file (`CONTRIBUTING.md`, article 16). Article 15's Guard says the
DCO check runs on every pull request and article 16's calls it a required
status; until now no workflow ran one and no code read a trailer, so both
sentences described a check that did not exist.

The mechanism is `scripts/check_developer_certificate_of_origin.py`, and it is
proved here against real commits in a throwaway repository — the defect planted
rather than assumed, because a check nobody has watched refuse is not a check.
Whether the public repository's branch protection marks the job *required* is a
setting of that repository, which this test cannot read and does not claim; the
Guard says so.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "scripts" / "check_developer_certificate_of_origin.py"

sys.path.insert(0, str(REPOSITORY / "scripts"))

from check_developer_certificate_of_origin import (  # noqa: E402
    RangeUnreadable,
    uncertified,
)


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=repository, capture_output=True, text=True, check=True
    )
    return result.stdout


def _repository_with(commits: list[tuple[str, bool]], root: Path) -> Path:
    """A throwaway history, one commit per entry, signed off where asked."""
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.name", "A Contributor")
    _git(root, "config", "user.email", "contributor@example.org")
    (root / "file").write_text("base\n", encoding="utf-8")
    _git(root, "add", "file")
    _git(root, "commit", "-q", "-s", "-m", "the commit the range starts from")
    for subject, signed in commits:
        (root / "file").write_text(subject, encoding="utf-8")
        _git(root, "add", "file")
        _git(root, "commit", "-q", *(["-s"] if signed else []), "-m", subject)
    return root


def test_a_commit_without_a_sign_off_fails_the_check(tmp_path: Path) -> None:
    """Article 15: the certificate is what the trailer certifies; no trailer, no certificate."""
    root = _repository_with(
        [("a signed change", True), ("a change nobody certified", False)], tmp_path / "planted"
    )
    missing = uncertified("main~2", "main", repository=root)
    assert len(missing) == 1, missing
    assert "a change nobody certified" in missing[0]


def test_a_range_that_certifies_throughout_passes(tmp_path: Path) -> None:
    """Anti-vacuity: the check that refuses above must accept a correct range."""
    root = _repository_with(
        [("a signed change", True), ("another signed change", True)], tmp_path / "clean"
    )
    assert uncertified("main~2", "main", repository=root) == []


def test_a_range_that_cannot_be_read_is_never_reported_as_passing(tmp_path: Path) -> None:
    """Article 2: a shallow checkout has no range, and no range is not a pass."""
    root = _repository_with([("a signed change", True)], tmp_path / "unreadable")
    with pytest.raises(RangeUnreadable):
        uncertified("no-such-ref", "main", repository=root)


def test_the_script_exits_non_zero_and_names_the_commit(tmp_path: Path) -> None:
    """Article 16: the check is a step of a workflow, so its exit code is the verdict."""
    root = _repository_with([("a change nobody certified", False)], tmp_path / "exit")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--base", "main~1", "--head", "main"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "a change nobody certified" in result.stderr


def test_the_workflow_runs_the_check_on_every_pull_request() -> None:
    """Article 15: "runs on every pull request" is a claim about the workflow."""
    workflow = (REPOSITORY / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "pull_request:" in workflow
    assert "check_developer_certificate_of_origin.py" in workflow
    body = workflow.partition("\n  developer-certificate-of-origin:")[2]
    assert body, "the workflow defines no sign-off job"
    # Up to the next job: a line at two spaces of indent that is not blank.
    job = re.split(r"\n  \S", body, maxsplit=1)[0]
    assert "check_developer_certificate_of_origin.py" in job, job
    assert "pull_request" in job, "the job would run outside a pull request or not at all"
