# SPDX-License-Identifier: Apache-2.0
"""Article 14: a copy carries the copyright holder and the licence, and nothing more.

A rule of the repository, not of one package: it belongs to no package, and it
is held in two places at once. The **record** is a tracked file, `PROVENANCE.md`,
because `SECURITY.md` publishes this project by creating a repository fresh from
this tree with no history behind it, and a record kept only in commit messages
would not travel — leaving the public repository with copied material and no
account of the copy, or pushing whoever publishes to carry historical material
across, which is what article 0's fresh-repository path exists to prevent. The
**history**, wherever one exists, is held to the same note: every paragraph of
it that records a copy says the copyright holder and the licence and nothing
else. A fresh repository records no copy in its history and is green on the
second rule without carrying anything across. One rule per file, so a new rule
arrives as a new file and a new file never conflicts (`CONTRIBUTING.md`,
article 16).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]

#: The tracked record the publication recipe carries over with the tree.
RECORD = "PROVENANCE.md"

#: The opening of a copy note, in either wording the constitution allows.
COPIES = re.compile(r"copied from a (?:private|parent)", re.IGNORECASE)

#: The whole of what a copy from a source this repository does not hold says in public.
COPY_NOTE = (
    "copied from a private repository of the project; "
    "copyright holder: Frédéric Aime; licence: Apache-2.0"
)


def _copy_paragraphs(messages: list[str]) -> list[str]:
    """Return every paragraph of a commit message that records a copy."""
    return [
        paragraph.strip()
        for message in messages
        for paragraph in re.split(r"\n\s*\n", message)
        if COPIES.search(paragraph)
    ]


def _history_messages(root: Path) -> list[str]:
    separator = "<<<end-of-commit-message>>>"
    result = subprocess.run(
        ("git", "log", f"--format=%B{separator}", "HEAD"),
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [part for part in result.stdout.split(separator) if part.strip()]


def _the_tree_records_the_copy(root: Path) -> None:
    """The tracked record says the note, once, and says nothing else about a copy."""
    record = (root / RECORD).read_text(encoding="utf-8")
    assert _copy_paragraphs([record]) == [COPY_NOTE]


def _the_history_says_no_more_than_the_note(root: Path) -> None:
    """Every copy paragraph of whatever history this tree sits on is the note.

    Nothing relaxes it. A history that records no copy at all — the one the
    publication recipe of `SECURITY.md` creates — has nothing for a register to
    relax, which is why the register this tree carries holds no entry against
    this rule.
    """
    assert set(_copy_paragraphs(_history_messages(root))) <= {COPY_NOTE}


def _tracked_files(root: Path) -> list[str]:
    result = subprocess.run(
        ("git", "ls-files", "-z"), cwd=root, capture_output=True, text=True, check=True
    )
    return [name for name in result.stdout.split("\0") if name]


def test_the_tree_records_the_copy_the_holder_and_the_licence_and_no_more() -> None:
    """Article 14: the record travels with the tree, because the history does not."""
    _the_tree_records_the_copy(REPOSITORY)


def test_every_copy_paragraph_of_this_history_says_the_holder_the_licence_and_no_more() -> None:
    """Article 14: the provenance review's record is private; the copy carries the note."""
    if not (REPOSITORY / ".git").exists() or shutil.which("git") is None:
        pytest.skip("no repository history here; the tree's record is held above")
    # Nothing here asserts that this history records a copy at all. That is a
    # fact about this repository, not a rule any repository meets, and asserting
    # it is what made the guard fail in a repository created the way
    # `SECURITY.md` creates one. Non-vacuity is held below, on messages this
    # file writes, where it does not depend on whose history is underneath.
    _the_history_says_no_more_than_the_note(REPOSITORY)


def test_the_repository_the_publication_recipe_creates_is_green_on_both_rules(
    tmp_path: Path,
) -> None:
    """Article 0 and `SECURITY.md`: the reviewed tree, pushed with no history behind it."""
    if not (REPOSITORY / ".git").exists() or shutil.which("git") is None:
        pytest.skip("no repository history here to publish from")
    public = tmp_path / "public"
    for name in _tracked_files(REPOSITORY):
        destination = public / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / name, destination)
    for command in (
        ("git", "init", "--quiet", "--initial-branch", "main"),
        ("git", "config", "user.name", "the publisher"),
        ("git", "config", "user.email", "publisher@example.invalid"),
        ("git", "add", "--all"),
        ("git", "commit", "--quiet", "--message", "the reviewed tree of the control plane"),
    ):
        subprocess.run(command, cwd=public, check=True, capture_output=True)
    assert _copy_paragraphs(_history_messages(public)) == [], "no copy is made by publishing"
    _the_tree_records_the_copy(public)
    _the_history_says_no_more_than_the_note(public)


def test_the_copy_note_guard_catches_a_note_that_says_more(tmp_path: Path) -> None:
    """Article 14: the guard is not vacuous — a note carrying more is named."""
    assert _copy_paragraphs([f"feat: a step\n\n{COPY_NOTE}\n"]) == [COPY_NOTE]
    said_more = f"{COPY_NOTE}, covering `ports/example.py`"
    assert _copy_paragraphs([f"feat: a step\n\n{said_more}\n"]) == [said_more]
    assert _copy_paragraphs(["feat: a step with no copy in it"]) == []
