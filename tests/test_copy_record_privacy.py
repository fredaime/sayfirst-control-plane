# SPDX-License-Identifier: Apache-2.0
"""Article 14: which files a copy brought belongs to the private record.

A rule of the repository, not of one package: it holds over every document this
repository publishes. Article 14 makes the provenance review a required step of
every copy from a source this repository does not hold, and keeps the review's
record private; a document may state the rule, but naming this repository's own
files beside a copy note is that review published. One rule per file, so a new
rule arrives as a new file and a new file never conflicts (`CONTRIBUTING.md`,
article 16).
"""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]

#: The opening of a copy note, in either wording the constitution allows.
COPIES = re.compile(r"copied from a (?:private|parent)", re.IGNORECASE)

#: A source-file path cited in prose.
CITED_PATH = re.compile(r"`([A-Za-z0-9_./-]+/[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,5})`")


def _public_copy_records(root: Path) -> list[tuple[Path, str]]:
    """Return public prose that names a file of this repository beside a copy note."""
    records = []
    for source in root.rglob("*"):
        if not source.is_file() or ".git" in source.parts or source.suffix != ".md":
            continue
        # A record is a copy note and the files it names, under one heading.
        for section in re.split(r"\n#{1,6} ", source.read_text(encoding="utf-8")):
            if not COPIES.search(section):
                continue
            records.extend(
                (source.relative_to(root), cited)
                for cited in CITED_PATH.findall(section)
                if (root / cited).exists()
            )
    return records


def test_no_public_document_records_which_files_a_copy_brought() -> None:
    """Article 14: which modules a copy brought belongs to the private record."""
    assert list((REPOSITORY / "docs").rglob("*.md"))
    assert _public_copy_records(REPOSITORY) == []


def test_the_copy_record_guard_catches_a_published_inventory(tmp_path: Path) -> None:
    """Article 14: the guard is proven against a planted inventory."""
    (tmp_path / "docs").mkdir()
    target = tmp_path / "docs" / "planted.md"
    target.write_text(
        "These were " + "copied from a private" + " repository:\n\n- `docs/planted.md`\n",
        encoding="utf-8",
    )
    assert _public_copy_records(tmp_path) == [(Path("docs/planted.md"), "docs/planted.md")]
