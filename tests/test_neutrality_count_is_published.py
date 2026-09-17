# SPDX-License-Identifier: Apache-2.0
"""Article 18: the count is published as reported, and an absent one is not a zero.

Article 18 asks the maintainers to publish, at each release, the number of
concepts the parent application had to add on its own side in order to
integrate, with the counting rule that produced it. This repository cannot
verify that number — it is measured on the other side of the boundary — so
article 18's Guard says it is published as reported and that this repository
says so.

What a guard CAN hold is the two things that go wrong without one. A release
that publishes no row at all, which turns the article into a sentence nobody
performs. And an absent count rendered as `0`, which article 2 forbids by name:
« an absent count is published as "not reported", never as zero ». Zero is a
measurement. « Not reported » is the absence of one, and the two mean opposite
things to a reader deciding whether this core is drifting.

What it must NOT hold is a wording. The row of the version this tree would
release says « not reported » *or* a number with the rule it was counted by,
because article 18 asks the maintainers of the parent application to answer at
each release and the answer is the state the article is aiming at — a guard
that pinned the newest row to « not reported » would turn the first real answer
red and teach the person who received it to weaken the guard. « Not reported »
therefore stays admissible at every row, the oldest included: the last row of a
newest-first table is the first count this project ever published, and a
project that published its first release before anyone had answered is exactly
the state this table already records.

One rule per file (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
NEUTRALITY = REPOSITORY / "docs" / "NEUTRALITY.md"

sys.path.insert(0, str(REPOSITORY / "scripts"))

from release_version import release_version  # noqa: E402

#: The one spelling of an absent count. Article 2 and article 18 both name it.
NOT_REPORTED = "not reported"

#: A row of the published table: version, count, counting rule.
ROW = re.compile(r"^\|\s*([0-9]+\.[0-9]+\.[0-9]+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$", re.M)


def rows(document: str) -> list[tuple[str, str, str]]:
    """Every published count, newest first, as (version, count, rule).

    Document order, and the table is written « Newest first », so the first
    item is the newest release and the LAST is the first count this project
    ever published.
    """
    return [(version, count, rule) for version, count, rule in ROW.findall(document)]


def row_for(document: str, version: str) -> tuple[str, str, str] | None:
    """The published row of one release, or None when there is none."""
    return next((row for row in rows(document) if row[0] == version), None)


def is_honest(count: str) -> bool:
    """Either a number somebody reported, or the one spelling of an absence."""
    return count == NOT_REPORTED or count.isdigit()


def test_the_document_exists_and_this_guard_reads_rows_from_it() -> None:
    """ANTI-VACUITY. A document with no row would make every assertion below
    pass by absence, which is the failure this repository keeps finding."""
    assert NEUTRALITY.is_file(), NEUTRALITY
    published = rows(NEUTRALITY.read_text(encoding="utf-8"))
    assert published, "the neutrality table has no row: article 18 is performed by nobody"


def test_the_version_this_tree_would_release_has_a_row() -> None:
    """Article 18: the count is published AT EACH RELEASE."""
    published = rows(NEUTRALITY.read_text(encoding="utf-8"))
    assert release_version(REPOSITORY) in {version for version, _, _ in published}


def test_the_row_of_this_release_is_a_reported_number_or_says_none_was() -> None:
    """Article 18 and article 2: the answer, or the absence of one, never a guess.

    Both states are what the article asks for at different moments — a number
    once the maintainers of the parent application have answered, « not
    reported » until they have — so the rule is that the row is one of the two
    and carries the rule it was counted by either way.
    """
    published = NEUTRALITY.read_text(encoding="utf-8")
    version = release_version(REPOSITORY)
    row = row_for(published, version)
    assert row is not None, version
    _, count, rule = row
    assert is_honest(count), row
    assert rule.strip(), row


def test_no_row_is_blank_or_a_dash_in_place_of_a_count() -> None:
    """Every row either carries a number the maintainers of the parent
    application reported, or says that none was reported. A row that is blank,
    or that carries a dash, is an absence wearing a measurement's clothes. A
    zero is a number: nothing here can tell a reported zero from an absence, so
    the rule that an absence is never written as zero is held by review."""
    published = rows(NEUTRALITY.read_text(encoding="utf-8"))
    for version, count, rule in published:
        assert is_honest(count), (version, count)
        assert rule.strip(), (version, rule)


def test_the_first_count_ever_published_may_say_that_none_was_reported() -> None:
    """The oldest row is the last of a newest-first table, and « not reported »
    is admissible there as it is anywhere else.

    Said as a case rather than left to be inferred, because the previous
    reading of this rule pinned a row to that spelling and would have turned
    red on the first release anybody answered for. The table's own order is
    asserted here, since everything above depends on it.
    """
    published = rows(NEUTRALITY.read_text(encoding="utf-8"))
    assert published, "the table has no row"
    oldest = published[-1]
    assert is_honest(oldest[1]), oldest
    assert [version for version, _, _ in published] == sorted(
        (version for version, _, _ in published),
        key=lambda version: tuple(int(part) for part in version.split(".")),
        reverse=True,
    ), "the table is written newest first; this rule reads the oldest row as the last"


def test_the_rule_fires_on_an_absence_dressed_as_a_measurement() -> None:
    """WATCHED FIRING. A rule whose only evidence is that it passes today would
    also pass if it had stopped applying — and every row of this table passes
    it, so the proof has to be planted. A dash and a blank are the two ways an
    unanswered request reaches a table without saying so."""
    for planted in ("| 0.2.0 | — | nobody answered |\n", "| 0.2.0 |  | nobody answered |\n"):
        published = rows(planted)
        assert published, f"the reader saw no row in {planted!r}: the probe proves nothing"
        assert not is_honest(published[0][1]), published[0]


def test_the_rule_leaves_a_reported_zero_alone() -> None:
    """WATCHED NOT FIRING. A reported zero is a measurement and is publishable —
    nothing had to be added — and it is publishable at the newest row like any
    other answer. What is refused is an ABSENCE rendered as a number, which is
    the case above."""
    planted = "| 0.9.0 | 0 | counted by the integration review, none added |\n"
    version, count, rule = rows(planted)[0]
    assert is_honest(count) and count.isdigit() and rule.strip()
    assert row_for(planted, "0.9.0") == (version, count, rule)
