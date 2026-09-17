# SPDX-License-Identifier: Apache-2.0
"""Article 0: every act this constitution puts on the publication checklist is a line of it.

Four articles point at this page. Article 0 requires the marks filed before
anything is published and the public repository created with its vulnerability
reporting enabled in the same act; article 15 requires counsel's two
confirmations recorded before the first public release; article 16 makes the
sign-off check's required status a setting no check can read; article 18 makes
the request for the next count a line here. A page that named some of those in a
paragraph saying they were not lines yet would satisfy a reader skimming it and
nobody following it, which is the shape this file refuses: an act is a LINE of
the list or it is missing.

**What it asserts.** The section `## Before the tag` parses into bullets; there
are at least as many as there are acts, and never fewer than the floor below;
every act in `ACTS` is carried by one of those bullets; and each act is carried
by a line of its OWN, no two acts resolving to the same line. That last one
closes the way round the others: delete a line, mention its phrase in passing
inside another line, and add a filler line to hold the count, and a rule that
bound a phrase to the section rather than to a line would vouch for a page that
had lost the act. A bullet is read folded — Markdown wraps every line of this
page, and a rule that read one physical line would report almost every act
missing and be turned off the same day. A line is a checkbox, because the page
asks the operator to tick it; the reader strips the box the way it strips
emphasis.

**What it does NOT assert, and must not be read as asserting.** That any act was
performed. No file can read a filing at a registry, an answer from counsel, or a
setting of a hosting platform, so whether a ticked line is true is held by
review — which is the same admission article 16's own Guard makes about the
required status. What is held here is that the operator is asked.

One rule per file, so a new rule arrives as a new file and a new file never
conflicts (`CONTRIBUTING.md`, article 16).

It reads Markdown and the standard library, so it speaks in a reduced run too.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
CHECKLIST = REPOSITORY / "docs" / "publication-checklist.md"

#: The heading the acts stand under. A rewrite that renames or drops it takes the
#: bullet count to zero, which the floor below turns red rather than vacuous.
SECTION = "## Before the tag"

#: Each act this constitution names, and a phrase the line carrying it must hold.
#: The phrase is the act's own few words rather than a whole sentence: a rule
#: that matched a sentence would go red on a rewording that kept the act, and a
#: guard that goes red on a rewording is a guard people learn to edit around.
#: Each entry stands on its own lines with a trailing comma, so that the
#: formatter leaves the shape alone and no line reaches the column limit.
ACTS: tuple[tuple[str, str], ...] = (
    (
        "the marks are filed before anything is published",
        "file the marks",
    ),
    (
        "counsel confirms the publicly-available-software reliance",
        "publicly available software",
    ),
    (
        "counsel confirms the sign-off's effect as a licence grant",
        "licence grant",
    ),
    (
        "the public repository's name is confirmed or renamed",
        "confirm or rename the public repository",
    ),
    (
        "the repository is created with its vulnerability reporting in the same act",
        "private vulnerability reporting",
    ),
    (
        "the display name the index shows",
        "display name",
    ),
    (
        "the deployment environment's reviewer and the trusted-publishing relationship",
        "trusted-publishing relationship",
    ),
    (
        "the sign-off check is a required status",
        "required status",
    ),
    (
        "the count of article 18",
        "concept count",
    ),
    (
        "the dry run",
        "dry run",
    ),
    (
        "the tag is cut on a commit whose whole gate is green",
        "green on the default branch",
    ),
)

#: At least this many bullets stand under the heading. A literal rather than
#: `len(ACTS)`, so that shrinking the act list cannot quietly shrink the floor
#: with it: the two have to be edited apart, and a diff that moves one alone is
#: a diff a reader can see.
BULLET_FLOOR = 11

#: A bullet and everything indented under it, up to the next bullet, the next
#: heading, or the end.
_BULLET_BLOCK = re.compile(r"^- .*?(?=^- |^#|\Z)", re.MULTILINE | re.DOTALL)


def acts_section(page: str) -> str:
    """The text between the acts heading and the next heading, or "" if absent."""
    found = re.search(
        r"^" + re.escape(SECTION) + r"\s*$(.*?)(?=^## |\Z)",
        page,
        re.MULTILINE | re.DOTALL,
    )
    return found.group(1) if found else ""


def bullets(page: str) -> list[str]:
    """Each line of the acts section, folded onto one line the way a person reads it."""
    return [_flat(found.group(0)) for found in _BULLET_BLOCK.finditer(acts_section(page))]


def carries(bullet: str, phrase: str) -> bool:
    """Whether this line holds that phrase."""
    return phrase.lower() in bullet.lower()


def acts_missing_from(page: str) -> list[str]:
    """Every act this page does not carry as a line of its acts section."""
    lines = bullets(page)
    return [act for act, phrase in ACTS if not any(carries(line, phrase) for line in lines)]


def line_carrying(page: str, phrase: str) -> int | None:
    """Which line of the acts section carries that phrase, counting from zero."""
    for index, line in enumerate(bullets(page)):
        if carries(line, phrase):
            return index
    return None


def acts_sharing_a_line(page: str) -> list[tuple[str, str]]:
    """Every pair of acts this page resolves to one and the same line.

    An act carried only by the line of another act is not a line of the list:
    the operator reading down the list has nothing to tick for it.
    """
    seat = {act: line_carrying(page, phrase) for act, phrase in ACTS}
    return [
        (first, second)
        for first, second in itertools.combinations([act for act, _ in ACTS], 2)
        if seat[first] is not None and seat[first] == seat[second]
    ]


def _flat(text: str) -> str:
    """One line, box, emphasis and code marks removed: the phrase survives all three."""
    body = text.removeprefix("- ")
    for box in ("[ ] ", "[x] ", "[X] "):
        body = body.removeprefix(box)
    return " ".join(body.replace("*", "").replace("`", "").split())


def _without(page: str, phrase: str) -> str:
    """The page with the one line carrying that phrase deleted, continuation and all."""
    section = acts_section(page)
    kept = _BULLET_BLOCK.sub(
        lambda found: "" if carries(_flat(found.group(0)), phrase) else found.group(0),
        section,
    )
    return page.replace(section, kept, 1)


def test_the_acts_section_parses_into_the_lines_this_rule_is_about() -> None:
    """ANTI-VACUITY. A walk that found nothing would satisfy every rule below by
    having nothing to check, and would report a page holding no act as complete."""
    found = bullets(CHECKLIST.read_text(encoding="utf-8"))
    assert len(found) >= BULLET_FLOOR, f"only {len(found)} lines found under {SECTION}: {found}"
    assert len(found) >= len(ACTS), (len(found), len(ACTS))


@pytest.mark.parametrize(("act", "phrase"), ACTS, ids=[phrase for _, phrase in ACTS])
def test_every_act_the_constitution_names_is_a_line(act: str, phrase: str) -> None:
    """Article 0: the page is the operator's list, so the act is on the list."""
    lines = bullets(CHECKLIST.read_text(encoding="utf-8"))
    assert any(carries(line, phrase) for line in lines), (
        f"{act} is not a line of {SECTION}: no bullet holds {phrase!r}. Naming it in a "
        f"paragraph above the list is not a line — the operator works from the list."
    )


@pytest.mark.parametrize(("act", "phrase"), ACTS, ids=[phrase for _, phrase in ACTS])
def test_a_copy_of_this_page_with_that_line_removed_is_refused(act: str, phrase: str) -> None:
    """WATCHED FIRING, once per act. A rule whose only evidence is that it passes
    today would also pass if it had stopped applying. Each act in turn is deleted
    from the real page and the rule is required to report it."""
    page = CHECKLIST.read_text(encoding="utf-8")
    without = _without(page, phrase)
    assert len(bullets(without)) == len(bullets(page)) - 1, (
        f"deleting the line carrying {phrase!r} removed "
        f"{len(bullets(page)) - len(bullets(without))} lines: exactly one line carries each act"
    )
    assert act in acts_missing_from(without), (act, phrase)


def test_every_act_stands_on_a_line_of_its_own() -> None:
    """Article 0: a list the operator works down has one line per act, so no line
    is asked to carry two. Holding it as a property rather than as today's luck is
    what keeps the rule above from being satisfied by a passing mention."""
    page = CHECKLIST.read_text(encoding="utf-8")
    assert acts_sharing_a_line(page) == [], (
        "these acts resolve to one line, so one of them has no line of its own: "
        f"{acts_sharing_a_line(page)}"
    )


def test_an_act_moved_into_another_line_behind_a_filler_is_refused() -> None:
    """WATCHED FIRING, on the one shape the rules above cannot see: the act's line
    deleted, its phrase left inside a neighbouring line in passing, and a filler
    line added so the count still clears the floor. Every earlier rule passes on
    that page — which is why this one exists."""
    page = CHECKLIST.read_text(encoding="utf-8")
    deleted = _without(page, "required status")
    mentioned = deleted.replace(
        "Cut the tag on a commit whose whole gate is green",
        "Cut the tag, once the required status is set, on a commit whose whole gate is green",
        1,
    )
    planted = mentioned.replace(
        "\n## The order across the three repositories",
        "\n- [ ] Read this page through once before starting.\n\n"
        "## The order across the three repositories",
        1,
    )

    # The page has lost the act as a line, and every earlier rule is content.
    assert len(bullets(planted)) == len(bullets(page)) >= BULLET_FLOOR
    assert acts_missing_from(planted) == []

    assert acts_sharing_a_line(planted) == [
        (
            "the sign-off check is a required status",
            "the tag is cut on a commit whose whole gate is green",
        )
    ]


def test_a_ticked_line_is_read_the_same_as_an_unticked_one() -> None:
    """WATCHED NOT FIRING. The page asks the operator to tick each line, so the
    box arrives on lines this rule has to keep reading. A reader that keyed on
    `- ` alone would go red the first time someone ticked something, and a guard
    that goes red on being used is a guard that gets deleted."""
    page = (
        "## Before the tag\n\n"
        "- [x] **Set the sign-off check as a required status** in branch protection.\n"
        "- [ ] Prove the dry run before the tag.\n"
    )
    assert bullets(page) == [
        "Set the sign-off check as a required status in branch protection.",
        "Prove the dry run before the tag.",
    ]
    assert carries(bullets(page)[0], "required status")
    assert line_carrying(page, "required status") == 0
    assert line_carrying(page, "dry run") == 1


def test_an_act_named_in_a_paragraph_above_the_list_is_not_a_line() -> None:
    """WATCHED FIRING, on the shape this page used to have. A paragraph naming
    acts « so that their absence is not read as their completion » is a warning to
    a reader and not a line for an operator, and a rule that read the whole page
    would have taken it for one. The one real line is required to still pass, so
    this proves the reading and not a refusal of everything."""
    page = (
        "# Publication checklist\n\n"
        "Three acts are not lines of this page yet, and are named here so that their\n"
        "absence is not read as their completion: the marks filed, counsel's two\n"
        "confirmations, and private vulnerability reporting enabled in the same act.\n\n"
        "## Before the tag\n\n"
        "- Confirm or rename the public repository before the tag.\n"
    )
    assert len(bullets(page)) == 1
    missing = acts_missing_from(page)
    assert "the repository is created with its vulnerability reporting in the same act" in missing
    assert "the public repository's name is confirmed or renamed" not in missing


def test_a_page_whose_acts_section_was_renamed_is_refused() -> None:
    """WATCHED FIRING on the other half: a rewrite that renames or drops the
    heading leaves the walk with nothing, and a rule that passed on nothing would
    vouch for a page holding no act at all."""
    page = CHECKLIST.read_text(encoding="utf-8").replace(SECTION, "## Things to do", 1)
    assert bullets(page) == []
    assert len(acts_missing_from(page)) == len(ACTS)


def test_a_line_wrapped_across_several_lines_is_read_as_one() -> None:
    """WATCHED NOT FIRING. Every line of this page is wrapped at the column limit,
    so a rule that read one physical line would report almost every act missing
    and would be turned off the same day."""
    page = (
        "## Before the tag\n\n"
        "- **Require a reviewer on the `pypi` deployment environment, and create the\n"
        "  trusted-publishing relationship** for this repository's release workflow.\n"
    )
    assert bullets(page) == [
        "Require a reviewer on the pypi deployment environment, and create the "
        "trusted-publishing relationship for this repository's release workflow."
    ]
    assert carries(bullets(page)[0], "trusted-publishing relationship")
