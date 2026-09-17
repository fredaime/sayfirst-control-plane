# SPDX-License-Identifier: Apache-2.0
"""Articles 2 and 7: a document offers the grades this version can obtain, and no others.

A rule of the repository, not of one package: the integrity grade is the
strongest thing this software says about itself, and the front page is where a
reader meets it first. Article 7 defines three grades and this repository holds
itself to all three; `evaluate_grade` returns two of them, because evidence
grade needs a proof of exclusivity no store adapter here can make. A document
that names the third without saying that reads as an offer, and an offer no
deployment can take up is the claim article 2 exists to prevent. One rule per
file, so a new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
EVALUATOR = (
    REPOSITORY
    / "packages"
    / "control-plane"
    / "src"
    / "sayfirst_control_plane"
    / "domain"
    / "integrity_grade.py"
)

#: The documents that tell a reader which grade a deployment runs at. Each names
#: every grade this version can obtain, so that the reader can tell from the
#: document rather than from the source.
NAMING_THE_GRADES = (
    Path("README.md"),
    Path("SECURITY.md"),
    Path("packages/control-plane/README.md"),
)

#: `CONSTITUTION.md` states the rule the project holds itself to, which is not a
#: claim about what this version ships; a specification under `docs/specs` is a
#: dated record of a decision and speaks for the day it was written. Every other
#: document speaks in the present tense about this version and is held below.
NOT_A_CLAIM_ABOUT_THIS_VERSION = (Path("CONSTITUTION.md"), Path("docs/specs"))

#: Directories that carry no document this repository authored.
NOT_AUTHORED_HERE = frozenset({".git", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache"})

#: A paragraph that names a grade this version cannot obtain has to say so. The
#: marker is deliberately coarse — the words "this version" beside a negation —
#: because the rule is that the reader is told, not that they are told in one
#: prescribed sentence. A paragraph that names the grade and neither is an offer.
THIS_VERSION = re.compile(r"this version", re.IGNORECASE)
A_NEGATION = re.compile(r"\b(?:no|not|never|cannot)\b", re.IGNORECASE)


def _names(grade: str) -> re.Pattern[str]:
    """A grade named as a grade: "evidence grade", or the value in code or bold."""
    return re.compile(
        rf"\b{re.escape(grade)}\b[*`_ ]*grade|`{re.escape(grade)}`|\*\*{re.escape(grade)}\*\*",
        re.IGNORECASE,
    )


def _grades_the_evaluator_can_return(source: str) -> frozenset[str]:
    """The grade values `evaluate_grade` hands back, read from its own returns."""
    evaluator = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name == "evaluate_grade"
    )
    return frozenset(
        member.attr
        for statement in ast.walk(evaluator)
        if isinstance(statement, ast.Return) and statement.value is not None
        for member in ast.walk(statement.value)
        if isinstance(member, ast.Attribute)
        and isinstance(member.value, ast.Name)
        and member.value.id == "Grade"
    )


def _grades_article_7_defines(source: str) -> frozenset[str]:
    """The three values of article 7, read from the enum that carries them."""
    grade = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ClassDef) and node.name == "Grade"
    )
    return frozenset(
        target.id
        for statement in grade.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
    )


def _offered(text: str, grade: str) -> list[str]:
    """Paragraphs naming a grade without saying this version cannot obtain it."""
    named = _names(grade)
    return [
        paragraph
        for paragraph in re.split(r"\n\s*\n", text)
        if named.search(paragraph)
        and not (THIS_VERSION.search(paragraph) and A_NEGATION.search(paragraph))
    ]


def _documents_held() -> list[Path]:
    """Every document of this repository that speaks about this version."""
    excluded = tuple(REPOSITORY / part for part in NOT_A_CLAIM_ABOUT_THIS_VERSION)
    return sorted(
        document
        for document in REPOSITORY.rglob("*.md")
        if not NOT_AUTHORED_HERE.intersection(document.parts)
        and document not in excluded
        and not any(parent in excluded for parent in document.parents)
    )


def test_every_grade_this_version_can_obtain_is_named_where_a_reader_looks() -> None:
    """Article 2: which grades a deployment can obtain is readable without the source."""
    obtainable = _grades_the_evaluator_can_return(EVALUATOR.read_text(encoding="utf-8"))
    assert obtainable, "the evaluator returns no grade at all"
    for document in NAMING_THE_GRADES:
        text = (REPOSITORY / document).read_text(encoding="utf-8")
        for grade in sorted(obtainable):
            assert _names(grade).search(text), f"{document} does not name the {grade} grade"


def test_no_document_offers_a_grade_this_version_cannot_obtain() -> None:
    """Articles 2 and 7: article 7's third grade is a rule held, not a capability shipped."""
    source = EVALUATOR.read_text(encoding="utf-8")
    unobtainable = _grades_article_7_defines(source) - _grades_the_evaluator_can_return(source)
    # The day the evaluator can return `evidence`, every document below says
    # something that is no longer true and the loop under it goes vacuous. This
    # line is where that is noticed, so it is pinned rather than derived.
    assert unobtainable == {"evidence"}, "the grades this version cannot obtain have changed"
    documents = _documents_held()
    assert REPOSITORY / "README.md" in documents
    offered = [
        (document.relative_to(REPOSITORY), paragraph)
        for document in documents
        for grade in sorted(unobtainable)
        for paragraph in _offered(document.read_text(encoding="utf-8"), grade)
    ]
    assert offered == []


def test_the_grade_claim_guard_catches_a_document_that_offers_the_grade() -> None:
    """Article 2: the guard is not vacuous — an offer, a denial and plain prose."""
    offer = "It can be verified from the outside at evidence grade (article 7)."
    assert _offered(offer, "evidence") == [offer]
    denial = "Article 7 defines evidence grade; no deployment of this version reaches it."
    assert _offered(denial, "evidence") == []
    assert _offered("The daemon keeps the evidence a decision produced.", "evidence") == []
    assert _names("observability").search("emits only `observability`")
    assert not _names("observability").search("a governance and observability layer")
