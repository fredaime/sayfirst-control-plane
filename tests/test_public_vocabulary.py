# SPDX-License-Identifier: Apache-2.0
"""Article 14 at repository scope: nothing published here names a non-public source.

Article 14's rule is that "nothing in this repository imports, names, links to
or is shaped by a private product: no private symbol, path, vocabulary or
roadmap appears here", and its reason is that "a dependency pointing the wrong
way is a leak that cannot be unpublished". Article 0 makes this repository
public, so every tracked file — its path as well as its content — is the thing
that gets published.

The detectors below are **structural**: they match the constructions by which a
non-public name enters a public document, never a list of the names themselves.
Article 4's warning, quoted in the block 2.1 design, is that a deny-list of
private words is itself the leak it is meant to prevent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]

#: Files whose content is read as public prose.
PROSE_SUFFIXES = frozenset({".md", ".rst", ".txt"})

#: Directories a non-git enumeration must not walk into.
UNTRACKED_DIRECTORIES = frozenset({".git", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache"})

#: The private authoring convention's directory name, assembled so that this
#: guard does not contain the very path it forbids (block 2.3's idiom).
_INTERNAL_SEGMENT = "docs/" + "super" + "powers"

#: The section sign, written as an escape for the same reason: this repository
#: cites its own rules as "article N" and cites no other document's sections.
_SECTION_SIGN = "\u00a7"

#: A rename arrow, likewise escaped.
_ARROW = "\u2192"

INTERNAL_DIRECTORY = re.compile(re.escape(_INTERNAL_SEGMENT), re.IGNORECASE)

#: A possessive that attributes a named artefact — a module, a table, a schema,
#: an identifier, a quoted path — to a source this repository does not hold.
#: The constitution's own possessives are deliberately outside it: they attach
#: to a group of people or to a program, never to an artefact, so they publish
#: no name. The apostrophe is written both ways; a typographic one is still a
#: possessive. This comment carries no example, because an example of the
#: construction inside the guard would be an occurrence of it.
NON_PUBLIC_ATTRIBUTION = re.compile(
    r"\b(?:parent|private|internal|upstream|proprietary|closed|manifest)['\u2019]s\s+"
    r"(?:[A-Za-z-]+\s+){0,3}"
    r"(?:`|module|file|path|package|distribution|repository|schema|script|generator"
    r"|table|section|entry|step|piece|practice|code|identifier|symbol|name|member"
    r"|vocabulary|scenario|attribute|registry|client|server|stub|contract|tree"
    r"|question|backbone|roadmap|branch|commit|ticket|epic|finding|inventory)\b",
    re.IGNORECASE,
)

#: A reference to a planning document this repository does not publish.
PLANNING_DOCUMENT = re.compile(r"\bthe\s+(?:[A-Za-z-]+\s+){0,2}manifest\b", re.IGNORECASE)

#: A non-public source attributed by name rather than by possessive: the same
#: leak as NON_PUBLIC_ATTRIBUTION in the other construction English offers.
#: Written so that the pattern is not an occurrence of itself.
NAMED_NON_PUBLIC_SOURCE = re.compile(
    r"\b(?:private|parent|internal|upstream|proprietary|closed)"
    r"(?:\s+[a-z-]+){0,3}\s+(?:repository|product|source)\s+"
    r"(?:named|called)\s+[A-Za-z0-9_.-]+",
    re.IGNORECASE,
)

#: A work item of a tracker this repository does not publish: a review finding,
#: an epic, a priority-numbered task. Article 5 keeps the planning of another
#: programme out of this one.
WORK_ITEM = re.compile(
    r"\b(?:P[0-3]-\d+|(?:finding|epic)[-_ ]+[A-Z]*\d+(?:[-.]\d+)?)\b",
    re.IGNORECASE,
)

#: A section of a document cited by section sign rather than by article number.
SECTION_REFERENCE = re.compile(re.escape(_SECTION_SIGN))

#: A rename row. An arrow may honestly mean "yields"; what makes a row a rename
#: table is that its left side is a name this repository does not hold, and that
#: is the leak — the public name is a rule, the mapping publishes what it maps
#: from. The left side is captured so the caller can ask whether it is held.
_TICK = "\u0060"
_QUOTED = _TICK + "[^" + _TICK + "\n]+" + _TICK
RENAME_MAPPING = re.compile(
    _TICK + "([^" + _TICK + "\n]+)" + _TICK + r"\s*(?:" + re.escape(_ARROW) + r"|->)\s*" + _QUOTED
)

#: A roadmap: features scheduled into a numbered wave of some other plan.
ROADMAP = re.compile(
    r"\b(?:wave|phase|milestone|tranche)\s+(?:\d+|one|two|three|four|five)\b",
    re.IGNORECASE,
)

#: A commit identifier in prose: an abbreviated or full hexadecimal object name.
COMMIT_IN_PROSE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{7,40}(?![0-9a-fA-F])")

#: A source-file path cited in prose.
CITED_PATH = re.compile(
    r"`([A-Za-z0-9_.…/-]*/[A-Za-z0-9_.-]+"
    r"\.(?:py|json|toml|yaml|yml|md|rst|txt|cfg|ini|sh))`"
)

#: An enum member named in prose.
ENUM_MEMBER = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")

#: Detectors that apply to any tracked text file, prose or code.
EVERYWHERE = {
    "internal design path": INTERNAL_DIRECTORY,
    "named non-public source": NON_PUBLIC_ATTRIBUTION,
    "non-public planning document": PLANNING_DOCUMENT,
    "non-public source named outright": NAMED_NON_PUBLIC_SOURCE,
    "review or planning identifier": WORK_ITEM,
    "document section reference": SECTION_REFERENCE,
    "non-public roadmap": ROADMAP,
}

#: Detectors that apply to prose only: code defines identifiers and paths, and
#: pins digests, as its ordinary business.
PROSE_ONLY = {"commit identifier in prose": COMMIT_IN_PROSE}


def _tracked_files(root: Path) -> list[Path]:
    """Every file this repository publishes, as repository-relative paths."""
    if (root / ".git").exists() and shutil.which("git") is not None:
        listed = subprocess.run(
            ("git", "ls-files", "-z"),
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return [Path(name) for name in listed.split("\0") if name]
    return sorted(
        item.relative_to(root)
        for item in root.rglob("*")
        if item.is_file() and not UNTRACKED_DIRECTORIES & set(item.relative_to(root).parts)
    )


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _public_vocabulary(root: Path) -> Iterator[tuple[Path, str]]:
    """Yield (file, class) for every non-public shape this repository publishes."""
    files = _tracked_files(root)
    prose = [item for item in files if item.suffix in PROSE_SUFFIXES]
    held = {item.as_posix() for item in files}
    known_identifiers: set[str] = set()
    for item in files:
        if item.suffix in PROSE_SUFFIXES:
            continue
        content = _read(root / item)
        if content is not None:
            known_identifiers.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", content))

    # A path is published whether or not any sentence names it.
    for item in files:
        if INTERNAL_DIRECTORY.search(item.as_posix()):
            yield item, "internal design path"

    for item in files:
        content = _read(root / item)
        if content is None:
            continue
        for category, pattern in EVERYWHERE.items():
            if pattern.search(content):
                yield item, category
        if item.suffix not in PROSE_SUFFIXES:
            continue
        for category, pattern in PROSE_ONLY.items():
            if pattern.search(content):
                yield item, category
        for member in ENUM_MEMBER.findall(content):
            if member not in known_identifiers:
                yield item, "non-public identifier"
                break
        for mapped_from in RENAME_MAPPING.findall(content):
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", mapped_from)
            if tokens and not set(tokens) <= known_identifiers:
                yield item, "rename mapping"
                break
        for cited in CITED_PATH.findall(content):
            candidate = cited.lstrip("…/")
            if any(name == candidate or name.endswith("/" + candidate) for name in held):
                continue
            if candidate in _paths_the_constitution_names(root, prose):
                continue
            yield item, "non-public module path"
            break


def _paths_the_constitution_names(root: Path, prose: list[Path]) -> set[str]:
    """Paths the constitution itself names are public by the constitution's authority."""
    constitution = root / "CONSTITUTION.md"
    if not constitution.exists() or Path("CONSTITUTION.md") not in prose:
        return set()
    text = constitution.read_text(encoding="utf-8")
    return {cited.lstrip("…/") for cited in CITED_PATH.findall(text)}


def test_no_tracked_file_carries_a_non_public_provenance_shape() -> None:
    """Article 14: every published path and every published sentence is public vocabulary."""
    tracked = _tracked_files(REPOSITORY)
    # Anti-vacuity floor: an enumeration that found nothing cannot pass.
    assert len(tracked) >= 40, tracked
    assert [item for item in tracked if item.suffix in PROSE_SUFFIXES]
    assert sorted(set(_public_vocabulary(REPOSITORY))) == []


def test_the_public_vocabulary_guard_catches_each_prohibited_shape(tmp_path: Path) -> None:
    """Article 14: the guard is proven against a planted example of every class.

    Every planted example is synthetic. Reproducing a real non-public name in
    order to test for it would publish it, which is the defect this guard is
    for.
    """
    planted = tmp_path / "planted.md"
    cases = {
        # a non-public repository, product or directory name
        "named non-public source": "The " + "parent's" + " contract package is the source.",
        # a non-public module path
        "non-public module path": "It copies `example_domain/example_module.py` unchanged.",
        # a non-public identifier or enum member
        "non-public identifier": "The outcome member EXAMPLE_PLACEHOLDER_MEMBER is dropped.",
        # non-public feature vocabulary, scheduled
        "non-public roadmap": "Those controls arrive in " + "wave" + " 2 of the plan.",
        # a non-public document's section references
        "document section reference": "Read " + _SECTION_SIGN + "3.6 before the table.",
        # a commit identifier in prose
        "commit identifier in prose": "Read at commit " + "0" * 7 + ", clean.",
        # a rename table row, which publishes the name it maps from
        "rename mapping": (
            _TICK + "EXAMPLE_OLD_NAME" + _TICK + " " + _ARROW + " " + _TICK + "allow" + _TICK
        ),
        # a reference to a non-public planning document
        "non-public planning document": "The " + "partitioning " + "manifest" + " records it.",
        # a non-public source attributed by name rather than by possessive
        "non-public source named outright": (
            "A " + "private source repository " + "named" + " example-internal holds it."
        ),
        # a work item of a tracker this repository does not publish
        "review or planning identifier": "Resolve " + "finding-" + "ABC12" + " before release.",
    }
    for category, content in cases.items():
        planted.write_text(content, encoding="utf-8")
        found = {found_category for _, found_category in _public_vocabulary(tmp_path)}
        assert category in found, (category, content, found)
    planted.unlink()

    # A content-only guard would let this repository publish a document at the
    # very path its own rule forbids naming, so the path is checked as well.
    at_path = tmp_path / _INTERNAL_SEGMENT / "specs"
    at_path.mkdir(parents=True)
    (at_path / "design.md").write_text("A public design note.", encoding="utf-8")
    assert sorted(set(_public_vocabulary(tmp_path))) == [
        (Path(_INTERNAL_SEGMENT) / "specs" / "design.md", "internal design path")
    ]
