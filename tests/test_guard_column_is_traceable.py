# SPDX-License-Identifier: Apache-2.0
"""Article 2: the constitution's Guard column names only what this tree can run.

The constitution's own preamble says what the Guard column is for: it "names
what enforces [the rule] mechanically, or says 'not yet mechanised', which is a
statement about the guard, never a licence to break the rule". A Guard
paragraph is therefore a claim about this repository, and article 2 binds it
like every other claim the software makes: no stronger than the evidence held
for it. This file is that evidence, read back out of the tree.

**What it asserts, exactly.** For every article of `CONSTITUTION.md`:

1. **The paragraph parses.** Every article heading is followed by a `**Guard.**`
   paragraph, and there are at least nineteen of them. The floor is the
   anti-vacuity floor of the whole file: a parse that found nothing would
   otherwise satisfy every rule below by having nothing to check, and a
   twentieth article added later is walked, never enumerated
   (`docs/specs/2026-09-04-skeleton-21-contract-design.md`, "Guards").
2. **Every citation resolves.** A path ending `.py`, `.md`, `.yml`, `.yaml`,
   `.json` or `.toml`, and every `test_*` identifier, is a citation. A citation
   must name a file that exists on this branch, or a test function some file on
   this branch defines. One that does not is a mechanism the reader cannot find.
3. **Every executable citation is executed.** A cited test file must lie under
   one of the `testpaths` globs pytest expands, so the suite collects it; a
   cited test function must be defined in such a file; a cited source module —
   a `.py` file under one of the `packages/*/src` roots `conftest.py` puts on
   the import path — must be reached by the import graph of the tests the suite
   collects, directly or through another module, because what executes a module
   is an import of it and never a mention of its path; a cited script must be
   named somewhere in a workflow file or in the source of a collected test — a
   substring, not a parse of the step; a cited workflow must carry a trigger.
   A mechanism nothing runs is what the audit of 2026-09-06 called
   indistinguishable from absent, and the failure message says which of the two
   it is. Documents (`.md`, `.toml`, `.json`) are held to rule
   2 only: a document is read, not executed.
4. **A deferral names what is missing.** "not yet mechanised", "held by review"
   and "cannot verify" are the column's three admissions. The sentence carrying
   one must name a subject besides the admission itself — measured as at least
   three words of three letters or more, once the admission and a short list of
   function words are removed. Nothing here reads what the subject *is*; the
   measure is that "not yet mechanised" alone cannot silence this file.
5. **Every clause points somewhere a reader can follow.** The unit is the
   clause, not the sentence: the column joins independent promises with
   semicolons, and article 15 makes four of them in one sentence, so at
   sentence scope a single honest admission at the end would carry three
   unnamed mechanisms in front of it. Each clause must carry a citation
   (rules 2 and 3), an admission (rule 4), or a `(article N)` cross-reference.
   Without this rule, a row silences every rule above it by deleting its
   citations, and the near-miss — a row that keeps one true citation and adds
   three unnamed claims beside it — passes.

**What it does not assert, and must not be read as asserting.** It never judges
whether a mechanism *covers what its sentence claims*. That a test named in
article 7 really lowers a grade on a permission change, that the checker named
in article 15 really reads licence text, that the verifier named in article 9
really rejects a pack that proves nothing — each of those is a human reading of
one row against one implementation, and a test that pretended to make it would
itself be a Guard claiming more than it holds, which is the defect this file
exists to catch. The rows that are expected-red below are red for exactly that
kind of defect, and there are as many of them as `RULE_FIVE_IS_RED_TODAY`
holds entries — none, at the time of writing, so the run reports nineteen
articles against four parametrised rules with no `xfail` and no `xpass`;
making a red row green is a repair of that row, not of this file.

One thing it reads rather than measures, said plainly because the rest of the
file measures: what pytest *collects* is taken from the `testpaths` globs in
`pyproject.toml` and expanded against the tree, rather than from a collection
this file runs. A subprocess collection would be the stronger reading, and it
would also make this guard fail whenever the suite cannot be imported — which
is the exact condition, found by the audit, under which the column drifted
unopposed. `tests/test_package_discovery.py` holds those globs against the
tree, so the reading has a guard of its own.

The import graph is read the same way, from `import` statements rather than
from a run, and the same limit is said here: an import written inside a
function or under a condition that never holds is counted as an import, so the
graph is an over-approximation of what a run touches. It is the right side to
err on for this rule — the finding is "nothing runs it", and a mechanism some
test really does import must never be reported as unrun — and it is strictly
narrower than the substring the rule used before it, which counted a comment.

**The rows that are red today** carry `xfail(strict=True)` with the article
number and the reason. Strict is the coordination: when a sibling repair makes
a row honest the xfail becomes an unexpected pass and the suite goes red until
the marker is deleted, so no repair can land while still claiming to be pending.

**Self-proof.** Planted defects, run against the real tree that has just
passed, so what they prove is that this run's checks would have caught them: a
Guard citing a file that does not exist, a Guard citing an absent test function
whose name is a substring of a cited path, a Guard citing a real file nothing
executes (planted into this repository and removed again), a Guard citing a
real module that only a comment names, and a Guard whose deferral names
nothing. Each asserts the check goes red. One more is built as a small tree of
its own rather than planted into this one — the reading rule 3 is handed, which
needs a branch holding a module nothing imports, which this branch, by
intention, does not. A guard that has never been seen to fail is not known to
be a guard (`scripts/check_dependency_closure.py` of the client repository,
article 13).
"""

from __future__ import annotations

import ast
import fnmatch
import re
import shutil
import tempfile
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from functools import cache
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
CONSTITUTION = REPOSITORY / "CONSTITUTION.md"

#: At least this many articles carry a Guard paragraph. The constitution has
#: nineteen; a parse that finds fewer has stopped reading the document rather
#: than found a shorter one, and every rule below would pass on its silence.
ARTICLE_FLOOR = 19

#: At least this many citations resolve across the whole column, so that rule 2
#: cannot pass by recognising nothing as a citation.
CITATION_FLOOR = 3

#: At least this many test files are collected and this many test functions
#: defined, so that "nothing is executed" cannot be an empty index answering.
COLLECTED_FILE_FLOOR = 20
DEFINED_FUNCTION_FLOOR = 200

#: Where a workspace package's modules live: the same glob `conftest.py` puts on
#: the import path, so a package that joins the repository is walked by
#: existing. `tests/test_package_discovery.py` holds the pair against the tree.
SOURCE_ROOT_GLOB = "packages/*/src"

#: At least this many workspace modules are reached by the collected tests'
#: imports, so that a graph that read nothing cannot report every module unrun
#: — the failure this floor names would be of the reading, not of the column.
IMPORTED_MODULE_FLOOR = 50

#: At least one Guard defers, so that rule 4 is never checked against nothing.
DEFERRAL_FLOOR = 1

#: The three admissions the column is allowed to make instead of a mechanism.
ADMISSIONS = ("not yet mechanised", "held by review", "cannot verify")

#: A sentence may point at another article instead of at a file.
CROSS_REFERENCE = re.compile(r"\(article \d+\)")

#: A path citation: a file name with one of the suffixes this repository holds.
PATH_CITATION = re.compile(r"(?:[A-Za-z0-9_.\-]+/)*[A-Za-z0-9_\-]+\.(?:py|md|ya?ml|json|toml)")

#: A test-function citation. pytest's own default for what a test is named.
FUNCTION_CITATION = re.compile(r"\btest_[A-Za-z0-9_]+\b")

#: Words that carry no subject, removed before rule 4 counts what a deferral named.
FUNCTION_WORDS = frozenset(
    {"a", "an", "and", "are", "as", "at", "be", "been", "being", "by", "for", "from"}
    | {"has", "have", "in", "is", "it", "its", "not", "of", "on", "or", "that", "the"}
    | {"their", "them", "there", "they", "this", "to", "was", "were", "which", "with", "yet"}
)


@dataclass(frozen=True)
class Citation:
    """One thing a Guard paragraph named, and what kind of thing it is."""

    text: str
    kind: str  # "test file" | "source module" | "script" | "workflow"
    #          | "document" | "test function"


@dataclass(frozen=True)
class Tree:
    """What this branch holds, read once and handed to every check.

    `functions_anywhere` is wider than `functions_collected` on purpose: the
    difference between the two is exactly the difference between "the mechanism
    does not exist" and "it exists and nothing runs it", which rule 3 must say.

    `imported_modules` is the same distinction for a module: it holds the
    dotted name of every module of this workspace the collected tests reach
    through their imports, so a module that exists and that no test imports is
    told apart from one that is not there at all.
    """

    root: Path
    collected_files: frozenset[str]
    functions_collected: frozenset[str]
    functions_anywhere: frozenset[str]
    executed_sources: str
    workflows: frozenset[str]
    imported_modules: frozenset[str]


def guard_paragraphs(text: str) -> dict[int, str]:
    """Every article's Guard paragraph, by article number, whitespace normalised.

    The document is walked from its article headings, never from a list of
    article numbers written here: an article added later is parsed by existing.
    """
    guards: dict[int, str] = {}
    heading = re.compile(r"^## Article (\d+) — ", re.MULTILINE)
    positions = [(int(match.group(1)), match.start()) for match in heading.finditer(text)]
    for index, (number, start) in enumerate(positions):
        end = positions[index + 1][1] if index + 1 < len(positions) else len(text)
        for block in text[start:end].split("\n\n"):
            if block.lstrip().startswith("**Guard.**"):
                guards[number] = " ".join(block.split())
                break
    return guards


def sentences(paragraph: str) -> list[str]:
    """The paragraph's sentences, the `**Guard.**` label itself removed."""
    body = paragraph.removeprefix("**Guard.**").strip()
    return [part for part in re.split(r"(?<=[.!?])\s+(?=[A-Z`])", body) if part.strip()]


def clauses(paragraph: str) -> list[str]:
    """The paragraph's independent claims.

    The column joins independent claims with semicolons — article 15 makes four
    separate promises in one sentence — so the sentence is too coarse a unit for
    rule 5: one honest admission at the end of a sentence would carry three
    unnamed mechanisms in front of it. Rule 4 still reads the whole sentence,
    because what an admission defers is said around it, not inside its clause.
    """
    return [
        part.strip()
        for sentence in sentences(paragraph)
        for part in sentence.split(";")
        if part.strip()
    ]


def citations(paragraph: str) -> list[Citation]:
    """Everything the paragraph named that this branch could be asked to hold."""
    found: list[Citation] = []
    seen: set[str] = set()
    for path in PATH_CITATION.findall(paragraph):
        if path in seen:
            continue
        seen.add(path)
        found.append(Citation(path, _kind_of_path(path)))
    text_without_paths = PATH_CITATION.sub(" ", paragraph)
    for name in FUNCTION_CITATION.findall(text_without_paths):
        if name in seen:
            continue
        seen.add(name)
        found.append(Citation(name, "test function"))
    return found


def _kind_of_path(path: str) -> str:
    """What kind of thing a citation named, decided by where the tree keeps it.

    The three `.py` classes are three different answers to "what would run
    this": the suite collects a test file, an import executes a source module,
    and a step invokes a script. Rule 3 asks each of them its own question, and
    the class a path has no answer for is the one that made an honest citation
    of a module read as unrun.
    """
    if path.endswith((".yml", ".yaml")):
        return "workflow" if path.startswith(".github/workflows/") else "document"
    if path.endswith(".py"):
        if _under_a_testpath(path):
            return "test file"
        return "source module" if _dotted_name(path) else "script"
    return "document"


@cache
def _testpath_globs(root: Path) -> tuple[str, ...]:
    """The globs pytest expands, read from the configuration pytest reads."""
    configuration = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return tuple(configuration["tool"]["pytest"]["ini_options"]["testpaths"])


def _under_a_testpath(path: str, root: Path = REPOSITORY) -> bool:
    """Would pytest's own `testpaths` reach this file? Its globs decide, not a list here."""
    return any(re.fullmatch(fnmatch.translate(f"{glob}/*"), path) for glob in _testpath_globs(root))


@cache
def _source_roots(root: Path) -> tuple[Path, ...]:
    """The directories an import resolves against, read the way `conftest.py` reads them."""
    return tuple(sorted(item for item in root.glob(SOURCE_ROOT_GLOB) if item.is_dir()))


def _below_a_source_root(path: Path, root: Path) -> tuple[str, ...] | None:
    """This file's position below the source root that would import it, suffix removed."""
    for source_root in _source_roots(root):
        try:
            return path.relative_to(source_root).with_suffix("").parts
        except ValueError:
            continue
    return None


def _dotted_name(path: str, root: Path = REPOSITORY) -> str | None:
    """The name an `import` statement would write for this path, or None if none can.

    A path no source root holds is not a module: it is a script a step invokes,
    a test the suite collects, or a document, and rule 3 asks it a different
    question.
    """
    parts = _below_a_source_root(root / path, root)
    if parts is None:
        return None
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or None


def _package_of(path: Path, root: Path) -> str:
    """The package a relative import inside this file counts from; "" outside the workspace."""
    parts = _below_a_source_root(path, root)
    return "" if parts is None else ".".join(parts[:-1])


def _imported_names(path: Path, package: str) -> set[str]:
    """Every module name this file's `import` statements name, read from its syntax."""
    try:
        module = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):  # pragma: no cover - defect elsewhere
        return set()
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                if not package:  # a relative import outside the workspace anchors nowhere here
                    continue
                anchor = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                base = f"{anchor}.{base}" if base else anchor
            if not base:
                continue
            # `from a.b import c` reaches `a.b`, and reaches `a.b.c` when `c` is
            # a module rather than a name `a.b` defines. The statement does not
            # say which, so both are offered and only what resolves to a file
            # below is kept.
            names.add(base)
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def _modules_by_name(root: Path) -> dict[str, Path]:
    """Every module this workspace holds, by the name a test would import it as."""
    found: dict[str, Path] = {}
    for source_root in _source_roots(root):
        for item in sorted(source_root.rglob("*.py")):
            relative = item.relative_to(root)
            if any(part.startswith((".", "__pycache__")) for part in relative.parts):
                continue
            name = _dotted_name(relative.as_posix(), root)
            if name:
                found[name] = item
    return found


def _reached_by_imports(root: Path, collected: Iterable[str]) -> frozenset[str]:
    """Every module of this workspace the collected tests import, however indirectly.

    The walk follows `import` statements rather than the text of a path:
    importing `a.b.c` executes `a`, `a.b` and `a.b.c`, so every package on the
    way is reached, and a name this workspace holds no file for is a standard
    library or third-party import that ends that branch of the walk. This is
    what rule 3 means by "something on this branch runs it" for a module — a
    mention of its path runs nothing.
    """
    modules = _modules_by_name(root)
    pending = [
        name
        for relative in sorted(collected)
        for name in _imported_names(root / relative, _package_of(root / relative, root))
    ]
    reached: set[str] = set()
    while pending:
        parts = pending.pop().split(".")
        for depth in range(1, len(parts) + 1):
            prefix = ".".join(parts[:depth])
            if prefix in reached or prefix not in modules:
                continue
            reached.add(prefix)
            pending.extend(_imported_names(modules[prefix], _package_of(modules[prefix], root)))
    return frozenset(reached)


def read_tree(root: Path) -> Tree:
    """Read the branch: what pytest collects, what those files define, what CI runs."""
    globs = _testpath_globs(root)
    collected: set[str] = set()
    for glob in globs:
        for directory in sorted(root.glob(glob)):
            if directory.is_dir():
                collected.update(
                    item.relative_to(root).as_posix() for item in directory.rglob("test_*.py")
                )
    sources = [(root / relative).read_text(encoding="utf-8") for relative in sorted(collected)]
    everywhere = _function_names(
        item
        for item in sorted(root.rglob("*.py"))
        if not any(part.startswith((".", "__pycache__")) for part in item.relative_to(root).parts)
    )
    in_collected = _function_names(root / relative for relative in sorted(collected))
    workflows = {
        item.relative_to(root).as_posix()
        for item in sorted((root / ".github" / "workflows").glob("*.y*ml"))
    }
    for workflow in sorted(workflows):
        sources.append((root / workflow).read_text(encoding="utf-8"))
    return Tree(
        root=root,
        collected_files=frozenset(collected),
        functions_collected=in_collected,
        functions_anywhere=everywhere,
        executed_sources="\n".join(sources),
        workflows=frozenset(workflows),
        imported_modules=_reached_by_imports(root, collected),
    )


def _function_names(files: Iterable[Path]) -> frozenset[str]:
    """Every function these files define, read from their syntax rather than their text."""
    names: set[str] = set()
    for path in files:
        try:
            module = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):  # pragma: no cover - defect elsewhere
            continue
        for node in ast.walk(module):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                names.add(node.name)
    return frozenset(names)


def unresolved(paragraph: str, tree: Tree) -> list[str]:
    """Rule 2: every citation this paragraph made that this branch cannot show."""
    reported = []
    for citation in citations(paragraph):
        if citation.kind == "test function":
            if citation.text not in tree.functions_anywhere:
                reported.append(
                    f"cites the test function {citation.text}, which no file on this branch "
                    "defines: the mechanism does not exist"
                )
        elif not (tree.root / citation.text).is_file():
            reported.append(
                f"cites {citation.kind} {citation.text}, which is not a file on this branch: "
                "the mechanism does not exist"
            )
    return reported


def unexecuted(paragraph: str, tree: Tree) -> list[str]:
    """Rule 3: every citation that exists on this branch and that nothing runs."""
    reported = []
    for citation in citations(paragraph):
        if citation.kind == "document":
            continue
        if citation.kind == "test function":
            if citation.text in tree.functions_collected:
                continue
            if citation.text not in tree.functions_anywhere:
                continue  # its absence is rule 2's finding, not this one's
            reported.append(
                f"cites the test function {citation.text}, which is defined on this branch but "
                "in no file the suite collects: it exists and nothing runs it"
            )
            continue
        if not (tree.root / citation.text).is_file():
            continue  # likewise
        if citation.kind == "test file":
            if citation.text in tree.collected_files:
                continue
            reported.append(
                f"cites the test file {citation.text}, which exists but lies under no testpath "
                "glob, so the suite never collects it: it exists and nothing runs it"
            )
        elif citation.kind == "workflow":
            if re.search(r"^on:", (tree.root / citation.text).read_text(encoding="utf-8"), re.M):
                continue
            reported.append(
                f"cites the workflow {citation.text}, which exists but carries no trigger: "
                "it exists and nothing runs it"
            )
        elif citation.kind == "source module":
            # A module is executed by being imported. It is deliberately not
            # cleared by a workflow step naming its path: no step in this
            # repository runs a module that way, and widening this to a text
            # match is exactly the defect the class was added to remove.
            if _dotted_name(citation.text, tree.root) in tree.imported_modules:
                continue
            reported.append(
                f"cites the source module {citation.text}, which exists but no test the suite "
                "collects imports it, directly or through another module: it exists and "
                "nothing runs it"
            )
        elif citation.text not in tree.executed_sources:
            reported.append(
                f"cites the script {citation.text}, which exists but no workflow step and no "
                "collected test names it: it exists and nothing runs it"
            )
    return reported


def _content_words(text: str) -> list[str]:
    words = re.findall(r"[A-Za-z][A-Za-z'-]+", text.lower())
    return [word for word in words if len(word) >= 3 and word not in FUNCTION_WORDS]


def empty_deferrals(paragraph: str) -> list[str]:
    """Rule 4: every admission in this paragraph that names nothing it defers."""
    reported = []
    for sentence in sentences(paragraph):
        for admission in ADMISSIONS:
            if admission not in sentence.lower():
                continue
            remainder = re.sub(re.escape(admission), " ", sentence, flags=re.IGNORECASE)
            named = _content_words(remainder)
            if len(named) < 3:
                reported.append(
                    f'defers with "{admission}" in a sentence that names nothing it defers: '
                    f"{sentence!r}"
                )
    return reported


def unfollowable(paragraph: str, tree: Tree) -> list[str]:
    """Rule 5: every clause that points at no citation, no admission, no article."""
    del tree  # rules 2 and 3 read the tree; this one reads only what the clause points at
    reported = []
    for clause in clauses(paragraph):
        if citations(clause):
            continue
        if any(admission in clause.lower() for admission in ADMISSIONS):
            continue
        if CROSS_REFERENCE.search(clause):
            continue
        reported.append(
            "claims a mechanism it does not name, and does not defer: a reader "
            f"cannot follow it to anything on this branch: {clause!r}"
        )
    return reported


@pytest.fixture(scope="module")
def tree() -> Tree:
    return read_tree(REPOSITORY)


@pytest.fixture(scope="module")
def guards() -> dict[int, str]:
    return guard_paragraphs(CONSTITUTION.read_text(encoding="utf-8"))


#: Rule 5 is red on no row today: every Guard clause names a mechanism this
#: tree runs, admits one of the three deferrals and says what it defers, or
#: cites another article. The dictionary, `_rows(RULE_FIVE_IS_RED_TODAY)` and
#: its parametrisation stay in place, empty, because they are the coordination
#: the docstring above describes and the next red row needs them: an entry
#: added here is strict, so the sibling repair that makes the row honest turns
#: its expected failure into an unexpected pass and the suite goes red until
#: the entry is deleted with the repair. Deleting the mechanism would leave the
#: next red row with nowhere to be recorded but a comment.
RULE_FIVE_IS_RED_TODAY: dict[int, str] = {}


def _articles() -> list[int]:
    return sorted(guard_paragraphs(CONSTITUTION.read_text(encoding="utf-8")))


def _rows(red: dict[int, str] | None = None) -> list[object]:
    """One parameter per article, walked from the document, never enumerated here."""
    red = red or {}
    return [
        pytest.param(
            number,
            id=f"article-{number}",
            marks=[pytest.mark.xfail(strict=True, reason=red[number])] if number in red else [],
        )
        for number in _articles()
    ]


def _report(number: int, rule: str, lines: list[str]) -> str:
    detail = "\n".join(f"  - {line}" for line in lines)
    return f"the Guard paragraph of article {number} {rule}:\n{detail}"


def test_every_article_carries_a_guard_paragraph(guards: dict[int, str]) -> None:
    """Rule 1: the parse reaches every article, and at least nineteen of them."""
    headings = re.findall(r"^## Article (\d+) — ", CONSTITUTION.read_text(encoding="utf-8"), re.M)
    assert len(headings) >= ARTICLE_FLOOR, "the parse found fewer articles than the document has"
    missing = sorted(set(map(int, headings)) - set(guards))
    assert not missing, f"articles with no Guard paragraph this file could parse: {missing}"
    assert len(guards) >= ARTICLE_FLOOR


def test_the_tree_these_rules_are_read_against_is_not_empty(
    tree: Tree, guards: dict[int, str]
) -> None:
    """The anti-vacuity floors: no rule below may pass by having found nothing."""
    assert len(tree.collected_files) >= COLLECTED_FILE_FLOOR
    assert len(tree.functions_collected) >= DEFINED_FUNCTION_FLOOR
    assert len(tree.imported_modules) >= IMPORTED_MODULE_FLOOR, (
        f"the collected tests reach {len(tree.imported_modules)} modules; rule 3 would report "
        "every cited module unrun, which would be a finding about this reading"
    )
    assert tree.workflows, "no workflow: rule 3 could never find a mechanism CI runs"
    found = [citation for paragraph in guards.values() for citation in citations(paragraph)]
    assert len(found) >= CITATION_FLOOR, f"the column cites {len(found)} things; rule 2 is vacuous"
    deferring = [number for number, text in guards.items() if _admissions_in(text)]
    assert len(deferring) >= DEFERRAL_FLOOR, "no Guard defers; rule 4 is checked against nothing"


def _admissions_in(text: str) -> list[str]:
    return [admission for admission in ADMISSIONS if admission in text.lower()]


@pytest.mark.parametrize("number", _rows())
def test_every_citation_in_a_guard_resolves(
    number: int, guards: dict[int, str], tree: Tree
) -> None:
    """Rule 2: what a Guard names is on this branch."""
    reported = unresolved(guards[number], tree)
    assert not reported, _report(number, "names something this branch does not hold", reported)


@pytest.mark.parametrize("number", _rows())
def test_every_cited_mechanism_is_executed(number: int, guards: dict[int, str], tree: Tree) -> None:
    """Rule 3: what a Guard names, something on this branch runs."""
    reported = unexecuted(guards[number], tree)
    assert not reported, _report(
        number, "names a mechanism that exists and that nothing executes", reported
    )


@pytest.mark.parametrize("number", _rows())
def test_a_deferral_names_what_it_defers(number: int, guards: dict[int, str]) -> None:
    """Rule 4: an admission says what is missing, so it cannot silence this file."""
    reported = empty_deferrals(guards[number])
    assert not reported, _report(number, "defers without saying what it defers", reported)


@pytest.mark.parametrize("number", _rows(RULE_FIVE_IS_RED_TODAY))
def test_every_clause_points_at_something_a_reader_can_follow(
    number: int, guards: dict[int, str], tree: Tree
) -> None:
    """Rule 5: every claim in the column names a file, admits a deferral, or cites an article."""
    reported = unfollowable(guards[number], tree)
    assert not reported, _report(number, "claims what a reader cannot follow", reported)


def test_this_guard_is_itself_executed_by_the_public_gate(tree: Tree) -> None:
    """Rule 3, applied to this file: a guard the gate never runs is indistinguishable from absent.

    The audit's first finding was that the public workflow reached no guard at
    all, so nothing on the branch could contradict the column. A file that holds
    the column honest and that CI does not run would repeat that defect one
    level up, and it would be this file claiming a guard it does not hold.
    """
    mine = Path(__file__).resolve().relative_to(REPOSITORY).as_posix()
    assert mine in tree.collected_files, "the suite does not collect this file"
    assert mine in tree.executed_sources, "no workflow step names this file: the gate never runs it"


# The self-proof. Each of the three plants runs against the real branch, after
# the checks above have run on it, so what a plant proves is that *this* run's
# check would have caught that defect. A plant that is not caught is a failure
# of the gate and not a decoration of it: a guard nobody has seen fail is not
# known to be a guard.
#
# Every line these three produce is a defect this file planted on purpose and
# removed again. None of them is a live violation of the constitution, and a
# failure here reads "PLANT NOT CAUGHT", never "article N".

PLANT_NOT_CAUGHT = "PLANT NOT CAUGHT — this guard cannot fail: "


def _planted(lines: list[str]) -> str:
    """What a plant caught, labelled so that a line quoted out of context stays a plant.

    A reader of the client repository's gate log misread its two proof lines as
    a live violation this morning and reported one that did not exist. Every
    line these three tests can put in front of a reader carries the label, so
    the same quotation cannot happen here.
    """
    label = "  PLANTED DEFECT, NOT A LIVE VIOLATION — caught by: "
    return "\n".join(label + line for line in lines)


def test_the_guard_catches_a_guard_that_cites_a_file_that_does_not_exist(tree: Tree) -> None:
    """Plant 1 of 3: an unresolvable citation is caught, and called absent, not unrun."""
    absent = "tests/test_a_guard_this_branch_does_not_hold.py"
    assert not (REPOSITORY / absent).exists(), "the plant must name something really absent"
    planted = f"**Guard.** `{absent}` fails on any occurrence of the defect."

    caught = unresolved(planted, tree)
    assert caught, PLANT_NOT_CAUGHT + "a Guard citing a file that does not exist was accepted"
    assert absent in caught[0] and "the mechanism does not exist" in caught[0], _planted(caught)
    # The two states rule 3 must tell apart: an absent mechanism is reported by
    # rule 2 alone, so that neither report can be read as the other.
    assert unexecuted(planted, tree) == []


def test_the_guard_catches_an_absent_test_function_whose_name_is_a_path_substring(
    tree: Tree,
) -> None:
    """Plant: a cited test function whose name is a substring of a cited path is not dropped."""
    planted = "**Guard.** `tests/test_decided_name.py` carries `test_decided` to verify the rule."
    caught = unresolved(planted, tree)
    assert caught, (
        PLANT_NOT_CAUGHT + "an absent test function was dropped because its name was in a path"
    )
    assert "test_decided" in caught[0] and "the mechanism does not exist" in caught[0], _planted(
        caught
    )


def test_the_guard_catches_a_guard_that_cites_a_real_file_nothing_executes(tree: Tree) -> None:
    """Plant 2 of 3: a mechanism that exists and that nothing runs is caught, and called that."""
    planted_directory = Path(tempfile.mkdtemp(dir=REPOSITORY / "scripts", prefix="planted-"))
    script = planted_directory / "no_step_and_no_test_names_this.py"
    try:
        script.write_text("# SPDX-License-Identifier: Apache-2.0\n", encoding="utf-8")
        relative = script.relative_to(REPOSITORY).as_posix()
        planted = f"**Guard.** `{relative}` is run in public CI on every change."
        # Read the branch again, as it now is, rather than trusting the reading
        # taken before the plant: the file is really there for this check.
        after = read_tree(REPOSITORY)
        assert unresolved(planted, after) == [], "the plant must be a file that really exists"
        caught = unexecuted(planted, after)
    finally:
        shutil.rmtree(planted_directory)
    assert caught, PLANT_NOT_CAUGHT + "a Guard citing a file no step and no test runs was accepted"
    assert "it exists and nothing runs it" in caught[0], _planted(caught)
    assert not (REPOSITORY / relative).exists(), "the plant was not removed"


def _a_module_the_collected_tests_import(tree: Tree) -> str:
    """One module of this workspace some collected test really imports, by path.

    Chosen from the tree rather than written here, so the plant below keeps
    proving the same thing after the module it happened to pick is renamed.
    """
    for name, path in sorted(_modules_by_name(tree.root).items()):
        if name in tree.imported_modules:
            return path.relative_to(tree.root).as_posix()
    raise AssertionError("no module of this workspace is imported: the graph read nothing")


def test_a_module_the_collected_tests_import_is_not_reported_unrun(tree: Tree) -> None:
    """The other half of the same defect: an honest citation of a module is not a finding.

    Rule 3's report is "it exists and nothing runs it". Said of a module some
    collected test imports, it is false, and a column repaired to satisfy it
    would have to delete a true citation or write the path into prose — the
    bending this file's own docstring forbids. So the honest case is held here
    beside the plant, and the two together pin the rule from both sides.
    """
    module = _a_module_the_collected_tests_import(tree)
    planted = f"**Guard.** `{module}` is what this article's rule is enforced by."
    assert unexecuted(planted, tree) == [], (
        "rule 3 reports a module the collected tests import as unrun: it measures spelling"
    )


def test_the_guard_catches_a_source_module_that_only_a_comment_names(tree: Tree) -> None:
    """Plant: a module is executed by an import, and a comment naming its path is not one.

    This is the defect this file carried until 2026-09-08 and the review of
    2026-09-07 filed: rule 3 asked whether the cited path appeared verbatim in
    the concatenated source of the collected tests and the workflows. Article
    3's honest citation of the information contract was reported unrun — four
    collected tests import that module by dotted name and none of them spells
    the path — while one comment line naming any path cleared the check. Both
    halves are planted here: the path written into the text the old rule read,
    and the module taken out of the graph the new one reads.
    """
    module = _a_module_the_collected_tests_import(tree)
    assert _kind_of_path(module) == "source module", "the plant must cite a module, not a script"
    planted = f"**Guard.** `{module}` is what this article's rule is enforced by."
    named_only = replace(
        tree,
        executed_sources=f"{tree.executed_sources}\n# {module}\n",
        imported_modules=tree.imported_modules - {_dotted_name(module, tree.root)},
    )
    caught = unexecuted(planted, named_only)
    assert caught, PLANT_NOT_CAUGHT + "a module cleared by a comment naming its path was accepted"
    assert "no test the suite collects imports it" in caught[0], _planted(caught)
    assert "it exists and nothing runs it" in caught[0], _planted(caught)


def test_the_import_graph_reaches_what_an_import_reaches_and_nothing_else(tmp_path: Path) -> None:
    """Plant: the reading rule 3 is handed, over a branch whose import graph is known exactly.

    The plants around this one run against the real tree, which is the stronger
    reading and the one this file prefers. This one cannot: it needs a branch
    holding a module that nothing imports, and this branch — measured, not
    assumed — holds none. So the branch is built, small and whole, and the same
    `_reached_by_imports` is run over it.
    """
    source = tmp_path / "packages" / "sample" / "src" / "sample"
    (source / "deep").mkdir(parents=True)
    (source / "__init__.py").write_text("", encoding="utf-8")
    (source / "deep" / "__init__.py").write_text("", encoding="utf-8")
    (source / "imported.py").write_text(
        "import json\nfrom .deep import reached\n", encoding="utf-8"
    )
    (source / "deep" / "reached.py").write_text("", encoding="utf-8")
    (source / "unimported.py").write_text("", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_it.py").write_text(
        "from sample.imported import thing\n\n# sample/unimported.py\n", encoding="utf-8"
    )

    reached = _reached_by_imports(tmp_path, ["tests/test_it.py"])

    assert _dotted_name("packages/sample/src/sample/deep/reached.py", tmp_path) == (
        "sample.deep.reached"
    ), PLANT_NOT_CAUGHT + "a module under a source root was not given the name an import writes"
    assert "sample.imported" in reached, PLANT_NOT_CAUGHT + "a directly imported module was missed"
    assert "sample.deep.reached" in reached, (
        PLANT_NOT_CAUGHT + "a module reached only through another module was missed"
    )
    assert {"sample", "sample.deep"} <= reached, (
        PLANT_NOT_CAUGHT + "a package executed on the way to a module was missed"
    )
    assert "sample.unimported" not in reached, (
        PLANT_NOT_CAUGHT + "a module named only in a comment was read as imported"
    )
    assert "json" not in reached, "the walk must stop at the edge of this workspace"


def test_the_guard_catches_a_deferral_that_names_nothing() -> None:
    """Plant 3 of 3: an admission that defers nothing is caught, so it cannot silence this file."""
    honest = "**Guard.** The corporate agreements signed are recorded by a maintainer "
    assert empty_deferrals(honest + "(not yet mechanised).") == [], (
        "an admission that names what it defers must pass, or rule 4 forbids honest deferral"
    )
    caught = empty_deferrals("**Guard.** Not yet mechanised.")
    assert caught, (
        PLANT_NOT_CAUGHT + "a Guard that defers everything and names nothing was accepted"
    )
    assert "names nothing it defers" in caught[0], _planted(caught)
