# SPDX-License-Identifier: Apache-2.0
"""Article 14: every operator-facing name this repository publishes is claimed once, here.

A rule of the repository, not of one package: a distribution name, an import
package and a console script are claimed globally, and two claims on one name is
a collision that cannot be unpublished. One rule per file, so a new rule arrives
as a new file and a new file never conflicts (`CONTRIBUTING.md`, article 16).

Two repositories claimed the same three names. The operator settled it on
2026-09-05: `sayfirst` in all three forms — the distribution, the import package
and the console script — belongs to the **product** command-line interface,
which is not published from this repository. What this repository publishes is
the daemon and the commands that inspect it — `plugins list`, the forwarding of
`whoami`, `status` and `conformance replay` — and by the conventional Unix shape
the daemon and its inspection share one binary. That binary is **`sayfirstd`**:
the distribution `sayfirstd`, the import package `sayfirstd`, the console script
`sayfirstd`, all three declared by `packages/cli`.

`sayfirst` the *product name* is untouched by that (article 0, `TRADEMARKS.md`,
the contract vocabulary): only the three claims moved. So the rules here are
about claiming, and they are four.

1. No distribution of this repository claims `sayfirst`, `sayfirst-cli` or
   `sayfirst_cli` — as a distribution name, as a console script, or as an
   import package on disk.
2. `sayfirstd` is claimed in all three forms by exactly one distribution.
3. No console script is installed by two distributions of this repository, which
   is the collision rule the first two are a special case of.
4. No document of this repository gives `sayfirstd` away, and none claims the
   product command as its own. Both halves read the same documents.

Rule 4 reads **claims**, not records. A document that invokes the command —
`sayfirst something` inside backticks or in a console block — claims it. A
sentence this repository *quotes* from its own constitution is the
constitution's claim and not the document's, so a quoted passage is exempt; and
a dated design note under `docs/specs/` records a decision as it stood on its
own date, which a later decision does not falsify, so the specs are outside the
scan. What is inside it and still disagrees is named in `AMENDED_ELSEWHERE`:
the constitution's Rule of article 7, the security policy, and article 8's
Guard still write the caller's grade and the plugin listing as `sayfirst`;
articles 6 and 11's Guards each name that spelling once more, to say precisely
that it is the product client's and not the surface being held. A
repository-scope document is amended by a change of its own, never from a
block branch (`CONTRIBUTING.md`). The list is an admission with an owner, not
a silence: any other document that claims the product command fails this
guard by name.

The names are read from the `[project]` tables and from the source tree, the way
`tests/test_decided_name.py` reads them, and every rule is proven against a
planted defect.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"
CONFORMANCE = REPOSITORY / "packages" / "conformance"

#: The distribution of this repository that holds the operator surface.
OPERATOR_DISTRIBUTION = Path("packages") / "cli" / "pyproject.toml"

#: The one binary that starts nothing and inspects everything: article 6's
#: `whoami`, article 7's `status`, article 8's `plugins list`, under one console
#: script, one distribution and one import package of the same name.
OPERATOR_SURFACE = "sayfirstd"

#: The product command. It is the product's in all three forms, and this
#: repository publishes none of them. Written as a tuple rather than derived
#: from the operator surface by trimming a letter, because a guard that derives
#: what it forbids from what it requires cannot see the two drift apart. Each
#: name is refused in every kind, not only in the kind it was claimed as: a
#: distribution named for the console script would collide just as badly.
PRODUCT_NAMES: tuple[str, ...] = ("sayfirst", "sayfirst-cli", "sayfirst_cli")

#: The one exception, and the article that requires it. Article 8 names the port
#: conformance kit `sayfirst.testing`, so a portion of the top-level namespace
#: `sayfirst` is published from here and cannot move with the command. It is a
#: namespace portion (PEP 420) and not an import package: it carries no
#: `__init__.py`, so it contributes a subpackage to a shared name rather than
#: owning the name, and a wheel that ships `sayfirst_cli` is unaffected by it.
#: The exception is conditional on that, and `_import_packages` refuses it the
#: moment the directory becomes a regular package.
NAMESPACE_PORTION = Path("packages") / "control-plane" / "src" / "sayfirst"

#: The bare product command, the form a document invokes.
PRODUCT_COMMAND = "sayfirst"

#: The documents that still write the command of articles 6, 7, 8 and 11 as the
#: product's. Both are repository-scope documents: they are amended by a change
#: that names them, never from a block branch, so this guard records them as
#: outstanding rather than passing over them in silence.
AMENDED_ELSEWHERE: frozenset[str] = frozenset({"CONSTITUTION.md", "SECURITY.md"})

#: The sentences by which a document says a name belongs to another repository,
#: assembled from pieces so that this guard is not itself an occurrence of what
#: it looks for (the idiom of `tests/test_public_vocabulary.py`).
_ELSEWHERE: tuple[str, ...] = (
    "separate " + "client repository",
    "not published " + "from this repository",
)

#: An inline code span, newlines included: Markdown wraps a span across lines
#: and the reader still reads one command.
_TICK = "`"
INLINE_CODE = re.compile(_TICK + "([^" + _TICK + "]+)" + _TICK)

#: A fenced block, of any info string.
FENCED_BLOCK = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)

#: A double-quoted passage, the form this repository quotes its constitution in.
QUOTED_PASSAGE = re.compile(r"\"([^\"\n]+(?:\n[^\"\n]+)*)\"")


def _imports(root: Path) -> set[str]:
    imported = set()
    for source in root.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    return imported


def _projects(root: Path) -> dict[Path, dict[str, object]]:
    """The `[project]` table of every distribution the workspace builds."""
    return {
        manifest.relative_to(root): tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
        for manifest in sorted(root.glob("packages/*/pyproject.toml"))
    }


def _import_packages(root: Path) -> dict[str, list[Path]]:
    """Which package directories claim each importable top-level name.

    A namespace portion the constitution names is not a claim on the name: it
    contributes a subpackage to a name no single distribution owns. The test is
    the absence of `__init__.py`, read from the tree rather than trusted from
    the list, so the exception disappears the moment the portion becomes a
    regular package.
    """
    claims: dict[str, list[Path]] = {}
    for package in sorted(root.glob("packages/*/src/*")):
        if not package.is_dir() or package.name.startswith((".", "_")):
            continue
        here = package.relative_to(root)
        if here == NAMESPACE_PORTION and not (package / "__init__.py").exists():
            continue
        claims.setdefault(package.name, []).append(here)
    return claims


def _script_claims(root: Path) -> dict[str, list[Path]]:
    """Which manifests claim each console script, in path order."""
    claims: dict[str, list[Path]] = {}
    for manifest, table in _projects(root).items():
        scripts = table.get("scripts") or {}
        assert isinstance(scripts, dict), manifest
        for script in scripts:
            claims.setdefault(script, []).append(manifest)
    return claims


def _twice_claimed(root: Path) -> dict[str, list[Path]]:
    """Every console script two distributions of one repository both install."""
    return {name: where for name, where in _script_claims(root).items() if len(where) > 1}


def _distribution_claims(root: Path) -> dict[str, list[Path]]:
    """Which manifests claim each distribution name."""
    claims: dict[str, list[Path]] = {}
    for manifest, table in _projects(root).items():
        name = table["name"]
        assert isinstance(name, str), manifest
        claims.setdefault(name, []).append(manifest)
    return claims


def _names_claimed(root: Path) -> set[str]:
    """Every distribution name and console script this repository publishes."""
    claimed: set[str] = set(_distribution_claims(root))
    for table in _projects(root).values():
        claimed.update(table.get("scripts") or {})
    return claimed


def _product_claims(root: Path) -> Iterator[tuple[str, str, Path]]:
    """Yield (kind, name, where) for every product name this repository claims."""
    for name in PRODUCT_NAMES:
        for where in _distribution_claims(root).get(name, ()):
            yield "distribution", name, where
        for where in _script_claims(root).get(name, ()):
            yield "console script", name, where
        for where in _import_packages(root).get(name, ()):
            yield "import package", name, where


def _documents(root: Path) -> list[Path]:
    """The documents of this repository that state a claim, in path order.

    `docs/specs/` is outside: a dated design note records the decision of its
    own date, and a later decision does not make the record untrue. The dated
    note the specs carry is what keeps them honest, and rewriting a record to
    agree with a decision taken after it would erase the history the note is
    there to preserve.
    """
    found = sorted(root.glob("*.md"))
    found += sorted(item for item in root.glob("docs/**/*.md") if "specs" not in item.parts)
    found += sorted(root.glob("packages/*/README.md"))
    return found


def _quotations(root: Path, text: str) -> list[str]:
    """The passages of this document that are quotations of its own constitution."""
    constitution = root / "CONSTITUTION.md"
    if not constitution.exists():
        return []
    quoted = _flat(constitution.read_text(encoding="utf-8"))
    return [
        passage
        for passage in QUOTED_PASSAGE.findall(text)
        if _flat(passage) and _flat(passage) in quoted
    ]


def _flat(text: str) -> str:
    """One line, so a sentence survives Markdown's wrapping on either side."""
    return " ".join(text.split())


def _invocations(text: str) -> Iterator[str]:
    """Every command this document invokes: a block line, or an inline code span.

    The fenced blocks are read first and then removed, because their fences are
    backticks too: pairing inline spans across a fence pairs the closing tick of
    one span with the opening tick of the next, and every span after the first
    fence reads as the prose between two commands.
    """
    for block in FENCED_BLOCK.findall(text):
        for line in block.splitlines():
            yield _flat(line.removeprefix("$ "))
    for span in INLINE_CODE.findall(FENCED_BLOCK.sub("", text)):
        yield _flat(span)


def _claims_the_product_command(root: Path) -> Iterator[tuple[Path, str]]:
    """Prose of this repository invoking the product command as its own.

    Yields the document and the invocation. A name in a sentence is not an
    invocation — `sayfirst` names the product in article 0 and in the contract
    vocabulary, and must keep doing so — but `sayfirst` followed by a subcommand,
    written where a reader is meant to type it, is this document claiming the
    command.
    """
    for document in _documents(root):
        text = document.read_text(encoding="utf-8")
        quoted = [_flat(passage) for passage in _quotations(root, text)]
        for invocation in _invocations(text):
            if not re.fullmatch(PRODUCT_COMMAND + r"\s+\S.*", invocation):
                continue
            if any(invocation in passage for passage in quoted):
                continue
            yield document.relative_to(root), invocation


def _claims_given_away(root: Path) -> Iterator[tuple[Path, str, str]]:
    """Prose of this repository saying a name its own tables claim is published elsewhere.

    Yields the document, the name, and the sentence by which it is given away.
    A paragraph is the unit, because that is where the name and the disclaimer
    have to meet for a reader to take the one as being about the other.

    The range is `_documents`, the same range the other half of rule 4 reads:
    one rule reads one set of documents, or the half that reads fewer reports a
    tree clean that the other half would have failed. `docs/deployment.md` is
    the document an operator follows, so it is exactly where a give-away would
    do its damage.
    """
    claimed = _names_claimed(root)
    for document in _documents(root):
        text = document.read_text(encoding="utf-8")
        for paragraph in text.split("\n\n"):
            for sentence in _ELSEWHERE:
                if sentence not in paragraph:
                    continue
                for name in sorted(claimed):
                    if name in paragraph:
                        yield document.relative_to(root), name, sentence


def test_no_console_script_is_claimed_by_two_distributions() -> None:
    """Article 14: a console script is claimed once, and installing two is a collision."""
    claims = _script_claims(REPOSITORY)
    # Anti-vacuity floor: an enumeration that found no script proves nothing.
    assert len(claims) >= 3, claims
    assert _twice_claimed(REPOSITORY) == {}


def test_no_distribution_of_this_repository_claims_a_product_name() -> None:
    """Article 14: `sayfirst` in all three forms is the product's, published elsewhere."""
    projects = _projects(REPOSITORY)
    # Anti-vacuity floor: a workspace with nothing in it claims nothing.
    assert len(projects) >= 5, projects
    assert sorted(_product_claims(REPOSITORY)) == []


def test_the_operator_surface_is_claimed_by_exactly_one_distribution() -> None:
    """Article 14: one binary starts nothing and inspects everything, and it is named once."""
    projects = _projects(REPOSITORY)
    surface = projects[OPERATOR_DISTRIBUTION]

    assert _distribution_claims(REPOSITORY)[OPERATOR_SURFACE] == [OPERATOR_DISTRIBUTION]
    assert _script_claims(REPOSITORY)[OPERATOR_SURFACE] == [OPERATOR_DISTRIBUTION]
    assert surface["name"] == OPERATOR_SURFACE
    assert surface["scripts"] == {OPERATOR_SURFACE: f"{OPERATOR_SURFACE}.main:run"}
    assert _import_packages(REPOSITORY)[OPERATOR_SURFACE] == [
        Path("packages") / "cli" / "src" / OPERATOR_SURFACE
    ]


def test_the_conformance_distribution_claims_no_operator_facing_name() -> None:
    """Article 14: the replayer is its own distribution and takes no name of the surface's."""
    contract = tomllib.loads((CONTRACT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    conformance = tomllib.loads((CONFORMANCE / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert "scripts" not in contract
    assert conformance["name"] == "sayfirst-conformance"
    assert conformance["scripts"] == {"sayfirst-conformance": "sayfirst_conformance.main:main"}
    assert conformance["dependencies"] == ["sayfirst-contract==0.2.0"]
    assert _imports(CONFORMANCE / "src" / "sayfirst_conformance") <= sys.stdlib_module_names | {
        "sayfirst_contract",
        "sayfirst_conformance",
    }
    assert OPERATOR_SURFACE not in (conformance.get("scripts") or {})
    assert not (CONFORMANCE / "src" / OPERATOR_SURFACE).exists()


def test_no_document_claims_the_product_command_or_gives_the_surface_away() -> None:
    """Article 2: a claim about who publishes a name is no stronger than the tables."""
    assert sorted(_claims_given_away(REPOSITORY)) == []
    claiming = sorted(
        {document.as_posix() for document, _ in _claims_the_product_command(REPOSITORY)}
    )
    assert set(claiming) <= AMENDED_ELSEWHERE, claiming


def test_the_documents_that_still_disagree_are_the_ones_named() -> None:
    """Article 2: the admission is an admission, and it is not allowed to go stale.

    `AMENDED_ELSEWHERE` is a list of documents this branch may not write, not a
    list of documents that may say anything. Naming one that no longer claims
    the product command would leave a carve-out with nothing under it, and the
    next document to regress would fall into the hole it left.
    """
    scanned = {document.relative_to(REPOSITORY).as_posix() for document in _documents(REPOSITORY)}
    assert scanned >= AMENDED_ELSEWHERE, sorted(AMENDED_ELSEWHERE - scanned)
    claiming = {document.as_posix() for document, _ in _claims_the_product_command(REPOSITORY)}
    assert claiming >= AMENDED_ELSEWHERE, sorted(AMENDED_ELSEWHERE - claiming)


def test_the_guard_catches_every_defect_it_exists_to_catch(tmp_path: Path) -> None:
    """The guard is proven against each defect, one at a time, in a tree of its own.

    A guard whose subject has never existed in the tree it reads holds nothing,
    which is what the retired `packages/client` assertion did. Each defect is
    planted alone, so a passing run can say which one it caught.
    """
    manifest = tmp_path / "packages" / "cli" / "pyproject.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        f'[project]\nname = "{OPERATOR_SURFACE}"\n\n'
        f'[project.scripts]\n{OPERATOR_SURFACE} = "{OPERATOR_SURFACE}.main:run"\n',
        encoding="utf-8",
    )
    assert _twice_claimed(tmp_path) == {}
    assert sorted(_product_claims(tmp_path)) == []

    # The namespace portion article 8 names is not a claim — while it stays a
    # namespace portion. An `__init__.py` in it makes it a regular package that
    # owns the name, and the exception ends there.
    portion = tmp_path / NAMESPACE_PORTION
    portion.mkdir(parents=True)
    assert sorted(_product_claims(tmp_path)) == []
    (portion / "__init__.py").write_text("", encoding="utf-8")
    assert sorted(_product_claims(tmp_path)) == [("import package", "sayfirst", NAMESPACE_PORTION)]
    (portion / "__init__.py").unlink()

    # Rule 1, in each of its three forms.
    second = tmp_path / "packages" / "conformance" / "pyproject.toml"
    second.parent.mkdir(parents=True)
    second.write_text(
        '[project]\nname = "sayfirst-cli"\n\n[project.scripts]\nsayfirst = "b:main"\n',
        encoding="utf-8",
    )
    package = tmp_path / "packages" / "conformance" / "src" / "sayfirst_cli"
    package.mkdir(parents=True)
    assert sorted(_product_claims(tmp_path)) == [
        ("console script", "sayfirst", Path("packages") / "conformance" / "pyproject.toml"),
        ("distribution", "sayfirst-cli", Path("packages") / "conformance" / "pyproject.toml"),
        (
            "import package",
            "sayfirst_cli",
            Path("packages") / "conformance" / "src" / "sayfirst_cli",
        ),
    ]

    # Rule 3: two distributions installing one console script.
    second.write_text(
        f'[project]\nname = "sayfirst-conformance"\n\n'
        f'[project.scripts]\n{OPERATOR_SURFACE} = "b:main"\n',
        encoding="utf-8",
    )
    assert _twice_claimed(tmp_path) == {
        OPERATOR_SURFACE: [
            Path("packages") / "cli" / "pyproject.toml",
            Path("packages") / "conformance" / "pyproject.toml",
        ]
    }

    # Rule 4, first half: the operator surface given away.
    readme = second.parent / "README.md"
    readme.write_text(
        f"The {_ELSEWHERE[0]} owns the `{OPERATOR_SURFACE}` distribution.\n", encoding="utf-8"
    )
    where = Path("packages") / "conformance" / "README.md"
    assert sorted(_claims_given_away(tmp_path)) == [
        (where, OPERATOR_SURFACE, _ELSEWHERE[0]),
    ]

    # The same give-away under `docs/`, where an operator actually reads it.
    # Both halves of rule 4 read one range of documents: a give-away planted in
    # the deployment guide is the same defect as one planted in a package
    # README, and a half that stopped at the READMEs would report the tree
    # clean while the document the operator follows gave the surface away.
    guide = tmp_path / "docs" / "deployment.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(f"The `{OPERATOR_SURFACE}` command is {_ELSEWHERE[1]}.\n", encoding="utf-8")
    assert sorted(_claims_given_away(tmp_path)) == [
        (Path("docs") / "deployment.md", OPERATOR_SURFACE, _ELSEWHERE[1]),
        (where, OPERATOR_SURFACE, _ELSEWHERE[0]),
    ]

    # Rule 4, second half: the product command claimed, in prose and in a block.
    readme.write_text(
        "Run `sayfirst status --socket PATH` to read it.\n\n"
        "```console\nsayfirst whoami\n```\n\n"
        f"The surface is `{OPERATOR_SURFACE}`, and `{OPERATOR_SURFACE} status` reads it.\n",
        encoding="utf-8",
    )
    assert sorted(_claims_the_product_command(tmp_path)) == [
        (where, "sayfirst status --socket PATH"),
        (where, "sayfirst whoami"),
    ]


def test_the_guard_does_not_read_a_name_or_a_quotation_as_a_claim(tmp_path: Path) -> None:
    """Article 0: the product *name* stays everywhere it names the product.

    A guard that fired on the word would be turned off within a week, and a
    guard nobody runs holds nothing (article 2). Three shapes are asserted
    innocent: the product named in a sentence, a longer distribution name that
    merely starts with it, and a passage quoted from this repository's own
    constitution — the constitution's claim, reported against the constitution
    and against no document that cites it.
    """
    quoted = "`sayfirst whoami` names the separate product client, which does not answer it"
    assert _flat(quoted) in _flat((REPOSITORY / "CONSTITUTION.md").read_text(encoding="utf-8"))

    innocent = tmp_path / "packages" / "cli" / "README.md"
    innocent.parent.mkdir(parents=True)
    innocent.write_text(
        "The product is `sayfirst`, and this is not it.\n\n"
        "```console\nsayfirst-conformance replay --socket allow=/run/allow.sock\n```\n\n"
        f'Article 6\'s Guard: "{quoted}". The surface that renders it is\n'
        f"`{OPERATOR_SURFACE}`.\n",
        encoding="utf-8",
    )
    # The constitution travels with the tree, because the exemption is defined
    # against the constitution of the repository being read, not of this one.
    (tmp_path / "CONSTITUTION.md").write_text(f"Guard. {quoted}.\n", encoding="utf-8")
    assert sorted(_claims_the_product_command(tmp_path)) == [
        (Path("CONSTITUTION.md"), "sayfirst whoami")
    ]
