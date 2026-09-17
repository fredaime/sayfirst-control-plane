# SPDX-License-Identifier: Apache-2.0
"""A package registers itself by existing, and the discovery is proven here.

The root `pyproject.toml` used to name every package twice — once in pytest's
search paths, once in its import paths — so a new package could only join the
test run by editing two shared lists. Blocks are built in parallel from one
base, so a list every block edits is a conflict every pair of blocks has, and
that conflict carries no information: its resolution is always the union
(`CONTRIBUTING.md`, article 16).

Discovery replaces the lists, and discovery that silently misses a package is
worse than a list, because a list is at least visible. So the configuration is
held by these two tests: the first asserts that every directory matching
`packages/*/tests` is collected by the configuration as it stands, the second
that every import root matching `packages/*/src` is on the path the tests
import from, and each names the package it did not find.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def _test_directories(root: Path) -> list[Path]:
    """Every package's test directory, as repository-relative paths."""
    return sorted(item.relative_to(root) for item in root.glob("packages/*/tests") if item.is_dir())


def _source_roots(root: Path) -> list[Path]:
    """Every package's import root, as repository-relative paths."""
    return sorted(item.relative_to(root) for item in root.glob("packages/*/src") if item.is_dir())


def _collected(root: Path) -> set[Path]:
    """The directories the current configuration collects at least one test from.

    Collection is run the way the gate runs it — no arguments, from the
    repository root — because that is the invocation whose behaviour is being
    held, and it is the only one for which pytest reads the search paths at all.
    """
    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ),
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    collected: set[Path] = set()
    for line in completed.stdout.splitlines():
        node, separator, _ = line.partition("::")
        if separator:
            collected.add(Path(node).parent)
    # Anti-vacuity floor: a collection that found nothing proves nothing.
    assert len(collected) >= 2, completed.stdout
    return collected


def _resolves_under(found: importlib.machinery.ModuleSpec | None, root: Path) -> bool:
    """Whether an import of this name reaches this source root.

    A regular package answers with the file it was found in. A namespace
    package (PEP 420) has no single file and answers with its search
    locations instead, and it is no less imported for that: `packages/*/src`
    is exactly the layout that lets one distribution contribute a portion of
    a shared top-level name.
    """
    if found is None:
        return False
    if found.origin is not None:
        return root in Path(found.origin).parents
    return any(root in Path(item).parents for item in found.submodule_search_locations or ())


def test_every_package_test_directory_is_collected() -> None:
    """Article 16: a package's tests run because it exists, not because a list says so."""
    directories = _test_directories(REPOSITORY)
    assert directories, "no package carries tests; the guard would hold vacuously"
    collected = _collected(REPOSITORY)
    missed = [
        directory
        for directory in directories
        if not any(item == directory or directory in item.parents for item in collected)
    ]
    assert missed == [], missed


def test_every_package_source_root_is_importable() -> None:
    """Article 16: a package's modules import because it exists, not because a list says so."""
    roots = _source_roots(REPOSITORY)
    assert roots, "no package carries sources; the guard would hold vacuously"
    unreachable = []
    for root in roots:
        for module in sorted((REPOSITORY / root).iterdir()):
            if module.name.startswith((".", "_")) or not module.is_dir():
                continue
            found = importlib.util.find_spec(module.name)
            if not _resolves_under(found, REPOSITORY / root):
                unreachable.append(root / module.name)
    assert unreachable == [], unreachable
