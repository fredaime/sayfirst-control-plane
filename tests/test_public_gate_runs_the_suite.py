# SPDX-License-Identifier: Apache-2.0
"""Articles 2 and 16: the public gate reaches the guards it reports on.

One rule per file (`CONTRIBUTING.md`, article 16). A guard that exists but that
the workflow never executes is, to a reader of the constitution's Guard column,
indistinguishable from one that does not exist — and a Guard paragraph saying
"runs in CI" over a workflow that stops before collection is the overclaim
article 2 forbids. So the three invocation properties the gate depends on are
held here rather than remembered: the workspace is installed, the environment
is the one `uv.lock` records, and the checkout carries the history the guards
read.

The middle one is scoped to the steps that run the suite, and the scope is said
rather than left to be inferred: `uv run ruff check .` and `uv run ruff format
--check .` are not held to `--frozen` here. Making them frozen would turn a
stale lock into a failure of the lint steps as well, which is a decision about
how this project wants to be told, not a property of the guards reaching the
suite, and it is held by review until somebody takes it.

The workflow is read as text on purpose: the properties are of the command line
the runner will type, and a parsed job graph would have to be re-derived into
that same string to be checked at all.

**The one exemption, and what it costs to take.** The constitution leg exists
to run on a day the workspace cannot be installed — the exact condition under
which the Guard column drifted unopposed — so requiring `--all-packages` of it
would delete its reason for being a leg of its own. It is therefore allowed to
run uninstalled, and the permission is not a spelling. A step takes it by
declaring `imports-no-workspace-package`, and the declaration is honoured only
where the tree bears it out: the invocation must pass `--basetemp`, because the
repository `conftest.py` imports a workspace package to derive a run root and
does so only when it is not given one, and every file the invocation names must
import no workspace package, read from that file's own syntax. A step that
declares the exemption and does either wrong is reported like any other, which
is what `test_a_declared_exemption_without_basetemp_is_still_caught` and
`test_a_declared_exemption_over_a_file_that_imports_the_workspace_is_caught`
plant and run. What the pair does not cover is a pytest plugin or a `conftest.py`
below the named file pulling the workspace in by another route; that is held by
review, and the failure it would produce is a loud collection error rather than
a silent pass.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
WORKFLOWS = REPOSITORY / ".github" / "workflows"

#: What a step writes to claim it needs no installed workspace. Read as a claim
#: and never as a licence: `_exempt` decides whether the tree bears it out.
DECLARES_NO_WORKSPACE_IMPORT = "imports-no-workspace-package"


def _workflows() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def _workspace_packages(root: Path = REPOSITORY) -> frozenset[str]:
    """The top-level names an import of this workspace writes, read from the tree.

    The same `packages/*/src` glob `conftest.py` puts on the import path, so a
    package that joins the repository is recognised by existing.
    """
    return frozenset(
        item.stem if item.suffix == ".py" else item.name
        for source_root in root.glob("packages/*/src")
        for item in source_root.iterdir()
        if not item.name.startswith((".", "_"))
    )


def _imports_a_workspace_package(path: Path, packages: frozenset[str]) -> bool:
    """Does this file import a package this workspace ships? Its syntax says, not its text."""
    try:
        module = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return True  # a file this guard cannot read is not one it will vouch for
    return bool(_imported_roots(module) & packages)


def _imported_roots(module: ast.Module) -> set[str]:
    """The top-level name of every module this syntax tree imports."""
    roots: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _step_around(lines: list[str], number: int) -> list[str]:
    """The lines of the workflow step this line belongs to, from its `- ` to the next one."""
    starts = [n for n, line in enumerate(lines) if re.match(r"\s*- ", line)]
    before = [n for n in starts if n <= number] or [0]
    after = [n for n in starts if n > number]
    return lines[before[-1] : after[0] if after else len(lines)]


def _exempt(step: list[str], root: Path = REPOSITORY) -> bool:
    """Is this step's claim to need no installed workspace one the tree bears out?

    Three things, and the declaration on its own is none of them. `--basetemp`
    is what keeps `conftest.py` out of the workspace; the files the step names
    must import no workspace package themselves; and the step must say that it
    is claiming this, so that a step which merely happens to satisfy both is
    still read as an ordinary run and still owes `--all-packages`.
    """
    if not any(DECLARES_NO_WORKSPACE_IMPORT in line for line in step):
        return False
    commands = [line for line in step if not line.strip().startswith("#")]
    if not any("--basetemp" in line for line in commands):
        return False
    named = [word for line in commands for word in line.split() if word.endswith(".py")]
    if not named:
        return False  # an invocation that names no file collects the whole suite
    packages = _workspace_packages(root)
    return all(
        (root / name).is_file() and not _imports_a_workspace_package(root / name, packages)
        for name in named
    )


def _runs_the_suite(line: str) -> bool:
    """Is this line a `uv run` that will collect or execute part of this repository?"""
    return "uv run" in line and bool(re.search(r"\b(pytest|python)\b", line))


def _unfrozen_in(lines_by_workflow: dict[str, list[str]]) -> list[str]:
    """Article 2: a run that may re-resolve the lock reports on an environment nothing records.

    Without `--frozen`, `uv run` is free to resolve again and rewrite
    `uv.lock`, so a green gate would be evidence about an environment this
    branch does not hold and a reader could not rebuild. There is no exemption:
    the flag costs an uninstalled step nothing.
    """
    return [
        f"{origin}:{number + 1}: {line.strip()}"
        for origin, lines in lines_by_workflow.items()
        for number, line in enumerate(lines)
        if _runs_the_suite(line) and "--frozen" not in line
    ]


def _uninstalled_in(lines_by_workflow: dict[str, list[str]], root: Path = REPOSITORY) -> list[str]:
    uninstalled = []
    for origin, lines in lines_by_workflow.items():
        for number, line in enumerate(lines):
            if not _runs_the_suite(line) or "--all-packages" in line:
                continue
            if _exempt(_step_around(lines, number), root):
                continue
            uninstalled.append(f"{origin}:{number + 1}: {line.strip()}")
    return uninstalled


def _shallow_in(lines_by_workflow: dict[str, list[str]]) -> list[str]:
    shallow = []
    for origin, lines in lines_by_workflow.items():
        for number, line in enumerate(lines):
            if "actions/checkout@" not in line:
                continue
            following = "\n".join(lines[number + 1 : number + 4])
            if "fetch-depth: 0" not in following:
                shallow.append(f"{origin}:{number + 1}: {line.strip()}")
    return shallow


def _read_workflows() -> dict[str, list[str]]:
    return {w.name: w.read_text(encoding="utf-8").splitlines() for w in _workflows()}


def test_every_step_that_runs_the_suite_installs_the_workspace() -> None:
    """Article 2: an uninstalled run fails before collection and proves nothing."""
    workflows = _read_workflows()
    uninstalled = _uninstalled_in(workflows)
    invocations = sum(1 for lines in workflows.values() for line in lines if _runs_the_suite(line))
    assert uninstalled == [], uninstalled
    # Anti-vacuity: a workflow set in which nothing runs the suite passes the
    # assertion above by having nothing to check.
    assert invocations >= 4, invocations


def test_every_step_that_runs_the_suite_runs_it_from_the_recorded_lock() -> None:
    """Article 2: a gate that may re-resolve reports on an environment this branch has not got."""
    workflows = _read_workflows()
    unfrozen = _unfrozen_in(workflows)
    invocations = sum(1 for lines in workflows.values() for line in lines if _runs_the_suite(line))
    assert unfrozen == [], unfrozen
    assert invocations >= 4, invocations


def test_this_guard_still_catches_a_planted_unfrozen_step() -> None:
    """Article 2: a guard that cannot fail cannot prove the lock was the one used."""
    planted = {"planted.yml": ["      - name: Tests", "        run: uv run --all-packages pytest"]}
    caught = _unfrozen_in(planted)
    assert caught, "FAIL the planted unfrozen step was not caught: this guard cannot fail."
    assert "planted.yml:2: run: uv run --all-packages pytest" in caught


def test_every_checkout_takes_the_history_the_guards_read() -> None:
    """Article 14: the copy-note guard reads commit messages a shallow clone lacks."""
    workflows = _read_workflows()
    shallow = _shallow_in(workflows)
    checkouts = sum(
        1 for lines in workflows.values() for line in lines if "actions/checkout@" in line
    )
    assert shallow == [], shallow
    assert checkouts >= 3, checkouts


def test_the_exemption_is_taken_by_a_real_step_of_this_workflow_set() -> None:
    """An exemption nothing exercises is a hole nobody has looked through.

    The three conditions above are only worth stating if some step in this
    repository really meets them; otherwise the branch is unexecuted code in a
    guard, which is the finding this repository keeps making about other
    people's guards (article 2).
    """
    workflows = _read_workflows()
    exempt = [
        f"{origin}:{number + 1}"
        for origin, lines in workflows.items()
        for number, line in enumerate(lines)
        if _runs_the_suite(line)
        and "--all-packages" not in line
        and _exempt(_step_around(lines, number))
    ]
    assert exempt, "no step takes the exemption: its three conditions are checked against nothing"


def test_this_guard_still_catches_a_planted_uninstalled_step() -> None:
    """Article 2: a guard that cannot fail cannot prove the suite is installed."""
    planted = {"planted.yml": ["      - name: Tests", "        run: uv run pytest -rs"]}
    caught = _uninstalled_in(planted)
    assert caught, "FAIL the planted uninstalled step was not caught: this guard cannot fail."
    assert "planted.yml:2: run: uv run pytest -rs" in caught


def test_a_declared_exemption_without_basetemp_is_still_caught() -> None:
    """Plant: the declaration is a claim, and `--basetemp` is what makes it true.

    Without it the repository `conftest.py` derives a run root, and importing a
    workspace package is how it decides where — so the step would fail before
    collection, which is the state this whole file exists to keep out of CI.
    """
    mine = Path(__file__).resolve().relative_to(REPOSITORY).as_posix()
    planted = {
        "planted.yml": [
            "      - name: Guards only",
            f"        # {DECLARES_NO_WORKSPACE_IMPORT}: it does not, but it derives a run root",
            f"        run: uv run pytest {mine}",
        ]
    }
    caught = _uninstalled_in(planted)
    assert caught, (
        "FAIL a step declaring the exemption without --basetemp was exempted: "
        "the declaration alone is being read as a licence."
    )


def test_a_declared_exemption_over_a_file_that_imports_the_workspace_is_caught() -> None:
    """Plant: a declared step that names a test importing the workspace is not exempt.

    The file named here is chosen from the tree rather than written in, so the
    plant keeps meaning the same thing after that file is renamed; the run
    would fail on the import, uninstalled, and say nothing about any guard.
    """
    packages = _workspace_packages()
    assert packages, "no workspace package was found: the check below would vouch for anything"
    importer = next(
        path.relative_to(REPOSITORY).as_posix()
        for path in sorted((REPOSITORY / "packages").rglob("test_*.py"))
        if _imports_a_workspace_package(path, packages)
    )
    planted = {
        "planted.yml": [
            "      - name: Guards only",
            f"        # {DECLARES_NO_WORKSPACE_IMPORT}: not for this file, which imports one",
            f'        run: uv run pytest --basetemp="${{RUNNER_TEMP}}/x" {importer}',
        ]
    }
    caught = _uninstalled_in(planted)
    assert caught, (
        f"FAIL a step declaring the exemption over {importer}, which imports a workspace "
        "package, was exempted: the declaration is not being checked against the file."
    )


def test_this_guard_still_catches_a_planted_shallow_checkout() -> None:
    """Article 14: a guard that cannot fail cannot prove history is full."""
    planted = {"planted.yml": ["- uses: actions/checkout@v4", "  with:", "    fetch-depth: 1"]}
    caught = _shallow_in(planted)
    assert caught, "FAIL the planted shallow checkout was not caught: this guard cannot fail."
    assert "planted.yml:1: - uses: actions/checkout@v4" in caught
