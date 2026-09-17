# SPDX-License-Identifier: Apache-2.0
"""Which guards a runner owes, and which of them a run actually held.

A platform gate is written in the guard's own source, so the set a runner owes
is read from the source and never from a hand-kept list that can drift away
from it (article 2: the claim and its evidence are the same thing). What a run
did is read from its JUnit report, because "reported as skipped" and "held" are
two outcomes and a step that treats them alike proves nothing.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final
from xml.etree import ElementTree

OS_REAL_PLATFORMS: Final[tuple[str, ...]] = ("linux", "darwin")
"""The two operating systems article 6's guards bind, and the two adapters."""

GATE_DECORATORS: Final[frozenset[str]] = frozenset({"requires_platform", "requires_platforms"})
"""The two decorators that gate a guard to an operating system."""

PRIVILEGE_DECORATORS: Final[Mapping[str, str]] = {
    "requires_root": "root",
    "requires_unprivileged": "unprivileged",
}
"""The two decorators that gate a guard to a privilege, and the privilege each names.

A privilege gate is the second axis of the same question a platform gate asks.
A guard that only a root container can hold is not owed by an ordinary runner,
and one whose premise is that the tester is not root is not owed by a root one:
either way the runner that *can* hold it owes it, and the runner that cannot
reports a skip that is not counted as a pass (article 2).
"""

_STARRED: Final[Mapping[str, tuple[str, ...]]] = {"OS_REAL_PLATFORMS": OS_REAL_PLATFORMS}


def gated_guards(*trees: Path) -> dict[str, frozenset[str]]:
    """Every platform-gated guard under `trees`, with the platforms it admits."""
    gates: dict[str, frozenset[str]] = {}
    for tree in trees:
        for source in sorted(Path(tree).rglob("test_*.py")):
            module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(module):
                if not isinstance(node, ast.FunctionDef):
                    continue
                platforms = _gate_of(node)
                if platforms is not None:
                    gates[node.name] = platforms
    return gates


def _gate_of(node: ast.FunctionDef) -> frozenset[str] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if ast.unparse(decorator.func) not in GATE_DECORATORS:
            continue
        platforms: set[str] = set()
        for argument in decorator.args:
            rendered = ast.unparse(argument)
            if rendered.startswith("*"):
                platforms |= set(_STARRED.get(rendered[1:], ()))
            else:
                platforms.add(rendered.strip("\"'"))
        return frozenset(platforms)
    return None


def privilege_gated_guards(*trees: Path) -> dict[str, str]:
    """Every privilege-gated guard under `trees`, with the privilege it needs."""
    gates: dict[str, str] = {}
    for tree in trees:
        for source in sorted(Path(tree).rglob("test_*.py")):
            module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(module):
                if not isinstance(node, ast.FunctionDef):
                    continue
                privilege = _privilege_of(node)
                if privilege is not None:
                    gates[node.name] = privilege
    return gates


def _privilege_of(node: ast.FunctionDef) -> str | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        privilege = PRIVILEGE_DECORATORS.get(ast.unparse(decorator.func))
        if privilege is not None:
            return privilege
    return None


def guards_required_on(
    platform: str, *trees: Path, privilege: str = "unprivileged"
) -> frozenset[str]:
    """The gated guards this runner owes: every one both of its gates admit.

    A guard gated to one operating system is owed by that runner alone — it has
    nowhere else it can be held, so a run of that runner in which it did not
    run is a run that proved nothing about it. A guard gated to a privilege as
    well is owed only by the runner that has that privilege too: requiring a
    root-container guard of an ordinary runner would fail every ordinary run
    over a skip that runner was right to report.
    """
    privileges = privilege_gated_guards(*trees)
    return frozenset(
        name
        for name, platforms in gated_guards(*trees).items()
        if platform in platforms and privileges.get(name, privilege) == privilege
    )


def outcomes(junit_report: Path) -> dict[str, str]:
    """Each test case in a JUnit report, as `held`, `not runnable` or `broken`.

    Parametrised cases collapse onto their guard's name; a guard is `held` only
    when every case of it was.
    """
    read: dict[str, str] = {}
    root = ElementTree.parse(junit_report).getroot()
    for case in root.iter("testcase"):
        name = str(case.get("name", "")).partition("[")[0]
        if not name:
            continue
        outcome = "held"
        if case.find("skipped") is not None:
            outcome = "not runnable"
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "broken"
        if read.get(name) in {"broken", "not runnable"}:
            continue
        read[name] = outcome
    return read


def guards_not_held(required: Iterable[str], read: Mapping[str, str]) -> dict[str, str]:
    """The required guards this run did not hold, and what happened instead."""
    return {
        name: read.get(name, "never ran") for name in sorted(required) if read.get(name) != "held"
    }
