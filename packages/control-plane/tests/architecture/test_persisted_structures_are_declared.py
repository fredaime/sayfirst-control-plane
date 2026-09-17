# SPDX-License-Identifier: Apache-2.0
"""Article 3: nothing this package persists is missing from the information contract.

One rule per file (`CONTRIBUTING.md`, article 16). The rule here is the first
half of article 3's Guard: every persisted structure declares its authority
kind. It is held by walking the shipped source for the surfaces that outlive a
process, not by reading a list of the ones somebody remembered — a list is
checked against itself, and the structure added later is exactly the one the
list does not name.

Two kinds of surface are discovered, because two kinds exist here: a table the
code creates, and a module that writes durably to the filesystem. Each must be
claimed by exactly one declaration in `INFORMATION_CONTRACT`. A declaration may
own no discovered surface — the policy authority is written by the operator and
read here — but a surface owned by no declaration is the defect this rule is
for.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from pathlib import Path

from sayfirst_control_plane.architecture.information_contract import INFORMATION_CONTRACT

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "sayfirst_control_plane"

_CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE
)

#: Calls that put bytes somewhere a later process can read them.
_DURABLE = frozenset({"os.write", "os.pwrite", "sqlite3.connect"})
_DURABLE_METHODS = frozenset({"write_text", "write_bytes"})
_WRITING_FLAGS = ("O_CREAT", "O_WRONLY", "O_RDWR", "O_APPEND")


def _qualified(node: ast.expr, names: dict[str, str]) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(names.get(node.id, node.id))
    return ".".join(reversed(parts))


def _aliases(tree: ast.Module) -> dict[str, str]:
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _writes_durably(node: ast.Call, names: dict[str, str]) -> bool:
    qualified = _qualified(node.func, names)
    if qualified in _DURABLE or qualified.rsplit(".", 1)[-1] in _DURABLE_METHODS:
        return True
    if qualified == "os.open" and len(node.args) > 1:
        return any(flag in ast.unparse(node.args[1]) for flag in _WRITING_FLAGS)
    return False


def _shipped() -> list[tuple[str, str]]:
    """Every shipped module, as the walk reads it: its dotted name and its text."""
    shipped = []
    for source in sorted(PACKAGE.rglob("*.py")):
        module = ".".join(
            ("sayfirst_control_plane", *source.relative_to(PACKAGE).with_suffix("").parts)
        ).removesuffix(".__init__")
        shipped.append((module, source.read_text(encoding="utf-8")))
    return shipped


def discovered_surfaces(modules: Iterable[tuple[str, str]] | None = None) -> dict[str, str]:
    """Every surface that outlives a process, and where the walk read it.

    The modules may be supplied so that the same discovery can be run over a
    planted one below. A walk that can only be pointed at the tree that passes
    cannot be shown to notice the structure that was added without a
    declaration, which is the whole defect it exists for.
    """
    surfaces: dict[str, str] = {}
    for module, text in _shipped() if modules is None else modules:
        tree = ast.parse(text, filename=module)
        names = _aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for table in _CREATE_TABLE.findall(node.value):
                    surfaces[f"table:{table}"] = f"{module}:{node.lineno}"
            elif isinstance(node, ast.Call) and _writes_durably(node, names):
                surfaces.setdefault(f"store:{module}", f"{module}:{node.lineno}")
    return surfaces


def _declared() -> dict[str, str]:
    return {
        surface: name
        for name, structure in INFORMATION_CONTRACT.items()
        for surface in structure.surfaces
    }


def _undeclared(discovered: dict[str, str], declared: dict[str, str]) -> dict[str, str]:
    return {surface: where for surface, where in discovered.items() if surface not in declared}


#: A module that persists two surfaces and declares neither, written the way
#: the audit of 2026-09-06 wrote its plant. It is planted below on every run;
#: it is never written into the package.
PLANTED_MODULE = """
import os as _os
import sqlite3 as _db

SCHEMA = "CREATE TABLE IF NOT EXISTS audit_planted (id TEXT)"


def remember(path: str) -> None:
    handle = _os.open(path, _os.O_CREAT | _os.O_WRONLY)
    _os.write(handle, b"outlives this process")
    _db.connect(path).executescript(SCHEMA)
"""


def test_every_persisted_structure_declares_its_authority_kind() -> None:
    """Article 3: a surface no declaration owns has no stated authority kind."""
    declared = _declared()
    discovered = discovered_surfaces()
    assert _undeclared(discovered, declared) == {}, _undeclared(discovered, declared)
    # Anti-vacuity: a walk that found nothing declares nothing, and a
    # declaration naming a surface the walk cannot find is a label, not a fact.
    assert len(discovered) >= 3, discovered
    assert set(declared) <= set(discovered), set(declared) - set(discovered)


def test_this_guard_still_catches_a_planted_undeclared_structure() -> None:
    """Article 3: a register checked against itself passes by checking nothing.

    The surfaces this names on success are the ones it *would* have reported
    had the plant been real. They are not a live violation: the module they
    name does not exist in this package and is never written to it.
    """
    discovered = discovered_surfaces(
        [("sayfirst_control_plane.a_module_this_package_does_not_ship", PLANTED_MODULE)]
    )
    undeclared = _undeclared(discovered, _declared())
    assert undeclared, (
        "FAIL the planted structure was not caught: this guard cannot fail. "
        "The walk read a module that creates a table and writes durably, and "
        "found no surface no declaration owns."
    )
    # Both kinds of surface, so a walk that has stopped recognising one of them
    # cannot be carried by the other.
    assert "table:audit_planted" in undeclared, undeclared
    assert any(surface.startswith("store:") for surface in undeclared), undeclared
