# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
import shutil
from collections.abc import Iterable, Mapping
from dataclasses import fields
from pathlib import Path

import pytest
from sayfirst_contract.decisions import Decision
from sayfirst_control_plane import ports as ports_package
from sayfirst_control_plane.architecture.information_contract import INFORMATION_CONTRACT, Plane
from sayfirst_control_plane.architecture.scope import (
    PERSISTED_AS,
    SCOPE_REGISTER,
    Carries,
    ScopeDeclaration,
)
from sayfirst_control_plane.domain.evidence_chain import EvidenceEntry, EvidenceRecord

EXCEPTION_REGISTER = Path(__file__).resolve().parents[4] / "docs" / "exceptions.md"
#: Structures this package persists that the modules under `ports/` do not
#: define: one the contract distribution owns (`Decision`), two this package's
#: own domain owns (`EvidenceRecord`, `EvidenceEntry`).
FOREIGN_STRUCTURES = {
    "Decision": Decision,
    "EvidenceRecord": EvidenceRecord,
    "EvidenceEntry": EvidenceEntry,
}


def _discovered_port_modules(directory: Path | None = None) -> tuple[Path, ...]:
    """Every source file of a `ports/`-shaped directory, discovered rather than named.

    A tuple written by hand stops growing the day someone forgets to add to it;
    a module joins this guard's reach by existing in the directory, the same
    discipline `tests/test_package_discovery.py` holds project-wide.
    `_enumerate_module` reads a file's source with `ast`, never imports it, so
    discovery is a directory listing and nothing a port's own relative imports
    can break. The directory defaults to the real `ports/` package and is only
    ever substituted in a test, to prove the walk against a planted file rather
    than against a dictionary the test built by hand.
    """
    assert ports_package.__file__ is not None
    root = directory if directory is not None else Path(ports_package.__file__).parent
    return tuple(sorted(source for source in root.glob("*.py") if source.stem != "__init__"))


PORT_MODULES = _discovered_port_modules()


def _decorator_names(node: ast.ClassDef) -> set[str]:
    names = set()
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _mentioned(node: ast.AST | None) -> set[str]:
    return (
        set()
        if node is None
        else {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
    )


def _enumerate_module(source: Path) -> dict[str, tuple[str, ...]]:
    """Name every structure and port operation one ports module defines.

    The value is every word the declaration puts in reach of `scope`: a
    structure's field names, or an operation's parameter names together with
    the type names its signature mentions.
    """
    found: dict[str, tuple[str, ...]] = {}
    for node in ast.parse(source.read_text(encoding="utf-8")).body:
        if not isinstance(node, ast.ClassDef):
            continue
        if "dataclass" in _decorator_names(node):
            found[node.name] = tuple(
                item.target.id
                for item in node.body
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
            )
            continue
        if not any(isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases):
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef) or item.name.startswith("_"):
                continue
            words = {argument.arg for argument in item.args.args}
            words |= _mentioned(item.returns)
            for argument in item.args.args:
                words |= _mentioned(argument.annotation)
            found[f"{node.name}.{item.name}"] = tuple(sorted(words))
    return found


def _enumerated(port_sources: Iterable[Path] = PORT_MODULES) -> dict[str, tuple[str, ...]]:
    found: dict[str, tuple[str, ...]] = {}
    for source in port_sources:
        found.update(_enumerate_module(source))
    for name, structure in FOREIGN_STRUCTURES.items():
        found[name] = tuple(item.name for item in fields(structure))
    return found


def _scope_failures(
    enumerated: Mapping[str, tuple[str, ...]],
    register: Mapping[str, ScopeDeclaration],
) -> list[str]:
    """Return every enumerated port or structure article 5 is not held on."""
    scoped_structures = {
        name for name, words in enumerated.items() if "." not in name and "scope" in words
    }
    failures = [
        f"{name}: not declared in the scope register" for name in enumerated if name not in register
    ]
    for name, declaration in register.items():
        if name not in enumerated:
            failures.append(f"{name}: declared but no longer defined")
            continue
        if declaration.carries is not Carries.RECORD:
            continue
        words = set(enumerated[name])
        if "scope" in words or words & scoped_structures:
            continue
        if declaration.exemption is None:
            failures.append(f"{name}: carries a record without scope and without an exemption")
    return sorted(failures)


def test_every_port_and_persisted_structure_is_held_to_article_five() -> None:
    """Article 5's named guard: enumerate ports and persisted structures.

    The guard fails on one that carries a record without `scope` and without an
    exemption recorded here and published in the exception register.
    """
    enumerated = _enumerated()
    assert len(enumerated) >= 10
    assert _scope_failures(enumerated, SCOPE_REGISTER) == []


def test_the_scope_guard_fails_on_a_structure_nobody_declared() -> None:
    """Article 5: a port or structure added later cannot slip past the guard."""
    planted = {**_enumerated(), "PlantedRecord": ("policy_version", "rules")}
    assert _scope_failures(planted, SCOPE_REGISTER) == [
        "PlantedRecord: not declared in the scope register"
    ]


def test_a_new_file_under_ports_is_discovered_without_editing_this_guard(
    tmp_path: Path,
) -> None:
    """Article 5: the guard's reach is the `ports/` directory, not a tuple naming some of it.

    Before this test, `PORT_MODULES` named three of the package's eight port
    modules by hand, and the guard above proved its predicate against a
    dictionary the test had already augmented — never against a file the
    discovery step had not been told about. This plants a real file, in a real
    copy of the directory, and calls the same walk the guard runs at import
    time: `_discovered_port_modules`, not `_enumerated`'s caller-supplied input.
    """
    assert ports_package.__file__ is not None
    real_ports = Path(ports_package.__file__).parent
    for source in real_ports.glob("*.py"):
        if source.stem != "__init__":
            shutil.copy(source, tmp_path / source.name)
    (tmp_path / "audit_store.py").write_text(
        "from __future__ import annotations\n"
        "from typing import Protocol\n"
        "\n"
        "\n"
        "class AuditStore(Protocol):\n"
        "    def read(self, record_ref: str) -> None: ...\n",
        encoding="utf-8",
    )

    discovered = _discovered_port_modules(tmp_path)
    assert any(source.stem == "audit_store" for source in discovered)
    enumerated = _enumerated(discovered)
    assert "AuditStore.read" in enumerated
    assert "AuditStore.read: not declared in the scope register" in _scope_failures(
        enumerated, SCOPE_REGISTER
    )


def test_the_scope_guard_fails_on_a_record_with_neither_scope_nor_exemption() -> None:
    """Article 5: a record-carrying declaration without scope is a failure, not a silence."""
    register = {**SCOPE_REGISTER, "PolicyStore.load": ScopeDeclaration(Carries.RECORD)}
    assert _scope_failures(_enumerated(), register) == [
        "PolicyStore.load: carries a record without scope and without an exemption"
    ]


def test_the_scope_guard_fails_on_a_declaration_of_something_removed() -> None:
    """Article 2: a register that outlives its subject stops describing the code."""
    register = {**SCOPE_REGISTER, "RemovedPort.read": ScopeDeclaration(Carries.RECORD)}
    assert "RemovedPort.read: declared but no longer defined" in _scope_failures(
        _enumerated(), register
    )


def test_the_decision_port_needs_no_exemption() -> None:
    """Article 5: the governed record this block writes carries scope on both sides."""
    for name in ("DecisionStore.append", "DecisionStore.get", "Decision"):
        assert SCOPE_REGISTER[name].carries is Carries.RECORD
        assert SCOPE_REGISTER[name].exemption is None


def test_every_persisted_structure_of_the_information_contract_is_declared() -> None:
    """Articles 3 and 5: the persisted structures and the scope register name the same things.

    Every declaration but an observation. An observation is what the system saw
    rather than what it wrote down — the daemon's event sink is held in memory
    and a restart loses it — so it is written as no structure and the register
    has nothing to name; an entry for it would claim a record this code does not
    keep (article 2). The exemption is held rather than trusted: an observation
    that did persist would be discovered as a surface by
    `test_persisted_structures_are_declared.py`, would have to own it here, and
    the second assertion below then sends it back to `PERSISTED_AS`.
    """
    observations = {
        name
        for name, structure in INFORMATION_CONTRACT.items()
        if structure.plane is Plane.OBSERVATION
    }
    assert set(PERSISTED_AS) == set(INFORMATION_CONTRACT) - observations
    for name in observations:
        assert INFORMATION_CONTRACT[name].surfaces == (), name
    for structure in PERSISTED_AS.values():
        assert SCOPE_REGISTER[structure].carries is Carries.RECORD


def test_an_exemption_cannot_be_recorded_against_a_declaration_that_carries_no_record() -> None:
    """Article 2: an exemption states what it relaxes, so it cannot relax nothing."""
    with pytest.raises(ValueError, match="record-carrying"):
        ScopeDeclaration(Carries.NO_RECORD, "no reason can apply here")
    with pytest.raises(ValueError, match="reason"):
        ScopeDeclaration(Carries.RECORD, "   ")


def test_every_recorded_exemption_is_published_in_the_exception_register() -> None:
    """Article 0: a relaxation is public, named, reasoned, and carries a way back."""
    content = EXCEPTION_REGISTER.read_text(encoding="utf-8")
    exempted = {
        name: declaration.exemption
        for name, declaration in SCOPE_REGISTER.items()
        if declaration.exemption is not None
    }
    assert exempted
    for name, reason in exempted.items():
        assert f"`{name}`" in content, name
        assert reason in content, name
    assert "Restoration condition" in content
