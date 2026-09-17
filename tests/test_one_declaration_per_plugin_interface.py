# SPDX-License-Identifier: Apache-2.0
"""Article 8: each plugin interface version is declared once, wherever it is declared.

A rule of the repository, not of one package: the plugin interfaces are what a
third party builds against, and article 8 gives each of them one integer
version. Two declarations of one interface under one version are two contracts
sold under one name, and a provider can satisfy only one of them; the skeleton
shipped exactly that — two `PrivacyRedactor` classes, both claiming version 1,
over two shapes — and bootstrap could compose only the provider both happened
to spell the same way. One rule per file, so a new rule arrives as a new file
and a new file never conflicts (`CONTRIBUTING.md`, article 16).

**What it walks.** Every `.py` under every `packages/*/src` — a distribution
joins the walk by existing, never by being listed. Two kinds of declaration
claim a version:

1. a class definition named exactly as an interface the contract distribution
   registers in `PLUGIN_INTERFACE_VERSIONS`; the class claims the version the
   registry currently gives that name, so a second class of that name is a
   second claim on it;
2. a module-level integer constant named `<INTERFACE>_VERSION` or
   `<INTERFACE>_INTERFACE_VERSION`, the interface in upper snake case; the
   contract distribution's own constant is the one claim allowed, and a second
   constant is a version that can drift from it.

Exactly one of each per registered interface passes. Zero fails too: an
interface the registry names and nothing declares is a claim with no
mechanism, and a walk that found nothing would otherwise hold vacuously.

**What it proves about itself.** After the real tree passes, the walk is run
again over a copy of the same roots into which a second `PrivacyRedactor` class
and a second version constant have been planted, and the run fails unless both
are caught and named by file. What that proves is that this run's walk would
have caught them; a guard that cannot fail is reported as a failure, not as a
pass.

**What it does not assert.** That the one declaration has the shape the
conformance kit tests, or that the kit's rule is right: the kit and
`packages/control-plane/tests/test_default_providers.py` hold those. And a
version arriving under a new class name — `PrivacyRedactorV2` beside
`PrivacyRedactor` during a deprecation window — is not two claims on one
version and passes; a second `PrivacyRedactor` class is, and does not.
"""

from __future__ import annotations

import ast
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from sayfirst_contract.plugins import PLUGIN_INTERFACE_VERSIONS

REPOSITORY = Path(__file__).resolve().parents[1]

#: Where the version constants are allowed to live: the one place article 13
#: puts the vocabulary a client and a server both read.
CONTRACT_REGISTRY = Path("packages/contract/src/sayfirst_contract/plugins.py")


@dataclass(frozen=True)
class Declaration:
    interface: str
    kind: str  # "class" or "version constant"
    path: Path
    line: int
    version: int

    def sentence(self) -> str:
        return f"{self.path}:{self.line} declares {self.interface} version {self.version}"


def _upper_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


def _shipped_roots(repository: Path) -> list[Path]:
    """Every distribution's import root, found the way the test run finds them."""
    return sorted(item for item in repository.glob("packages/*/src") if item.is_dir())


def _version_constant(node: ast.stmt) -> tuple[str, int] | None:
    """The `(NAME, value)` of a module-level integer constant, or `None`."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target, value = node.targets[0], node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        target, value = node.target, node.value
    else:
        return None
    if not isinstance(target, ast.Name):
        return None
    if not (isinstance(value, ast.Constant) and type(value.value) is int):
        return None
    return target.id, value.value


def declarations(roots: list[Path], registry: dict[str, int]) -> list[Declaration]:
    """Every declaration in the shipped sources that claims a registered interface."""
    by_constant = {
        f"{_upper_snake(name)}_{suffix}": name
        for name in registry
        for suffix in ("VERSION", "INTERFACE_VERSION")
    }
    found: list[Declaration] = []
    for root in roots:
        for source in sorted(root.rglob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name in registry:
                    found.append(
                        Declaration(node.name, "class", source, node.lineno, registry[node.name])
                    )
            for node in tree.body:
                constant = _version_constant(node)
                if constant is not None and constant[0] in by_constant:
                    found.append(
                        Declaration(
                            by_constant[constant[0]],
                            "version constant",
                            source,
                            node.lineno,
                            constant[1],
                        )
                    )
    return found


def findings(roots: list[Path], registry: dict[str, int]) -> list[str]:
    """One sentence per rule broken, or an empty list."""
    found = declarations(roots, registry)
    broken: list[str] = []
    for interface in sorted(registry):
        for kind in ("class", "version constant"):
            matching = [item for item in found if item.interface == interface and item.kind == kind]
            if len(matching) == 1:
                continue
            if not matching:
                broken.append(f"FAIL {interface} is registered and no {kind} declares it")
                continue
            broken.append(
                f"FAIL {interface} version {registry[interface]} is claimed by "
                f"{len(matching)} {kind} declarations: "
                + "; ".join(item.sentence() for item in matching)
            )
    return broken


def test_each_plugin_interface_version_is_declared_once() -> None:
    """Article 8: one interface, one version, one declaration of each."""
    registry = dict(PLUGIN_INTERFACE_VERSIONS)
    assert registry, "the contract registers no plugin interface; the walk would hold vacuously"
    roots = _shipped_roots(REPOSITORY)
    assert roots, "no distribution exists; the walk would hold vacuously"
    found = declarations(roots, registry)
    # Anti-vacuity floor: the walk reaches the registry's own constants.
    constants = {item.path.relative_to(REPOSITORY) for item in found if item.kind != "class"}
    assert CONTRACT_REGISTRY in constants, "the walk does not reach the contract's registry"
    broken = findings(roots, registry)
    assert broken == [], "\n".join(broken)


def _plant(copied_roots: list[Path]) -> Path:
    """A second `PrivacyRedactor` and a second version constant, in a copied tree."""
    planted = copied_roots[0] / "planted_second_interface.py"
    planted.write_text(
        "from typing import Protocol\n"
        "PRIVACY_REDACTOR_INTERFACE_VERSION = 1\n"
        "class PrivacyRedactor(Protocol):\n"
        "    def redact(self, payload: object) -> object: ...\n",
        encoding="utf-8",
    )
    return planted


def test_the_walk_catches_a_second_declaration_planted_into_a_copy_of_the_tree(
    tmp_path: Path,
) -> None:
    """The guard is proven against the defect it exists to catch, on this tree's copy."""
    registry = dict(PLUGIN_INTERFACE_VERSIONS)
    copied_roots = []
    for root in _shipped_roots(REPOSITORY):
        target = tmp_path / root.relative_to(REPOSITORY)
        shutil.copytree(root, target, ignore=shutil.ignore_patterns("__pycache__"))
        copied_roots.append(target)
    assert findings(copied_roots, registry) == [], "the copy does not pass as the tree does"

    planted = _plant(copied_roots)
    caught = findings(copied_roots, registry)

    # Both kinds of claim are caught, and each names the planted file.
    kinds = [line for line in caught if "PrivacyRedactor" in line]
    assert len(kinds) == 2, (
        "FAIL the planted second interface was not caught on both counts: "
        f"this guard cannot fail\n{caught}"
    )
    assert all(str(planted) in line for line in kinds), caught
    assert any("2 class declarations" in line for line in kinds), caught
    assert any("2 version constant declarations" in line for line in kinds), caught
