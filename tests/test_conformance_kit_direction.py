# SPDX-License-Identifier: Apache-2.0
"""Article 14: the conformance kit depends inward, and nothing shipped depends on it.

A rule of the repository, not of one package: it holds over every distribution
this repository publishes at once, which is what makes it a repository-scope
rule rather than a property of the kit. Article 14's reason is that a
dependency pointing the wrong way is a leak that cannot be unpublished, and a
test kit is the easiest place for one to appear, because everything is happy to
import a double. One rule per file, so a new rule arrives as a new file and a
new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"
STUB = REPOSITORY / "packages" / "contract-stub"
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"
TESTING = REPOSITORY / "packages" / "testing"


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


def test_the_dependency_between_distributions_points_one_way() -> None:
    """Article 14: the contract points at nothing; nothing shipped points at the kit."""
    kit = tomllib.loads((TESTING / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert kit["dependencies"] == [
        "sayfirst-contract==0.2.0",
        "sayfirst-control-plane==0.2.0",
    ]
    server = tomllib.loads((CONTROL_PLANE / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert server["dependencies"] == ["sayfirst-contract==0.2.0"]
    assert _imports(TESTING / "src" / "sayfirst_testing") <= sys.stdlib_module_names | {
        "sayfirst_contract",
        "sayfirst_control_plane",
        "sayfirst_testing",
        "jsonschema",
        "pytest",
        "referencing",
    }
    for shipped in (
        CONTRACT / "src" / "sayfirst_contract",
        STUB / "src" / "sayfirst_contract_stub",
        CONTROL_PLANE / "src" / "sayfirst_control_plane",
    ):
        assert "sayfirst_testing" not in _imports(shipped), shipped
