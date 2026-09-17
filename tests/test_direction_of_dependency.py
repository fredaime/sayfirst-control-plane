# SPDX-License-Identifier: Apache-2.0
"""Article 14: a published distribution points in no server direction.

One rule, held over each distribution this repository publishes: the contract
imports nothing of the server, and the optional fake imports nothing but the
contract it implements. Article 14's reason is that a dependency pointing the
wrong way is a leak that cannot be unpublished, which is a property of the
repository and not of any one package. One rule per file, so a new rule arrives
as a new file and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"
STUB = REPOSITORY / "packages" / "contract-stub"


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


def test_the_contract_distribution_imports_nothing_of_the_server() -> None:
    """Article 14: the contract is standard-library-only and points in no server direction."""
    package = CONTRACT / "src" / "sayfirst_contract"
    imports = _imports(package)
    assert imports <= sys.stdlib_module_names | {"sayfirst_contract"}
    assert "sayfirst_control_plane" not in imports
    transport = _imports(package / "transport")
    assert transport
    assert transport <= sys.stdlib_module_names | {"sayfirst_contract"}


def test_the_stub_depends_on_the_contract_alone() -> None:
    """Article 14: the optional fake depends only on the contract it implements."""
    project = tomllib.loads((STUB / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == ["sayfirst-contract==0.2.0"]
    imports = _imports(STUB / "src" / "sayfirst_contract_stub")
    assert imports <= sys.stdlib_module_names | {
        "sayfirst_contract",
        "sayfirst_contract_stub",
    }
    assert "sayfirst_control_plane" not in imports
