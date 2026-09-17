# SPDX-License-Identifier: Apache-2.0
"""Article 14: the server distribution imports the contract and the standard library.

A rule of the repository, not of one package. `tests/test_direction_of_dependency.py`
holds the same article over what the contract and the optional fake may import;
this one holds it over the server, whose whole reason to exist is to depend on
the contract and on nothing else the repository publishes. One rule per file, so
a new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


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


def test_the_server_distribution_imports_the_contract_and_the_standard_library() -> None:
    """Article 14: the server depends on the contract, and the contract on no one."""
    imports = _imports(CONTROL_PLANE / "src" / "sayfirst_control_plane")
    assert imports <= sys.stdlib_module_names | {
        "sayfirst_contract",
        "sayfirst_control_plane",
    }
