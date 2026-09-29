# SPDX-License-Identifier: Apache-2.0
"""Article 14: a published kit declares every distribution it imports.

`sayfirst_testing.platforms` and `.privileges` import pytest, which the kit did not
declare: installed from the index into an environment without pytest, two of its
modules could not be imported. One rule per file (`CONTRIBUTING.md`).
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
KIT = REPOSITORY / "packages" / "testing"
OWN = {"sayfirst_testing", "sayfirst_contract", "sayfirst_control_plane"}


def _declared() -> set[str]:
    project = tomllib.loads((KIT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    items = [*project["dependencies"]]
    for extra in project.get("optional-dependencies", {}).values():
        items.extend(extra)
    return {
        re.split(r"[\[<>=!~; ]", item, maxsplit=1)[0].lower().replace("-", "_") for item in items
    }


def _imported() -> set[str]:
    names: set[str] = set()
    for path in (KIT / "src" / "sayfirst_testing").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return {name for name in names if name not in sys.stdlib_module_names and name not in OWN}


def test_every_third_party_import_of_the_kit_is_declared() -> None:
    undeclared = sorted(_imported() - _declared())
    assert undeclared == [], f"sayfirst-testing imports {undeclared} without declaring it"
