# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
import tomllib
from pathlib import Path

PACKAGE = Path(__file__).parents[2]
SOURCE = PACKAGE / "src" / "sayfirst_control_plane"


def test_the_server_depends_on_the_contract_alone() -> None:
    project = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == ["sayfirst-contract==0.2.0"]

    imports = set()
    for source in SOURCE.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".")[0])
    assert (
        imports
        <= {"sayfirst_contract", "sayfirst_control_plane"} | __import__("sys").stdlib_module_names
    )


def test_the_documentation_names_retention_and_grade_detection_latency() -> None:
    readme = (PACKAGE / "README.md").read_text(encoding="utf-8").lower()
    assert "latency of detection" in readme
    assert "nothing survives a restart" in readme
    assert "there is no purge command" in readme


def test_the_grade_domain_does_not_know_the_file_adapters_suffix() -> None:
    """Article 4: the pure grade rule depends on facts, not adapter naming."""
    source = SOURCE / "domain" / "integrity_grade.py"
    assert ".jsonl" not in source.read_text(encoding="utf-8")


def test_path_existence_queries_stay_behind_the_path_access_port() -> None:
    """Article 7: application and domain code receive operating-system facts."""
    offenders = []
    for layer in ("application", "domain"):
        for source in (SOURCE / layer).rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "exists"
                ):
                    offenders.append((source, node.lineno))
    assert offenders == []
