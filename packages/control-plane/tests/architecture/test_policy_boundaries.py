# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
from pathlib import Path

import sayfirst_control_plane


def _package_root() -> Path:
    return Path(sayfirst_control_plane.__file__).parent


def test_policy_decisions_read_the_authoritative_file() -> None:
    """Article 3: the decision path has no dependency on a policy projection."""
    for relative in (("application", "decisions.py"), ("domain", "policy.py")):
        source = _package_root().joinpath(*relative)
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        assert not any("projection" in imported for imported in imports), source


def test_the_distribution_ships_no_policy_file() -> None:
    """Article 1: installation cannot widen policy by creating an authority."""
    package = _package_root()
    assert not tuple(package.rglob("*.toml"))


def test_policy_documentation_claims_only_composed_runtime_behavior() -> None:
    """Articles 2 and 3: docs distinguish projections and unscheduled hooks."""
    readme = _package_root().parents[1] / "README.md"
    content = readme.read_text(encoding="utf-8")
    assert "disposable observations" not in content
    assert "rebuildable" in content and "projections" in content
    assert "PolicyService.reload_if_due" in content
    assert "DecisionService.sweep" in content
    # The grant endings this package composes are claimed plainly, the two
    # sweeps name the paths that call them, and the case no path reaches — a
    # connection holding no grant and asking nothing — is stated rather than
    # left to be read as covered (article 2).
    assert "Composing `DecisionService`" in content
    assert "GrantConnections.tick" in content and "GrantConnections.shutdown" in content
    assert "on no timer" in content
    assert "Nothing scans for a\nconnection that holds no grant and asks nothing" in content
    assert "no timer scans for one" in content
    assert "selector the published binding names" in content


def test_no_public_document_records_which_files_a_copy_brought() -> None:
    """Article 14: which modules a copy brought is the private record, not a document."""
    repository = _package_root().parents[3]
    assert not (repository / "docs" / "provenance").exists()
