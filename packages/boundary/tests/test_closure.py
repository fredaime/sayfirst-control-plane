# SPDX-License-Identifier: Apache-2.0
"""Article 13: installing the boundary installs the contract and nothing else.

Measured from the declared dependency set rather than from a hand-written list,
so a dependency added tomorrow is caught without anyone remembering this file.
The planted case is what makes the rule more than a restatement: a set that had
gained a web framework must fail.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
PERMITTED = frozenset({"sayfirst-contract"})
FORBIDDEN_SHAPES = ("starlette", "fastapi", "flask", "sqlalchemy", "django", "psycopg")


def _declared() -> frozenset[str]:
    document = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = document["project"]["dependencies"]
    assert requirements, "anti-vacuity: a package with no dependencies proves nothing here"
    return frozenset(str(item).split("==")[0].split(">")[0].split("[")[0] for item in requirements)


def test_the_declared_closure_is_the_contract_and_nothing_else() -> None:
    assert _declared() == PERMITTED


def test_no_declared_dependency_is_a_server_shape() -> None:
    for name in _declared():
        for shape in FORBIDDEN_SHAPES:
            assert shape not in name.lower(), f"{name} is a server dependency (article 13)"


def test_the_rule_fires_on_a_planted_web_framework() -> None:
    """WATCHED FIRING. A rule only observed passing may have stopped applying."""
    planted = frozenset({"sayfirst-contract", "starlette"})
    assert planted != PERMITTED
    assert any(shape in name.lower() for name in planted for shape in FORBIDDEN_SHAPES), (
        "the forbidden-shape rule did not recognise a planted web framework"
    )


def test_the_boundary_imports_no_command_line_interface() -> None:
    """The product CLI is another repository's distribution (article 14)."""
    sources = sorted((PACKAGE / "src").rglob("*.py"))
    assert sources, "anti-vacuity: no sources were scanned"
    for source in sources:
        text = source.read_text(encoding="utf-8")
        assert "sayfirst_cli" not in text, f"{source.name} reaches for the product CLI"
