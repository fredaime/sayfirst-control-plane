# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).parents[4]
PACKAGE = Path(__file__).parents[2]

#: The status rendering reads a document this package writes, and it lives in
#: the contract distribution: the operator surface renders the daemon's status
#: and must not depend on the daemon to do it (article 14). The guard follows
#: the source rather than the package, because what it holds is that no
#: rendering of these members claims protection nothing performs.
STATUS_RENDERING = (
    REPOSITORY / "packages" / "contract" / "src" / "sayfirst_contract" / "transport" / "cli.py"
)
SCHEMAS = (
    REPOSITORY
    / "packages"
    / "contract"
    / "src"
    / "sayfirst_contract"
    / "_contracts"
    / "domain"
    / "schemas"
)


def _claim_failure(text: str) -> str | None:
    match = re.search(
        r"\b(proof|tamper-proof|tamper detection|protected|masked|redacted)\b", text.lower()
    )
    return match.group(0) if match else None


def _descriptions(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        own = (value["description"],) if isinstance(value.get("description"), str) else ()
        return own + tuple(
            description for item in value.values() for description in _descriptions(item)
        )
    if isinstance(value, list):
        return tuple(description for item in value for description in _descriptions(item))
    return ()


def _schema_descriptions() -> str:
    return "\n".join(
        description
        for source in SCHEMAS.glob("*.json")
        for description in _descriptions(json.loads(source.read_text(encoding="utf-8")))
    )


def test_no_open_rendering_calls_the_no_op_protection() -> None:
    sources = (
        STATUS_RENDERING,
        PACKAGE / "src" / "sayfirst_control_plane" / "plugins" / "privacy" / "none.py",
    )
    texts = [source.read_text(encoding="utf-8") for source in sources]
    texts.append(_schema_descriptions())
    assert not [_claim_failure(source) for source in texts if _claim_failure(source)]


def test_no_grade_rendering_claims_proof_or_tamper_detection() -> None:
    source = STATUS_RENDERING
    assert _claim_failure(source.read_text(encoding="utf-8") + _schema_descriptions()) is None


def test_the_claim_guard_catches_a_planted_overclaim() -> None:
    with pytest.raises(AssertionError):
        assert _claim_failure("tamper-proof") is None


def test_the_schema_description_guard_catches_a_planted_no_op_overclaim() -> None:
    planted = {"description": "none means captured content is redacted"}
    with pytest.raises(AssertionError):
        assert not [
            failure
            for description in _descriptions(planted)
            if (failure := _claim_failure(description))
        ]


def test_no_sealing_call_survives_in_the_open_adapters() -> None:
    forbidden = {"seal", "encrypt", "pseudonymise"}
    called = set()
    root = PACKAGE / "src" / "sayfirst_control_plane" / "adapters"
    for source in root.rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Name):
                    called.add(function.id)
                elif isinstance(function, ast.Attribute):
                    called.add(function.attr)
    assert not (called & forbidden)
