# SPDX-License-Identifier: Apache-2.0
"""Access to every artefact published as package data."""

from __future__ import annotations

import json
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Final

DOMAIN_SCHEMAS: Final[tuple[str, ...]] = (
    "decision-ask-request",
    "decision-result",
    "decision-record",
    "grant",
    "grant-signal",
    "policy-status",
    "approval-resolve-request",
    "approval-result",
    "evidence-entry",
    "evidence-entry-writer",
    "evidence-verdict",
    "evidence-page-result",
    "evidence-export-result",
    "status-result",
    "problem-document",
    "principal",
    "peer",
    "delegation",
    "whoami-result",
)
DOMAIN_RECIPES: Final[tuple[str, ...]] = (
    "domain/policy-evaluation-v1.json",
    "domain/evidence-preimage-v1.json",
    "domain/evidence-export-manifest-vectors.json",
)
"""The recipe vectors published beside the schemas (article 13): each is the
one fixture arbiter between two implementations, read from the installed wheel."""
DOMAIN_DOCUMENTS: Final[tuple[str, ...]] = ("domain/recipes/policy-evaluation-v1.md",)
"""The normative recipe texts, published as prose beside their vectors and
digested with them; a document is read, never parsed as a schema."""
DOMAIN_ARTIFACTS: Final[tuple[str, ...]] = (
    "domain/generation.json",
    "domain/problem-codes.json",
    "domain/attributes.json",
    "domain/golden-scenarios.json",
    *(f"domain/schemas/{name}.schema.json" for name in DOMAIN_SCHEMAS),
    *DOMAIN_RECIPES,
)
BINDING_ARTIFACTS: Final[tuple[str, ...]] = ("binding/http-unix-socket/openapi.json",)


def artifact(*parts: str) -> Traversable:
    """Return one published artefact by its parts below the contract root."""
    return files(__package__).joinpath("_contracts", *parts)


def load_json(*parts: str) -> object:
    return json.loads(artifact(*parts).read_text(encoding="utf-8"))


def domain_schema(name: str) -> dict[str, object]:
    if name not in DOMAIN_SCHEMAS:
        raise KeyError(name)
    document = load_json("domain", "schemas", f"{name}.schema.json")
    if not isinstance(document, dict):
        raise ValueError(f"schema {name!r} is not an object")
    return document
