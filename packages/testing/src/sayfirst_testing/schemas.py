# SPDX-License-Identifier: Apache-2.0
"""Validation of a document against one published schema and its neighbours.

The published schemas point at each other by file name; a validator needs
them all before it can read one. The validator itself is an optional extra of
this kit, never a dependency of the contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from functools import cache
from typing import Any

from sayfirst_contract.artifacts import DOMAIN_SCHEMAS, domain_schema


@cache
def _validator(schema_name: str) -> Any:
    """One validator per published schema, built once.

    Building it reads every published schema into a registry, which is work
    proportional to the contract and not to the document; a caller driving a
    generated corpus through this pays it once rather than once per document.
    The published schemas do not change while a process runs — they are
    packaged artefacts — so one validator answers for all of them.
    """
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    resources = [
        (f"{name}.schema.json", Resource(contents=domain_schema(name), specification=DRAFT202012))
        for name in DOMAIN_SCHEMAS
    ]
    registry = Registry().with_resources(resources)
    return jsonschema.Draft202012Validator(domain_schema(schema_name), registry=registry)


class ByteBoundExceeded(ValueError):
    """A string longer than the UTF-8 byte bound its schema publishes."""


def _byte_bounds(schema: object, document: object) -> None:
    """Hold `x-max-bytes`, the bound JSON Schema has no keyword for.

    `maxLength` counts code points, so a published byte bound needs its own
    keyword and its own check; without it the contract would accept strings
    the daemon refuses.
    """
    if not isinstance(schema, Mapping):
        return
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.endswith(".schema.json"):
        _byte_bounds(domain_schema(reference.removesuffix(".schema.json")), document)
        return
    limit = schema.get("x-max-bytes")
    if isinstance(limit, int) and isinstance(document, str):
        try:
            width = len(document.encode())
        except UnicodeEncodeError as failure:
            # A lone surrogate has no UTF-8 form at all, so it is not within a
            # bound counted in UTF-8 bytes; refusing it is the honest answer,
            # and raising `UnicodeEncodeError` at a caller asking a yes-or-no
            # question is not.
            raise ByteBoundExceeded(f"{document!r} is not UTF-8: {failure}") from None
        if width > limit:
            raise ByteBoundExceeded(f"{document!r} is longer than {limit} bytes")
    if isinstance(document, Mapping):
        for member, value in document.items():
            _byte_bounds(schema.get("properties", {}).get(member), value)
    elif isinstance(document, list):
        for item in document:
            _byte_bounds(schema.get("items"), item)
    for keyword in ("oneOf", "anyOf", "allOf"):
        for branch in schema.get(keyword, ()):
            with suppress(ByteBoundExceeded):
                _byte_bounds(branch, document)


def validate_document(document: Mapping[str, object], schema_name: str) -> None:
    """Raise when a document does not satisfy its published schema."""
    _validator(schema_name).validate(dict(document))
    _byte_bounds(domain_schema(schema_name), dict(document))


def document_is_valid(document: Mapping[str, object], schema_name: str) -> bool:
    """Whether a document satisfies its published schema."""
    if not _validator(schema_name).is_valid(dict(document)):
        return False
    try:
        _byte_bounds(domain_schema(schema_name), dict(document))
    except ByteBoundExceeded:
        return False
    return True


def jsonschema_accepts(document: Mapping[str, object], schema_name: str) -> bool:
    """Whether JSON Schema alone accepts `document`, byte bounds set aside.

    `document_is_valid` is the published schema read whole; this is the part of
    it a generic validator can check on its own. The two part company exactly
    where `x-max-bytes` does the work, which is the one thing JSON Schema has
    no keyword for, so a test that needs to name that gap needs both.
    """
    return bool(_validator(schema_name).is_valid(dict(document)))
