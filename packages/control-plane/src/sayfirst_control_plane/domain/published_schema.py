# SPDX-License-Identifier: Apache-2.0
"""Refusing a request by the schema the contract publishes for it.

Article 13: "the open project's product boundary *is* the contract", so what
the daemon accepts is what `decision-ask-request.schema.json` accepts, and it is
read from that file rather than spelled a second time in Python. Two spellings
of one rule drift, and they had: the hand-written check carried the patterns and
dropped `capability`'s published `maxLength` and `correlation`'s altogether, so
an ordinary request produced an answer and a chain entry that the published
readers for them refuse.

The contract wheel installs no third-party runtime (articles 13 and 14), so the
checker is written here over the keywords the published request schemas use. It
refuses to be built at all from a schema carrying a keyword it does not
implement: a checker that silently ignored one would claim to hold a schema it
does not (article 2), and a contract that grew such a keyword would pass in
silence. Failing at import is where that belongs — the daemon does not start
rather than answering one request wrongly.

Annotations are not assertions and are named as such: `format` is an annotation
in JSON Schema 2020-12 and is not checked, and neither are `title`,
`description` or the extensions that only describe. The extensions are named
one by one rather than passed over by their `x-` prefix, because one of them
asserts: `x-max-bytes` is the UTF-8 byte bound the delegation schema counts its
lengths in, published beside the weaker code-point bound `maxLength` that a
generic validator can check on its own. Skipping it by prefix accepted a
multi-byte string inside `maxLength` and past the byte bound, which is the same
class of divergence as dropping `maxLength` itself, and an extension invented
tomorrow would have been skipped the same way. An `x-` keyword this checker has
never seen now stops it, exactly as any other unheld keyword does.

JSON Schema equality is not Python's, and this is where a checker written in
Python goes wrong quietly. `2.0` is the integer 2 (6.1.1), `1` and `1.0` are
one value, `true` is not `1`, and an object is its members and not their order;
`_identity` is that equality, and `enum`, `const` and `uniqueItems` are held
through it rather than through `==` and `repr`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from sayfirst_contract.artifacts import domain_schema

#: Keywords that assert something, and are held.
_ASSERTIONS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "enum",
        "const",
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "uniqueItems",
        "items",
        "properties",
        "additionalProperties",
        "required",
        "$ref",
        "x-max-bytes",
    }
)

#: Keywords that describe rather than assert, and are skipped by name.
_ANNOTATIONS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "$id",
        "title",
        "description",
        "format",
        "default",
        "examples",
        #: The `x-` extensions that describe. An extension that asserts belongs
        #: in `_ASSERTIONS` beside the keywords it stands next to, and one in
        #: neither set stops this checker rather than being read as either.
        "x-contract-generation",
        "x-spdx-license-identifier",
        "x-documented-values",
        "x-reserved-values",
        "x-diagnostic",
    }
)

_TYPES: Final[dict[str, type | tuple[type, ...]]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


class UnheldSchemaKeyword(NotImplementedError):
    """A published schema asserts something this checker does not hold."""


def _resolve(schema: Mapping[str, object]) -> Mapping[str, object]:
    reference = schema.get("$ref")
    if not isinstance(reference, str):
        return schema
    if not reference.endswith(".schema.json") or "/" in reference:
        raise UnheldSchemaKeyword(f"$ref {reference!r} is not a published domain schema")
    return _resolve(domain_schema(reference.removesuffix(".schema.json")))


def _audit(schema: Mapping[str, object], where: str) -> None:
    """Refuse a schema asserting anything this checker does not hold."""
    for keyword in schema:
        if keyword in _ANNOTATIONS or keyword in _ASSERTIONS:
            continue
        raise UnheldSchemaKeyword(f"{where}: {keyword!r} is not held by this checker")
    if "$ref" in schema:
        # In 2020-12 a `$ref` does not replace what stands beside it; both
        # apply. Resolving one and dropping its siblings would hold half a
        # schema while claiming the whole (article 2).
        beside = {keyword for keyword in schema if keyword in _ASSERTIONS} - {"$ref"}
        if beside:
            raise UnheldSchemaKeyword(f"{where}: {sorted(beside)} beside a $ref is not held")
        _audit(_resolve(schema), where)
        return
    properties = schema.get("properties") or {}
    assert isinstance(properties, Mapping)
    for member, subschema in properties.items():
        assert isinstance(subschema, Mapping)
        _audit(subschema, f"{where}.{member}")
    items = schema.get("items")
    if isinstance(items, Mapping):
        _audit(items, f"{where}[]")
    extra = schema.get("additionalProperties", True)
    if extra not in (True, False):
        raise UnheldSchemaKeyword(f"{where}: a schema for additionalProperties is not held")


def _is_number(value: object) -> bool:
    """Whether `value` is a JSON number. Python spells `True` as an `int`."""
    return isinstance(value, int | float) and not isinstance(value, bool)


def _matches_type(declared: object, value: object) -> bool:
    names = declared if isinstance(declared, list) else [declared]
    for name in names:
        expected = _TYPES.get(str(name))
        if expected is None:
            raise UnheldSchemaKeyword(f"type {name!r} is not held by this checker")
        if str(name) == "boolean":
            if isinstance(value, bool):
                return True
            continue
        if str(name) == "integer":
            # 6.1.1: JSON has one number type, so `integer` matches any number
            # with a zero fractional part and `2.0` on the wire is the integer
            # 2. Reading the keyword as Python's `int` refused a request a
            # client generated from the published contract may send.
            if _is_number(value) and float(value).is_integer():
                return True
            continue
        # A boolean is never a number here, because the schemas that publish
        # `integer` or `number` mean a count and not a flag.
        if isinstance(value, bool) and expected is not bool:
            continue
        if isinstance(value, expected):
            return True
    return False


def _identity(value: object) -> object:
    """A key equal for JSON-equal values and different for any other pair.

    JSON Schema compares values, and Python's `==` and `repr` each compare
    something else: `==` calls `true` equal to `1`, and `repr` calls `1` and
    `1.0` different and two objects with the same members in a different order
    different too. `enum`, `const` and `uniqueItems` are all this comparison.
    """
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, int | float):
        # `1` and `1.0` are one number, and Python hashes them as one.
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if value is None:
        return ("null",)
    if isinstance(value, Mapping):
        return ("object", tuple(sorted((key, _identity(item)) for key, item in value.items())))
    if isinstance(value, Sequence):
        return ("array", tuple(_identity(item) for item in value))
    raise UnheldSchemaKeyword(f"{type(value).__name__} is not a JSON value")


def _refuse(schema: Mapping[str, object], value: object, where: str) -> str | None:
    """Say why the published schema refuses `value`, or `None` if it does not."""
    schema = _resolve(schema)
    declared = schema.get("type")
    if declared is not None and not _matches_type(declared, value):
        return f"{where} is not of type {declared if isinstance(declared, str) else ' or '.join(declared)}"  # noqa: E501
    allowed = schema.get("enum")
    published = isinstance(allowed, Sequence) and not isinstance(allowed, str)
    if published and not any(_identity(value) == _identity(item) for item in allowed):  # type: ignore[union-attr]
        return f"{where} is not one of the published values"
    if "const" in schema and _identity(value) != _identity(schema["const"]):
        return f"{where} is not the published value"
    if isinstance(value, str):
        complaint = _refuse_string(schema, value, where)
        if complaint is not None:
            return complaint
    if _is_number(value):
        # 6.2.4: a bound is a bound on a number, not only on an integer, and it
        # may itself be published as one. Reading either as Python's `int`
        # passed every non-integer through unbounded.
        minimum, maximum = schema.get("minimum"), schema.get("maximum")
        if _is_number(minimum) and value < minimum:  # type: ignore[operator]
            return f"{where} is below the published minimum"
        if _is_number(maximum) and value > maximum:  # type: ignore[operator]
            return f"{where} is above the published maximum"
    if isinstance(value, list):
        return _refuse_array(schema, value, where)
    if isinstance(value, Mapping):
        return _refuse_object(schema, value, where)
    return None


def _refuse_string(schema: Mapping[str, object], value: str, where: str) -> str | None:
    smallest, largest = schema.get("minLength"), schema.get("maxLength")
    if isinstance(smallest, int) and len(value) < smallest:
        return f"{where} is shorter than the published minimum"
    if isinstance(largest, int) and len(value) > largest:
        return f"{where} is longer than the published maximum"
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, value) is None:
        return f"{where} does not match the published pattern"
    return _refuse_bytes(schema, value, where)


def _refuse_bytes(schema: Mapping[str, object], value: str, where: str) -> str | None:
    """Hold `x-max-bytes`, the bound JSON Schema has no keyword for.

    The delegation schema counts every length it publishes in UTF-8 bytes and
    says so in its own description; `maxLength` is the weaker code-point bound
    published beside it for a validator with no way to say the stronger one. A
    multi-byte string inside the code-point bound and past the byte bound was
    accepted here and refused by the published schema read whole (article 13).
    """
    largest = schema.get("x-max-bytes")
    if not isinstance(largest, int) or isinstance(largest, bool):
        return None
    try:
        width = len(value.encode())
    except UnicodeEncodeError:
        # A lone surrogate has no UTF-8 form, so it is not inside a bound
        # counted in UTF-8 bytes. `json.loads` produces one, so a request can
        # carry one, and measuring it would raise on the decision route where
        # the honest answer is a refusal (article 1).
        return f"{where} is not UTF-8, and its published bound is counted in UTF-8 bytes"
    if width > largest:
        return f"{where} is longer than the published bound in bytes"
    return None


def _refuse_array(schema: Mapping[str, object], value: list[object], where: str) -> str | None:
    fewest, most = schema.get("minItems"), schema.get("maxItems")
    if isinstance(fewest, int) and len(value) < fewest:
        return f"{where} has fewer items than the published minimum"
    if isinstance(most, int) and len(value) > most:
        return f"{where} has more items than the published maximum"
    unique = {_identity(item) for item in value}
    if schema.get("uniqueItems") is True and len(value) != len(unique):
        return f"{where} repeats an item where the published schema requires unique ones"
    items = schema.get("items")
    if isinstance(items, Mapping):
        for index, item in enumerate(value):
            complaint = _refuse(items, item, f"{where}[{index}]")
            if complaint is not None:
                return complaint
    return None


def _refuse_object(
    schema: Mapping[str, object], value: Mapping[str, object], where: str
) -> str | None:
    properties = schema.get("properties") or {}
    assert isinstance(properties, Mapping)
    required = schema.get("required") or ()
    assert isinstance(required, Sequence)
    for member in required:
        if member not in value:
            return f"{where}.{member} is required" if where else f"{member} is required"
    if schema.get("additionalProperties") is False:
        for member in value:
            if member not in properties:
                return (
                    f"{where}.{member} is not a member of this generation"
                    if where
                    else f"{member} is not a member of this generation"
                )
    for member, item in value.items():
        subschema = properties.get(member)
        if isinstance(subschema, Mapping):
            complaint = _refuse(subschema, item, f"{where}.{member}" if where else member)
            if complaint is not None:
                return complaint
    return None


def is_published_integer(value: object) -> bool:
    """Whether the published schemas read `value` as an `integer` (6.1.1).

    A route that answers a published problem code of its own about one member —
    `generation_unreadable` names `contract_generation` and nothing else — has
    to know what the schema means by `integer` before it can answer. Asking
    here is what keeps there being one answer: the reading is the checker's,
    used by the checker, so a route and the checker cannot come to differ about
    `1.0` again.

    They did differ. The route asked `isinstance(value, int)`, which is a
    question about Python and not about JSON, and answered
    `generation_unreadable` to a request the checker beside it had just
    accepted — the divergence article 13 forbids, one layer above where it was
    last closed.
    """
    return _matches_type("integer", value)


def refused_by(document: Mapping[str, object], schema_name: str) -> str | None:
    """Say why the published schema `schema_name` refuses `document`, or `None`."""
    schema = domain_schema(schema_name)
    _audit(schema, schema_name)
    return _refuse(schema, document, "")


#: Audited at import, so a published schema this checker cannot hold stops the
#: daemon from starting rather than passing one request through unchecked.
for _name in ("decision-ask-request", "approval-resolve-request"):
    _audit(domain_schema(_name), _name)
del _name
