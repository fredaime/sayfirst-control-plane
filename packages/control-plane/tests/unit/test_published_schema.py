# SPDX-License-Identifier: Apache-2.0
"""The checker that reads a published request schema, judged against a real validator.

Article 2: "a checker written here holds the published schema" is a claim, and
its evidence is that it answers what a conforming validator answers. So every
case below is put to both — `jsonschema`, which is a development dependency and
never a runtime one (articles 13 and 14), and the checker the daemon runs — and
the two must agree on each. Where they disagree, the checker is wrong, whichever
way round it is: too strict refuses a request the contract publishes, too lax is
the defect this module exists to close.
"""

from __future__ import annotations

import pytest
from sayfirst_contract.artifacts import domain_schema
from sayfirst_control_plane.domain.published_schema import UnheldSchemaKeyword, refused_by
from sayfirst_testing.schemas import document_is_valid

ASK = "decision-ask-request"

_DIGEST = "sha256:" + "a" * 64
_DELEGATION = {"chain": [{"kind": "user", "name": "alice", "uid": 1000, "via": "scheduler"}]}

#: One document per way an ask can be well formed or not, including every case
#: the re-review executed against a live daemon.
CASES: tuple[dict[str, object], ...] = (
    {"contract_generation": 1, "capability": "example.effect"},
    {"contract_generation": 1, "capability": "example.effect", "scope": "local"},
    {"contract_generation": 1, "capability": "a.b.c", "arguments_digest": _DIGEST},
    {"contract_generation": 1, "capability": "a.b", "correlation": "c" * 128},
    {"contract_generation": 1, "capability": "a.b", "delegation": _DELEGATION},
    {"contract_generation": 1, "capability": "a" * 128},
    # and the ways it is refused
    {},
    {"capability": "example.effect"},
    {"contract_generation": 1},
    {"contract_generation": 0, "capability": "a.b"},
    {"contract_generation": "1", "capability": "a.b"},
    {"contract_generation": 1, "capability": "a.b", "principal": "claimed"},
    {"contract_generation": 1, "capability": 42},
    {"contract_generation": 1, "capability": ""},
    {"contract_generation": 1, "capability": "a" * 129},
    {"contract_generation": 1, "capability": "Not.A.Capability"},
    {"contract_generation": 1, "capability": "a.b", "scope": 42},
    {"contract_generation": 1, "capability": "a.b", "scope": True},
    {"contract_generation": 1, "capability": "a.b", "scope": None},
    {"contract_generation": 1, "capability": "a.b", "scope": ["local"]},
    {"contract_generation": 1, "capability": "a.b", "scope": ""},
    {"contract_generation": 1, "capability": "a.b", "scope": "a" * 129},
    {"contract_generation": 1, "capability": "a.b", "scope": "../../escape"},
    {"contract_generation": 1, "capability": "a.b", "arguments_digest": 12345},
    {"contract_generation": 1, "capability": "a.b", "arguments_digest": {"x": 1}},
    {"contract_generation": 1, "capability": "a.b", "arguments_digest": "not-a-digest"},
    {"contract_generation": 1, "capability": "a.b", "correlation": 7},
    {"contract_generation": 1, "capability": "a.b", "correlation": "c" * 129},
    {"contract_generation": 1, "capability": "a.b", "delegation": {"chain": []}},
    {"contract_generation": 1, "capability": "a.b", "delegation": {"chain": [{"kind": "user"}]}},
    {"contract_generation": 1, "capability": "a.b", "delegation": {"status": "declared"}},
    {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [dict(_DELEGATION["chain"][0], uid=-1)]},  # type: ignore[index]
    },
    {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [dict(_DELEGATION["chain"][0], kind="")]},  # type: ignore[index]
    },
    {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [_DELEGATION["chain"][0]] * 5},  # type: ignore[index]
    },
)


@pytest.mark.parametrize("document", CASES, ids=range(len(CASES)))
def test_the_checker_answers_what_a_conforming_validator_answers(document) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the schema is the arbiter, and this reads it the way one does."""
    assert (refused_by(document, ASK) is None) == document_is_valid(document, ASK), document


def test_the_corpus_holds_both_answers() -> None:
    """Anti-vacuity: a corpus that was all one answer would prove nothing."""
    refused = [item for item in CASES if refused_by(item, ASK) is not None]
    assert len(refused) >= 20
    assert len(CASES) - len(refused) >= 5


def test_a_schema_keyword_this_checker_does_not_hold_stops_it_rather_than_passing() -> None:
    """Article 2: a check that ignored a keyword would claim a schema it does not hold."""
    with pytest.raises(UnheldSchemaKeyword, match="dependentRequired"):
        refused_by({}, _named({"type": "object", "dependentRequired": {"a": ["b"]}}))
    with pytest.raises(UnheldSchemaKeyword, match="oneOf"):
        refused_by({}, _named({"type": "object", "properties": {"a": {"oneOf": []}}}))


def test_every_request_schema_the_daemon_serves_is_one_this_checker_holds() -> None:
    """Article 13: what the route publishes is what the route can check."""
    for name in ("decision-ask-request", "approval-resolve-request"):
        assert refused_by({}, name) is not None
        assert domain_schema(name)["additionalProperties"] is False


def _named(schema: dict[str, object]) -> str:
    """Publish `schema` under a borrowed name, so the audit can be put to it.

    The checker reads its schemas from the contract's published artefacts, so a
    schema that is not published cannot be handed to it except by standing in
    for one that is; the substitution is undone before the next case.
    """
    import sayfirst_control_plane.domain.published_schema as module

    name = "planted"
    module.domain_schema = lambda asked, _real=domain_schema: (  # type: ignore[assignment]
        schema if asked == name else _real(asked)
    )
    return name


@pytest.fixture(autouse=True)
def _restore_the_published_reader():  # type: ignore[no-untyped-def]
    import sayfirst_control_plane.domain.published_schema as module

    original = module.domain_schema
    yield
    module.domain_schema = original


# ---------------------------------------------------------------------------
# The cases a generator found and this corpus did not, shrunk to the smallest
# document that still shows each. `test_published_schema_differential.py` is
# what found them; they are named here because a named case says what the rule
# *is*, where a generated one only says that two readers agreed on one Tuesday.
# ---------------------------------------------------------------------------

RESOLVE = "approval-resolve-request"


def test_a_number_with_no_fractional_part_is_the_integer_the_schema_publishes() -> None:
    """JSON Schema 2020-12 6.1.1: `integer` matches any number with a zero fraction.

    JSON has one number type, so `2.0` on the wire is the integer 2 and a
    conforming validator accepts it where `type: integer` is published. Reading
    the keyword as Python's `int` refused a request a client generated from the
    published contract may send, which is a daemon not implementable from its
    own contract (article 13).
    """
    for document in (
        {"contract_generation": 2.0, "capability": "a.b"},
        {"contract_generation": 1.0, "capability": "a.b"},
        {
            "contract_generation": 1,
            "capability": "a.b",
            "delegation": {"chain": [dict(_DELEGATION["chain"][0], uid=2.0)]},  # type: ignore[index]
        },
    ):
        assert document_is_valid(document, ASK), document
        assert refused_by(document, ASK) is None, document

    # and the fractional part still refuses, on both sides
    fractional = {"contract_generation": 1.5, "capability": "a.b"}
    assert not document_is_valid(fractional, ASK)
    assert refused_by(fractional, ASK) is not None


def test_a_string_past_the_published_byte_bound_is_refused() -> None:
    """Article 13: `x-max-bytes` is published, so it is part of what a request must be.

    The delegation schema counts every length bound in UTF-8 bytes and says so;
    `maxLength` is the weaker code-point bound published beside it for a generic
    validator. Thirty-three `é` are 33 code points and 66 bytes, so they sit
    inside `kind`'s `maxLength` of 64 and past its `x-max-bytes` of 64: the
    published schema refuses them and the checker has to as well.
    """
    over = {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [dict(_DELEGATION["chain"][0], kind="é" * 33)]},  # type: ignore[index]
    }
    assert not document_is_valid(over, ASK)
    assert refused_by(over, ASK) == (
        "delegation.chain[0].kind is longer than the published bound in bytes"
    )

    within = {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [dict(_DELEGATION["chain"][0], kind="é" * 32)]},  # type: ignore[index]
    }
    assert document_is_valid(within, ASK)
    assert refused_by(within, ASK) is None


def test_a_string_with_no_utf8_form_is_refused_where_a_byte_bound_is_published() -> None:
    """A lone surrogate is not UTF-8, so it is not within a bound counted in UTF-8.

    `json.loads` produces one from `"\\ud800"`, so a request can carry one, and
    a checker that measured it would raise `UnicodeEncodeError` on the decision
    route — a daemon fault, where the honest answer is a refusal (article 1).
    """
    document = {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [dict(_DELEGATION["chain"][0], kind="\ud800")]},  # type: ignore[index]
    }
    assert not document_is_valid(document, ASK)
    assert refused_by(document, ASK) is not None


def test_a_bound_holds_a_number_and_not_only_an_integer() -> None:
    """JSON Schema 2020-12 6.2.4: `minimum` and `maximum` apply to any number.

    No published request member is a `number` today, so no corpus of requests
    can reach this; the checker claims the keywords all the same, and a schema
    that grew one would have passed unchecked in silence (article 2).
    """
    for schema, value, refused in (
        ({"type": "number", "minimum": 1}, 0.5, True),
        ({"type": "number", "minimum": 1}, 1.5, False),
        ({"type": "number", "maximum": 1}, 1.5, True),
        ({"type": "number", "minimum": 1.5}, 1, True),
        ({"type": "number", "minimum": 1.5}, 2, False),
    ):
        name = _named(schema)
        assert (refused_by(value, name) is not None) is refused, (schema, value)  # type: ignore[arg-type]


def test_a_flag_is_not_the_number_one_where_a_value_is_published() -> None:
    """JSON Schema equality is not Python's: `true` is not `1` and `false` is not `0`."""
    for schema, value, refused in (
        ({"enum": [1, 2]}, True, True),
        ({"enum": [0, 1]}, False, True),
        ({"enum": [1, 2]}, 1, False),
        ({"const": 1}, True, True),
        ({"const": 0}, False, True),
        ({"const": True}, True, False),
    ):
        name = _named(schema)
        assert (refused_by(value, name) is not None) is refused, (schema, value)  # type: ignore[arg-type]


def test_items_are_unique_by_what_they_are_and_not_by_how_python_prints_them() -> None:
    """JSON Schema 2020-12 6.4.3: `uniqueItems` compares values, not their spellings.

    `1` and `1.0` are one JSON value printed two ways, and two objects with the
    same members in a different order are one JSON value too; comparing `repr`
    called both of those unique. `true` and `1` are two values that `repr`
    happens to print differently and Python's `==` calls equal.
    """
    name = _named({"type": "array", "uniqueItems": True})
    for value, refused in (
        ([1, 1.0], True),
        ([{"a": 1, "b": 2}, {"b": 2, "a": 1}], True),
        ([1, True], False),
        ([0, False], False),
        ([1, 2], False),
        ([[1], [1]], True),
    ):
        assert (refused_by(value, name) is not None) is refused, value  # type: ignore[arg-type]


def test_a_reference_beside_another_assertion_is_refused_rather_than_half_read() -> None:
    """A `$ref` does not replace its siblings in 2020-12; this checker cannot join them."""
    with pytest.raises(UnheldSchemaKeyword, match="beside"):
        refused_by({}, _named({"$ref": "delegation.schema.json", "maxItems": 1}))


def test_an_unknown_extension_keyword_stops_the_checker_rather_than_being_ignored() -> None:
    """Article 2: `x-max-bytes` asserted while being skipped by name; the next one will not.

    Extensions were passed over by prefix, so the one that asserted a bound was
    passed over with the ones that annotate. Each is named now, and one this
    checker has never seen stops it the way any unheld keyword does.
    """
    with pytest.raises(UnheldSchemaKeyword, match="x-invented-bound"):
        refused_by({}, _named({"type": "object", "x-invented-bound": 4}))
    # the ones that only describe are still passed over
    assert refused_by({}, _named({"type": "object", "x-documented-values": ["a"]})) is None
