# SPDX-License-Identifier: Apache-2.0
"""Articles 2, 3, 10, 11, 13: what block 2.7 adds to the published contract.

The record a daemon can explain after a restart carries the evaluator's answer
beside the outcome: the reason, the rule, the digest, the correlation and who
supplied it, the principal references the evaluation read, and the recipe it
was taken under. The same facts are copied into the effect entry, inside the
hashed body, so the chain's integrity mechanism covers them (articles 7, 10).
The evidence bodies are closed objects, so the new members are a schema change
with a historical-reader counterpart: the reader admits an old body, the
new-writer schema requires the new members (article 13).
"""

from __future__ import annotations

import copy

import jsonschema
import pytest
from sayfirst_contract.artifacts import DOMAIN_SCHEMAS, domain_schema, load_json
from sayfirst_contract.binding.http_unix_socket.routes import ROUTES
from sayfirst_contract.golden import schema_examples
from sayfirst_contract.problems import ProblemCode, problem_retryable
from sayfirst_testing.schemas import validate_document

NEW_DECISION_MEMBERS = ("principal_references", "evaluation_recipe", "correlation_source")
COPIED_EFFECT_MEMBERS = (
    "reason",
    "rule_id",
    "arguments_digest",
    "correlation",
    "correlation_source",
    "principal_references",
    "evaluation_recipe",
    "decision_position",
)


@pytest.mark.parametrize("name", ["decision-record", "decision-result"])
def test_a_decision_carries_its_references_recipe_and_correlation_source(name: str) -> None:
    """Articles 3 and 11: the answer, and the inputs it was taken from, are one record."""
    properties = domain_schema(name)["properties"]
    for member in NEW_DECISION_MEMBERS:
        assert member in properties, member
    references = properties["principal_references"]
    assert references["type"] == "array"
    assert references["uniqueItems"] is True
    assert references["maxItems"] == 131072
    assert set(properties["correlation_source"]["enum"]) == {"boundary_supplied", "absent"}
    assert properties["evaluation_recipe"]["minLength"] == 1
    example = dict(schema_examples()[name])
    for member in NEW_DECISION_MEMBERS:
        assert member in example, member
    validate_document(example, name)


def test_the_historical_reader_admits_an_old_effect_body_and_the_writer_requires_the_new() -> None:
    """Article 13: an old body is tolerated by the reader and refused by the writer schema."""
    old = dict(schema_examples()["evidence-entry"])
    assert not (set(COPIED_EFFECT_MEMBERS) & set(old["body"]))
    validate_document(old, "evidence-entry")
    assert "evidence-entry-writer" in DOMAIN_SCHEMAS
    with pytest.raises(jsonschema.ValidationError):
        validate_document(old, "evidence-entry-writer")
    new = dict(schema_examples()["evidence-entry-writer"])
    assert set(COPIED_EFFECT_MEMBERS) <= set(new["body"])
    validate_document(new, "evidence-entry-writer")
    validate_document(new, "evidence-entry")
    # A body that mixes the two shapes is neither: the members come together.
    mixed = copy.deepcopy(new)
    del mixed["body"]["evaluation_recipe"]
    with pytest.raises(jsonschema.ValidationError):
        validate_document(mixed, "evidence-entry")


def test_a_gap_names_the_decisions_it_lost_and_a_recovery_marker_is_a_kind() -> None:
    """Article 10: a known-decision loss is declared by identity, never id-less."""
    schema = domain_schema("evidence-entry")
    assert "recovery" in schema["properties"]["kind"]["enum"]
    gap = schema["$defs"]["gap-body"]["properties"]
    assert "unflushed" in gap["reason"]["enum"]
    assert gap["decision_ids"]["maxItems"] == 8192
    assert gap["decision_positions"]["items"]["required"] == ["store_id", "position"]
    assert set(gap["accounting"]["enum"]) == {"physical_record", "decision", "event"}
    recovery = schema["$defs"]["recovery-body"]
    events = {variant["properties"]["event"]["const"] for variant in recovery["oneOf"]}
    assert events == {"baseline", "clean_stop", "unclean_stop"}
    unclean = next(
        v for v in recovery["oneOf"] if v["properties"]["event"]["const"] == "unclean_stop"
    )
    assert unclean["properties"]["lost_event_count"]["type"] == "null"
    assert unclean["properties"]["coverage"]["const"] == "unknown"


def test_an_export_carries_its_recipe_the_policy_map_and_the_recovery_context() -> None:
    """Articles 10 and 13: what the offline verifier needs travels in the bundle."""
    properties = domain_schema("evidence-export-result")["properties"]
    assert properties["manifest_version"]["minLength"] == 1
    attachment = properties["policy_versions"]["additionalProperties"]
    states = {variant["properties"]["state"]["const"] for variant in attachment["oneOf"]}
    assert states == {"present", "absent", "damaged"}
    assert properties["recovery_context"]["items"] == {"$ref": "evidence-entry.schema.json"}
    example = dict(schema_examples()["evidence-export-result"])
    assert {"manifest_version", "policy_versions", "recovery_context"} <= set(example)
    validate_document(example, "evidence-export-result")


def test_the_status_names_the_decision_store_and_its_reconciliations() -> None:
    """Articles 2 and 3: nulls, never zeros, when a reconciliation has not run."""
    store = domain_schema("status-result")["properties"]["decision_store"]
    assert set(store["properties"]["store"]["enum"]) == {"file", "memory", "unknown"}
    item = store["properties"]["reconciliations"]["items"]["properties"]
    assert set(item["state"]["enum"]) == {"agrees", "disagrees", "contradicts", "not_run"}
    assert set(item["baseline"]["properties"]["state"]["enum"]) == {
        "established",
        "unknown",
        "not_established",
    }
    assert item["through_sequence"]["type"] == ["integer", "null"]
    assert item["effects_without_decision"]["type"] == ["integer", "null"]


def test_the_two_storage_problems_are_published_retryable_and_answered_could_not_ask() -> None:
    """Articles 1 and 2: a store that could not answer is never a denial."""
    codes = load_json("domain", "problem-codes.json")["codes"]
    for code in ("decision_store_unavailable", "policy_archive_unavailable"):
        assert codes[code]["retryable"] is True
        assert codes[code]["origin"] == "server"
        assert problem_retryable(ProblemCode(code)) is True
    operations = {route.operation: route for route in ROUTES}
    assert {"decision_store_unavailable", "policy_archive_unavailable"} <= set(
        operations["ask_decision"].problems[503]
    )
    assert "decision_store_unavailable" in operations["read_decision"].problems[503]
    assert "no decision taken" not in codes["decision_store_unavailable"]["meaning"]
