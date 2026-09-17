# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import jsonschema
import pytest
from referencing import Registry, Resource
from sayfirst_contract.artifacts import DOMAIN_SCHEMAS, domain_schema, load_json
from sayfirst_contract.binding.http_unix_socket.routes import ROUTES
from sayfirst_contract.golden import schema_examples
from sayfirst_contract.problems import ProblemCode


def _validate(document: object, name: str) -> None:
    registry = Registry()
    for schema_name in DOMAIN_SCHEMAS:
        registry = registry.with_resource(
            f"{schema_name}.schema.json",
            Resource.from_contents(domain_schema(schema_name)),
        )
    jsonschema.Draft202012Validator(domain_schema(name), registry=registry).validate(document)


def test_the_evidence_schemas_are_published_domain_contracts() -> None:
    names = {
        "evidence-entry",
        "evidence-verdict",
        "evidence-page-result",
        "evidence-export-result",
    }
    assert names <= set(DOMAIN_SCHEMAS)
    examples = schema_examples()
    for name in names:
        _validate(examples[name], name)


def test_the_verdict_schema_requires_grades_with_three_values() -> None:
    schema = domain_schema("evidence-verdict")
    assert "grades" in schema["required"]
    grade = schema["properties"]["grades"]["items"]["properties"]["grade"]
    assert set(grade["enum"]) == {"unverified", "observability", "evidence"}


def test_the_status_schema_carries_the_grade_evaluation_and_provider() -> None:
    properties = domain_schema("status-result")["properties"]
    grade = properties["integrity_grade"]
    assert set(grade["required"]) == {
        "grade",
        "basis",
        "evaluated_at",
        "store",
        "reevaluation_interval_seconds",
    }
    assert set(grade["properties"]["grade"]["enum"]) == {
        "unverified",
        "observability",
        "evidence",
    }
    assert properties["privacy_provider"]["x-reserved-values"] == ["none", "unknown"]


def test_the_verdict_condition_has_an_unknown_value() -> None:
    values = domain_schema("evidence-verdict")["properties"]["condition"]["enum"]
    assert set(values) == {"intact", "broken_at", "gap_at", "unverifiable"}


def test_the_evidence_problem_codes_and_read_routes_are_published() -> None:
    assert ProblemCode.EVIDENCE_RANGE_INVALID.value == "evidence_range_invalid"
    assert ProblemCode.EVIDENCE_STORE_UNAVAILABLE.value == "evidence_store_unavailable"
    codes = load_json("domain", "problem-codes.json")["codes"]
    assert codes["evidence_range_invalid"]["origin"] == "server"
    operations = {route.operation: route for route in ROUTES}
    assert operations["read_evidence"].path == "/scopes/{scope}/evidence"
    assert operations["export_evidence"].path == "/scopes/{scope}/evidence/export"
    assert operations["export_evidence"].response == "evidence-export-result"


def test_a_dropped_record_has_no_synchronous_refusal_code() -> None:
    """Article 10: asynchronous loss is a marker, not a refused decision."""
    assert "evidence_not_recorded" not in {item.value for item in ProblemCode}
    assert all(
        "evidence_not_recorded" not in codes
        for route in ROUTES
        for codes in route.problems.values()
    )


def test_an_entry_kind_cannot_carry_another_kinds_body() -> None:
    entry = dict(schema_examples()["evidence-entry"])
    entry["body"] = {
        "grade": "unverified",
        "basis": "access_not_established",
        "evaluated_at": "2026-09-04T00:00:00Z",
        "paths_inspected": 0,
    }
    with pytest.raises(jsonschema.ValidationError):
        _validate(entry, "evidence-entry")


def test_the_status_schema_carries_the_emission_state() -> None:
    """Article 10: a pipeline that is not delivering has somewhere to say so."""
    emission = domain_schema("status-result")["properties"]["evidence_emission"]
    assert set(emission["required"]) == {
        "delivering",
        "undelivered_records",
        "scopes_undelivered",
    }
    assert emission["properties"]["delivering"]["type"] == "boolean"
    assert emission["properties"]["undelivered_records"]["minimum"] == 0


def test_a_malformed_scope_on_a_read_is_its_own_code_not_a_permission_refusal() -> None:
    """Articles 2, 5, 13: a code is used only with the meaning its registry gives it."""
    codes = load_json("domain", "problem-codes.json")["codes"]
    assert codes["scope_invalid"]["origin"] == "server"
    assert codes["scope_invalid"]["retryable"] is False
    assert "permission" not in codes["scope_invalid"]["meaning"]
    assert "may not write" in codes["scope_refused"]["meaning"]
    assert ProblemCode.SCOPE_INVALID.value == "scope_invalid"

    operations = {route.operation: route for route in ROUTES}
    for name in ("read_evidence", "export_evidence"):
        assert "scope_invalid" in operations[name].problems[400]
        # These two reads never consult a permission, so they never answer the
        # code that says a principal may not write the scope.
        assert "scope_refused" not in operations[name].problems[403]
