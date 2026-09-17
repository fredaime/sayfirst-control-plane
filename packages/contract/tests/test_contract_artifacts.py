# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import inspect
import re
import tomllib
from pathlib import Path

import jsonschema
import pytest
from sayfirst_contract import (
    approvals,
    decisions,
    golden,
    grants,
    policy,
    problems,
    replay,
    status,
    whoami,
)
from sayfirst_contract.approvals import (
    Approval,
    ApprovalResolution,
    ApprovalState,
    Resolution,
    wait_until_resolved,
)
from sayfirst_contract.artifacts import (
    BINDING_ARTIFACTS,
    DOMAIN_ARTIFACTS,
    DOMAIN_DOCUMENTS,
    DOMAIN_SCHEMAS,
    artifact,
    domain_schema,
    load_json,
)
from sayfirst_contract.client import Answered
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_contract.generation import (
    CONTRACT_GENERATION,
    SUPPORTED_GENERATIONS,
    load_generation_marker,
)
from sayfirst_contract.grants import GrantEndReason, GrantSignalKind
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.status import Authority, IntegrityGrade
from sayfirst_contract.values import Unknown
from sayfirst_testing.schemas import validate_document


def _contract_files() -> set[str]:
    root = Path(str(artifact()))
    return {item.relative_to(root).as_posix() for item in root.rglob("*") if item.is_file()}


def test_every_artefact_is_listed() -> None:
    """Article 13: every one of at least ten published artefacts is classified."""
    expected = (
        set(DOMAIN_ARTIFACTS) | set(DOMAIN_DOCUMENTS) | set(BINDING_ARTIFACTS) | {"digests.json"}
    )
    assert len(expected) >= 12
    assert _contract_files() == expected


def test_the_pinned_generation_matches_the_marker() -> None:
    """Article 13: the executable pin is derived from the published marker."""
    marker = load_generation_marker()
    assert marker.contract_generation == CONTRACT_GENERATION
    assert (marker.contract_generation,) == SUPPORTED_GENERATIONS


def test_the_problem_code_enum_matches_the_registry() -> None:
    """Article 13: code and registry expose one problem vocabulary."""
    registry = load_json("domain", "problem-codes.json")
    assert isinstance(registry, dict)
    codes = tuple(registry["codes"])
    assert len(codes) >= 22
    assert tuple(item.value for item in ProblemCode) == codes


@pytest.mark.parametrize(
    ("schema_name", "property_path", "enum"),
    [
        ("decision-result", ("outcome",), Outcome),
        ("decision-result", ("reason",), Reason),
        ("approval-result", ("state",), ApprovalState),
        ("approval-resolve-request", ("resolution",), Resolution),
        ("status-result", ("integrity_grade", "grade"), IntegrityGrade),
        ("status-result", ("store", "authority"), Authority),
        ("grant-signal", ("kind",), GrantSignalKind),
        ("grant-signal", ("reason",), GrantEndReason),
    ],
)
def test_every_schema_enum_matches_its_python_enum(
    schema_name: str, property_path: tuple[str, ...], enum: type
) -> None:
    """Articles 1 and 13: schemas and readers use the same closed values."""
    node = domain_schema(schema_name)["properties"]
    for index, member in enumerate(property_path):
        node = node[member]
        if index + 1 < len(property_path):
            node = node["properties"]
    assert set(node["enum"]) == {item.value for item in enum}


def test_attribute_values_agree_with_the_schemas() -> None:
    """Articles 1 and 13: registered observed values mirror domain values."""
    registry = load_json("domain", "attributes.json")
    attributes = registry["attributes"]
    assert set(attributes["decision.outcome"]["values"]) == {
        *(item.value for item in Outcome),
        "unknown",
    }
    assert set(attributes["decision.reason"]["values"]) == {
        *(item.value for item in Reason),
        "unknown",
    }
    assert set(attributes["approval.state"]["values"]) == {item.value for item in ApprovalState}
    assert set(attributes["integrity.grade"]["values"]) == {item.value for item in IntegrityGrade}
    assert set(attributes["authority"]["values"]) == {item.value for item in Authority}


_TRANSPORT_TERMS = (
    "http",
    "https",
    "url",
    "uri",
    "header",
    "socket",
    "tcp",
    "port",
    "path",
    "route",
    "endpoint",
    "method",
    "get",
    "post",
    "status code",
    "grpc",
    "websocket",
    "json-rpc",
)
_TRANSPORT_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(term) for term in _TRANSPORT_TERMS) + r")\b",
    re.IGNORECASE,
)


def _strings(value: object):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _assert_transport_free(documents: list[object]) -> int:
    inspected = 0
    for document in documents:
        for value in _strings(document):
            inspected += 1
            if value == "https://json-schema.org/draft/2020-12/schema":
                continue
            assert _TRANSPORT_PATTERN.search(value) is None, value
    return inspected


def _module_docstrings(module: object) -> list[str]:
    documents = [module.__doc__] if module.__doc__ else []
    for _, member in inspect.getmembers(module):
        if getattr(member, "__module__", None) != module.__name__:
            continue
        if member.__doc__:
            documents.append(member.__doc__)
        if inspect.isclass(member):
            documents.extend(
                value.__doc__
                for value in vars(member).values()
                if getattr(value, "__module__", None) == module.__name__ and value.__doc__
            )
    return documents


def test_the_domain_contract_names_no_transport() -> None:
    """Articles 4 and 13: the domain layer does not name a transport."""
    documents = [load_json(*name.split("/")) for name in DOMAIN_ARTIFACTS]
    module_docs = [
        document
        for module in (
            decisions,
            approvals,
            grants,
            policy,
            status,
            problems,
            golden,
            replay,
            whoami,
        )
        for document in _module_docstrings(module)
    ]
    assert len(documents) >= 10
    assert _assert_transport_free([*documents, *module_docs]) >= 200


def test_the_transport_guard_catches_a_planted_term() -> None:
    """Article 13: the vocabulary guard is proven non-vacuous by a planted defect."""
    planted = copy.deepcopy(load_json("domain", "generation.json"))
    planted["path"] = "planted"
    with pytest.raises(AssertionError, match="path"):
        _assert_transport_free([planted])


def test_the_transport_guard_reads_method_docstrings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Articles 4 and 13: a method docstring cannot hide transport vocabulary."""
    monkeypatch.setattr(golden.Scenario.binds_server, "__doc__", "Uses a socket.")
    with pytest.raises(AssertionError, match="socket"):
        _assert_transport_free(_module_docstrings(golden))


def test_every_attribute_is_in_this_project_namespace() -> None:
    """Articles 0 and 14: the project's own prefix is written in one registry only.

    The registry carried the placeholder in its angle brackets while the name
    was open; the brackets were the placeholder's syntax, not the prefix's, so
    the decided name stands in the registry bare and is read from the one
    distribution name that also carries it.
    """
    registry = load_json("domain", "attributes.json")
    package_project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    distribution_prefix = package_project["name"].removesuffix("-contract")
    assert registry["prefix"] == distribution_prefix
    assert len(registry["attributes"]) >= 12
    assert all(
        re.fullmatch(r"[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*", key) for key in registry["attributes"]
    )


def test_no_registered_attribute_carries_a_payload() -> None:
    """Article 11: the default attribute surface records identity, not payload."""
    attributes = load_json("domain", "attributes.json")["attributes"]
    assert len(attributes) >= 12
    forbidden = {"argument", "content", "payload", "return", "prompt", "input", "output"}
    for key in attributes:
        assert not (set(key.split(".")) & forbidden)
        assert key not in {"arguments.value", "result.value"}
    assert attributes["arguments.digest"]["type"] == "string"
    assert not any(key.startswith("arguments.") and key != "arguments.digest" for key in attributes)


def test_a_request_writer_emits_only_defined_members() -> None:
    """Article 13: writers emit only request members defined by their generation."""
    examples = (
        (
            DecisionAsk(
                "example.effect",
                arguments_digest="sha256:" + "0" * 64,
            ).to_document(1),
            "decision-ask-request",
        ),
        (
            ApprovalResolution("local", "approval-1", Resolution.APPROVE).to_document(1),
            "approval-resolve-request",
        ),
    )
    for document, schema_name in examples:
        schema = domain_schema(schema_name)
        assert set(document) <= set(schema["properties"])
        jsonschema.validate(document, schema)


def test_request_schemas_close_and_response_schemas_open() -> None:
    """Article 13: requests reject additions while responses permit them."""
    requests = {"decision-ask-request", "approval-resolve-request", "delegation"}
    closed_values = {"grant"}
    for name in DOMAIN_SCHEMAS:
        assert domain_schema(name)["additionalProperties"] is (name not in requests | closed_values)


def test_every_response_schema_requires_the_generation() -> None:
    """Article 13: every response document echoes a generation."""
    for name in {
        "decision-result",
        "decision-record",
        "grant-signal",
        "policy-status",
        "approval-result",
        "status-result",
        "problem-document",
        "whoami-result",
    }:
        assert "contract_generation" in domain_schema(name)["required"]


def test_no_request_schema_names_a_principal() -> None:
    """Article 6: request claims never replace the established principal."""
    forbidden = {"principal", "user", "uid", "caller", "requested_by", "on_behalf"}
    for name in {"decision-ask-request", "approval-resolve-request"}:
        assert not (set(domain_schema(name)["properties"]) & forbidden)


def _status_enums(value: object, path: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
    if not isinstance(value, dict):
        return
    for name, property_schema in value.get("properties", {}).items():
        property_path = (*path, name)
        if (
            isinstance(property_schema, dict)
            and "enum" in property_schema
            and name.endswith(("state", "grade", "authority"))
        ):
            yield property_path, property_schema["enum"]
        yield from _status_enums(property_schema, property_path)


def _assert_three_valued_status_fields(schemas: list[dict[str, object]]) -> int:
    inspected = 0
    for schema in schemas:
        for path, values in _status_enums(schema):
            inspected += 1
            assert len(values) >= 3, ".".join(path)
            assert {"unknown", "unverified"} & set(values), ".".join(path)
    assert inspected >= 3
    return inspected


def test_a_status_field_has_at_least_three_values() -> None:
    """Article 2: uncertain state surfaces are not reduced to two values."""
    requests = {"decision-ask-request", "approval-resolve-request"}
    responses = [domain_schema(name) for name in DOMAIN_SCHEMAS if name not in requests]
    assert _assert_three_valued_status_fields(responses) >= 3
    properties = domain_schema("status-result")["properties"]
    grade = properties["integrity_grade"]["properties"]["grade"]["enum"]
    authority = properties["store"]["properties"]["authority"]["enum"]
    assert len(grade) >= 3 and "unverified" in grade
    assert len(authority) >= 3 and "unknown" in authority
    assert properties["privacy_provider"]["x-reserved-values"] == ["none", "unknown"]
    projection = domain_schema("policy-status")["properties"]["projection"]["properties"]
    assert projection["in_step"]["enum"] == ["yes", "no", "unknown"]
    # A third-party provider names its own kind, so the shape is open and the
    # reserved list keeps a value meaning "not established" (articles 2 and 8).
    assert "enum" not in projection["kind"]
    assert "unknown" in projection["kind"]["x-reserved-values"]


def test_the_three_value_guard_catches_a_planted_binary_state() -> None:
    """Article 2: the generic status guard is proven against a future binary field."""
    planted = copy.deepcopy(domain_schema("approval-result"))
    planted["properties"]["state"]["enum"] = ["pending", "approved"]
    with pytest.raises(AssertionError, match="state"):
        _assert_three_valued_status_fields(
            [
                planted,
                domain_schema("status-result"),
            ]
        )


def test_the_default_ask_emits_no_payload_member() -> None:
    """Article 11: the default ask carries no effect payload."""
    assert set(domain_schema("decision-ask-request")["properties"]) == {
        "contract_generation",
        "capability",
        "scope",
        "arguments_digest",
        "correlation",
        "delegation",
    }
    assert "arguments_digest" not in DecisionAsk("example.effect").to_document(1)


def test_a_reader_keeps_unknown_response_members() -> None:
    """Article 13: additive response members survive tolerant reading."""
    document = {
        "contract_generation": 1,
        "authority": "authoritative",
        "decision_ref": "decision-1",
        "scope": "local",
        "capability": "example.effect",
        "outcome": "allow",
        "reason": "policy_allows",
        "policy_version": "sha256:" + "0" * 64,
        "approval_ref": None,
        "decided_at": "2026-09-04T00:00:00+00:00",
        "correlation": None,
        "future_member": {"retained": True},
    }
    assert Decision.from_document(document).extra == {"future_member": {"retained": True}}


def test_an_unknown_approval_state_never_permits() -> None:
    """Article 3: a future approval state is returned but never interpreted as permission."""
    approval = Approval(
        "approval-1",
        "decision-1",
        "local",
        "example.effect",
        Unknown("zz-synthetic-state"),
        "2026-09-04T00:00:00+00:00",
        "2026-09-04T00:01:00+00:00",
        None,
        None,
        1,
        {},
    )

    class Client:
        def read_approval(self, scope: str, approval_ref: str):  # type: ignore[no-untyped-def]
            return Answered(approval, 1)

    result = wait_until_resolved(Client(), "local", "approval-1", pause=lambda: None, max_polls=2)  # type: ignore[arg-type]
    assert isinstance(result, Answered)
    assert isinstance(result.value.state, Unknown)
    assert result.value.state is not ApprovalState.APPROVED


def test_every_response_document_validates_examples() -> None:
    """Article 13: representative generation-one documents satisfy every schema."""
    assert set(golden.schema_examples()) == set(DOMAIN_SCHEMAS)
    for schema_name, document in golden.schema_examples().items():
        validate_document(document, schema_name)


def test_policy_and_grant_shapes_are_published_in_generation_one() -> None:
    """Article 13: every block 2.3 wire value is part of the domain contract."""
    assert {
        "decision-record",
        "grant",
        "grant-signal",
        "policy-status",
    } <= set(DOMAIN_SCHEMAS)
    decision = domain_schema("decision-result")
    assert {"principal", "arguments_digest", "rule_id", "grant"} <= set(decision["properties"])
    conditions = domain_schema("grant")["properties"]["conditions"]["properties"]
    assert "arguments_digest" in conditions


def test_a_suspended_decision_schema_does_not_require_an_approval_reference() -> None:
    """Article 3: an approval reference exists only after an approval record does."""
    schema = domain_schema("decision-result")
    assert "approval_ref" not in schema["required"]
    document = dict(golden.schema_examples()["decision-result"])
    document["outcome"] = "suspend"
    document["reason"] = "policy_requires_review"
    document.pop("approval_ref", None)
    jsonschema.validate(document, schema)


def test_policy_version_is_an_opaque_content_version() -> None:
    """Articles 3 and 13: the contract does not choose the policy file's version format."""
    document = dict(golden.schema_examples()["decision-result"])
    document["policy_version"] = "file-version-1"
    validate_document(document, "decision-result")


_GENERATION_ONE_REQUESTS = {
    "decision-ask-request": (
        (
            "arguments_digest",
            "capability",
            "contract_generation",
            "correlation",
            "delegation",
            "scope",
        ),
        ("capability", "contract_generation"),
    ),
    "approval-resolve-request": (
        ("approval_ref", "contract_generation", "reason", "resolution", "scope"),
        ("approval_ref", "contract_generation", "resolution", "scope"),
    ),
}


def test_generation_one_request_members_are_frozen() -> None:
    """Article 13: a new request member is a new generation, never an amendment."""
    assert load_generation_marker().contract_generation == 1
    for name, (members, required) in _GENERATION_ONE_REQUESTS.items():
        schema = domain_schema(name)
        assert tuple(sorted(schema["properties"])) == members, name
        assert tuple(sorted(schema["required"])) == required, name


def test_every_scenario_ask_sends_only_generation_one_request_members() -> None:
    """Article 13: the arbiter fixtures never script a member the generation lacks."""
    sendable = set(domain_schema("decision-ask-request")["properties"]) - {"contract_generation"}
    document = load_json("domain", "golden-scenarios.json")
    assert isinstance(document, dict)
    scenarios = document["scenarios"]
    assert len(scenarios) >= 8
    for name, scenario in scenarios.items():
        assert set(scenario["ask"]) <= sendable, name
