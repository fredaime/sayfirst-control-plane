# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import enum

from sayfirst_contract import problems
from sayfirst_contract.artifacts import domain_schema, load_json
from sayfirst_contract.binding.http_unix_socket.routes import ROUTES
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.whoami import (
    COULD_NOT_ASK_CODES,
    REFUSAL_CODES,
    WELL_KNOWN_KINDS,
    Delegation,
    Peer,
    Principal,
    WhoAmI,
    classify,
)
from sayfirst_testing.schemas import document_is_valid, validate_document

_EXPECTED = {
    "peer_not_admitted": ("server", False, 403),
    "peer_uid_unmapped": ("server", False, 403),
    "peer_credential_unavailable": ("server", True, 503),
    "principal_groups_unavailable": ("server", True, 503),
    "delegation_invalid": ("server", False, 400),
    "server_not_the_daemon_principal": ("client", False, None),
    "peer_identity_unsupported": ("client", False, None),
}


def test_the_identity_problem_codes_state_one_fact_each() -> None:
    """Articles 2 and 6: each refusal of the host boundary names its own fact."""
    registry = load_json("domain", "problem-codes.json")["codes"]
    for code, (origin, retryable, _) in _EXPECTED.items():
        assert code in registry, code
        assert registry[code]["origin"] == origin
        assert registry[code]["retryable"] is retryable
        assert registry[code]["article"] == "6"
        assert ProblemCode(code)


def test_the_identity_codes_name_no_token_session_or_issuer() -> None:
    """Article 6: no tokens, no sessions, no rotation, so no vocabulary for them."""
    registry = load_json("domain", "problem-codes.json")["codes"]
    forbidden = ("token", "session", "issuer", "rotation", "bearer", "password", "secret")
    for code, entry in registry.items():
        text = f"{code} {entry['meaning']}".lower()
        assert not any(word in text for word in forbidden), code


def test_a_refusal_and_a_could_not_ask_are_distinct() -> None:
    """Article 1: the daemon answered no, and no answer exists, are two results.

    The identity codes this file is about, read out of the registry's class
    column rather than named a second time here. Which class each published
    code carries is `test_problem_classes.py`'s to pin, for all of them at
    once; what belongs here is that the two sets stay disjoint and that each
    identity code falls on the side article 6 puts it on.
    """
    for code in ("peer_not_admitted", "peer_uid_unmapped"):
        assert code in REFUSAL_CODES, code
        assert classify(code) == "refused"
    for code in (
        "peer_credential_unavailable",
        "principal_groups_unavailable",
        "server_not_the_daemon_principal",
        "peer_identity_unsupported",
    ):
        assert code in COULD_NOT_ASK_CODES, code
        assert classify(code) == "could_not_ask"
    assert not REFUSAL_CODES & COULD_NOT_ASK_CODES
    assert classify("zz-synthetic-code") == "could_not_ask"


def test_groups_status_has_three_values() -> None:
    """Article 2: an uncertain identity surface is not reduced to two values."""
    principal = domain_schema("principal")["properties"]["groups_status"]["enum"]
    connection = domain_schema("whoami-result")["properties"]["status"]["enum"]
    assert len(principal) >= 3 and "unknown" in principal
    assert len(connection) >= 3 and "unknown" in connection


def test_the_well_known_principal_kinds_are_the_documented_four() -> None:
    """Article 6: the kinds of principal are an open registry, never an enumeration."""
    assert WELL_KNOWN_KINDS == ("user", "service", "workload", "process")
    registry = load_json("domain", "attributes.json")["attributes"]["principal.kind"]
    assert registry["values"] == "open"
    assert tuple(registry["documented_values"]) == WELL_KNOWN_KINDS
    for member in vars(problems).values():
        if isinstance(member, type) and issubclass(member, enum.Enum):
            assert not ({item.value for item in member} & set(WELL_KNOWN_KINDS))
    janitor = Principal(
        kind="janitor",
        uid=1000,
        gid=1000,
        name="alice",
        groups=("ops",),
        groups_status="resolved",
        unnamed_group_ids=(),
        established_by="peer_credential",
        established_at="2026-09-04T00:00:00+00:00",
    )
    assert janitor.reference == "janitor:1000"
    validate_document(janitor.to_document(), "principal")


def test_a_principal_carries_no_process_id() -> None:
    """Article 6, rule P4: a process id is diagnostic and never decisional."""
    import dataclasses

    assert not any(field.name == "pid" for field in dataclasses.fields(Principal))
    assert "pid" not in domain_schema("principal")["properties"]
    assert "pid" in domain_schema("peer")["properties"]


def test_the_whoami_result_reports_what_the_accept_saw() -> None:
    """Article 6: whoami reports the principal as the local boundary saw it."""
    result = WhoAmI(
        contract_generation=1,
        connection_id="connection-1",
        socket_path="/run/sayfirst/daemon.sock",
        mode="per_user",
        peer=Peer(uid=1000, gid=1000, pid=4242, captured_at="2026-09-04T00:00:00+00:00"),
        principal=None,
        status="unknown",
        refresh_due_at=None,
        group_lifetime_seconds=60,
        delegation=None,
        extra={},
    )
    document = result.to_document()
    assert document["delegation"] is None
    assert "delegation" in document
    validate_document(document, "whoami-result")
    assert WhoAmI.from_document(document) == result


def test_a_delegation_is_an_observation_beside_the_principal() -> None:
    """Article 3 and article 6: a declaration is recorded, never verified."""
    delegation = Delegation.declared(
        [{"kind": "user", "name": "alice", "uid": 1001, "via": "privilege_tool"}]
    )
    document = delegation.to_document()
    assert document["status"] == "declared"
    assert document["chain"][0]["name"] == "alice"
    assert "principal" not in document
    validate_document(document, "delegation")
    schema = domain_schema("delegation")
    assert schema["additionalProperties"] is False
    assert schema["properties"]["chain"]["maxItems"] == 4


def test_the_whoami_operation_is_bound_and_answers_the_identity_refusals() -> None:
    """Article 6: the guard the article names is part of the contract, not tooling."""
    route = next(route for route in ROUTES if route.operation == "read_whoami")
    assert route.method == "GET"
    assert route.response == "whoami-result"
    assert route.request is None
    assert set(route.problems[403]) == {"peer_not_admitted", "peer_uid_unmapped"}
    assert "peer_credential_unavailable" in route.problems[503]
    assert "principal_groups_unavailable" not in route.problems.get(503, ())


def test_a_decision_request_may_declare_a_delegation() -> None:
    """Article 6: for whom a peer acts is a request member, not a new identity."""
    schema = domain_schema("decision-ask-request")
    assert "delegation" in schema["properties"]
    assert "delegation" not in schema["required"]
    assert schema["additionalProperties"] is False
    assert not document_is_valid(
        {
            "contract_generation": 1,
            "capability": "example.effect",
            "delegation": {"chain": [{"kind": "user", "name": "a", "uid": 1, "via": "x"}] * 5},
        },
        "decision-ask-request",
    )
    assert document_is_valid(
        {
            "contract_generation": 1,
            "capability": "example.effect",
            "delegation": {"chain": [{"kind": "user", "name": "a", "uid": 1, "via": "x"}]},
        },
        "decision-ask-request",
    )


def test_the_binding_names_the_socket_and_says_the_host_is_a_placeholder() -> None:
    """Article 6, rule C3: the binding says where it is reached and what to ignore."""
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    assert binding["x-transport"] == "http-unix-socket"
    servers = binding["servers"]
    assert len(servers) == 1
    assert servers[0]["url"] == "http://sayfirst"
    assert "placeholder" in servers[0]["description"]
    assert servers[0]["x-socket-path-default"].endswith("daemon.sock")
