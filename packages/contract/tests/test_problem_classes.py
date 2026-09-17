# SPDX-License-Identifier: Apache-2.0
"""Article 1: one class per problem code, published once and read by every client.

The two clients of this contract classified the same codes differently — the
binding client read `decision_not_found` as a refusal and the transport read it
as « could not ask » — so one 404 reached two callers as two different facts.
The class is a property of the code, so the registry publishes it and nothing
derives it a second time.
"""

from __future__ import annotations

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.problems import CLASSES, ProblemCode, problem_class
from sayfirst_contract.whoami import COULD_NOT_ASK_CODES, REFUSAL_CODES, classify

#: The class every published code carries, written out rather than derived, so
#: a code whose class changes is a diff in this file and in the registry.
EXPECTED: dict[str, str] = {
    "answer_unreadable": "could_not_ask",
    "approval_provider_unavailable": "could_not_ask",
    "approval_resolved": "refused",
    "approval_unknown": "refused",
    "configuration_writable_by_principal": "refused",
    "decision_contended": "could_not_ask",
    "decision_not_found": "refused",
    "decision_store_unavailable": "could_not_ask",
    "delegation_invalid": "refused",
    "evidence_range_invalid": "refused",
    "evidence_store_unavailable": "could_not_ask",
    "generation_missing": "refused",
    "generation_unreadable": "refused",
    "generation_unsupported": "refused",
    "impostor": "could_not_ask",
    "internal": "could_not_ask",
    "member_unknown": "refused",
    "operation_unknown": "refused",
    "outcome_unknown": "could_not_ask",
    "peer_credential_unavailable": "could_not_ask",
    "peer_identity_unsupported": "could_not_ask",
    "peer_not_admitted": "refused",
    "peer_uid_unmapped": "refused",
    "policy_archive_unavailable": "could_not_ask",
    "policy_unavailable": "could_not_ask",
    "policy_writable_by_principal": "refused",
    "principal_groups_unavailable": "could_not_ask",
    "principal_refused": "refused",
    "request_malformed": "refused",
    "scope_invalid": "refused",
    "scope_refused": "refused",
    "scope_required": "refused",
    "server_not_the_daemon_principal": "could_not_ask",
    "unreachable": "could_not_ask",
}


def test_every_published_code_carries_a_class_and_only_the_two() -> None:
    document = load_json("domain", "problem-codes.json")
    assert isinstance(document, dict)
    codes = document["codes"]
    assert isinstance(codes, dict)
    assert set(codes) == {code.value for code in ProblemCode}
    for name, entry in sorted(codes.items()):
        assert entry.get("class") in CLASSES, f"{name} publishes class {entry.get('class')!r}"


@pytest.mark.parametrize(("code", "expected"), sorted(EXPECTED.items()))
def test_the_registry_publishes_the_class_this_contract_decided(code: str, expected: str) -> None:
    assert problem_class(ProblemCode(code)) == expected


def test_a_code_this_generation_does_not_define_is_never_a_refusal() -> None:
    """Article 3: no unknown input is read more permissively, and neither is it a verdict."""
    assert problem_class("zz-synthetic-code") == "could_not_ask"
    assert classify("zz-synthetic-code") == "could_not_ask"


def test_the_identity_sets_are_the_registry_column_and_not_a_second_list() -> None:
    refused = frozenset(name for name, klass in EXPECTED.items() if klass == "refused")
    could_not_ask = frozenset(name for name, klass in EXPECTED.items() if klass == "could_not_ask")
    assert refused == REFUSAL_CODES
    assert could_not_ask == COULD_NOT_ASK_CODES
    assert not REFUSAL_CODES & COULD_NOT_ASK_CODES
