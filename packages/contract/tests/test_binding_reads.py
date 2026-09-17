# SPDX-License-Identifier: Apache-2.0
"""The declared reads use the binding client over a real AF_UNIX socket."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from canned_daemon import answering
from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.decisions import Decision, DecisionAsk
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_contract.golden import schema_examples
from sayfirst_contract.policy import PolicyStatus
from sayfirst_contract.problems import ProblemCode, problem_retryable
from sayfirst_contract.values import Unknown
from sayfirst_contract_stub.stub import Stub
from sayfirst_contract_stub.stub_http import serve
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms

pytestmark = requires_platforms(*OS_REAL_PLATFORMS)


@contextmanager
def _connected(
    tmp_path: Path,
    status: int,
    document: object,
    *,
    raw_body: bytes | None = None,
    drop_posts: bool = False,
    drop_gets: bool = False,
) -> Iterator[tuple[SocketClient, list[tuple[str, str]]]]:
    address = tmp_path / "daemon.sock"
    with answering(
        address,
        status,
        document,
        raw_body=raw_body,
        drop_posts=drop_posts,
        drop_gets=drop_gets,
    ) as requests:
        client = SocketClient(socket_path=address, expected_uid=os.geteuid(), timeout=5.0)
        yield client, requests


def test_read_decision_quotes_the_target_and_returns_the_decision(tmp_path: Path) -> None:
    document = {
        **schema_examples()["decision-record"],
        "contract_generation": CONTRACT_GENERATION,
        "decision_ref": "decision/1 ?#",
        "scope": "team/ops +&",
    }
    with _connected(tmp_path, 200, document) as (connection, requests):
        result = connection.read_decision("team/ops +&", "decision/1 ?#")

    assert requests == [
        (
            "GET",
            f"/decisions/decision%2F1%20%3F%23?contract_generation={CONTRACT_GENERATION}"
            "&scope=team%2Fops+%2B%26",
        )
    ]
    assert isinstance(result, Answered)
    assert isinstance(result.value, Decision)
    assert result.value.decision_ref == document["decision_ref"]
    assert result.contract_generation == CONTRACT_GENERATION


def test_read_decision_carries_a_missing_records_code_and_retryability(tmp_path: Path) -> None:
    """The daemon answers 404 `decision_not_found`; the code and its retryability travel.

    The class is the registry's, and the registry publishes this code as a
    refusal: the daemon was asked and answered that it holds no such record.
    Both clients of this contract read the reply that way, so the reading is
    asserted here rather than left open (article 1). What travels with it is the
    code the daemon sent and the retryability it sent with it.
    """
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "code": "decision_not_found",
        "message": "no decision with that reference in this scope",
        "retryable": False,
    }
    with _connected(tmp_path, 404, document) as (connection, _):
        result = connection.read_decision("local", "missing")

    assert type(result) is Refused
    assert result.problem.code is ProblemCode.DECISION_NOT_FOUND
    assert result.problem.retryable is False


@pytest.mark.parametrize("status", [404, 503])
def test_read_decision_never_reads_an_unknown_code_as_a_refusal(
    tmp_path: Path, status: int
) -> None:
    """Article 3: a code this generation does not define is never a denial.

    The one consumer whose behaviour this rule moved. Before the class column
    this client answered `Refused` for every code outside a three-code tuple,
    an unknown one included, so a far end could refuse a governed caller with a
    word this generation cannot read. It is a « could not ask » now, at either
    status: the code is retained exactly as it arrived, and nothing is decided
    from a word nobody here defines (articles 2 and 3).
    """
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "code": "zz-synthetic-code",
        "message": "a code of some later generation",
        "retryable": False,
    }
    with _connected(tmp_path, status, document) as (connection, _):
        result = connection.read_decision("local", "missing")

    assert type(result) is CouldNotAsk
    assert result.problem.code == Unknown("zz-synthetic-code")


def test_read_decision_reports_a_malformed_record_as_unreadable(tmp_path: Path) -> None:
    """A record without its reference is not a record; the answer is unreadable, never a verdict."""
    document = {
        key: value
        for key, value in schema_examples()["decision-record"].items()
        if key != "decision_ref"
    }
    with _connected(tmp_path, 200, document) as (connection, _):
        result = connection.read_decision("local", "decision-1")

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE
    assert "decision_ref" in result.problem.message


def test_read_decision_preserves_the_readers_unknown_outcome(tmp_path: Path) -> None:
    document = {"contract_generation": CONTRACT_GENERATION, "outcome": "future-outcome"}
    with _connected(tmp_path, 200, document) as (connection, _):
        result = connection.read_decision("local", "decision-1")

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.OUTCOME_UNKNOWN


def test_read_decision_reads_the_published_record_which_carries_no_approval_ref(
    tmp_path: Path,
) -> None:
    """The `decision-record` schema neither lists nor requires `approval_ref`, and the
    daemon drops it before rendering a record. The reader must read what the schema
    allows; it used to raise `KeyError` on the contract's own golden record."""
    document = schema_examples()["decision-record"]
    assert "approval_ref" not in document
    with _connected(tmp_path, 200, document) as (connection, _):
        result = connection.read_decision("local", "decision-1")

    assert isinstance(result, Answered), result
    assert result.value.decision_ref == "decision-1"
    assert result.value.approval_ref is None


def test_read_policy_status_returns_the_typed_status(tmp_path: Path) -> None:
    document = {**schema_examples()["policy-status"], "contract_generation": CONTRACT_GENERATION}
    with _connected(tmp_path, 200, document) as (connection, requests):
        result = connection.read_policy_status()

    assert requests == [("GET", f"/policy/status?contract_generation={CONTRACT_GENERATION}")]
    assert isinstance(result, Answered)
    assert isinstance(result.value, PolicyStatus)
    assert result.value.to_document() == document
    assert result.contract_generation == CONTRACT_GENERATION


@pytest.mark.parametrize("format_value", [None, "not-an-integer"])
def test_read_policy_status_converts_reader_errors_to_unreadable(
    tmp_path: Path, format_value: object
) -> None:
    document = {**schema_examples()["policy-status"], "format": format_value}
    with _connected(tmp_path, 200, document) as (connection, _):
        result = connection.read_policy_status()

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE
    assert result.problem.contract_generation == CONTRACT_GENERATION


@pytest.mark.parametrize("operation", ["read_decision", "read_policy_status"])
@pytest.mark.parametrize("status", [200, 403])
def test_document_reads_check_generation_before_reading_or_classifying(
    tmp_path: Path, operation: str, status: int
) -> None:
    document = {
        "contract_generation": 99,
        "code": "peer_not_admitted",
        "message": "no",
        "retryable": False,
    }
    with _connected(tmp_path, status, document) as (connection, _):
        result = (
            connection.read_decision("local", "decision-1")
            if operation == "read_decision"
            else connection.read_policy_status()
        )

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED


def test_read_policy_status_classifies_a_refusal(tmp_path: Path) -> None:
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "code": "peer_not_admitted",
        "message": "no",
        "retryable": False,
    }
    with _connected(tmp_path, 403, document) as (connection, _):
        result = connection.read_policy_status()

    assert type(result) is Refused
    assert result.problem.code is ProblemCode.PEER_NOT_ADMITTED


def test_read_evidence_quotes_scope_and_preserves_the_page(tmp_path: Path) -> None:
    document = {
        "contract_version": str(CONTRACT_GENERATION),
        "scope": "team/ops +&",
        "from_sequence": 3,
        "to_sequence": 3,
        "entries": [],
        "verification": {},
        "next_from": None,
        "future_member": {"preserve": True},
    }
    with _connected(tmp_path, 200, document) as (connection, requests):
        result = connection.read_evidence("team/ops +&", 3, page_size=50)

    assert requests == [
        (
            "GET",
            f"/scopes/team%2Fops%20%2B%26/evidence?contract_generation={CONTRACT_GENERATION}"
            "&from_sequence=3&page_size=50",
        )
    ]
    assert isinstance(result, Answered)
    assert result.value == document
    assert result.contract_generation == CONTRACT_GENERATION


def test_read_evidence_defaults_to_one_hundred_without_validating_page_members(
    tmp_path: Path,
) -> None:
    document = {"contract_version": str(CONTRACT_GENERATION)}
    with _connected(tmp_path, 200, document) as (connection, requests):
        result = connection.read_evidence("local", 1)

    assert requests == [
        (
            "GET",
            f"/scopes/local/evidence?contract_generation={CONTRACT_GENERATION}"
            "&from_sequence=1&page_size=100",
        )
    ]
    assert isinstance(result, Answered)
    assert result.value == document


def test_export_evidence_omits_an_absent_end_and_includes_a_given_end(tmp_path: Path) -> None:
    document = {"contract_version": str(CONTRACT_GENERATION), "entries": []}
    with _connected(tmp_path, 200, document) as (connection, requests):
        unbounded = connection.export_evidence("team/ops +&", 3)
        bounded = connection.export_evidence("team/ops +&", 3, to_sequence=7)

    assert requests == [
        (
            "GET",
            f"/scopes/team%2Fops%20%2B%26/evidence/export?contract_generation={CONTRACT_GENERATION}"
            "&from_sequence=3",
        ),
        (
            "GET",
            f"/scopes/team%2Fops%20%2B%26/evidence/export?contract_generation={CONTRACT_GENERATION}"
            "&from_sequence=3&to_sequence=7",
        ),
    ]
    for result in (unbounded, bounded):
        assert isinstance(result, Answered)
        assert result.value == document
        assert result.contract_generation == CONTRACT_GENERATION


@pytest.mark.parametrize("operation", ["read_evidence", "export_evidence"])
@pytest.mark.parametrize(
    ("document", "rendered"),
    [
        ({"contract_version": "99"}, "'99'"),
        # The version as an integer, which is a different answer from the
        # string the contract declares. `rendered` is the whole point of this
        # row: asserting the bare digit would pass on the quoted form too,
        # since the expected version is the same single character.
        ({"contract_version": CONTRACT_GENERATION}, "1"),
        ({}, "None"),
    ],
)
def test_evidence_reads_require_a_matching_string_version(
    tmp_path: Path, operation: str, document: object, rendered: str
) -> None:
    with _connected(tmp_path, 200, document) as (connection, _):
        result = getattr(connection, operation)("local", 1)

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED
    assert result.problem.retryable is False
    assert result.problem.contract_generation == CONTRACT_GENERATION
    assert f"expected {str(CONTRACT_GENERATION)!r}" in result.problem.message
    assert f"contract version {rendered}," in result.problem.message


@pytest.mark.parametrize("operation", ["read_evidence", "export_evidence"])
def test_evidence_reads_classify_service_unavailable_problems(
    tmp_path: Path, operation: str
) -> None:
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "code": "evidence_store_unavailable",
        "message": "the evidence store is unavailable",
        "retryable": True,
    }
    with _connected(tmp_path, 503, document) as (connection, _):
        result = getattr(connection, operation)("local", 1)

    # An evidence authority that could not be read answered nothing about the
    # range asked for, so the registry classes it « could not ask » and this
    # client reads it as the transport does (article 1).
    assert type(result) is CouldNotAsk
    assert result.problem.code is ProblemCode.EVIDENCE_STORE_UNAVAILABLE
    assert result.problem.message == "the evidence store is unavailable"
    assert result.problem.retryable is True


@pytest.mark.parametrize("operation", ["read_evidence", "export_evidence"])
@pytest.mark.parametrize("generation", [CONTRACT_GENERATION, 99])
def test_evidence_reads_check_problem_generation_before_classification(
    tmp_path: Path, operation: str, generation: int
) -> None:
    document = {
        "contract_generation": generation,
        "code": "peer_not_admitted",
        "message": "no",
        "retryable": False,
    }
    with _connected(tmp_path, 403, document) as (connection, _):
        result = getattr(connection, operation)("local", 1)

    if generation == CONTRACT_GENERATION:
        assert type(result) is Refused
        assert result.problem.code is ProblemCode.PEER_NOT_ADMITTED
    else:
        assert type(result) is CouldNotAsk
        assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED


@pytest.mark.parametrize("operation", ["read_evidence", "export_evidence"])
def test_evidence_reads_report_a_non_object_as_unreadable(tmp_path: Path, operation: str) -> None:
    with _connected(tmp_path, 200, []) as (connection, _):
        result = getattr(connection, operation)("local", 1)

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE


def test_the_stub_serves_evidence_at_the_published_binding_target(tmp_path: Path) -> None:
    with serve(Stub("allow"), tmp_path / "stub.sock") as socket_path:
        client = SocketClient(socket_path=socket_path, expected_uid=os.geteuid(), timeout=5.0)
        result = client.read_evidence("local", 1)

    assert isinstance(result, Answered), result
    assert result.contract_generation == CONTRACT_GENERATION
    assert result.value["contract_version"] == str(CONTRACT_GENERATION)
    assert result.value["scope"] == "local"
    assert result.value["from_sequence"] == 1
    assert result.value["entries"] == []


def test_a_reply_nested_beyond_the_parser_is_unreadable_and_never_a_recursion_error(
    tmp_path: Path,
) -> None:
    """A hostile peer's 40 000-deep reply is an answer this client cannot read.

    Whether the standard library's parser refuses that depth is the
    interpreter's business — one raises `RecursionError` where another parses
    the same bytes — and this client answers the published unreadable problem
    either way, rather than letting a `RecursionError` reach its caller.
    """
    deeply_nested = b"[" * 40000 + b"]" * 40000
    with _connected(tmp_path, 200, None, raw_body=deeply_nested) as (connection, _):
        result = connection.read_decision("local", "decision-1")

    assert type(result) is CouldNotAsk, result
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE, result.problem


def _ask() -> DecisionAsk:
    return DecisionAsk(capability="example.effect", scope="local")


def test_a_lost_reply_to_a_write_does_not_claim_asking_again_is_safe(tmp_path: Path) -> None:
    """The far end read the ask and hung up. It may have taken and recorded the decision.

    The same rule the transport is held to, on the other client of this
    contract: one request on the wire, an outcome reported as unknown with the
    code the registry publishes for a control plane that could not be reached,
    and no claim that asking again is safe. `retryable` has a third value for
    exactly that, and an unknown is never read as the more permissive of the
    two (articles 1, 2 and 3).

    Non-repetition is what the far end saw, not what a flag says: the fake
    records every request it received, and it received one.
    """
    with _connected(tmp_path, 200, {}, drop_posts=True) as (client, asked):
        result = client.ask_decision(_ask())

    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.UNREACHABLE
    assert result.problem.retryable is None
    assert [method for method, _ in asked] == ["POST"]


def test_a_lost_reply_to_a_held_write_does_not_claim_asking_again_is_safe(
    tmp_path: Path,
) -> None:
    """`hold_decision` writes the same ask on a connection it means to keep.

    It has its own request and its own clauses, so the rule is held on it
    separately: a decision it never read the answer to may still have been
    taken, and there is no channel to hand back.
    """
    with _connected(tmp_path, 200, {}, drop_posts=True) as (client, asked):
        result, channel = client.hold_decision(_ask())

    assert channel is None
    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.UNREACHABLE
    assert result.problem.retryable is None
    assert [method for method, _ in asked] == ["POST"]


def test_a_lost_reply_to_a_read_still_takes_the_registrys_retryability(tmp_path: Path) -> None:
    """The other half of the rule: a read whose reply was lost decided nothing.

    Without this case the condition that weakens a lost write could quietly
    weaken every lost request, and the guard above would still pass.
    """
    with _connected(tmp_path, 200, {}, drop_gets=True) as (client, asked):
        result = client.read_policy_status()

    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.UNREACHABLE
    assert result.problem.retryable is problem_retryable(ProblemCode.UNREACHABLE)
    assert [method for method, _ in asked] == ["GET"]
