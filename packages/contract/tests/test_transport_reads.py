# SPDX-License-Identifier: Apache-2.0
"""The declared reads use the verified transport over a real AF_UNIX socket."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

import pytest
from canned_daemon import answering
from sayfirst_contract.approvals import Approval, ApprovalResolution, ApprovalState, Resolution
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.decisions import Decision
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_contract.golden import schema_examples
from sayfirst_contract.policy import PolicyStatus
from sayfirst_contract.problems import ProblemCode, problem_class, problem_retryable
from sayfirst_contract.transport.socket_client import (
    APPROVALS_TARGET,
    RESOLUTION_SUFFIX,
    SocketClientProblem,
    SocketProfile,
    VerifiedConnection,
    connect,
)
from sayfirst_contract.values import Unknown
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms

pytestmark = requires_platforms(*OS_REAL_PLATFORMS)


@contextmanager
def _connected(
    tmp_path: Path,
    status: int,
    document: object,
    *,
    closing_after_each: bool = False,
    drop_posts: bool = False,
    raw_body: bytes | None = None,
    record_bodies: list[bytes] | None = None,
) -> Iterator[tuple[VerifiedConnection, list[tuple[str, str]]]]:
    address = tmp_path / "daemon.sock"
    profile = SocketProfile(str(address), mode="system", daemon_user="daemon")
    with (
        answering(
            address,
            status,
            document,
            close_after_each=closing_after_each,
            drop_posts=drop_posts,
            raw_body=raw_body,
            record_bodies=record_bodies,
        ) as requests,
        closing(connect(profile, account_uid=lambda _: os.geteuid())) as connection,
    ):
        yield connection, requests


def test_read_decision_quotes_the_target_and_returns_the_decision(tmp_path: Path) -> None:
    document = {
        **schema_examples()["decision-record"],
        "contract_generation": CONTRACT_GENERATION,
        "decision_ref": "decision/1 ?#",
        "scope": "team/ops +&",
        # The existing decision reader requires this decision-result member.
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


def test_read_decision_classifies_a_missing_record_as_the_registry_says(tmp_path: Path) -> None:
    """The daemon answers 404 `decision_not_found`; the registry classes it a refusal.

    The daemon was asked and it answered: it holds no decision with that
    reference in that scope. That is a verdict on the question, not an absent
    answer, so the class column names it a refusal and this transport reads it
    as the binding's own client always did (article 1).
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


def test_read_decision_never_reads_an_unknown_code_as_a_refusal(tmp_path: Path) -> None:
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "code": "decision_unknown",
        "message": "the decision is unknown",
        "retryable": False,
    }
    with _connected(tmp_path, 404, document) as (connection, _):
        result = connection.read_decision("local", "missing")

    assert type(result) is CouldNotAsk
    assert result.problem.code == Unknown("decision_unknown")
    assert result.problem.message == "the decision is unknown"
    assert result.problem.retryable is False


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


@pytest.mark.parametrize(
    "operation", ["read_decision", "read_policy_status", "read_approval", "resolve_approval"]
)
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
        result = _invoke(connection, operation)

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
    assert f"contract version {str(CONTRACT_GENERATION)!r} " in result.problem.message
    assert f"answer carries {rendered}" in result.problem.message


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


def test_two_document_reads_share_one_connection_when_the_far_end_keeps_it(
    tmp_path: Path,
) -> None:
    """The daemon keeps a connection after a document answer, and this reads twice on it.

    Every answer an adapter wrote used to end its connection, so a caller that
    read a decision and then its policy status paid a connect and a
    re-verification for the second — and rule C4 forbids a client re-opening
    silently, so the cost was visible in every caller. Held against a canned
    far end that does not close, which is what the daemon now is.
    """
    status = schema_examples()["policy-status"]
    with _connected(tmp_path, 200, status) as (connection, asked):
        assert isinstance(connection.read_policy_status(), Answered)
        # No `reconnect()`: the point of the case.
        assert isinstance(connection.read_policy_status(), Answered)
        assert connection.verified
    assert len(asked) == 2


def test_a_read_after_the_daemon_closed_the_connection_is_refused_until_the_caller_reconnects(
    tmp_path: Path,
) -> None:
    """Rule C4: a dropped keep-alive is never re-opened on a caller's behalf.

    What this transport owes does not depend on whether the far end keeps its
    connections: a far end that closes after an answer leaves the next read on
    the same object « could not ask », and it is the caller's own `reconnect()`
    — which verifies the far end again — that makes the read answerable.
    """
    status = schema_examples()["policy-status"]
    with _connected(tmp_path, 200, status, closing_after_each=True) as (connection, asked):
        assert isinstance(connection.read_policy_status(), Answered)
        with pytest.raises(SocketClientProblem) as refusal:
            connection.read_policy_status()
        assert refusal.value.problem.code is ProblemCode.UNREACHABLE
        connection.reconnect()
        assert isinstance(connection.read_policy_status(), Answered)
        assert connection.verified
    assert len(asked) == 2


def test_a_post_on_a_closed_keep_alive_is_refused_and_never_re_opened(tmp_path: Path) -> None:
    """The socket the daemon closed after its last answer is not re-dialled for a
    POST either (rule C4): the request fails before a byte is sent, as could-not-ask."""
    from sayfirst_contract.decisions import DecisionAsk

    status = schema_examples()["policy-status"]
    with _connected(tmp_path, 200, status, closing_after_each=True) as (connection, asked):
        assert isinstance(connection.read_policy_status(), Answered)
        with pytest.raises(SocketClientProblem) as refusal:
            connection.ask_decision(DecisionAsk(capability="example.effect", scope="local"))
    assert refusal.value.problem.code is ProblemCode.UNREACHABLE
    assert len(asked) == 1


def test_a_post_the_daemon_received_and_dropped_is_put_once_and_reported_unknown(
    tmp_path: Path,
) -> None:
    """The far end read the question and hung up without answering. It may have
    recorded a decision.

    The transport puts the request exactly once and reports the code the
    registry publishes for a control plane it could not reach — and says
    nothing at all about asking again, because the decision may have been taken
    and recorded before the reply was lost. `retryable` has a third value for
    exactly that, and an unknown is never read as the more permissive of the two
    (article 3). What this transport owns, and what is pinned here, is that it
    does not take the decision itself: one request on the wire, and an outcome
    reported as unknown (articles 1 and 2). The binding client answers the same
    input with the same code and the same flag, held by
    `test_a_lost_reply_to_a_write_does_not_claim_asking_again_is_safe` and
    `test_a_lost_reply_to_a_held_write_does_not_claim_asking_again_is_safe` in
    `test_binding_reads.py` rather than claimed here.
    """
    from sayfirst_contract.decisions import DecisionAsk

    with (
        _connected(tmp_path, 200, {}, drop_posts=True) as (connection, asked),
        pytest.raises(SocketClientProblem) as refusal,
    ):
        connection.ask_decision(DecisionAsk(capability="example.effect", scope="local"))
    assert refusal.value.problem.code is ProblemCode.UNREACHABLE
    assert refusal.value.problem.retryable is None
    assert refusal.value.classification == "could_not_ask"
    assert asked == [("POST", "/decisions")]


#: The four reads this transport declares, plus the five operations that share
#: their classification of a non-200 — the guard below belongs to all nine. The
#: two approval operations joined the list with the code that added them: a
#: front guard shared by nine callers and proven for seven is a guard nobody
#: knows the shape of (articles 2 and 9).
FOUR_READS = ("read_decision", "read_policy_status", "read_evidence", "export_evidence")
NINE_OPERATIONS = (
    "read_status",
    "read_whoami",
    "ask_decision",
    "read_approval",
    "resolve_approval",
    *FOUR_READS,
)


def _invoke(connection: VerifiedConnection, operation: str) -> object:
    """Call one operation with arguments it accepts, so a row can name any of them."""
    from sayfirst_contract.decisions import DecisionAsk

    if operation in {"read_status", "read_whoami", "read_policy_status"}:
        return getattr(connection, operation)()
    if operation == "ask_decision":
        return connection.ask_decision(DecisionAsk(capability="example.effect", scope="local"))
    if operation == "read_decision":
        return connection.read_decision("local", "decision-1")
    if operation == "read_approval":
        return connection.read_approval("local", "approval-1")
    if operation == "resolve_approval":
        return connection.resolve_approval(
            ApprovalResolution("local", "approval-1", Resolution.APPROVE)
        )
    return getattr(connection, operation)("local", 1)


@pytest.mark.parametrize("operation", NINE_OPERATIONS)
@pytest.mark.parametrize(
    ("status", "document"),
    [
        (200, []),
        (200, "x"),
        (200, 5),
        (200, None),
        (404, []),
        (404, "x"),
        (404, 5),
        (404, None),
        (404, {"contract_generation": CONTRACT_GENERATION}),
        (503, ["evidence_store_unavailable"]),
    ],
)
def test_a_reply_that_is_no_document_of_this_generation_is_unreadable_and_never_raises(
    tmp_path: Path, operation: str, status: int, document: object
) -> None:
    """A body that is JSON but not a problem document is an unknown, not a traceback.

    The far end answered something; nothing in it can be read as this
    generation's record or as this generation's problem — a `code` a problem
    document is required to carry included. So the answer is « could not ask »
    with the published problem, carrying the status it arrived with, and never
    an exception the caller has to classify for itself (articles 1 and 2).
    """
    with _connected(tmp_path, status, document) as (connection, _):
        result = _invoke(connection, operation)

    assert type(result) is CouldNotAsk, result
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE, result.problem
    assert result.reported_outcome == "unknown"
    if status != 200:
        assert str(status) in result.problem.message, result.problem.message


#: Deeper than any parser here accepts by recursion, and still valid JSON.
DEEPLY_NESTED = b"[" * 40000 + b"]" * 40000


def test_a_reply_nested_beyond_the_parser_is_unreadable_and_never_a_recursion_error(
    tmp_path: Path,
) -> None:
    """A hostile peer's 40 000-deep reply is an answer this client cannot read.

    Whether the standard library's parser refuses that depth is the
    interpreter's business — one raises `RecursionError` where another parses
    the same bytes — so what is held here is the part this client owns: the
    caller is told « the answer is unreadable » by name either way, and no
    `RecursionError` reaches it to classify for itself (articles 1 and 2).
    """
    with _connected(tmp_path, 200, None, raw_body=DEEPLY_NESTED) as (connection, _):
        try:
            result = connection.read_decision("local", "decision-1")
        except SocketClientProblem as refused:
            assert refused.problem.code is ProblemCode.ANSWER_UNREADABLE, refused.problem
            assert refused.classification == "could_not_ask"
        else:
            assert type(result) is CouldNotAsk, result
            assert result.problem.code is ProblemCode.ANSWER_UNREADABLE, result.problem


def test_the_transports_own_problems_carry_the_registrys_retryability(tmp_path: Path) -> None:
    """Article 13: this client's rendering of a code never differs from the daemon's.

    Every problem this transport builds itself reads `retryable` from the
    registry that publishes the code, so a registry change reaches both sides
    at once. A flag written in by hand here is the drift the module's own
    `_problem` exists to prevent, and it drifts silently — hence a row per code.

    There is exactly one exception, and it is a row below rather than a silence:
    a request that asks for something to be DONE and whose reply was lost states
    no retryability at all. The registry publishes a column about a CODE; that
    occurrence carries an act the far end may already have taken, so what the
    column says cannot be true of it and the third value is what is honest
    (article 3). The read that was lost is a row too, immediately above it, so
    that the exception is proven to stay that narrow.
    """
    status = schema_examples()["policy-status"]

    with _connected(tmp_path, 200, []) as (connection, _):
        unreadable = connection.read_decision("local", "decision-1")
    with _connected(tmp_path, 200, {"contract_version": "99"}) as (connection, _):
        version = connection.read_evidence("local", 1)
    with _connected(tmp_path, 200, {**status, "contract_generation": 99}) as (connection, _):
        echoed = connection.read_policy_status()
    with _connected(tmp_path, 200, status, closing_after_each=True) as (connection, _):
        assert isinstance(connection.read_policy_status(), Answered)
        with pytest.raises(SocketClientProblem) as dropped:
            connection.read_policy_status()

    for result, code in (
        (unreadable, ProblemCode.ANSWER_UNREADABLE),
        (version, ProblemCode.GENERATION_UNSUPPORTED),
        (echoed, ProblemCode.GENERATION_UNSUPPORTED),
    ):
        assert isinstance(result, CouldNotAsk), result
        assert result.problem.code is code, result.problem
        assert result.problem.retryable is problem_retryable(code), result.problem
    assert dropped.value.problem.code is ProblemCode.UNREACHABLE
    assert dropped.value.problem.retryable is problem_retryable(ProblemCode.UNREACHABLE)

    # The one exception the docstring names, held here so that the rule this
    # guard publishes is the rule the module follows.
    from sayfirst_contract.decisions import DecisionAsk

    with (
        _connected(tmp_path, 200, {}, drop_posts=True) as (connection, _),
        pytest.raises(SocketClientProblem) as lost_write,
    ):
        connection.ask_decision(DecisionAsk(capability="example.effect", scope="local"))
    assert lost_write.value.problem.code is ProblemCode.UNREACHABLE
    assert lost_write.value.problem.retryable is None
    assert lost_write.value.problem.retryable is not problem_retryable(ProblemCode.UNREACHABLE)


# -- the two approval operations -----------------------------------------------
#
# A person reads where a wait stands and then ends it. Both go through the front
# guard the four reads go through, which is why the rows above already name them;
# what is held below is the part that is each operation's own — the address it
# builds, the document it PUTS, and the once-ness of the act.


def _pending_document(**changes: object) -> dict[str, object]:
    """The published `approval-result`, of this generation, with the named changes."""
    document = {**schema_examples()["approval-result"], "contract_generation": CONTRACT_GENERATION}
    document.update(changes)
    return document


def test_the_transports_approval_targets_are_the_published_paths() -> None:
    """Article 13: one binding document, so the daemon and the fake agree on the address.

    The binding's own client reads its method and path out of the shipped
    OpenAPI document at run time; this transport spells them, so the two could
    drift and a caller of one would reach an address the other does not serve.
    The document is the arbiter here as everywhere: it is read, the operation
    is found by its identifier, and the path template is compared with what
    this transport builds for the same reference.
    """
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    published = {
        operation["operationId"]: (method.upper(), path)
        for path, item in binding["paths"].items()
        for method, operation in item.items()
        if isinstance(operation, dict) and isinstance(operation.get("operationId"), str)
    }
    assert published["read_approval"] == ("GET", f"{APPROVALS_TARGET}/{{approval_ref}}")
    assert published["resolve_approval"] == (
        "POST",
        f"{APPROVALS_TARGET}/{{approval_ref}}{RESOLUTION_SUFFIX}",
    )


def test_read_approval_quotes_the_target_and_returns_the_pending_wait(tmp_path: Path) -> None:
    """The address carries the reference and the scope; the answer is the record."""
    document = _pending_document(approval_ref="approval/1 ?#", scope="team/ops +&")
    with _connected(tmp_path, 200, document) as (connection, requests):
        result = connection.read_approval("team/ops +&", "approval/1 ?#")

    assert requests == [
        (
            "GET",
            f"/approvals/approval%2F1%20%3F%23?contract_generation={CONTRACT_GENERATION}"
            "&scope=team%2Fops+%2B%26",
        )
    ]
    assert isinstance(result, Answered), result
    assert isinstance(result.value, Approval)
    assert result.value.state is ApprovalState.PENDING
    assert result.value.approval_ref == "approval/1 ?#"
    assert result.value.resolved_at is None
    assert result.contract_generation == CONTRACT_GENERATION


def test_read_approval_reports_a_record_it_cannot_read_as_unreadable(tmp_path: Path) -> None:
    """A document without its state is not an approval: unreadable, never a verdict."""
    document = {key: value for key, value in _pending_document().items() if key != "state"}
    with _connected(tmp_path, 200, document) as (connection, _):
        result = connection.read_approval("local", "approval-1")

    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE
    assert "state" in result.problem.message


def test_resolve_approval_puts_the_act_once_and_answers_the_record_it_left(
    tmp_path: Path,
) -> None:
    """The act is one POST of the published request, and the answer is the approval."""
    document = _pending_document(
        state="approved",
        resolved_at="2026-09-04T00:00:30+00:00",
        resolution_reason="the walk approves",
    )
    bodies: list[bytes] = []
    with _connected(tmp_path, 200, document, record_bodies=bodies) as (connection, requests):
        result = connection.resolve_approval(
            ApprovalResolution("local", "approval-1", Resolution.APPROVE, "the walk approves")
        )

    assert requests == [("POST", "/approvals/approval-1/resolution")]
    # What was PUT is the published request document of this connection's
    # generation, and it names no person: who acted is what the boundary says.
    assert json.loads(bodies[0]) == {
        "contract_generation": CONTRACT_GENERATION,
        "scope": "local",
        "approval_ref": "approval-1",
        "resolution": "approve",
        "reason": "the walk approves",
    }
    assert isinstance(result, Answered), result
    assert result.value.state is ApprovalState.APPROVED
    assert result.value.resolution_reason == "the walk approves"
    assert result.contract_generation == CONTRACT_GENERATION


def test_resolve_approval_quotes_the_reference_in_the_address_it_posts_to(
    tmp_path: Path,
) -> None:
    """A reference with reserved characters addresses one approval, not a path of its own."""
    document = _pending_document(
        approval_ref="approval/1 ?#", state="rejected", resolved_at="2026-09-04T00:00:30+00:00"
    )
    with _connected(tmp_path, 200, document) as (connection, requests):
        result = connection.resolve_approval(
            ApprovalResolution("local", "approval/1 ?#", Resolution.REJECT)
        )

    assert requests == [("POST", "/approvals/approval%2F1%20%3F%23/resolution")]
    assert isinstance(result, Answered), result
    assert result.value.state is ApprovalState.REJECTED


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (409, ProblemCode.APPROVAL_RESOLVED),
        (404, ProblemCode.APPROVAL_UNKNOWN),
        (503, ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE),
    ],
)
def test_a_refused_act_is_classed_exactly_as_the_registry_classes_its_code(
    tmp_path: Path, status: int, code: ProblemCode
) -> None:
    """Article 1: the code is the answer, and one classifier says what kind of answer it is.

    All three codes the resolution route publishes for a refusal arrive here
    with the retryability the registry gives them. What kind of result each is
    is the registry's answer, asserted against the published class itself
    rather than written in by hand: a row that spelled « refused » or « could
    not ask » would be a second classifier, and this transport and the binding
    client read one column.
    """
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "code": code.value,
        "message": "the daemon looked and answered",
        "retryable": problem_retryable(code),
    }
    with _connected(tmp_path, status, document) as (connection, requests):
        result = connection.resolve_approval(
            ApprovalResolution("local", "approval-1", Resolution.APPROVE)
        )

    expected = Refused if problem_class(code) == "refused" else CouldNotAsk
    assert type(result) is expected, result
    assert result.problem.code is code
    assert result.problem.retryable is problem_retryable(code)
    assert len(requests) == 1, requests


def test_a_read_and_an_act_go_over_one_connection_without_reconnecting(tmp_path: Path) -> None:
    """The daemon leaves this connection open, so the person's two steps are two requests.

    The one behaviour that separates this pair from `read_decision` and
    `read_policy_status`: the daemon writes these answers through its own
    handler and does not hang up, so a person reads a wait and then ends it
    without the caller re-verifying an address in between. A far end that DOES
    close is the next case.
    """
    with _connected(tmp_path, 200, _pending_document()) as (connection, requests):
        assert isinstance(connection.read_approval("local", "approval-1"), Answered)
        assert isinstance(
            connection.resolve_approval(
                ApprovalResolution("local", "approval-1", Resolution.APPROVE)
            ),
            Answered,
        )
        assert connection.verified
    assert [method for method, _ in requests] == ["GET", "POST"]


def test_an_approval_operation_on_a_closed_keep_alive_needs_the_callers_reconnect(
    tmp_path: Path,
) -> None:
    """Rule C4: a dropped keep-alive is never re-opened on a caller's behalf.

    The same rule the closing reads are held to, on the pair the daemon does
    not close after: what this transport owes is the same either way, and it is
    the caller's `reconnect()` — which verifies the far end again — that makes
    the next request possible.
    """
    with _connected(tmp_path, 200, _pending_document(), closing_after_each=True) as (
        connection,
        asked,
    ):
        assert isinstance(connection.read_approval("local", "approval-1"), Answered)
        with pytest.raises(SocketClientProblem) as refusal:
            connection.resolve_approval(
                ApprovalResolution("local", "approval-1", Resolution.APPROVE)
            )
        assert refusal.value.problem.code is ProblemCode.UNREACHABLE
        connection.reconnect()
        assert isinstance(connection.read_approval("local", "approval-1"), Answered)
        assert connection.verified
    assert len(asked) == 2


def test_an_act_the_daemon_received_and_dropped_is_put_once_and_reported_unknown(
    tmp_path: Path,
) -> None:
    """The far end read the act and hung up without answering. It may have recorded it.

    The same rule `ask_decision` is held to, on the other POST this transport
    makes: one request on the wire, an outcome reported as unknown with the code
    the registry publishes for a control plane that could not be reached, and no
    claim that the act is safe to send again — the wait may already be over
    (articles 1, 2 and 3).
    """
    with (
        _connected(tmp_path, 200, {}, drop_posts=True) as (connection, asked),
        pytest.raises(SocketClientProblem) as refusal,
    ):
        connection.resolve_approval(ApprovalResolution("local", "approval-1", Resolution.APPROVE))

    assert refusal.value.problem.code is ProblemCode.UNREACHABLE
    assert refusal.value.problem.retryable is None
    assert refusal.value.classification == "could_not_ask"
    assert asked == [("POST", "/approvals/approval-1/resolution")]
