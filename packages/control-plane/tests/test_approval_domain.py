# SPDX-License-Identifier: Apache-2.0
"""The approval record: what it refuses to be, and what it renders.

Article 12's simple form is one person approving or rejecting one suspended
effect, so the record carries exactly one person and exactly one act. Article 3
puts the authority for that fact here: the record owns its own invariants, and a
state it could not have reached is refused at construction rather than rendered.
Article 2 is the other half — the document a reader is handed says what the
record holds as of the instant it is read, and an absence is an absence.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import ValidationError
from sayfirst_contract.artifacts import domain_schema
from sayfirst_control_plane.domain.approval import Approval, ApprovalState, Question
from sayfirst_testing.schemas import validate_document

REQUESTED_AT = datetime(2026, 9, 15, 12, tzinfo=UTC)
DEADLINE = REQUESTED_AT + timedelta(seconds=300)
DIGEST = "sha256:" + "a" * 64
GENERATION = 1


def _question() -> Question:
    return Question(
        scope="local",
        principal_reference="user:build",
        capability="mail.send",
        arguments_digest=DIGEST,
    )


def _pending() -> Approval:
    return Approval(
        approval_ref="approval-1",
        decision_ref="decision-1",
        question=_question(),
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


def _approved(person: str = "user:alice") -> Approval:
    return replace(
        _pending(),
        state=ApprovalState.APPROVED,
        resolved_at=REQUESTED_AT + timedelta(seconds=10),
        person=person,
        resolution_reason="the recipient is on the list",
    )


def _rejected(person: str = "user:alice") -> Approval:
    return replace(
        _pending(),
        state=ApprovalState.REJECTED,
        resolved_at=REQUESTED_AT + timedelta(seconds=10),
        person=person,
        resolution_reason=None,
    )


def _expired() -> Approval:
    return replace(_pending(), state=ApprovalState.EXPIRED, resolved_at=DEADLINE)


def _in_state(state: str) -> Approval:
    """The record in the state named, so a case can walk the states by name."""
    return {
        "pending": _pending,
        "approved": _approved,
        "rejected": _rejected,
        "expired": _expired,
    }[state]()


# -- what the reader is handed ------------------------------------------------


@pytest.mark.parametrize(
    "approval",
    [_pending(), _approved(), _rejected(), _expired()],
    ids=["pending", "approved", "rejected", "expired"],
)
def test_the_document_satisfies_the_published_schema_in_every_state(approval: Approval) -> None:
    """Article 13: the authority renders the contract it publishes, in each state it holds."""
    validate_document(approval.to_document(REQUESTED_AT, GENERATION), "approval-result")


def test_the_document_carries_exactly_the_members_the_schema_requires() -> None:
    """Article 13: the members are read out of the published schema, never listed twice."""
    required = domain_schema("approval-result")["required"]
    assert isinstance(required, list)
    assert set(_pending().to_document(REQUESTED_AT, GENERATION)) == set(required)


def test_a_pending_approval_renders_a_null_resolved_at_and_a_null_reason() -> None:
    """Article 2: nobody has acted, so the absence is rendered as an absence."""
    document = _pending().to_document(REQUESTED_AT, GENERATION)
    assert document["state"] == "pending"
    assert document["resolved_at"] is None
    assert document["resolution_reason"] is None
    validate_document(document, "approval-result")


def test_the_document_renders_instants_with_an_offset() -> None:
    """Article 13: `date-time` is an instant, so every one carries its offset."""
    document = _approved().to_document(REQUESTED_AT, GENERATION)
    assert document["requested_at"] == "2026-09-15T12:00:00Z"
    assert document["deadline"] == "2026-09-15T12:05:00Z"
    assert document["resolved_at"] == "2026-09-15T12:00:10Z"


def test_the_document_names_the_authority_and_the_generation_it_speaks() -> None:
    """Article 3: the record says it is the authority, never leaving a reader to assume it."""
    document = _pending().to_document(REQUESTED_AT, 2)
    assert document["authority"] == "authoritative"
    assert document["contract_generation"] == 2


def test_the_document_refuses_a_generation_no_contract_has() -> None:
    """Article 13: a generation below the first is not a generation."""
    with pytest.raises(ValueError, match="contract generation"):
        _pending().to_document(REQUESTED_AT, 0)


def test_the_document_renders_the_state_as_of_the_instant_it_is_read() -> None:
    """Article 2: a read after the deadline says `expired` without waiting for a sweep."""
    document = _pending().to_document(DEADLINE, GENERATION)
    assert document["state"] == "expired"
    validate_document(document, "approval-result")


def test_a_pending_approval_read_after_its_deadline_names_the_instant_it_expired() -> None:
    """Article 2: the instant is held — it is the deadline — so it is not rendered absent."""
    document = _pending().to_document(DEADLINE + timedelta(seconds=1), GENERATION)
    assert document["state"] == "expired"
    assert document["resolved_at"] == "2026-09-15T12:05:00Z"


# -- who acted ----------------------------------------------------------------


@pytest.mark.parametrize("approval", [_approved, _rejected], ids=["approved", "rejected"])
def test_a_resolution_renders_the_person_who_acted(approval) -> None:  # type: ignore[no-untyped-def]
    """Article 13 B.7: a resolution's person is readable, not only recorded.

    The domain has held `person` since the record was built and validated it —
    exactly one person behind an act, nobody behind a lapse — and `to_document`
    dropped it, so a reader of `read_approval` could see THAT somebody acted and
    never who. An approval is the one record in this core that exists because a
    person acted; naming nobody on it is an absence where a fact is held
    (article 2).
    """
    document = approval(person="user:1000").to_document(REQUESTED_AT, GENERATION)
    assert document["person"] == "user:1000"
    validate_document(document, "approval-result")


@pytest.mark.parametrize("state", ["pending", "expired"])
def test_a_wait_nobody_acted_on_names_no_person(state: str) -> None:
    """Absent, not null: nobody acted, so there is no person member to render."""
    document = _in_state(state).to_document(REQUESTED_AT, GENERATION)
    assert "person" not in document
    validate_document(document, "approval-result")


def test_the_published_schema_admits_the_person_and_holds_its_shape() -> None:
    """Article 13: the member is published, additive within this generation, and bounded."""
    schema = domain_schema("approval-result")
    assert "person" in schema["properties"]  # type: ignore[operator]
    assert "person" not in schema["required"], "additive within generation 1"  # type: ignore[operator]
    document = _approved(person="user:1000").to_document(REQUESTED_AT, GENERATION)
    validate_document(document, "approval-result")
    with pytest.raises(ValidationError):
        validate_document(dict(document, person=""), "approval-result")


# -- the state a reader reads -------------------------------------------------


def test_state_at_reads_pending_before_the_deadline() -> None:
    """The wait is bounded and has not run out."""
    assert _pending().state_at(DEADLINE - timedelta(seconds=1)) is ApprovalState.PENDING


def test_state_at_reads_expired_at_the_deadline_instant_itself() -> None:
    """The bound is inclusive: at the deadline the wait is over, not one second later."""
    assert _pending().state_at(DEADLINE) is ApprovalState.EXPIRED


def test_state_at_leaves_an_approved_approval_approved_after_the_deadline() -> None:
    """A person acted inside the wait, and a clock does not undo an act."""
    assert _approved().state_at(DEADLINE + timedelta(days=7)) is ApprovalState.APPROVED


def test_state_at_leaves_a_rejected_approval_rejected_after_the_deadline() -> None:
    """The same for the other verdict: « deny » is an answer, not a lapse."""
    assert _rejected().state_at(DEADLINE + timedelta(days=7)) is ApprovalState.REJECTED


def test_the_question_answers_for_the_scope_and_the_capability() -> None:
    """One spelling of each: the record reads them through the question it answers."""
    approval = _pending()
    assert approval.scope == "local"
    assert approval.capability == "mail.send"


# -- what the record refuses to be -------------------------------------------


@pytest.mark.parametrize(
    ("member", "changes"),
    [
        ("requested_at", {"requested_at": REQUESTED_AT.replace(tzinfo=None)}),
        ("deadline", {"deadline": DEADLINE.replace(tzinfo=None)}),
        ("deadline", {"deadline": REQUESTED_AT}),
        ("deadline", {"deadline": REQUESTED_AT - timedelta(seconds=1)}),
        (
            "resolved_at",
            {
                "state": ApprovalState.APPROVED,
                "person": "user:alice",
                "resolved_at": REQUESTED_AT.replace(tzinfo=None),
            },
        ),
        ("resolved_at", {"state": ApprovalState.APPROVED, "person": "user:alice"}),
        ("resolved_at", {"state": ApprovalState.REJECTED, "person": "user:alice"}),
        ("resolved_at", {"state": ApprovalState.EXPIRED}),
        ("resolved_at", {"resolved_at": REQUESTED_AT}),
        ("person", {"state": ApprovalState.APPROVED, "resolved_at": REQUESTED_AT}),
        ("person", {"state": ApprovalState.REJECTED, "resolved_at": REQUESTED_AT}),
        ("person", {"person": "user:alice"}),
        ("person", {"state": ApprovalState.EXPIRED, "resolved_at": DEADLINE, "person": "user:a"}),
        # Article 12 asks for one person, and an empty reference names none.
        ("person", {"state": ApprovalState.APPROVED, "resolved_at": REQUESTED_AT, "person": ""}),
        ("person", {"state": ApprovalState.REJECTED, "resolved_at": REQUESTED_AT, "person": ""}),
        ("person", {"state": ApprovalState.EXPIRED, "resolved_at": DEADLINE, "person": ""}),
        # An act outside the wait it ended could not have happened: the store
        # ends a wait that ran out before it will hear one.
        (
            "resolved_at",
            {
                "state": ApprovalState.APPROVED,
                "person": "user:alice",
                "resolved_at": DEADLINE + timedelta(seconds=1),
            },
        ),
        (
            "resolved_at",
            {
                "state": ApprovalState.REJECTED,
                "person": "user:alice",
                "resolved_at": DEADLINE + timedelta(days=1),
            },
        ),
        (
            "resolved_at",
            {
                "state": ApprovalState.APPROVED,
                "person": "user:alice",
                "resolved_at": REQUESTED_AT - timedelta(seconds=1),
            },
        ),
        # A lapse ended when the wait ran out, so it names that instant and no other.
        ("resolved_at", {"state": ApprovalState.EXPIRED, "resolved_at": REQUESTED_AT}),
        (
            "resolved_at",
            {"state": ApprovalState.EXPIRED, "resolved_at": DEADLINE + timedelta(seconds=1)},
        ),
        ("resolution_reason", {"resolution_reason": "a reason for nothing"}),
        ("consumed", {"consumed": True}),
        (
            "consumed",
            {
                "state": ApprovalState.REJECTED,
                "resolved_at": REQUESTED_AT,
                "person": "user:alice",
                "consumed": True,
            },
        ),
        (
            "consumed",
            {"state": ApprovalState.EXPIRED, "resolved_at": DEADLINE, "consumed": True},
        ),
    ],
)
def test_the_record_refuses_a_state_it_could_not_have_reached(
    member: str, changes: dict[str, object]
) -> None:
    """Article 3: the record owns its invariants, and the refusal names the member."""
    with pytest.raises(ValueError) as refused:
        replace(_pending(), **changes)
    assert member in str(refused.value), str(refused.value)


def test_an_act_at_the_last_instant_of_the_wait_is_a_record_this_core_holds() -> None:
    """The bound on an act is « not after the deadline », so the deadline itself is inside it.

    The store will not produce this record — it ends a wait at the deadline
    before it will hear an act (`resolve`'s bound is inclusive) — so the record
    is the more permissive of the two by exactly one instant, and says so here
    rather than leaving a reader to infer which bound is which.
    """
    acted = replace(
        _pending(),
        state=ApprovalState.APPROVED,
        resolved_at=DEADLINE,
        person="user:alice",
    )
    assert acted.state_at(DEADLINE + timedelta(days=7)) is ApprovalState.APPROVED
    validate_document(acted.to_document(DEADLINE, GENERATION), "approval-result")


@pytest.mark.parametrize(
    "member", ["scope", "principal_reference", "capability", "arguments_digest"]
)
def test_the_question_refuses_an_empty_member(member: str) -> None:
    """A question missing a member is a question that matches whatever it is asked."""
    with pytest.raises(ValueError) as refused:
        replace(_question(), **{member: ""})
    assert member in str(refused.value), str(refused.value)


def test_an_expired_approval_refuses_a_resolution_reason() -> None:
    """Nobody gave a reason for a lapse; rendering one would attribute a verdict."""
    from dataclasses import replace

    with pytest.raises(ValueError, match="expired approval carries no resolution_reason"):
        replace(_expired(), resolution_reason="took too long")
