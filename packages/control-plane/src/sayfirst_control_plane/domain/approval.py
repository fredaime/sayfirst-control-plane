# SPDX-License-Identifier: Apache-2.0
"""The one-person approval this core holds, and the state a reader reads.

Article 12: the simple form of an approval is one person approving or rejecting
one suspended effect, and the three outcomes of article 1 stay closed — nothing
here is a fourth answer, only the state of a suspension that has not yet
become one. Article 3 puts the authority for that state here: the record owns
its invariants, so a state it could not have reached — approved by nobody,
consumed without an approval, resolved while still pending — is refused at
construction instead of rendered to a reader.

Two instants and one clock, which is why `state_at` exists. The wait is bounded
by a `deadline` its caller computed; a sweep ends the ones that ran out, and a
sweep runs when it runs. A read must not depend on it having run, so a read
renders the state AS OF the instant it is taken (article 2: what is rendered is
what is held, and « nobody has swept yet » is not permission to wait longer).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class ApprovalState(StrEnum):
    """The states the published `approval-result` spells, spelled the same.

    The contract carries an `unknown` a client reads for a state this
    generation does not name (article 2). It is not here: this is the
    authority, and an authority that does not know its own record's state has
    no record.
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


#: The states no later act can change: the wait is over, one way or another.
TERMINAL: frozenset[ApprovalState] = frozenset(
    {ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.EXPIRED}
)

#: The states a person's act produced, and which therefore carry that person.
ACTED: frozenset[ApprovalState] = frozenset({ApprovalState.APPROVED, ApprovalState.REJECTED})


@dataclass(frozen=True)
class Question:
    """The thing an approval answers: the same question asked again finds the same approval.

    Every member is part of the question, so every member must be there: a
    question with an empty member is a question that matches whatever it is
    compared against, and a match is what lets one person's act authorise an
    execution (article 3 — a decision is pinned to what the policy names).
    """

    scope: str
    principal_reference: str
    capability: str
    arguments_digest: str

    def __post_init__(self) -> None:
        for member in ("scope", "principal_reference", "capability", "arguments_digest"):
            value = getattr(self, member)
            if not isinstance(value, str) or not value:
                raise ValueError(f"an approval question needs a non-empty {member}")


@dataclass(frozen=True)
class Approval:
    """One suspended effect, the question it suspends, and how its wait ended."""

    approval_ref: str
    decision_ref: str
    question: Question
    requested_at: datetime
    deadline: datetime
    state: ApprovalState = ApprovalState.PENDING
    resolved_at: datetime | None = None
    person: str | None = None
    resolution_reason: str | None = None
    consumed: bool = False
    #: Taken by one ask, before the decision that spends it is recorded. The
    #: claim is what makes « one resolution authorises one execution » hold
    #: between two asks running at once: a claimed approval answers no other
    #: question, and the ask that claimed it either spends it or gives it back.
    claimed: bool = False

    def __post_init__(self) -> None:
        for member in ("requested_at", "deadline"):
            instant = getattr(self, member)
            if instant.tzinfo is None or instant.utcoffset() is None:
                raise ValueError(f"an approval's {member} must be offset-aware")
        if self.deadline <= self.requested_at:
            raise ValueError("an approval's deadline must follow its requested_at")
        self._hold_the_end_of_the_wait()
        self._hold_the_one_person()
        if self.state is ApprovalState.PENDING and self.resolution_reason is not None:
            raise ValueError("a pending approval carries no resolution_reason: there is no verdict")
        if self.state is ApprovalState.EXPIRED and self.resolution_reason is not None:
            raise ValueError("an expired approval carries no resolution_reason: nobody gave one")
        if self.consumed and self.state is not ApprovalState.APPROVED:
            raise ValueError(
                f"a {self.state.value} approval cannot be consumed: it authorises nothing"
            )
        if self.claimed and self.state is not ApprovalState.APPROVED:
            raise ValueError(
                f"a {self.state.value} approval cannot be claimed: it authorises nothing"
            )
        if self.consumed and not self.claimed:
            raise ValueError(
                "a consumed approval was claimed first: the one execution is taken before "
                "it is spent, so a record that was spent and never claimed is one no ask made"
            )

    def _hold_the_end_of_the_wait(self) -> None:
        """`resolved_at` is inside the wait it ended, and for a lapse it *is* the deadline.

        The bounds are not decoration. An act recorded after the deadline is an
        act that could not have happened — the store ends a wait that ran out
        before it will hear one (article 2) — and a lapse that does not name the
        deadline names an instant nothing decided.
        """
        resolved_at = self.resolved_at
        if self.state is ApprovalState.PENDING:
            if resolved_at is not None:
                raise ValueError("a pending approval carries no resolved_at: nothing ended it")
            return
        if resolved_at is None:
            raise ValueError(
                f"a {self.state.value} approval must carry the resolved_at it ended at"
            )
        if resolved_at.tzinfo is None or resolved_at.utcoffset() is None:
            raise ValueError("an approval's resolved_at must be offset-aware")
        if resolved_at < self.requested_at:
            raise ValueError(
                "an approval's resolved_at cannot precede its requested_at: "
                "nothing ends a wait before it is opened"
            )
        if self.state is ApprovalState.EXPIRED and resolved_at != self.deadline:
            raise ValueError(
                "an expired approval's resolved_at is its deadline: "
                "a wait that ran out ended when it ran out"
            )
        if self.state in ACTED and resolved_at > self.deadline:
            raise ValueError(
                f"a {self.state.value} approval's resolved_at cannot follow its deadline: "
                "the wait had already run out, so no person could act"
            )

    def _hold_the_one_person(self) -> None:
        """Article 12: exactly one person behind an act, and nobody at all behind a lapse."""
        person = self.person
        if self.state in ACTED:
            if not isinstance(person, str) or not person:
                raise ValueError(
                    f"a {self.state.value} approval must carry the person who acted, "
                    "as a non-empty reference"
                )
            return
        if person is None:
            return
        if self.state is ApprovalState.PENDING:
            raise ValueError("a pending approval carries no person: nobody has acted yet")
        # An expired approval is one nobody acted on; naming a person on it —
        # an empty string included — would attribute an act that never
        # happened (article 2).
        raise ValueError(f"a {self.state.value} approval carries no person: nobody acted")

    @property
    def scope(self) -> str:
        return self.question.scope

    @property
    def capability(self) -> str:
        return self.question.capability

    def state_at(self, now: datetime) -> ApprovalState:
        """PENDING past the deadline reads as EXPIRED; every other state is what it is.

        The bound is inclusive — at the deadline the wait is over — because the
        deadline is the last instant a person could have acted, not the first
        one after it.
        """
        if self.state is ApprovalState.PENDING and now >= self.deadline:
            return ApprovalState.EXPIRED
        return self.state

    def to_document(self, now: datetime, contract_generation: int) -> dict[str, object]:
        """Exactly the members of the published `approval-result`, and no other.

        The state is the one `state_at` renders, so a reader is never told
        `pending` about a wait that has run out. When that is the only reason
        the state is `expired`, the instant it expired at is the deadline — a
        fact this record holds — so it is rendered rather than left null;
        article 2 forbids rendering an absence where a fact is held. The person
        is the same rule on the other side: an act carries one, so the document
        names it, and a wait nobody acted on carries none, so the member is not
        there at all. Whether the document satisfies its schema is the
        contract's question and is asserted in the tests, not here.
        """
        if contract_generation < 1:
            raise ValueError("contract generation must be positive")
        state = self.state_at(now)
        resolved_at = self.resolved_at
        if resolved_at is None and state is ApprovalState.EXPIRED:
            resolved_at = self.deadline
        document: dict[str, object] = {
            "contract_generation": contract_generation,
            "authority": "authoritative",
            "approval_ref": self.approval_ref,
            "decision_ref": self.decision_ref,
            "scope": self.scope,
            "capability": self.capability,
            "state": state.value,
            "requested_at": _instant(self.requested_at),
            "deadline": _instant(self.deadline),
            "resolved_at": None if resolved_at is None else _instant(resolved_at),
            "resolution_reason": self.resolution_reason,
        }
        if state in ACTED and self.person is not None:
            # Additive within generation 1 (article 13): a reader that does not
            # know it keeps it, and it is ABSENT rather than null where nobody
            # acted, because null would be a person this record does not have.
            document["person"] = self.person
        return document


def _instant(value: datetime) -> str:
    """The one text this contract records an instant in, offset and all."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
