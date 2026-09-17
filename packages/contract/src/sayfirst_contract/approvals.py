# SPDX-License-Identifier: Apache-2.0
"""One-person approval values and bounded waiting."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Self

from .values import Unknown, read_enum

if TYPE_CHECKING:
    from .client import ControlPlaneClient, Result


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class Resolution(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


@dataclass(frozen=True)
class ApprovalResolution:
    scope: str
    approval_ref: str
    resolution: Resolution
    reason: str | None = None

    def to_document(self, contract_generation: int) -> dict[str, object]:
        if contract_generation < 1:
            raise ValueError("contract generation must be positive")
        document: dict[str, object] = {
            "contract_generation": contract_generation,
            "scope": self.scope,
            "approval_ref": self.approval_ref,
            "resolution": self.resolution.value,
        }
        if self.reason is not None:
            document["reason"] = self.reason
        return document


@dataclass(frozen=True)
class Approval:
    approval_ref: str
    decision_ref: str
    scope: str
    capability: str
    state: ApprovalState | Unknown
    requested_at: str
    deadline: str
    resolved_at: str | None
    resolution_reason: str | None
    contract_generation: int
    extra: Mapping[str, object]
    #: Who acted, where a person did. Additive within generation 1 (article
    #: 13): a server that does not send it leaves this `None`, and a reader of
    #: this generation renders it only where it has one — absent rather than
    #: null on a wait nobody acted on, because null would be a person the
    #: record does not have (article 2). Last and defaulted rather than beside
    #: `resolution_reason`, which is where it belongs by meaning: the members
    #: before it are a positional signature a caller may already be writing,
    #: and inserting one in the middle of it would move every argument after it
    #: without a word from the reader.
    person: str | None = None

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Self:
        defined = {
            "contract_generation",
            "authority",
            "approval_ref",
            "decision_ref",
            "scope",
            "capability",
            "state",
            "requested_at",
            "deadline",
            "resolved_at",
            "resolution_reason",
            "person",
        }
        return cls(
            approval_ref=str(document["approval_ref"]),
            decision_ref=str(document["decision_ref"]),
            scope=str(document["scope"]),
            capability=str(document["capability"]),
            state=read_enum(ApprovalState, document["state"]),
            requested_at=str(document["requested_at"]),
            deadline=str(document["deadline"]),
            resolved_at=document["resolved_at"]
            if isinstance(document["resolved_at"], str)
            else None,
            resolution_reason=(
                document["resolution_reason"]
                if isinstance(document["resolution_reason"], str)
                else None
            ),
            contract_generation=int(document["contract_generation"]),
            extra={key: value for key, value in document.items() if key not in defined},
            person=document["person"] if isinstance(document.get("person"), str) else None,
        )

    def to_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "contract_generation": self.contract_generation,
            "authority": "authoritative",
            "approval_ref": self.approval_ref,
            "decision_ref": self.decision_ref,
            "scope": self.scope,
            "capability": self.capability,
            "state": self.state.value if isinstance(self.state, ApprovalState) else self.state.raw,
            "requested_at": self.requested_at,
            "deadline": self.deadline,
            "resolved_at": self.resolved_at,
            "resolution_reason": self.resolution_reason,
        }
        if self.person is not None:
            document["person"] = self.person
        document.update(self.extra)
        return document


def wait_until_resolved(
    client: ControlPlaneClient,
    scope: str,
    approval_ref: str,
    *,
    pause: Callable[[], None],
    max_polls: int,
) -> Result[Approval]:
    """Read until pending ends, without interpreting an unknown state as permission."""
    from .client import Answered

    if max_polls < 1:
        raise ValueError("max_polls must be positive")
    last: Result[Approval] | None = None
    for poll in range(max_polls):
        last = client.read_approval(scope, approval_ref)
        if not isinstance(last, Answered) or last.value.state is not ApprovalState.PENDING:
            return last
        if poll + 1 < max_polls:
            pause()
    assert last is not None
    return last
