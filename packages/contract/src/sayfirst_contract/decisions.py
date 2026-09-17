# SPDX-License-Identifier: Apache-2.0
"""Decision request and authoritative answer values."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from .problems import Problem, ProblemCode
from .values import Unknown, read_enum


class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    SUSPEND = "suspend"


class Reason(StrEnum):
    POLICY_ALLOWS = "policy_allows"
    POLICY_DENIES = "policy_denies"
    POLICY_ABSENT = "policy_absent"
    POLICY_REQUIRES_REVIEW = "policy_requires_review"
    CAPABILITY_UNKNOWN = "capability_unknown"
    # What a re-ask of a suspended question answers once one person has acted.
    # Two reasons, not two outcomes: the three outcomes of article 1 stay
    # closed, and a reader of an older generation reads an unknown reason as
    # `Unknown` rather than refusing the answer, which is what makes these
    # additive.
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"


@dataclass(frozen=True)
class DecisionAsk:
    capability: str
    scope: str = "local"
    arguments_digest: str | None = None
    correlation: str | None = None

    def to_document(self, contract_generation: int) -> dict[str, object]:
        if contract_generation < 1:
            raise ValueError("contract generation must be positive")
        document: dict[str, object] = {
            "contract_generation": contract_generation,
            "capability": self.capability,
            "scope": self.scope,
        }
        if self.arguments_digest is not None:
            document["arguments_digest"] = self.arguments_digest
        if self.correlation is not None:
            document["correlation"] = self.correlation
        return document


@dataclass(frozen=True)
class Decision:
    decision_ref: str
    scope: str
    capability: str
    outcome: Outcome
    reason: Reason | Unknown
    policy_version: str | None
    approval_ref: str | None
    decided_at: str
    correlation: str | None
    contract_generation: int
    extra: Mapping[str, object]

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Self:
        outcome = read_enum(Outcome, document["outcome"])
        if isinstance(outcome, Unknown):
            raise ValueError(f"unknown outcome {outcome.raw!r}")
        defined = {
            "contract_generation",
            "authority",
            "decision_ref",
            "scope",
            "capability",
            "outcome",
            "reason",
            "policy_version",
            "approval_ref",
            "decided_at",
            "correlation",
        }
        return cls(
            decision_ref=str(document["decision_ref"]),
            scope=str(document["scope"]),
            capability=str(document["capability"]),
            outcome=outcome,
            reason=read_enum(Reason, document["reason"]),
            policy_version=document["policy_version"]
            if isinstance(document["policy_version"], str)
            else None,
            # Optional on both documents that carry a decision: `decision-result`
            # lists it without requiring it, and `decision-record` — what a read
            # back gives — does not list it at all, and the daemon drops it before
            # rendering one. A reader that required it could read no record.
            approval_ref=document["approval_ref"]
            if isinstance(document.get("approval_ref"), str)
            else None,
            decided_at=str(document["decided_at"]),
            correlation=document["correlation"]
            if isinstance(document["correlation"], str)
            else None,
            contract_generation=int(document["contract_generation"]),
            extra={key: value for key, value in document.items() if key not in defined},
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_generation": self.contract_generation,
            "authority": "authoritative",
            "decision_ref": self.decision_ref,
            "scope": self.scope,
            "capability": self.capability,
            "outcome": self.outcome.value,
            "reason": self.reason.value if isinstance(self.reason, Reason) else self.reason.raw,
            "policy_version": self.policy_version,
            "approval_ref": self.approval_ref,
            "decided_at": self.decided_at,
            "correlation": self.correlation,
            **self.extra,
        }


def read_decision(document: Mapping[str, object]):  # type: ignore[no-untyped-def]
    """Read an answer, stopping safely when its outcome is not defined here."""
    from .client import Answered, CouldNotAsk

    outcome = read_enum(Outcome, document.get("outcome"))
    if isinstance(outcome, Unknown):
        generation = document.get("contract_generation")
        return CouldNotAsk(
            Problem(
                code=ProblemCode.OUTCOME_UNKNOWN,
                message=f"unknown decision outcome {outcome.raw!r}",
                retryable=False,
                contract_generation=generation if isinstance(generation, int) else None,
            )
        )
    value = Decision.from_document(document)
    return Answered(value, value.contract_generation)
