# SPDX-License-Identifier: Apache-2.0
"""Three distinct client results and the domain operation protocol."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from .problems import Problem


@dataclass(frozen=True)
class Answered[T]:
    value: T
    contract_generation: int

    @property
    def is_ok(self) -> bool:
        return True


@dataclass(frozen=True)
class Refused:
    problem: Problem

    @property
    def is_ok(self) -> bool:
        return False


@dataclass(frozen=True)
class CouldNotAsk:
    problem: Problem
    reported_outcome: Literal["unknown"] = "unknown"

    @property
    def is_ok(self) -> bool:
        return False


type Result[T] = Answered[T] | Refused | CouldNotAsk


class ControlPlaneClient(Protocol):
    def read_status(self) -> Result[Status]: ...

    def read_whoami(self) -> Result[WhoAmI]: ...

    def ask_decision(self, ask: DecisionAsk) -> Result[Decision]: ...

    def read_decision(self, scope: str, decision_ref: str) -> Result[Decision]: ...

    def read_policy_status(self) -> Result[PolicyStatus]: ...

    def read_approval(self, scope: str, approval_ref: str) -> Result[Approval]: ...

    def resolve_approval(self, resolution: ApprovalResolution) -> Result[Approval]: ...

    def read_evidence(
        self, scope: str, from_sequence: int, page_size: int = 100
    ) -> Result[Mapping[str, object]]: ...

    def export_evidence(
        self, scope: str, from_sequence: int, to_sequence: int | None = None
    ) -> Result[Mapping[str, object]]: ...


from .approvals import Approval, ApprovalResolution  # noqa: E402
from .decisions import Decision, DecisionAsk  # noqa: E402
from .policy import PolicyStatus  # noqa: E402
from .status import Status  # noqa: E402
from .whoami import WhoAmI  # noqa: E402
