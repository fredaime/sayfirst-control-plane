# SPDX-License-Identifier: Apache-2.0
"""The two integer-versioned plugin interfaces shipped by the skeleton."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from sayfirst_contract.plugins import (
    APPROVAL_PROVIDER_INTERFACE as APPROVAL_PROVIDER_INTERFACE,
)
from sayfirst_contract.plugins import (
    APPROVAL_PROVIDER_VERSION as APPROVAL_PROVIDER_VERSION,
)
from sayfirst_contract.plugins import (
    PRIVACY_REDACTOR_INTERFACE as PRIVACY_REDACTOR_INTERFACE,
)
from sayfirst_contract.plugins import (
    PRIVACY_REDACTOR_VERSION as PRIVACY_REDACTOR_VERSION,
)


@dataclass(frozen=True)
class Redaction:
    """What a provider answers for one bounded capture.

    `status` is one of `applied` (the content differs from what was read),
    `not_applicable` (nothing to apply, the content as given) or `failed`;
    `provider` is the provider's own name, as the status surface renders it.
    """

    content: bytes
    status: str
    provider: str


@runtime_checkable
class PrivacyRedactor(Protocol):
    """PrivacyRedactor plugin interface, version 1: a bounded capture in, a redaction out.

    Article 11: the provider sees only the captured payload, already bounded by
    the capture rule; the identity of the effect — capability, scope,
    principal, decision, timing — is never handed to it. `interface_version`
    is the integer version the provider was built for (article 8) and `name`
    the one name the composition evidence, the status surface and every
    capture record carry for it (article 2). The conformance kit is published
    as `sayfirst.testing.PrivacyRedactorContract` and
    `sayfirst_control_plane.testing.PrivacyRedactorContract`, one rule under
    two entrances.
    """

    interface_version: int
    name: str

    def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction:
        """Answer a redaction of exactly this content, and a status that says what happened."""
        ...


class ApprovalResolution(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


@dataclass(frozen=True)
class ApprovalRequest:
    """One suspended effect and the bounded wait generation one publishes for it."""

    approval_ref: str
    decision_ref: str
    scope: str
    capability: str
    requested_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        for name in ("requested_at", "deadline"):
            instant = getattr(self, name)
            if instant.tzinfo is None or instant.utcoffset() is None:
                raise ValueError(f"approval {name} must be offset-aware")
        if self.deadline <= self.requested_at:
            raise ValueError("approval deadline must follow the request")


@dataclass(frozen=True)
class ApprovalAction:
    approval_ref: str
    scope: str
    person: str
    resolution: ApprovalResolution
    reason: str | None = None


@dataclass(frozen=True)
class SuspendedApproval:
    request: ApprovalRequest
    scope: str

    def __post_init__(self) -> None:
        if self.scope != self.request.scope:
            raise ValueError("suspension scope must match its request")

    @property
    def approval_ref(self) -> str:
        return self.request.approval_ref


@dataclass(frozen=True)
class ResolvedApproval:
    approval_ref: str
    decision_ref: str
    scope: str
    person: str
    resolution: ApprovalResolution
    reason: str | None = None


class ApprovalProviderError(RuntimeError):
    """Base class for a provider refusing an invalid approval operation."""


class ApprovalRequestMismatch(ApprovalProviderError):
    """An action or provider result names a different suspended request."""


class ApprovalAlreadyExists(ApprovalProviderError):
    """A suspension already exists for this approval reference."""


class ApprovalAlreadyResolved(ApprovalProviderError):
    """A person attempted to act on a terminal approval."""


@runtime_checkable
class ApprovalProvider(Protocol):
    """ApprovalProvider plugin interface, version 1."""

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        """Open a suspended approval for exactly this decision request."""
        ...

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        """Apply one person's approve or reject act to this request."""
        ...
