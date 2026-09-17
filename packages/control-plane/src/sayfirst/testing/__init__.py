# SPDX-License-Identifier: Apache-2.0
"""Reusable conformance suites for plugin providers."""

from .adversaries import (
    ADVERSARIAL_APPROVAL_PROVIDERS,
    ADVERSARIAL_COMPLETION_FIXTURES,
    AdversarialApprovalProvider,
    AdversarialCompletionFixture,
)
from .approval import (
    ApprovalCompletionActions,
    ApprovalProviderContract,
    unsupported_by_acts,
)
from .privacy import PrivacyRedactorContract

__all__ = [
    "ADVERSARIAL_APPROVAL_PROVIDERS",
    "ADVERSARIAL_COMPLETION_FIXTURES",
    "AdversarialApprovalProvider",
    "AdversarialCompletionFixture",
    "ApprovalCompletionActions",
    "ApprovalProviderContract",
    "PrivacyRedactorContract",
    "unsupported_by_acts",
]
