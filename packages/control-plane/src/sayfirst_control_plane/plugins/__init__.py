# SPDX-License-Identifier: Apache-2.0
"""Versioned interfaces offered to explicitly activated providers."""

from .activation import ActivatedProvider, activate_plugins
from .approval import (
    ApprovalAnswerRefused,
    ApprovalResolutionRecorder,
    RefusedProviderAnswer,
    UnrecordedApprovalResolution,
    resume_through_provider,
    unsupported_by_acts,
)
from .composition import (
    ComposedProviderEvidence,
    CompositionEvidence,
    CompositionEvidenceSink,
    EvidencePrincipal,
    PluginComposition,
    bootstrap_plugins,
    bootstrap_plugins_from_toml,
    compose_plugins,
)
from .configuration import PluginConfiguration, ProviderSelection
from .defaults import SingleApprover
from .discovery import discover_plugins
from .errors import (
    AmbiguousPluginProvider,
    InvalidCompositionEvidence,
    InvalidPluginProvider,
    MissingPluginProvider,
    PluginCompositionError,
    UnknownPluginInterface,
    UnknownPluginInterfaceVersion,
    UnknownPluginProvider,
)
from .interfaces import (
    APPROVAL_PROVIDER_INTERFACE,
    APPROVAL_PROVIDER_VERSION,
    PRIVACY_REDACTOR_INTERFACE,
    PRIVACY_REDACTOR_VERSION,
    ApprovalAction,
    ApprovalAlreadyExists,
    ApprovalAlreadyResolved,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    PrivacyRedactor,
    Redaction,
    ResolvedApproval,
    SuspendedApproval,
)
from .privacy.none import NoRedaction
from .registration import PluginRegistration

__all__ = [
    "APPROVAL_PROVIDER_INTERFACE",
    "APPROVAL_PROVIDER_VERSION",
    "PRIVACY_REDACTOR_INTERFACE",
    "PRIVACY_REDACTOR_VERSION",
    "ActivatedProvider",
    "AmbiguousPluginProvider",
    "ApprovalAction",
    "ApprovalAlreadyExists",
    "ApprovalAlreadyResolved",
    "ApprovalAnswerRefused",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalRequestMismatch",
    "ApprovalResolution",
    "ApprovalResolutionRecorder",
    "ComposedProviderEvidence",
    "CompositionEvidence",
    "CompositionEvidenceSink",
    "EvidencePrincipal",
    "InvalidCompositionEvidence",
    "InvalidPluginProvider",
    "MissingPluginProvider",
    "NoRedaction",
    "PluginComposition",
    "PluginCompositionError",
    "PluginConfiguration",
    "PluginRegistration",
    "PrivacyRedactor",
    "ProviderSelection",
    "Redaction",
    "RefusedProviderAnswer",
    "ResolvedApproval",
    "SingleApprover",
    "SuspendedApproval",
    "UnknownPluginInterface",
    "UnknownPluginInterfaceVersion",
    "UnknownPluginProvider",
    "UnrecordedApprovalResolution",
    "activate_plugins",
    "bootstrap_plugins",
    "bootstrap_plugins_from_toml",
    "compose_plugins",
    "discover_plugins",
    "resume_through_provider",
    "unsupported_by_acts",
]
