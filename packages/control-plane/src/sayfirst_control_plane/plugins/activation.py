# SPDX-License-Identifier: Apache-2.0
"""Configuration-driven activation of discovered plugin providers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sayfirst_contract.plugins import (
    SUPPORTED_PLUGIN_INTERFACE_VERSIONS,
    accepts_plugin_interface_version,
)

from .configuration import PluginConfiguration
from .discovery import DiscoveredProvider
from .errors import (
    AmbiguousPluginProvider,
    InvalidPluginProvider,
    MissingPluginProvider,
    UnknownPluginInterface,
    UnknownPluginInterfaceVersion,
    UnknownPluginProvider,
)
from .interfaces import (
    APPROVAL_PROVIDER_INTERFACE,
    APPROVAL_PROVIDER_VERSION,
    PRIVACY_REDACTOR_INTERFACE,
    PRIVACY_REDACTOR_VERSION,
    ApprovalProvider,
    PrivacyRedactor,
)
from .registration import PluginRegistration

SUPPORTED_INTERFACES = {
    PRIVACY_REDACTOR_INTERFACE: (PRIVACY_REDACTOR_VERSION, PrivacyRedactor),
    APPROVAL_PROVIDER_INTERFACE: (APPROVAL_PROVIDER_VERSION, ApprovalProvider),
}
SupportedVersions = Mapping[str, tuple[int, ...]]


def _supported(supported_versions: SupportedVersions | None) -> SupportedVersions:
    """The integer versions this bootstrap accepts today, per interface.

    Article 8: the current version plus every deprecated version whose window
    is still open. The window itself is the contract distribution's rule, and so
    is the acceptance test applied to it.
    """
    return SUPPORTED_PLUGIN_INTERFACE_VERSIONS if supported_versions is None else supported_versions


@dataclass(frozen=True)
class ActivatedProvider:
    registration: PluginRegistration
    instance: object
    distribution: str
    distribution_version: str
    entry_point: str
    content_digest: str


def supported_protocol(
    registration: PluginRegistration, *, supported_versions: SupportedVersions | None = None
) -> type:
    """The protocol a registration must satisfy, refusing an unknown interface or version."""
    if registration.interface_name not in SUPPORTED_INTERFACES:
        raise UnknownPluginInterface(
            f"provider registered unknown interface {registration.interface_name!r}"
        )
    _, protocol = SUPPORTED_INTERFACES[registration.interface_name]
    if not accepts_plugin_interface_version(
        registration.interface_name,
        registration.interface_version,
        supported=_supported(supported_versions),
    ):
        raise UnknownPluginInterfaceVersion(
            f"provider {registration.provider_name!r} uses unsupported interface version "
            f"{registration.interface_version!r}"
        )
    return protocol


def _validate_configuration(
    configuration: PluginConfiguration, supported_versions: SupportedVersions | None
) -> None:
    configured = set(configuration.providers)
    supported = set(SUPPORTED_INTERFACES)
    unknown = configured - supported
    if unknown:
        raise UnknownPluginInterface(f"unknown plugin interface {sorted(unknown)[0]!r}")
    missing = supported - configured
    if missing:
        raise MissingPluginProvider(f"no provider configured for {sorted(missing)[0]!r}")
    for interface_name, selection in configuration.providers.items():
        version = selection.interface_version
        if not accepts_plugin_interface_version(
            interface_name, version, supported=_supported(supported_versions)
        ):
            raise UnknownPluginInterfaceVersion(
                f"unsupported {interface_name} interface version {version!r}"
            )


def activate_plugins(
    discovered: tuple[DiscoveredProvider, ...],
    configuration: PluginConfiguration,
    *,
    supported_versions: SupportedVersions | None = None,
) -> tuple[ActivatedProvider, ...]:
    """Load and instantiate exactly the provider named for each configured port."""
    _validate_configuration(configuration, supported_versions)
    activated: list[ActivatedProvider] = []
    for interface_name, selection in configuration.providers.items():
        candidates = [item for item in discovered if item.name == selection.provider]
        if not candidates:
            raise UnknownPluginProvider(
                f"provider {selection.provider!r} for {interface_name} was not discovered"
            )
        if len(candidates) != 1:
            raise AmbiguousPluginProvider(
                f"provider name {selection.provider!r} has more than one entry point"
            )
        loaded = candidates[0].load()
        if not isinstance(loaded, PluginRegistration):
            raise InvalidPluginProvider(
                f"entry point {selection.provider!r} did not load a PluginRegistration"
            )
        if loaded.provider_name != selection.provider:
            raise InvalidPluginProvider("entry point and registration provider names differ")
        if loaded.interface_name not in SUPPORTED_INTERFACES:
            raise UnknownPluginInterface(
                f"provider registered unknown interface {loaded.interface_name!r}"
            )
        if loaded.interface_name != interface_name:
            raise InvalidPluginProvider(
                f"provider {selection.provider!r} registered for {loaded.interface_name}, "
                f"not {interface_name}"
            )
        protocol = supported_protocol(loaded, supported_versions=supported_versions)
        if loaded.interface_version != selection.interface_version:
            raise UnknownPluginInterfaceVersion(
                f"provider {selection.provider!r} uses unsupported interface version "
                f"{loaded.interface_version!r}"
            )
        instance = loaded.factory()
        if not isinstance(instance, protocol):
            raise InvalidPluginProvider(
                f"provider {selection.provider!r} does not implement {interface_name} "
                f"v{loaded.interface_version}"
            )
        activated.append(
            ActivatedProvider(
                loaded,
                instance,
                candidates[0].distribution,
                candidates[0].distribution_version,
                candidates[0].target,
                candidates[0].content_digest(),
            )
        )
    return tuple(activated)
