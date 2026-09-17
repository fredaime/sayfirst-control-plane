# SPDX-License-Identifier: Apache-2.0
"""Configuration is the sole authority that activates plugin providers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from sayfirst_contract.plugins import (
    APPROVAL_PROVIDER_INTERFACE,
    APPROVAL_PROVIDER_VERSION,
    PRIVACY_REDACTOR_INTERFACE,
    PRIVACY_REDACTOR_VERSION,
    ProviderSelection,
    parse_plugin_configuration,
    read_plugin_configuration,
)


@dataclass(frozen=True)
class PluginConfiguration:
    providers: Mapping[str, ProviderSelection]

    @classmethod
    def defaults(cls) -> PluginConfiguration:
        """The shipped configuration names both shipped open providers."""
        return cls(
            {
                PRIVACY_REDACTOR_INTERFACE: ProviderSelection("none", PRIVACY_REDACTOR_VERSION),
                APPROVAL_PROVIDER_INTERFACE: ProviderSelection(
                    "single-approver", APPROVAL_PROVIDER_VERSION
                ),
            }
        )

    @classmethod
    def from_mapping(cls, document: Mapping[str, object]) -> PluginConfiguration:
        return cls(parse_plugin_configuration(document))

    @classmethod
    def from_toml(cls, path: Path) -> PluginConfiguration:
        return cls(read_plugin_configuration(path))
