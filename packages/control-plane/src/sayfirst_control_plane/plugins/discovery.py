# SPDX-License-Identifier: Apache-2.0
"""Entry-point discovery that deliberately does not load provider code."""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from sayfirst_contract.plugins import CONTENT_DIGEST_UNKNOWN, discover_plugin_entry_points
from sayfirst_contract.plugins import (
    PluginEntryPointMetadata as PluginEntryPoint,
)


@dataclass(frozen=True)
class DiscoveredProvider:
    name: str
    target: str
    _entry_point: PluginEntryPoint = field(repr=False, compare=False)
    distribution: str
    distribution_version: str

    def load(self) -> object:
        """Load provider metadata only after configuration selected this provider."""
        return self._entry_point.load()

    def content_digest(self) -> str:
        """Hash the loaded target module, declaring the digest unknown when it cannot."""
        module_name, separator, _ = self.target.partition(":")
        module = sys.modules.get(module_name) if separator else None
        module_path = getattr(module, "__file__", None)
        if not isinstance(module_path, str):
            return CONTENT_DIGEST_UNKNOWN
        try:
            content = Path(module_path).read_bytes()
        except OSError:
            return CONTENT_DIGEST_UNKNOWN
        return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _distribution_identity(entry_point: PluginEntryPoint) -> tuple[str, str]:
    distribution = getattr(entry_point, "dist", None)
    if distribution is None:
        return ("unknown", "unknown")
    name = distribution.metadata.get("Name")
    version = distribution.version
    return (
        name if isinstance(name, str) and name else "unknown",
        version if isinstance(version, str) and version else "unknown",
    )


def discover_plugins(
    entry_points: Iterable[PluginEntryPoint] | None = None,
) -> tuple[DiscoveredProvider, ...]:
    """Read entry-point metadata without importing or instantiating provider code."""
    candidates = discover_plugin_entry_points(entry_points)
    discovered = []
    for entry_point in candidates:
        distribution, distribution_version = _distribution_identity(entry_point)
        discovered.append(
            DiscoveredProvider(
                entry_point.name,
                entry_point.value,
                entry_point,
                distribution,
                distribution_version,
            )
        )
    return tuple(discovered)
