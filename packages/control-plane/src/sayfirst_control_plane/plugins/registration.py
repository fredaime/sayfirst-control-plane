# SPDX-License-Identifier: Apache-2.0
"""Provider metadata loaded only after configuration activates an entry point."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class PluginRegistration:
    provider_name: str
    interface_name: str
    interface_version: int
    factory: Callable[[], object]
