# SPDX-License-Identifier: Apache-2.0
"""An atomically replaced in-memory policy projection."""

from __future__ import annotations

from threading import RLock

from ...ports.policy_projection import ProjectedPolicy
from ...ports.policy_store import LoadedPolicy


class MemoryPolicyProjection:
    VERSION = 1
    KIND = "memory"

    def __init__(self) -> None:
        self._lock = RLock()
        self._current: ProjectedPolicy | None = None

    def rebuild(self, loaded: LoadedPolicy) -> None:
        projected = ProjectedPolicy(
            loaded.policy_version,
            loaded.policy.format,
            loaded.loaded_at,
            len(loaded.policy.rules),
            loaded.policy.rules,
        )
        with self._lock:
            self._current = projected

    def current(self) -> ProjectedPolicy | None:
        with self._lock:
            return self._current

    def clear(self) -> None:
        with self._lock:
            self._current = None
