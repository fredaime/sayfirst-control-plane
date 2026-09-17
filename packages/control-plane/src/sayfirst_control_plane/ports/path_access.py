# SPDX-License-Identifier: Apache-2.0
"""Operating-system facts used to grade access to a store path."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class PathFacts:
    path: Path
    exists: bool
    owner_uid: int | None
    owner_gid: int | None
    mode: int | None
    acl_present: bool | None


class PathAccess(Protocol):
    def inspect(self, path: Path) -> PathFacts: ...
