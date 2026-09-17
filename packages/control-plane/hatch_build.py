# SPDX-License-Identifier: Apache-2.0
"""Reproduce repository notices in the wheel."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Include the repository licence and notice as wheel metadata."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # In the workspace the notices live at the repository root and have to
        # be carried in by hand. In an unpacked source distribution they
        # travel beside the package, where the backend's own licence globs
        # already find them, so carrying them again would add the same file
        # twice.
        root = Path(self.root)
        if not (root / "LICENSE").is_file():
            metadata_directory = (
                f"{self.metadata.core.name.replace('-', '_')}-{self.metadata.version}.dist-info"
            )
            repository = root.parents[1]
            build_data["force_include"].update(
                {
                    str(repository / "LICENSE"): f"{metadata_directory}/licenses/LICENSE",
                    str(repository / "NOTICE"): f"{metadata_directory}/licenses/NOTICE",
                }
            )
