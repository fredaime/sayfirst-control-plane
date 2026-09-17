# SPDX-License-Identifier: Apache-2.0
"""Wheel-only build facts and repository notices."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Embed the build date and reproduce repository notices in the wheel."""

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
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        build_date = (
            datetime.fromtimestamp(int(epoch), UTC).date() if epoch is not None else date.today()
        )
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="sayfirst-build-", suffix=".py", delete=False, encoding="utf-8"
        ) as descriptor:
            descriptor.write(
                f'# SPDX-License-Identifier: Apache-2.0\nBUILD_DATE = "{build_date.isoformat()}"\n'
            )
            self._descriptor = Path(descriptor.name)
        build_data["force_include"][str(self._descriptor)] = "sayfirst_contract/_build_info.py"

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        self._descriptor.unlink(missing_ok=True)
