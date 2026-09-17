# SPDX-License-Identifier: Apache-2.0
"""Article 8: system-mode documentation names both effective-access checks.

A rule of the repository, not of one package: an operator reads what protects
the configuration before installing anything, and a check the documentation
does not name is a check nobody relies on. One rule per file, so a new rule
arrives as a new file and a new file never conflicts (`CONTRIBUTING.md`,
article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_system_mode_configuration_protection_is_documented() -> None:
    """Article 8: system-mode documentation names both effective-access checks."""
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "root or its administrator group" in documentation
    assert "effective write access" in documentation
    assert "every parent directory" in documentation
    assert "governed program must run as another principal" in documentation
    assert "reports the selections in the supplied file" in documentation
    assert "omitting either interface is refused" in documentation
