# SPDX-License-Identifier: Apache-2.0
"""Article 13: the generation byte check runs from a plain checkout.

A rule of the repository, not of one package: a contributor who has only
cloned this repository can run the check that holds the published bytes, with
no unpublished environment setup. One rule per file, so a new rule arrives as a
new file and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def test_the_generation_check_runs_from_a_plain_checkout() -> None:
    """Article 13: the byte check needs no unpublished environment setup."""
    _run("uv", "run", "python", str(CONTRACT / "scripts" / "build_contract.py"), "--check")
