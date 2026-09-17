# SPDX-License-Identifier: Apache-2.0
"""Articles 13 and 14: the contract wheel installs no third-party runtime.

A rule of the repository, not of one package: what an adopter has to install in
order to speak the contract is a published fact. One rule per file, so a new
rule arrives as a new file and a new file never conflicts (`CONTRIBUTING.md`,
article 16).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"


def test_the_contract_distribution_has_no_runtime_dependency() -> None:
    """Articles 13 and 14: the contract wheel installs no third-party runtime."""
    project = tomllib.loads((CONTRACT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == []
    assert project["optional-dependencies"] == {"stub": ["sayfirst-contract-stub==0.2.0"]}
