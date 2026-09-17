# SPDX-License-Identifier: Apache-2.0
"""Article 15: every authored file declares the permissive licence it travels under.

A rule of the repository, not of one package. It enumerates the directories the
project authors in and the packages that exist, rather than naming packages,
for the reason `tests/test_package_discovery.py` gives: a list of packages
inside a repository-scope guard is a list every new package has to edit, and a
list every block edits is a conflict every pair of blocks has. Source and
documentation alike are in scope — the packages, the deployment and design
documents, the workflow that runs the guards, and the files at the root. One
rule per file, so a new rule arrives as a new file and a new file never
conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import json
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]

#: Everything the project authors, wherever it lives.
AUTHORED_ROOTS = ("packages", "docs", "tests", "scripts", ".github")

#: The suffixes whose format carries a comment line this repository can sign.
AUTHORED_SUFFIXES = ("*.py", "*.md", "*.toml", "*.yml", "*.yaml", "*.cfg", "*.sh")

#: The licence text and the NOTICE are excepted by article 15 itself, being
#: notices rather than works.
NOT_A_WORK = {"LICENSE", "NOTICE"}


def _packages(root: Path) -> list[Path]:
    """Every package that exists, found the way the test run finds it."""
    return sorted(item for item in root.glob("packages/*") if item.is_dir())


def _authored_files() -> list[Path]:
    found = []
    for root in AUTHORED_ROOTS:
        directory = REPOSITORY / root
        if not directory.is_dir():
            continue
        for pattern in AUTHORED_SUFFIXES:
            found.extend(
                item
                for item in directory.rglob(pattern)
                if item.is_file() and item.name not in NOT_A_WORK
            )
    found.extend(
        item
        for pattern in AUTHORED_SUFFIXES
        for item in REPOSITORY.glob(pattern)
        if item.is_file() and item.name not in NOT_A_WORK
    )
    return sorted(set(found))


def test_every_authored_file_carries_an_spdx_identifier() -> None:
    """Article 15: every authored file declares its permissive licence."""
    packages = _packages(REPOSITORY)
    # Anti-vacuity floor: an enumeration that found no package proves nothing.
    assert packages, "no package exists; the guard would hold vacuously"
    files = _authored_files()
    names = {item.name for item in files}
    assert "deployment.md" in names, "the documentation tree is outside the guard"
    assert "ci.yml" in names, "the workflow is outside the guard"
    assert "CHANGELOG.md" in names, "the changelog is outside the guard"
    assert any(item.suffix == ".md" and "specs" in item.parts for item in files)
    # Every JSON a package authors, not only the published contract artefacts:
    # a fixture is authored too, and article 15 does not exempt it.
    json_files = sorted(item for root in packages for item in root.rglob("*.json"))
    assert len(files) + len(json_files) >= 60
    for source in files:
        first_lines = "\n".join(source.read_text(encoding="utf-8").splitlines()[:3])
        assert "SPDX-License-Identifier: Apache-2.0" in first_lines, source
    for source in json_files:
        assert json.loads(source.read_text(encoding="utf-8"))["x-spdx-license-identifier"] in {
            "Apache-2.0",
            "Apache-2.0 OR MIT-0",
        }
