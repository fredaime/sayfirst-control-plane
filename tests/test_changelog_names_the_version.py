# SPDX-License-Identifier: Apache-2.0
"""Article 16: every release carries a changelog, so a release without one is red.

A rule of the repository, not of one package: the version is a fact about every
distribution here at once, and the changelog is one file for all of them. One
rule per file, so a new rule arrives as a new file and a new file never
conflicts (`CONTRIBUTING.md`, article 16).

The guard reads the FIRST heading that is a version. `## Unreleased` sits above
them and is skipped on purpose: ordinary development appends to it, and a guard
that demanded a release heading at the top would be red on every working branch
and would teach people to ignore it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
CHANGELOG = REPOSITORY / "CHANGELOG.md"

sys.path.insert(0, str(REPOSITORY / "scripts"))

from release_version import (  # noqa: E402
    distribution_versions,
    release_version,
)

#: A release section's heading: two hashes, a semantic version, nothing else
#: required after it. The shipped reader finds a section the same way
#: (`sayfirst_contract.plugins.unannounced_plugin_deprecations`), so this guard
#: and the deprecation window agree about what a release section is.
RELEASE_HEADING = re.compile(r"^## (\d+\.\d+\.\d+)\b", re.MULTILINE)


def top_release(changelog: str) -> str | None:
    """The version of the newest release section, or None when there is none."""
    found = RELEASE_HEADING.search(changelog)
    return found.group(1) if found else None


def test_every_distribution_here_carries_the_same_version() -> None:
    """Article 16: they move together or the release is not one release."""
    versions = distribution_versions(REPOSITORY)
    assert len(versions) == 7, versions
    assert len(set(versions.values())) == 1, versions


def test_the_changelog_names_the_version_this_tree_would_release() -> None:
    """Article 16: a release with no entry is red before it is tagged."""
    assert top_release(CHANGELOG.read_text(encoding="utf-8")) == release_version(REPOSITORY)


def test_an_unreleased_section_above_the_release_is_not_mistaken_for_one() -> None:
    """WATCHED NOT FIRING. Development appends to `## Unreleased`; a guard that
    read the first heading of any kind would be red on every working branch."""
    assert (
        top_release("# Changelog\n\n## Unreleased\n\n- a change\n\n## 0.2.0\n\n- shipped\n")
        == "0.2.0"
    )


def test_a_changelog_with_no_entry_for_the_version_is_caught() -> None:
    """WATCHED FIRING. A rule whose only evidence is that it passes today would
    also pass if it had stopped applying."""
    assert top_release("# Changelog\n\n## Unreleased\n\n- a change\n") is None
    assert top_release("# Changelog\n\n## 0.1.0\n\n- shipped\n") != release_version(REPOSITORY)


def test_a_repository_whose_distributions_disagree_is_refused(tmp_path: Path) -> None:
    """WATCHED FIRING on the other half: the versions moving apart is the defect
    the release rule exists to catch, and it is silent in every other guard."""
    for name, version in (("alpha", "0.2.0"), ("beta", "0.3.0")):
        package = tmp_path / "packages" / name
        package.mkdir(parents=True)
        (package / "pyproject.toml").write_text(
            f'[project]\nname = "sayfirst-{name}"\nversion = "{version}"\n', encoding="utf-8"
        )
    with pytest.raises(ValueError, match="sayfirst-beta"):
        release_version(tmp_path)
