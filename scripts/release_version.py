# SPDX-License-Identifier: Apache-2.0
"""The one reader of « the version this tree would release ».

Every distribution of this repository carries the same semantic version and they
move together (article 16). Three callers need to know it — the changelog guard,
the release workflow, and whoever is about to cut a tag — and a version spelled
three times is a version that will eventually be spelled two ways. So it is read
here, from the project files themselves.

What is never written down a second time is the DECLARATION: the seven project
files declare the version, this reader is how anything else asks what they say,
and a fourth place that decides it would be a second source of truth. A version
that appears in the changelog, in a row of `docs/NEUTRALITY.md` or in the
record of a dry run is the version RECORDED — a statement about a release that
happened, which stays true after the next bump and must not move with it. Those
occurrences are correct where they are; what this file keeps out is a second
place that answers « what would this tree release ».

The release workflow runs this through uv's own interpreter, never the runner's
system `python`, so that the version this reads is read by the toolchain the
gate itself installs:

    uv run --frozen --all-packages python scripts/release_version.py
    uv run --frozen --all-packages python scripts/release_version.py --expect 0.2.0

The second form is what the release workflow runs against the tag it was
started by, so a tag that names a version this tree does not carry publishes
nothing. The script needs no dependency beyond the standard library's TOML
reader, so it runs the same way under `uv run` as it does under a bare
interpreter — nothing here is resolved from an index.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def distribution_versions(repository: Path) -> dict[str, str]:
    """Every distribution this repository builds, and the version it carries.

    Found by walking `packages/`, never by a list here: a package added next
    month joins this reading without anyone remembering to add it, which is the
    rule `tests/test_package_discovery.py` states for the test run and this
    file applies to the release.
    """
    found: dict[str, str] = {}
    for package in sorted((repository / "packages").iterdir()):
        project_file = package / "pyproject.toml"
        if not project_file.is_file():
            continue
        project = tomllib.loads(project_file.read_text(encoding="utf-8"))["project"]
        found[project["name"]] = project["version"]
    return found


def release_version(repository: Path) -> str:
    """The one version every distribution carries.

    Raises `ValueError` naming the distributions that disagree. A repository
    that cannot answer this question has no release to make, and saying so is
    the point: the alternative is a tag that publishes six distributions at one
    version and a seventh at another.
    """
    versions = distribution_versions(repository)
    if not versions:
        raise ValueError(f"no distribution found under {repository / 'packages'}")
    distinct = sorted(set(versions.values()))
    if len(distinct) != 1:
        disagreeing = ", ".join(f"{name} {version}" for name, version in sorted(versions.items()))
        raise ValueError(f"the distributions carry more than one version: {disagreeing}")
    return distinct[0]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", default=None, help="fail unless this is the version")
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    arguments = parser.parse_args(argv)
    try:
        version = release_version(arguments.repository)
    except ValueError as problem:
        print(f"release_version: {problem}", file=sys.stderr)
        return 1
    if arguments.expect is not None and arguments.expect != version:
        print(
            f"release_version: the tag names {arguments.expect} and the distributions "
            f"carry {version}; nothing is published",
            file=sys.stderr,
        )
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
