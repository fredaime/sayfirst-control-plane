# SPDX-License-Identifier: Apache-2.0
"""Article 15: a redistribution nobody can build carries no notice at all.

A rule of the repository, not of one package. `uv build` makes the wheel from
the source distribution, so the licence and the notice have to travel in the
source distribution too — a build hook reaching two directories up finds
nothing once the tree is unpacked. One rule per file, so a new rule arrives as
a new file and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import subprocess
import tarfile
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def _packages(root: Path) -> list[Path]:
    """Every package that exists, found the way the test run finds it."""
    return sorted(item for item in root.glob("packages/*") if (item / "pyproject.toml").is_file())


def test_every_source_distribution_builds_a_wheel_that_carries_the_notices(
    tmp_path: Path,
) -> None:
    """Article 15: the notices survive the round trip through the source distribution."""
    packages = _packages(REPOSITORY)
    # Anti-vacuity floor: an enumeration that found no package proves nothing.
    assert packages, "no package exists; the guard would hold vacuously"
    output = tmp_path / "dist"
    _run("uv", "build", "--all-packages", "--out-dir", str(output))
    wheels = sorted(output.glob("*.whl"))
    sdists = sorted(output.glob("*.tar.gz"))
    assert len(wheels) == len(packages), wheels
    assert len(sdists) == len(packages), sdists
    for archive_path in sdists:
        with tarfile.open(archive_path) as archive:
            members = {Path(name).name for name in archive.getnames()}
            assert "LICENSE" in members, archive_path.name
            assert "NOTICE" in members, archive_path.name
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            for notice in ("LICENSE", "NOTICE"):
                member = next((name for name in names if name.endswith(f"licenses/{notice}")), None)
                assert member is not None, f"{wheel.name} carries no {notice}"
                assert archive.read(member) == (REPOSITORY / notice).read_bytes(), (
                    f"{wheel.name}: {notice}"
                )
