# SPDX-License-Identifier: Apache-2.0
"""Article 15: every wheel this repository publishes reproduces the notices.

A rule of the repository, not of one package: it holds over whatever the
repository ships, so it enumerates the packages that exist rather than naming
them, for the reason `tests/test_package_discovery.py` gives. It is narrower
than `tests/test_installed_wheel.py`, which verifies what one distribution's
artefacts do once installed; this one only asks that no redistribution leaves
here without the licence and the notice it travels under. One rule per file, so
a new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def _packages(root: Path) -> list[Path]:
    """Every package that exists, found the way the test run finds it."""
    return sorted(item for item in root.glob("packages/*") if (item / "pyproject.toml").is_file())


def test_every_shipped_wheel_reproduces_the_repository_notices(tmp_path: Path) -> None:
    """Article 15: every redistribution carries the licence and the notice."""
    packages = _packages(REPOSITORY)
    # Anti-vacuity floor: an enumeration that found no package proves nothing.
    assert packages, "no package exists; the guard would hold vacuously"
    wheelhouse = tmp_path / "wheels"
    for package in packages:
        _run("uv", "build", str(package), "--wheel", "--out-dir", str(wheelhouse))
    wheels = sorted(wheelhouse.glob("*.whl"))
    assert len(wheels) == len(packages), wheels
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            members = set(archive.namelist())
            licence = next(
                (name for name in members if name.endswith(".dist-info/licenses/LICENSE")), None
            )
            notice = next(
                (name for name in members if name.endswith(".dist-info/licenses/NOTICE")), None
            )
            assert licence is not None, wheel.name
            assert notice is not None, wheel.name
            assert archive.read(licence) == (REPOSITORY / "LICENSE").read_bytes(), wheel.name
            assert archive.read(notice) == (REPOSITORY / "NOTICE").read_bytes(), wheel.name
