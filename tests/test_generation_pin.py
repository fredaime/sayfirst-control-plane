# SPDX-License-Identifier: Apache-2.0
"""Articles 8 and 13: the module pin uses the package build date and release.

A rule of the repository, not of one package: it holds what leaves here as a
published distribution. One rule per file, so a new rule arrives as a new file
and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, date, datetime
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"

sys.path.insert(0, str(REPOSITORY / "scripts"))

from release_version import release_version  # noqa: E402


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def _the_release_after(version: str) -> str:
    """The next minor release, so the scenario is one this tree has not reached."""
    major, minor, _ = (int(part) for part in version.split("."))
    return f"{major}.{minor + 1}.0"


def test_the_module_pin_uses_the_package_build_date_and_release(tmp_path: Path) -> None:
    """Articles 8 and 13: a newly deprecated generation cannot break package import.

    The version this tree carries is read through `scripts/release_version.py`,
    the one reader of it, and the next release is derived from that. Spelling
    either of them here is what would make the substitution below a silent
    no-op at the first bump, leaving this module green over a scenario it had
    stopped setting up — so the substitution is asserted to have changed the
    file it was made in.
    """
    version = release_version(REPOSITORY)
    next_release = _the_release_after(version)
    package = tmp_path / "packages" / "contract"
    shutil.copytree(CONTRACT, package)
    shutil.copy2(REPOSITORY / "LICENSE", tmp_path / "LICENSE")
    shutil.copy2(REPOSITORY / "NOTICE", tmp_path / "NOTICE")
    project_file = package / "pyproject.toml"
    declared = project_file.read_text(encoding="utf-8")
    bumped = declared.replace(f'version = "{version}"', f'version = "{next_release}"')
    assert bumped != declared, (
        "the project file of the contract distribution does not declare the version "
        f"{version!r} in the form this test substitutes: the scenario below would be "
        "the tree as it stands rather than the release after it"
    )
    project_file.write_text(bumped, encoding="utf-8")
    marker_file = (
        package / "src" / "sayfirst_contract" / "_contracts" / "domain" / "generation.json"
    )
    marker = json.loads(marker_file.read_text(encoding="utf-8"))
    marker["contract_generation"] = 2
    marker["deprecated_generations"] = [
        {
            "contract_generation": 1,
            "deprecated_since": date.today().isoformat(),
            "deprecated_in_release": next_release,
        }
    ]
    marker_file.write_text(json.dumps(marker), encoding="utf-8")

    wheelhouse = tmp_path / "wheels"
    _run("uv", "build", str(package), "--wheel", "--out-dir", str(wheelhouse))
    wheel = next(wheelhouse.glob(f"sayfirst_contract-{next_release}-*.whl"))
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    expected_build_date = (
        datetime.fromtimestamp(int(epoch), UTC).date() if epoch is not None else date.today()
    )
    with zipfile.ZipFile(wheel) as archive:
        build_info = archive.read("sayfirst_contract/_build_info.py").decode()
    assert f'BUILD_DATE = "{expected_build_date.isoformat()}"' in build_info
    environment = tmp_path / "venv"
    _run("uv", "venv", str(environment))
    interpreter = environment / "bin" / "python"
    _run("uv", "pip", "install", "--python", str(interpreter), "--no-deps", str(wheel))
    result = _run(
        str(interpreter),
        "-I",
        "-c",
        "from sayfirst_contract.generation import SUPPORTED_GENERATIONS; "
        "print(*SUPPORTED_GENERATIONS)",
        cwd=tmp_path,
    )
    assert result.stdout.strip() == "2 1"
