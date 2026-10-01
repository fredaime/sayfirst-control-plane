# SPDX-License-Identifier: Apache-2.0
"""`sayfirst-daemon`, the distribution, holds a name and installs its owner.

Every page of this project teaches a command spelled `sayfirst-daemon`. The
command belongs to `sayfirst-control-plane`, which declares it; the index knew
no distribution of that name, so `pip install sayfirst-daemon` would have
installed whatever a stranger published under it. `packages/daemon-name` is the
project's own answer to that install line: a distribution that depends on the
owner at this release's version, and is nothing else.

« Nothing else » is the rule, and each part of it is a defect somebody could
add in good faith:

* a console script — `tests/test_client_distribution_names.py` already forbids
  two distributions of this repository to install one command, and this file
  forbids this distribution any command at all, so that the one it is named
  after is never declared twice here;
* a module — code under a name whose only job is to point elsewhere is code no
  gate reads;
* a second dependency, or a range in place of the pin — the name would then
  install something other than this release's daemon.

One rule per file (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import subprocess
import tomllib
import zipfile
from collections.abc import Mapping
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
PACKAGE = REPOSITORY / "packages" / "daemon-name"
OWNER = REPOSITORY / "packages" / "control-plane"

#: The name held, which is also the command the owner declares.
NAME = "sayfirst-daemon"

#: The distribution the name installs.
OWNER_NAME = "sayfirst-control-plane"

#: The tables of a project file that would make this distribution more than a
#: name: anything that installs a command, an import hook or an optional extra.
REFUSED_TABLES = ("scripts", "gui-scripts", "entry-points", "optional-dependencies")


def _project(package: Path) -> dict[str, object]:
    return tomllib.loads((package / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def problems(table: Mapping[str, object], owner: Mapping[str, object]) -> list[str]:
    """Every way a project table is more, or other, than the name and its one pin."""
    version = owner.get("version")
    reported = []
    if table.get("name") != NAME:
        reported.append(f"the distribution is named {table.get('name')!r}, and holds {NAME!r}")
    if table.get("version") != version:
        reported.append(
            f"it carries {table.get('version')} and {OWNER_NAME} carries {version}: "
            f"they are released together"
        )
    wanted = [f"{OWNER_NAME}=={version}"]
    if table.get("dependencies") != wanted:
        reported.append(
            f"it depends on {table.get('dependencies')} and the rule is exactly {wanted}"
        )
    for refused in REFUSED_TABLES:
        if table.get(refused):
            reported.append(f"it declares [project.{refused}], and a name declares nothing")
    return reported


def outside_the_metadata(members: list[str]) -> list[str]:
    """Every member of a wheel that is not part of its own metadata directory."""
    return sorted(name for name in members if ".dist-info/" not in name)


def test_the_project_file_is_the_name_and_one_pin() -> None:
    assert problems(_project(PACKAGE), _project(OWNER)) == []


def test_the_owner_still_declares_the_command_the_name_is_for() -> None:
    """ANTI-VACUITY. A name held for a command its owner no longer installs holds nothing."""
    scripts = _project(OWNER).get("scripts")
    assert isinstance(scripts, dict)
    assert NAME in scripts, scripts


def test_the_package_has_no_import_root_and_no_tests_of_its_own() -> None:
    """Discovery reads `packages/*/src` and `packages/*/tests`; neither exists here."""
    assert not (PACKAGE / "src").exists()
    assert not (PACKAGE / "tests").exists()


def test_the_wheel_carries_its_metadata_and_nothing_else(tmp_path: Path) -> None:
    subprocess.run(
        ("uv", "build", str(PACKAGE), "--wheel", "--out-dir", str(tmp_path)),
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = sorted(tmp_path.glob("*.whl"))
    assert len(wheels) == 1, wheels
    assert wheels[0].name.startswith("sayfirst_daemon-"), wheels[0].name
    with zipfile.ZipFile(wheels[0]) as archive:
        members = archive.namelist()
        # Anti-vacuity floor: an archive with no metadata is not a wheel that
        # ships no code, it is no wheel.
        metadata = next(name for name in members if name.endswith(".dist-info/METADATA"))
        assert outside_the_metadata(members) == []
        assert not any(name.endswith("entry_points.txt") for name in members), members
        version = _project(OWNER)["version"]
        assert f"Requires-Dist: {OWNER_NAME}=={version}" in archive.read(metadata).decode("utf-8")


def test_a_planted_console_script_is_caught() -> None:
    """WATCHED FIRING. The one defect this file exists for."""
    planted = {**_project(PACKAGE), "scripts": {NAME: "sayfirst_quickstart.command:main"}}
    assert problems(planted, _project(OWNER)) == [
        "it declares [project.scripts], and a name declares nothing"
    ]


def test_a_range_in_place_of_the_pin_is_caught() -> None:
    """WATCHED FIRING. `>=` installs whatever the index holds that day."""
    owner = _project(OWNER)
    ranged = {**_project(PACKAGE), "dependencies": [f"{OWNER_NAME}>={owner['version']}"]}
    reported = problems(ranged, owner)
    assert len(reported) == 1
    assert f"{OWNER_NAME}>={owner['version']}" in reported[0]


def test_a_second_dependency_is_caught() -> None:
    """WATCHED FIRING. The name installs the daemon, and only the daemon."""
    owner = _project(OWNER)
    more = {
        **_project(PACKAGE),
        "dependencies": [f"{OWNER_NAME}=={owner['version']}", "sayfirstd"],
    }
    reported = problems(more, owner)
    assert len(reported) == 1
    assert "sayfirstd" in reported[0]


def test_a_version_left_behind_is_caught() -> None:
    """WATCHED FIRING. The owner moved and the name did not."""
    owner = {**_project(OWNER), "version": "9.9.9"}
    reported = problems(_project(PACKAGE), owner)
    assert reported[0].endswith("carries 9.9.9: they are released together")
    assert len(reported) == 2, "the pin is stale too, and is named too"


def test_the_wheel_reading_catches_a_module_that_arrived() -> None:
    """WATCHED FIRING, on the list a wheel with one module in it would give."""
    members = ["sayfirst_daemon-1.0.0.dist-info/METADATA", "sayfirst_daemon/__init__.py"]
    assert outside_the_metadata(members) == ["sayfirst_daemon/__init__.py"]
