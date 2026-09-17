# SPDX-License-Identifier: Apache-2.0
"""Articles 13 and 14: the offline verifier runs from the contract wheel alone.

`verify_export(bundle)` is the promise that survived block 2.7's council: a
reader holding nothing but an export and the contract distribution recomputes
every hash and re-derives every recorded decision, with no server installed,
no conformance package, no connection and no filesystem. Held two ways. The
contract wheel is built and installed into an environment that holds nothing
else of the project, and a program there builds a chain under the published
recipes and verifies it through re-derivation, while `sayfirst_control_plane`
is proved absent. And the direction of dependency is proved to be guarded:
the contract's import guard is run over a copy of the contract with a server
import planted, and reports it, so the guard that holds article 14 is known
to fail when the direction flips.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"
PACKAGE = CONTRACT / "src" / "sayfirst_contract"


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


PROGRAM = REPOSITORY / "tests" / "offline_verifier_program.py"


def test_verify_export_re_derives_a_decision_with_the_server_package_absent(tmp_path: Path) -> None:
    """G30: a clean environment with the contract wheel, and nothing else of the project."""
    wheelhouse = tmp_path / "wheels"
    _run("uv", "build", str(CONTRACT), "--wheel", "--out-dir", str(wheelhouse))
    wheel = next(wheelhouse.glob("sayfirst_contract-*.whl"))
    environment = tmp_path / "venv"
    _run("uv", "venv", str(environment))
    interpreter = environment / "bin" / "python"
    _run("uv", "pip", "install", "--python", str(interpreter), "--no-deps", str(wheel))
    result = _run(str(interpreter), "-I", str(PROGRAM), cwd=tmp_path)
    assert result.stdout.strip() == "verified offline: 0", result.stdout


GUARD = REPOSITORY / "tests" / "test_direction_of_dependency.py"
STUB = REPOSITORY / "packages" / "contract-stub"
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane" / "src" / "sayfirst_control_plane"


def _imports_of(root: Path) -> set[str]:
    imported = set()
    for source in root.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(
                    "sayfirst_contract" if node.level else (node.module or "").split(".")[0]
                )
    return imported


def test_the_verifier_and_the_evaluator_import_the_standard_library_and_the_contract_only() -> None:
    """Article 14: the server imports the contract; the contract imports no server."""
    for module in ("evidence.py", "retrospective_policy.py"):
        imports = _imports_of(PACKAGE / module)
        assert imports <= sys.stdlib_module_names | {"sayfirst_contract"}, (module, imports)
        assert "sayfirst_control_plane" not in imports
    # The direction as the brief states it, both halves executable: the server
    # distribution does import the contract distribution, and nothing of the
    # contract names the server.
    assert "sayfirst_contract" in _imports_of(CONTROL_PLANE)
    assert "sayfirst_control_plane" not in _imports_of(PACKAGE)


def _guard_skeleton(tmp_path: Path) -> Path:
    """A repository holding the real guard file, unmodified, over copies of what it scans."""
    skeleton = tmp_path / "repository"
    (skeleton / "tests").mkdir(parents=True)
    shutil.copy(GUARD, skeleton / "tests" / GUARD.name)
    ignored = shutil.ignore_patterns("__pycache__", "_contracts", "*.egg-info")
    shutil.copytree(CONTRACT, skeleton / "packages" / "contract", ignore=ignored)
    shutil.copytree(STUB, skeleton / "packages" / "contract-stub", ignore=ignored)
    return skeleton


def _run_guard(skeleton: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--rootdir",
            str(skeleton),
            str(skeleton / "tests" / GUARD.name),
        ],
        cwd=skeleton,
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_direction_guard_fails_when_the_direction_flips(tmp_path: Path) -> None:
    """The test that fails if the contract ever imports the server, proved on a planted flip.

    `tests/test_direction_of_dependency.py` is the guard, and it is the guard
    itself that is run here: its file, byte for byte, over a copy of the
    contract package, once clean and once with a server import planted. What
    is proved is that this run's guard, not a reading of it, catches the flip.
    """
    skeleton = _guard_skeleton(tmp_path)
    clean = _run_guard(skeleton)
    assert clean.returncode == 0, clean.stdout + clean.stderr

    planted = skeleton / "packages" / "contract" / "src" / "sayfirst_contract" / "evidence.py"
    with planted.open("a", encoding="utf-8") as stream:
        stream.write("\nfrom sayfirst_control_plane.domain.policy import evaluate as _flipped\n")
    flipped = _run_guard(skeleton)
    assert flipped.returncode != 0, (
        "FAIL the planted server import was not caught: the direction guard cannot fail\n"
        + flipped.stdout
    )
    assert "test_the_contract_distribution_imports_nothing_of_the_server" in flipped.stdout
    assert "sayfirst_control_plane" in flipped.stdout
