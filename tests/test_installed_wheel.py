# SPDX-License-Identifier: Apache-2.0
"""Articles 13 and 14: a clean installed wheel carries the notices and verifies itself.

A rule of the repository, not of one package: it holds what leaves here as a
published distribution. These rules used to share one file inside one package's
test directory, so every block that discovered one appended its own wording to
that file, and every pair of blocks conflicted there. One rule per file now: a
new rule arrives as a new file, and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"
STUB = REPOSITORY / "packages" / "contract-stub"
CONFORMANCE = REPOSITORY / "packages" / "conformance"
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def test_the_contract_artifacts_load_from_an_installed_wheel(tmp_path: Path) -> None:
    """Articles 13 and 14: clean installed wheels contain and verify every artefact."""
    wheelhouse = tmp_path / "wheels"
    _run("uv", "build", str(CONTRACT), "--wheel", "--out-dir", str(wheelhouse))
    _run("uv", "build", str(STUB), "--wheel", "--out-dir", str(wheelhouse))
    _run("uv", "build", str(CONFORMANCE), "--wheel", "--out-dir", str(wheelhouse))
    _run("uv", "build", str(CONTROL_PLANE), "--wheel", "--out-dir", str(wheelhouse))
    contract_wheel = next(wheelhouse.glob("sayfirst_contract-*.whl"))
    stub_wheel = next(wheelhouse.glob("sayfirst_contract_stub-*.whl"))
    conformance_wheel = next(wheelhouse.glob("sayfirst_conformance-*.whl"))
    control_plane_wheel = next(wheelhouse.glob("sayfirst_control_plane-*.whl"))
    for wheel in (contract_wheel, stub_wheel, conformance_wheel, control_plane_wheel):
        with zipfile.ZipFile(wheel) as archive:
            members = archive.namelist()
            licence = next(name for name in members if name.endswith(".dist-info/licenses/LICENSE"))
            notice = next(name for name in members if name.endswith(".dist-info/licenses/NOTICE"))
            assert archive.read(licence) == (REPOSITORY / "LICENSE").read_bytes()
            assert archive.read(notice) == (REPOSITORY / "NOTICE").read_bytes()
    environment = tmp_path / "venv"
    _run("uv", "venv", str(environment))
    interpreter = environment / "bin" / "python"
    _run(
        "uv",
        "pip",
        "install",
        "--python",
        str(interpreter),
        "--no-deps",
        str(contract_wheel),
    )
    program = """
import hashlib
from sayfirst_contract.artifacts import BINDING_ARTIFACTS, DOMAIN_ARTIFACTS, artifact, load_json
from sayfirst_contract.generation import CONTRACT_GENERATION
digests = load_json("digests.json")["artifacts"]
for relative in (*DOMAIN_ARTIFACTS, *BINDING_ARTIFACTS):
    actual = hashlib.sha256(artifact(*relative.split("/")).read_bytes()).hexdigest()
    assert actual == digests[relative]
print(CONTRACT_GENERATION)
"""
    result = _run(str(interpreter), "-I", "-c", program, cwd=tmp_path)
    assert result.stdout.strip() == "1"
    _run(
        "uv",
        "pip",
        "install",
        "--python",
        str(interpreter),
        "--no-deps",
        str(conformance_wheel),
    )
    result = _run(str(environment / "bin" / "sayfirst-conformance"), "--help", cwd=tmp_path)
    assert "sayfirst-conformance" in result.stdout
    _run(
        "uv",
        "pip",
        "install",
        "--python",
        str(interpreter),
        "--no-deps",
        str(stub_wheel),
    )
    _run(
        str(interpreter),
        "-I",
        "-c",
        "import sayfirst_contract_stub; print(sayfirst_contract_stub.__name__)",
        cwd=tmp_path,
    )
    _run(
        "uv",
        "pip",
        "install",
        "--python",
        str(interpreter),
        "--no-deps",
        str(control_plane_wheel),
    )
    _run(
        str(interpreter),
        "-I",
        "-c",
        "from sayfirst_control_plane.testing import ("
        "EvidenceStoreContract, PrivacyRedactorContract); "
        "print(EvidenceStoreContract.__name__, PrivacyRedactorContract.__name__)",
        cwd=tmp_path,
    )
