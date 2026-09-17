# SPDX-License-Identifier: Apache-2.0
"""Article 8: the plugin conformance kit and its registrations survive publication.

A rule of the repository, not of one package: it holds what leaves here as a
published distribution. Article 8 says a provider is loaded only when
configuration names it, which is a promise to whoever installs the wheel — so
the kit the wheel offers and the registrations it declares have to be there in
a clean environment, not merely on this checkout's import path. One rule per
file, so a new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def _run(*command: str, cwd: Path = REPOSITORY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def test_the_control_plane_wheel_publishes_the_plugin_conformance_kit(
    tmp_path: Path,
) -> None:
    """Article 8: the plugin kit and registrations survive a clean wheel install."""
    wheelhouse = tmp_path / "wheels"
    _run("uv", "build", str(CONTRACT), "--wheel", "--out-dir", str(wheelhouse))
    _run("uv", "build", str(CONTROL_PLANE), "--wheel", "--out-dir", str(wheelhouse))
    contract_wheel = next(wheelhouse.glob("sayfirst_contract-*.whl"))
    control_plane_wheel = next(wheelhouse.glob("sayfirst_control_plane-*.whl"))
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
        str(control_plane_wheel),
    )
    program = """
import sayfirst
from importlib import metadata
from sayfirst.testing import ApprovalProviderContract, PrivacyRedactorContract
from sayfirst.testing import ADVERSARIAL_APPROVAL_PROVIDERS, ADVERSARIAL_COMPLETION_FIXTURES
assert sayfirst.__spec__.origin is None
assert ApprovalProviderContract and PrivacyRedactorContract
assert ADVERSARIAL_APPROVAL_PROVIDERS and ADVERSARIAL_COMPLETION_FIXTURES
found = metadata.entry_points().select(group="sayfirst.plugins")
assert {item.name for item in found} == {"none", "single-approver"}
"""
    _run(str(interpreter), "-I", "-c", program, cwd=tmp_path)
