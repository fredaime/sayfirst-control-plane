# SPDX-License-Identifier: Apache-2.0
"""Article 3: every proof the information contract names is a test that runs.

One rule per file (`CONTRIBUTING.md`, article 16). The rule here is the second
half of article 3's Guard: the suite exercises each kind as declared. Before the
audit of 2026-09-06 the declarations carried a `proof` string that nothing read,
so all three could have named tests that did not exist and the architecture
suite would still have been green — a guard that cannot fail, which is worse
than an absent one, because the absent one is honest.

What is mechanised here is resolution: the name is collected by pytest over this
repository, so a label pointing at nothing fails, by name. Collection is asked
of a separate run rather than of this one, because a run of one file collects
one file and would report every other proof as missing.

What is not mechanised is that the named test exercises the declared kind — that
a projection proof really rebuilds from its authority. The Guard says so; it is
held by review.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from sayfirst_control_plane.architecture.information_contract import INFORMATION_CONTRACT

REPOSITORY = Path(__file__).resolve().parents[4]


def _collected() -> set[str]:
    """Every test name pytest collects over this repository."""
    root = Path(tempfile.mkdtemp(prefix="sf-c")) / "b"
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                str(root),
            ],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
        )
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    names = set()
    for line in result.stdout.splitlines():
        _, separator, node = line.partition("::")
        if separator:
            names.add(node.split("[")[0].split("::")[-1].strip())
    return names


def _unresolved(declarations: dict[str, str], collected: set[str]) -> dict[str, str]:
    """Every declaration whose proof label names no test this repository collects."""
    return {name: proof for name, proof in declarations.items() if proof not in collected}


#: A label of the kind the audit of 2026-09-06 planted: well formed, plausible,
#: and naming nothing. It is resolved below on every run; it is never written
#: into the information contract.
PLANTED_PROOF = "test_nobody_ever_wrote_this_one"


def test_every_declared_proof_names_a_test_this_repository_collects() -> None:
    """Article 3: a proof label that resolves to nothing is a claim, not a proof."""
    collected = _collected()
    declarations = {name: structure.proof for name, structure in INFORMATION_CONTRACT.items()}
    assert _unresolved(declarations, collected) == {}, _unresolved(declarations, collected)
    # Anti-vacuity: a collection that came back nearly empty would resolve
    # every label by accident, and a contract with no declarations proves none.
    assert len(collected) > 500, len(collected)
    assert len(INFORMATION_CONTRACT) >= 4
    # And the resolution itself is shown to be able to fail, on the same
    # collection this run has just passed against: what that proves is that
    # *this run's* check would have caught a label naming nothing. The name it
    # reports is planted here and is not a declaration of this repository.
    planted = _unresolved(
        {"a structure this repository does not declare": PLANTED_PROOF}, collected
    )
    assert planted, (
        "FAIL the planted proof label was not caught: this guard cannot fail. "
        f"The label {PLANTED_PROOF!r} names no test, and resolution reported it as resolved."
    )
