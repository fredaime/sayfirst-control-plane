# SPDX-License-Identifier: Apache-2.0
"""Articles 3, 8 and 12: the claim about the provider seam is the seam's mechanism.

A rule of the repository, not of one package: article 3 puts the authority for
a decision in the core, and a document that implies a provider's answer is
taken on trust misplaces it for every reader at once. One rule per file, so a
new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_the_readme_states_that_the_core_judges_a_provider_answer_itself() -> None:
    """Articles 3, 8 and 12: the claim about the seam is the seam's mechanism."""
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "The core holds that same rule itself" in documentation
    assert "does not depend on a provider having\nrun the kit" in documentation
    assert "A refusal is recorded as a refusal, never as a decision." in documentation
