# SPDX-License-Identifier: Apache-2.0
"""Article 2: the published claim about the conformance kit is the kit's actual rule.

A rule of the repository, not of one package: a conformance kit is published
for others to build against, so the sentence describing what it judges by is
the contract, and a sentence stronger than the kit is a promise the repository
cannot keep. One rule per file, so a new rule arrives as a new file and a new
file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_the_readme_states_the_one_rule_the_approval_kit_judges_by() -> None:
    """Article 2: the published claim about the kit is the kit's actual rule."""
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "derivable from the acts of the people" in documentation
    assert "A result no act supports fails" in documentation
    assert "The fixture supplies the people, never the case" in documentation
    assert "ADVERSARIAL_APPROVAL_PROVIDERS" in documentation
    assert "ADVERSARIAL_COMPLETION_FIXTURES" in documentation
    assert "A provider refuses by raising `ApprovalProviderError`" in documentation
    assert "it\nnever requires a particular one of them" in documentation
