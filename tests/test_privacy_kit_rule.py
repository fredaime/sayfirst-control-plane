# SPDX-License-Identifier: Apache-2.0
"""Article 2: the published claim about the privacy conformance kit is the kit's actual rule.

A rule of the repository, not of one package: a conformance kit is published
for others to build against, so the sentence describing what it judges by is
the contract, and a sentence stronger than the kit is a promise the repository
cannot keep. This file holds the `PrivacyRedactor` kit to the same standard
`tests/test_approval_kit_rule.py` holds the approval kit to, and holds the
document to one interface: the one shape, the two entrances under one rule,
and the second implementation the rule is proven against. One rule per file,
so a new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_the_readme_states_the_one_rule_the_privacy_kit_judges_by() -> None:
    """Article 2: the published claim about the kit is the kit's actual rule."""
    # Read as prose: a sentence wrapped across two lines is the same claim.
    documentation = " ".join((CONTROL_PLANE / "README.md").read_text(encoding="utf-8").split())
    assert "`applied` means the content differs from what was read" in documentation
    assert "`not_applicable` means it is as given" in documentation
    assert "a no-op that answers `applied` fails the kit" in documentation
    assert "an empty capture yields an empty capture" in documentation
    assert "one rule under two entrances" in documentation
    assert "`sayfirst_control_plane.testing.PrivacyRedactorContract`" in documentation
    assert "proven against a second, independent implementation" in documentation
    assert "`tests/digit_mask_redactor.py`" in documentation
