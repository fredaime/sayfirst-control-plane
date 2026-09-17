# SPDX-License-Identifier: Apache-2.0
"""Articles 0, 6 and 13: the contributor notes hold both release handoffs.

A rule of the repository, not of one package: a later block must not be able to
miss a temporary implementation form the release carries. One rule per file, so
a new rule arrives as a new file and a new file never conflicts
(`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"


def test_the_contributor_notes_hold_both_release_handoffs() -> None:
    """Articles 0, 6 and 13: later blocks cannot miss the temporary implementation forms."""
    readme = (CONTRACT / "README.md").read_text(encoding="utf-8")
    assert all(form in readme for form in ("sayfirst", "sayfirst", "sayfirst"))
    assert all(code in readme for code in ("impostor", "unreachable", "answer_unreadable"))
