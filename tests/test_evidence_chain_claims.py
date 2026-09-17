# SPDX-License-Identifier: Apache-2.0
"""Article 2: no published claim is stronger than the mechanism this repository holds.

A rule of the repository, not of one package: evidence is what a reader trusts
last, so a claim about a chain nobody ships is the one claim that cannot be
corrected after the fact. One rule per file, so a new rule arrives as a new
file and a new file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"


def test_the_readme_claims_no_more_of_the_chain_than_the_daemon_holds() -> None:
    """Article 2: no claim is stronger than the mechanism the repository holds.

    The daemon now writes a chain, so the sentence that said it shipped none
    would be the false claim this rule exists to prevent. What the daemon does
    *not* do is unchanged and is what this pins: it writes through a sink the
    caller supplies, it does not verify the hash linkage where it writes, and it
    never calls the chain the authoritative record of what ran.
    """
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "the authoritative record of what ran" not in documentation
    assert "**The sink is a protocol the caller supplies**" in documentation
    assert "The hash linkage\nitself is **not** verified here" in documentation
    assert "two minor releases or six months" in documentation
    assert "the member is never omitted" in documentation


def test_the_readme_names_the_records_the_chain_does_not_carry() -> None:
    """Article 2: an absence from the chain is written down, never left to a reader.

    A connection opening, a principal changing and a connection closing are
    collected and not written, because the published entry kinds do not carry
    them. A reader who found only effects would otherwise conclude the
    connections were never made.
    """
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "**The connection records are not on the chain.**" in documentation
    assert "adding a fifth is a contract decision" in documentation
