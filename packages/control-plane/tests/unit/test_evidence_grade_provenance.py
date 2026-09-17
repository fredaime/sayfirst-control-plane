# SPDX-License-Identifier: Apache-2.0
"""Articles 2, 7 and 10: a grade is only as good as the record that carries it.

A page or an export that does not begin at the first entry needs the grades the
chain recorded before its range, because article 7 grades a *connection* over
the period a verdict covers, and the record that set a connection's grade may
be older than the range asked for. Those preceding records were read straight
out of the store and believed.

So a store that anybody could write — which is exactly what observability grade
*means* — could raise its own grade by editing one earlier record, and every
partial export from then on would carry `evidence` for that connection with
`condition: intact` beside it. Asking for the whole chain showed `broken_at` at
the edited record; asking for anything after it showed nothing at all. Article
7's own sentence is the one broken: "a verifier over an export reads the grades
the chain recorded and adds nothing" — the grades this added were not the ones
the chain recorded.

`manifest_hash` hid it too. It bound `condition` and `up_to` out of the whole
verdict, so the strongest claim an export makes — the grade — was outside the
one number a verifier is told to compare. The claim changed and that number
did not.

`counterexamples.py` from the first outside read is the case below.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sayfirst_control_plane.adapters.file.evidence_store import FileEvidenceStore
from sayfirst_control_plane.application.evidence_reads import EvidenceReads
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal
from sayfirst_control_plane.domain.evidence_export import (
    MANIFEST_V3,
    manifest_digest,
    manifest_hash,
)

AT = datetime(2026, 9, 4, 12, tzinfo=UTC)
STAMP = "2026-09-04T12:00:00Z"


def _graded(grade: str, basis: str) -> EvidenceRecord:
    return EvidenceRecord(
        "local",
        "grade",
        AT,
        "caller",
        Principal("user", "alice"),
        {
            "grade": grade,
            "basis": basis,
            "evaluated_at": STAMP,
            "paths_inspected": 1,
        },
    )


def _effect() -> EvidenceRecord:
    return EvidenceRecord(
        "local",
        "effect",
        AT,
        "caller",
        Principal("user", "alice"),
        {
            "capability": "storage.write",
            "decision_id": "d1",
            "outcome": "allow",
            "decided_at": STAMP,
            "policy_version": "sha256:" + "a" * 64,
        },
    )


def _chain(root: Path) -> tuple[EvidenceReads, Path]:
    store = FileEvidenceStore(root)
    store.append(_graded("observability", "caller_can_write"))
    store.append(_effect())
    return EvidenceReads(store), root / "local.jsonl"


def _raise_the_recorded_grade(path: Path) -> None:
    """Edit the grade record and nothing else: its hash and the next row stand."""
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["body"]["grade"] = "evidence"
    rows[0]["body"]["basis"] = "caller_cannot_write"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def _grades(bundle: dict) -> dict[str, str]:
    return {item["connection_id"]: item["grade"] for item in bundle["verification"]["grades"]}


def test_a_partial_export_does_not_promote_a_grade_from_a_prefix_it_cannot_verify(
    tmp_path: Path,
) -> None:
    """`counterexamples.py`: the edited grade is not the grade the export claims."""
    reads, path = _chain(tmp_path)
    before = reads.export(scope="local", from_sequence=2)
    assert _grades(before) == {"caller": "observability"}

    _raise_the_recorded_grade(path)
    after = reads.export(scope="local", from_sequence=2)
    whole = reads.export(scope="local", from_sequence=1)

    # The edit is visible from the first entry, and was invisible from the second.
    assert whole["verification"]["condition"] == "broken_at"
    assert whole["verification"]["sequence"] == 1
    # The requested range is still intact — it is — and the grade it carries
    # is now the one article 7 keeps for an answer nobody established.
    assert after["verification"]["condition"] == "intact"
    assert _grades(after) == {"caller": "unverified"}
    assert after["manifest_hash"] != before["manifest_hash"]


def test_a_page_does_not_promote_a_grade_from_a_prefix_it_cannot_verify(
    tmp_path: Path,
) -> None:
    """The same read, paged: `read_page` carries grades forward the same way."""
    reads, path = _chain(tmp_path)
    assert _grades(reads.read_page(scope="local", from_sequence=2)) == {"caller": "observability"}

    _raise_the_recorded_grade(path)

    assert _grades(reads.read_page(scope="local", from_sequence=2)) == {"caller": "unverified"}


def test_an_intact_prefix_still_carries_its_grade_forward(tmp_path: Path) -> None:
    """Anti-vacuity: verification is what is added, not a refusal of every prefix."""
    reads, _ = _chain(tmp_path)

    bundle = reads.export(scope="local", from_sequence=2)

    assert bundle["verification"]["condition"] == "intact"
    assert _grades(bundle) == {"caller": "observability"}


def test_the_manifest_covers_the_grades_the_export_claims(tmp_path: Path) -> None:
    """Article 10: an unchanged manifest is not an unchanged assurance claim."""
    reads, _ = _chain(tmp_path)
    bundle = reads.export(scope="local", from_sequence=1)
    verdict = dict(bundle["verification"])

    weakened = dict(verdict)
    weakened["grades"] = [{"connection_id": "caller", "grade": "unverified"}]
    recomputed = manifest_hash(
        scope="local",
        from_sequence=1,
        to_sequence=bundle["to_sequence"],
        contract_version=bundle["contract_version"],
        verdict=weakened,
        entry_hashes=[item["entry_hash"] for item in bundle["entries"]],
    )

    assert recomputed != bundle["manifest_hash"]


def test_the_manifest_a_verifier_recomputes_from_the_bundle_matches(tmp_path: Path) -> None:
    """The verifier's own recomputation, from the document and nothing else."""
    reads, _ = _chain(tmp_path)
    bundle = reads.export(scope="local", from_sequence=1)

    recomputed = manifest_digest(bundle, version=bundle["manifest_version"])

    assert recomputed == bundle["manifest_hash"]
    assert bundle["manifest_version"] == MANIFEST_V3
