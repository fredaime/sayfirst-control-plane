# SPDX-License-Identifier: Apache-2.0
"""Article 13: the server runs the published export-digest vectors on its own.

Two implementations of three export-digest recipes — the server's in
`domain/evidence_export.py` and the contract's — and one fixture arbiter,
`evidence-export-manifest-vectors.json`, read from the installed contract.
Neither imports the other; a vector one passes and the other fails is a
defect in one of the two.
"""

from __future__ import annotations

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_control_plane.domain.evidence_export import (
    MANIFEST_V1,
    MANIFEST_V2,
    MANIFEST_V3,
    MANIFEST_VERSION,
    manifest_digest,
)

VECTORS = load_json("domain", "evidence-export-manifest-vectors.json")


def _vectors() -> list[dict]:
    assert isinstance(VECTORS, dict)
    cases = VECTORS["vectors"]
    assert isinstance(cases, list) and len(cases) >= 10
    return cases


def test_the_server_writes_the_newest_recipe() -> None:
    assert MANIFEST_VERSION == MANIFEST_V3


@pytest.mark.parametrize("vector", _vectors(), ids=lambda item: item["name"])
def test_the_server_recomputes_every_manifest_vector_under_its_own_recipe_only(
    vector: dict,
) -> None:
    """Article 13: one digest per recipe, and a digest never recomputes under another."""
    bundle = vector["bundle"]
    version = vector["manifest_version"]
    assert manifest_digest(bundle, version=version) == vector["manifest_hash"]
    for other in (MANIFEST_V1, MANIFEST_V2, MANIFEST_V3):
        if other != version:
            assert manifest_digest(bundle, version=other) != vector["manifest_hash"]


def test_every_recipe_is_covered_by_the_vectors() -> None:
    assert {item["manifest_version"] for item in _vectors()} == {
        MANIFEST_V1,
        MANIFEST_V2,
        MANIFEST_V3,
    }
