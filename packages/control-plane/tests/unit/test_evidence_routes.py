# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sayfirst_control_plane.adapters.api.evidence_routes import EvidenceRoutes
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.evidence_reads import EvidenceRangeInvalid, EvidenceReads
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal


def test_a_repeated_query_member_is_refused() -> None:
    routes = EvidenceRoutes(EvidenceReads(InMemoryEvidenceStore()))
    with pytest.raises(EvidenceRangeInvalid):
        routes.read(
            "local",
            (("from_sequence", "1"), ("from_sequence", "2")),
        )


def test_the_export_route_returns_the_raw_bundle() -> None:
    store = InMemoryEvidenceStore()
    store.append(
        EvidenceRecord(
            "local",
            "grade",
            datetime(2026, 9, 4, tzinfo=UTC),
            "connection-1",
            Principal("user", "example"),
            {
                "grade": "unverified",
                "basis": "access_not_established",
                "evaluated_at": "2026-09-04T00:00:00Z",
                "paths_inspected": 0,
            },
        )
    )
    result = EvidenceRoutes(EvidenceReads(store)).export(
        "local",
        (("from_sequence", "1"),),
    )
    assert result["scope"] == "local"
    assert result["entry_count"] == 1
    assert result["entries"][0]["kind"] == "grade"
