# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import inspect
from typing import get_type_hints

from sayfirst_control_plane.application.evidence_emitter import EvidenceEmitter
from sayfirst_control_plane.domain.evidence_chain import EvidenceEntry, EvidenceRecord
from sayfirst_control_plane.ports.evidence_store import EvidenceStore


def test_every_port_carrying_a_record_carries_a_scope() -> None:
    """Article 5: enumerate record ports and every persisted evidence shape."""
    persisted_structures = (EvidenceRecord, EvidenceEntry)
    for structure in persisted_structures:
        assert "scope" in structure.__dataclass_fields__, structure.__name__

    record_parameters = (
        (EvidenceStore.append, "record"),
        (EvidenceEmitter.emit, "record"),
    )
    for method, parameter in record_parameters:
        record_type = get_type_hints(method)[parameter]
        assert record_type in persisted_structures
        assert "scope" in record_type.__dataclass_fields__

    explicitly_scoped_methods = (
        EvidenceStore.read_range,
        EvidenceStore.latest_sequence,
        EvidenceEmitter.emit_effect,
    )
    for method in explicitly_scoped_methods:
        assert "scope" in inspect.signature(method).parameters, method.__qualname__
