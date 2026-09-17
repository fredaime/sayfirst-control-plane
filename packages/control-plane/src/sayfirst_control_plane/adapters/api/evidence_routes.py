# SPDX-License-Identifier: Apache-2.0
"""Strict query decoding for the two evidence reads."""

from __future__ import annotations

from collections.abc import Sequence

from sayfirst_control_plane.application.evidence_emitter import EvidenceConnection
from sayfirst_control_plane.application.evidence_reads import (
    PAGE_BOUND,
    EvidenceRangeInvalid,
    EvidenceReads,
)
from sayfirst_control_plane.domain.evidence_chain import Principal


class EvidenceRoutes:
    def __init__(self, reads: EvidenceReads) -> None:
        self._reads = reads

    def read(
        self,
        scope: str,
        query: Sequence[tuple[str, str]],
        *,
        connection: EvidenceConnection | None = None,
        principal: Principal | None = None,
    ) -> dict[str, object]:
        values = _query(query, {"contract_generation", "from_sequence", "page_size"})
        start = _integer(values, "from_sequence", required=True)
        page_size = _integer(values, "page_size", required=False)
        return self._reads.read_page(
            scope=scope,
            from_sequence=start,
            page_size=PAGE_BOUND if page_size is None else page_size,
            connection=connection,
            principal=principal,
        )

    def export(
        self,
        scope: str,
        query: Sequence[tuple[str, str]],
        *,
        connection: EvidenceConnection | None = None,
        principal: Principal | None = None,
    ) -> dict[str, object]:
        values = _query(
            query,
            {"contract_generation", "from_sequence", "to_sequence"},
        )
        return self._reads.export(
            scope=scope,
            from_sequence=_integer(values, "from_sequence", required=True),
            to_sequence=_integer(values, "to_sequence", required=False),
            connection=connection,
            principal=principal,
        )


def _query(query: Sequence[tuple[str, str]], allowed: set[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for name, value in query:
        if name not in allowed or name in values:
            raise EvidenceRangeInvalid("an evidence query member is repeated or unknown")
        values[name] = value
    return values


def _integer(values: dict[str, str], name: str, *, required: bool) -> int | None:
    if name not in values:
        if required:
            raise EvidenceRangeInvalid(f"{name} is required")
        return None
    try:
        return int(values[name])
    except ValueError as error:
        raise EvidenceRangeInvalid(f"{name} must be an integer") from error
