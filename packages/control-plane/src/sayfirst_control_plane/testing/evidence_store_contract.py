# SPDX-License-Identifier: Apache-2.0
"""Reusable conformance tests for evidence authorities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord, Principal, verify
from sayfirst_control_plane.ports.evidence_store import EvidenceStore


def _record(scope: str = "local") -> EvidenceRecord:
    return EvidenceRecord(
        scope=scope,
        kind="grade",
        recorded_at=datetime(2026, 9, 4, tzinfo=UTC),
        connection_id="connection-1",
        principal=Principal("user", "conformance"),
        body={
            "grade": "unverified",
            "basis": "access_not_established",
            "evaluated_at": "2026-09-04T00:00:00Z",
            "paths_inspected": 0,
        },
    )


def _assert_refused(call: Any) -> None:
    try:
        call()
    except ValueError:
        return
    raise AssertionError("the evidence store accepted an invalid request")


class EvidenceStoreContract(ABC):
    """Subclass this suite and return a fresh provider from ``make_store``."""

    @abstractmethod
    def make_store(self, tmp_path: Path) -> EvidenceStore:
        raise NotImplementedError

    def test_the_first_entry_takes_the_first_place_and_names_no_predecessor(
        self, tmp_path: Path
    ) -> None:
        entry = self.make_store(tmp_path).append(_record())
        assert entry.sequence == 1
        assert entry.previous_hash is None

    def test_each_append_takes_the_next_place_and_names_the_one_before(
        self, tmp_path: Path
    ) -> None:
        store = self.make_store(tmp_path)
        first = store.append(_record())
        second = store.append(_record())
        assert second.sequence == first.sequence + 1
        assert second.previous_hash == first.entry_hash

    def test_a_long_chain_leaves_no_hole(self, tmp_path: Path) -> None:
        store = self.make_store(tmp_path)
        entries = tuple(store.append(_record()) for _ in range(100))
        assert [entry.sequence for entry in entries] == list(range(1, 101))

    def test_two_concurrent_appends_are_consecutive_with_no_gap_and_no_duplicate(
        self, tmp_path: Path
    ) -> None:
        store = self.make_store(tmp_path)
        with ThreadPoolExecutor(max_workers=8) as pool:
            entries = tuple(pool.map(lambda _: store.append(_record()), range(50)))
        assert sorted(entry.sequence for entry in entries) == list(range(1, 51))
        assert len({entry.entry_hash for entry in entries}) == 50

    def test_a_read_without_a_scope_is_refused(self, tmp_path: Path) -> None:
        store = self.make_store(tmp_path)
        _assert_refused(lambda: store.read_range("", from_sequence=1))

    def test_a_scope_outside_the_contract_is_refused(self, tmp_path: Path) -> None:
        store = self.make_store(tmp_path)
        _assert_refused(lambda: store.append(_record("../outside")))
        _assert_refused(lambda: store.latest_sequence("../outside"))

    def test_another_scopes_entries_are_never_read_here(self, tmp_path: Path) -> None:
        store = self.make_store(tmp_path)
        store.append(_record("local"))
        store.append(_record("other"))
        assert [entry.scope for entry in store.read_range("local", from_sequence=1)] == ["local"]

    def test_one_scopes_appends_never_move_anothers_sequence(self, tmp_path: Path) -> None:
        store = self.make_store(tmp_path)
        store.append(_record("local"))
        first_other = store.append(_record("other"))
        second_local = store.append(_record("local"))
        assert first_other.sequence == 1
        assert second_local.sequence == 2

    def test_each_scopes_chain_verifies_on_its_own(self, tmp_path: Path) -> None:
        store = self.make_store(tmp_path)
        for scope in ("local", "other"):
            store.append(_record(scope))
            store.append(_record(scope))
        for scope in ("local", "other"):
            entries = store.read_range(scope, from_sequence=1)
            verdict = verify(entries, scope=scope, from_sequence=1, grades_before={})
            assert verdict.up_to == 2

    def test_the_store_publishes_no_update_or_delete_verb_of_any_name(self, tmp_path: Path) -> None:
        forbidden = (
            "update",
            "delete",
            "remove",
            "replace",
            "redact",
            "purge",
            "truncate",
            "rewrite",
            "edit",
            "drop",
        )
        store = self.make_store(tmp_path)
        assert not [
            name
            for name in dir(store)
            if name != "append" and any(word in name.lower() for word in forbidden)
        ]
