# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.evidence_reads import (
    EXPORT_BOUND,
    PAGE_BOUND,
    EvidenceRangeInvalid,
    EvidenceReads,
    EvidenceStoreUnavailable,
    ScopeInvalid,
    ScopeRequired,
)
from sayfirst_control_plane.domain.evidence_chain import (
    EvidenceEntry,
    EvidenceRecord,
    Principal,
)


def record(identifier: int) -> EvidenceRecord:
    return EvidenceRecord(
        "local",
        "effect",
        datetime(2026, 9, 4, tzinfo=UTC),
        "connection-1",
        Principal("user", "example"),
        {
            "capability": "example.effect",
            "decision_id": f"decision-{identifier}",
            "outcome": "allow",
            "decided_at": "2026-09-04T00:00:00Z",
            "policy_version": "policy-1",
        },
    )


def test_a_read_that_names_no_scope_is_refused_before_the_store_is_consulted() -> None:
    class ExplodingStore:
        def latest_sequence(self, scope: str) -> int | None:
            raise AssertionError("the store must not be consulted")

    with pytest.raises(ScopeRequired):
        EvidenceReads(ExplodingStore()).read_page(scope=None, from_sequence=1)  # type: ignore[arg-type]


def test_a_page_size_over_the_bound_is_refused() -> None:
    with pytest.raises(EvidenceRangeInvalid):
        EvidenceReads(InMemoryEvidenceStore()).read_page(
            scope="local", from_sequence=1, page_size=PAGE_BOUND + 1
        )


def test_an_export_over_the_bound_is_bounded_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sayfirst_control_plane.application.evidence_reads.EXPORT_BOUND", 2)
    store = InMemoryEvidenceStore()
    for item in range(4):
        store.append(record(item))
    result = EvidenceReads(store).export(scope="local", from_sequence=1)
    assert result["entry_count"] == 2
    assert result["next_from"] == 3
    assert EXPORT_BOUND == 10_000


def test_next_from_is_computed_from_the_head_not_the_number_returned() -> None:
    """Article 10: the cursor comes from the head, and the short answer is a declared hole.

    The double drops the last entry of every range, which is a store with a
    hole at the tail of the page: `next_from` still steps past the page the
    head promised, and the page says so rather than reading intact.
    """

    class Store(InMemoryEvidenceStore):
        def read_range(self, scope: str, *, from_sequence: int, to_sequence=None):  # type: ignore[no-untyped-def]
            entries = super().read_range(
                scope,
                from_sequence=from_sequence,
                to_sequence=to_sequence,
            )
            return entries[:-1]

    store = Store()
    for item in range(3):
        store.append(record(item))
    result = EvidenceReads(store).read_page(scope="local", from_sequence=1, page_size=2)
    assert result["next_from"] == 3
    assert result["verification"]["condition"] == "gap_at"
    assert result["verification"]["sequence"] == 2


def test_an_unreadable_store_is_a_problem_never_an_empty_page() -> None:
    class Store:
        def latest_sequence(self, scope: str) -> int | None:
            raise OSError("synthetic read failure")

    with pytest.raises(EvidenceStoreUnavailable):
        EvidenceReads(Store()).read_page(scope="local", from_sequence=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("operation", ("page", "export"))
@pytest.mark.parametrize("scope", ("../outside", "a" * 129))
def test_a_scope_outside_the_contract_is_refused_before_the_store_is_consulted(
    operation: str, scope: str
) -> None:
    """Articles 2 and 5: malformed input is not reported as an authority outage."""

    class ExplodingStore:
        def latest_sequence(self, scope: str) -> int | None:
            raise AssertionError("the store must not be consulted")

    reads = EvidenceReads(ExplodingStore())  # type: ignore[arg-type]
    with pytest.raises(ScopeInvalid) as refusal:
        if operation == "page":
            reads.read_page(scope=scope, from_sequence=1)
        else:
            reads.export(scope=scope, from_sequence=1)
    # A malformed request is not a permission refusal: these reads never
    # consult the caller's permissions, so `scope_refused` would be a claim
    # about something never evaluated (articles 2, 13).
    assert refusal.value.code == "scope_invalid"


class HoledStore(InMemoryEvidenceStore):
    """A store whose sequence 3 was removed by whoever could write it."""

    def read_range(self, scope: str, *, from_sequence: int, to_sequence=None):  # type: ignore[no-untyped-def]
        entries = super().read_range(scope, from_sequence=from_sequence, to_sequence=to_sequence)
        return tuple(item for item in entries if item.sequence != 3)


def test_a_page_whose_tail_was_removed_is_never_intact() -> None:
    """Article 10: an undeclared gap at the tail of a page is a gap, not a clean page."""
    store = HoledStore()
    for item in range(5):
        store.append(record(item))
    first = EvidenceReads(store).read_page(scope="local", from_sequence=1, page_size=3)
    verification = first["verification"]
    assert isinstance(verification, dict)
    assert verification["condition"] == "gap_at"
    assert verification["sequence"] == 3
    assert verification["up_to"] is None


def test_no_page_of_a_holed_chain_reads_intact_over_the_hole() -> None:
    """Article 2: paging over a chain never renders a missing entry as a healthy state."""
    store = HoledStore()
    for item in range(5):
        store.append(record(item))
    reads = EvidenceReads(store)
    conditions = []
    cursor: object = 1
    while cursor is not None:
        assert isinstance(cursor, int)
        page = reads.read_page(scope="local", from_sequence=cursor, page_size=3)
        verification = page["verification"]
        assert isinstance(verification, dict)
        conditions.append(verification["condition"])
        cursor = page["next_from"]
    assert "gap_at" in conditions


def test_an_export_whose_tail_was_removed_is_never_intact() -> None:
    """Article 10: a bounded export declares the hole its own end walked over."""
    store = HoledStore()
    for item in range(5):
        store.append(record(item))
    bundle = EvidenceReads(store).export(scope="local", from_sequence=1, to_sequence=3)
    verification = bundle["verification"]
    assert isinstance(verification, dict)
    assert verification["condition"] == "gap_at"
    assert verification["sequence"] == 3


class TwoFacedEntry:
    """An entry that verifies, then renders another body to the caller.

    Every member is a property, so the verifier and the renderer are two reads
    of memory the store owns; the store picks what the second one says by
    counting the first. It is not an `EvidenceEntry` and it says it is:
    `__class__` is a property, which `isinstance` believes.
    """

    def __init__(self, honest: EvidenceEntry, forged: dict[str, object]) -> None:
        self._honest = honest
        self._forged = forged
        self._reads = 0

    @property  # type: ignore[misc]
    def __class__(self) -> type:  # type: ignore[override]
        return EvidenceEntry

    def __getattr__(self, name: str) -> object:
        return getattr(self._honest, name)

    @property
    def body(self) -> Mapping[str, object]:
        self._reads += 1
        return self._honest.body if self._reads == 1 else self._forged


class TwoFacedStore(InMemoryEvidenceStore):
    """A store whose entries change between the verdict and the document."""

    def __init__(self, forged: dict[str, object]) -> None:
        super().__init__()
        self._forged = forged

    def read_range(self, scope: str, **kwargs: object):  # type: ignore[no-untyped-def,override]
        return tuple(
            TwoFacedEntry(entry, self._forged)
            for entry in super().read_range(scope, **kwargs)  # type: ignore[arg-type]
        )


def test_a_page_renders_the_entries_its_verdict_was_reached_about() -> None:
    """Articles 2 and 10: the verdict and the document are one read of one value.

    A store is a port, so a page it answers with is memory it owns. The page
    was verified and then rendered — two reads — so a store could serve a body
    under a verdict reached about another. The entries are taken into the core
    once, before anything is claimed about them, and both the verdict and the
    document come from those.
    """
    forged = {
        "capability": "example.effect",
        "decision_id": "a-decision-nobody-took",
        "outcome": "allow",
        "decided_at": "2026-09-04T00:00:00Z",
        "policy_version": "policy-1",
    }
    store = TwoFacedStore(forged)
    store.append(record(0))
    page = EvidenceReads(store).read_page(scope="local", from_sequence=1)

    assert page["verification"]["condition"] == "intact"  # type: ignore[index]
    assert page["entries"][0]["body"]["decision_id"] == "decision-0"  # type: ignore[index]
    assert type(page["entries"][0]) is dict  # type: ignore[index]
