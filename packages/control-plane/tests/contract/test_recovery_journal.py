# SPDX-License-Identifier: Apache-2.0
"""Articles 2, 3 and 10: the coordination journal records the limits of evidence coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters.file.recovery_journal import FileRecoveryJournal
from sayfirst_control_plane.ports.recovery_journal import JournalRecord, RecoveryJournalUnavailable

HASH = "a" * 64


def _file(root: Path, scope: str = "local") -> Path:
    return root / "recovery" / f"{scope}.jsonl"


def test_an_epoch_is_open_until_its_closure_is_journaled(tmp_path: Path) -> None:
    """C3: an epoch never closes while a producer could still enqueue into it."""
    journal = FileRecoveryJournal(tmp_path / "evidence")
    assert journal.open_epochs("local") == ()
    journal.open_epoch("local", "epoch-1", store_id="store-1", from_sequence=1)
    opened = journal.open_epochs("local")
    assert [(item.epoch_id, item.store_id, item.from_sequence) for item in opened] == [
        ("epoch-1", "store-1", 1)
    ]
    assert all(isinstance(item, JournalRecord) for item in opened)
    journal.epoch_clean("local", "epoch-1", marker_sequence=4, marker_hash=HASH)
    assert journal.open_epochs("local") == ()
    journal.open_epoch("local", "epoch-2", store_id="store-1", from_sequence=5)
    journal.epoch_reconciled("local", "epoch-2", marker_sequence=9, marker_hash=HASH)
    assert journal.open_epochs("local") == ()
    positions = [
        json.loads(line)["position"]
        for line in _file(tmp_path / "evidence").read_text().splitlines()[1:]
    ]
    assert positions == [1, 2, 3, 4]


def test_the_journal_survives_reopening_and_a_torn_tail(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    journal = FileRecoveryJournal(root)
    journal.open_epoch("local", "epoch-1", store_id="store-1", from_sequence=1)
    with _file(root).open("ab") as stream:
        stream.write(b'{"journal_version": 1, "sco')
    reopened = FileRecoveryJournal(root)
    assert reopened.recover("local") == 27
    assert [item.epoch_id for item in reopened.open_epochs("local")] == ["epoch-1"]
    reopened.epoch_clean("local", "epoch-1", marker_sequence=2, marker_hash=HASH)
    assert reopened.open_epochs("local") == ()


def test_a_malformed_complete_line_makes_the_journal_unavailable_not_empty(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    journal = FileRecoveryJournal(root)
    journal.open_epoch("local", "epoch-1", store_id="store-1", from_sequence=1)
    with _file(root).open("ab") as stream:
        stream.write(b"not a record\n")
    with pytest.raises(RecoveryJournalUnavailable):
        FileRecoveryJournal(root).open_epochs("local")


def test_scopes_and_location_are_named(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    journal = FileRecoveryJournal(root)
    assert journal.scopes_present() == frozenset()
    journal.open_epoch("audit", "epoch-1", store_id=None, from_sequence=1)
    assert journal.scopes_present() == frozenset({"audit"})
    assert journal.location().root == root / "recovery"
    assert journal.location().kind == "file"
    assert _file(root, "audit").stat().st_mode & 0o777 == 0o600
