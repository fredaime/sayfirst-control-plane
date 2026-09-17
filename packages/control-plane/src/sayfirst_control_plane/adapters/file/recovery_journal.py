# SPDX-License-Identifier: Apache-2.0
"""One append-only JSON-lines coordination journal per scope, `<root>/recovery/<scope>.jsonl`."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from threading import Lock
from typing import Final

from sayfirst_control_plane.domain.evidence_chain import canonical_json
from sayfirst_control_plane.domain.scope import scope_matches_contract, validate_scope
from sayfirst_control_plane.ports.evidence_store import StoreLocation
from sayfirst_control_plane.ports.recovery_journal import JournalRecord, RecoveryJournalUnavailable

JOURNAL_VERSION: Final = 1
DIRECTORY: Final = "recovery"
RECORDS: Final = ("epoch_open", "epoch_clean", "epoch_reconciled")
_LINE_BOUND: Final = 65_536
RETENTION: Final = (
    "indefinite; the journal records where evidence coverage is known and where it is not, "
    "and a journal removed by hand leaves every epoch it named as unknown coverage"
)


class FileRecoveryJournal:
    """Header, record and torn-tail rules as for the decision store; positions per scope."""

    VERSION = 1

    def __init__(self, root: Path) -> None:
        self._directory = Path(root) / DIRECTORY
        self._locks_guard = Lock()
        self._locks: dict[str, Lock] = {}

    def _lock_for(self, scope: str) -> Lock:
        with self._locks_guard:
            return self._locks.setdefault(scope, Lock())

    def _file_for(self, scope: str) -> Path:
        validate_scope(scope)
        return self._directory / f"{scope}.jsonl"

    def _ensure_directory(self) -> None:
        if self._directory.is_dir():
            return
        self._directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self._directory, 0o700)
        _sync_directory(self._directory.parent)

    # -- appends -----------------------------------------------------------------

    def open_epoch(
        self, scope: str, epoch_id: str, *, store_id: str | None, from_sequence: int
    ) -> None:
        self._append(
            scope,
            {
                "record": "epoch_open",
                "epoch_id": epoch_id,
                "store_id": store_id,
                "from_sequence": from_sequence,
                "marker_sequence": None,
                "marker_hash": None,
            },
        )

    def epoch_clean(
        self, scope: str, epoch_id: str, *, marker_sequence: int | None, marker_hash: str | None
    ) -> None:
        self._append(
            scope,
            {
                "record": "epoch_clean",
                "epoch_id": epoch_id,
                "store_id": None,
                "from_sequence": None,
                "marker_sequence": marker_sequence,
                "marker_hash": marker_hash,
            },
        )

    def epoch_reconciled(
        self, scope: str, epoch_id: str, *, marker_sequence: int | None, marker_hash: str | None
    ) -> None:
        self._append(
            scope,
            {
                "record": "epoch_reconciled",
                "epoch_id": epoch_id,
                "store_id": None,
                "from_sequence": None,
                "marker_sequence": marker_sequence,
                "marker_hash": marker_hash,
            },
        )

    def _append(self, scope: str, members: dict[str, object]) -> None:
        target = self._file_for(scope)
        with self._lock_for(scope):
            self._ensure_directory()
            created = not target.exists()
            descriptor = _open(target)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                records = self._read_locked(scope, descriptor)
                position = (records[-1].position if records else 0) + 1
                lines: list[bytes] = []
                if created or os.fstat(descriptor).st_size == 0:
                    lines.append(
                        canonical_json(
                            {"journal_version": JOURNAL_VERSION, "header": {"scope": scope}}
                        )
                        + b"\n"
                    )
                lines.append(
                    canonical_json(
                        {
                            "journal_version": JOURNAL_VERSION,
                            "scope": scope,
                            "position": position,
                            **members,
                        }
                    )
                    + b"\n"
                )
                payload = b"".join(lines)
                view = memoryview(payload)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fsync(descriptor)
                if created:
                    _sync_directory(self._directory)
            except OSError as error:
                raise RecoveryJournalUnavailable(f"scope {scope!r}: {error}") from error
            finally:
                os.close(descriptor)

    # -- reads -------------------------------------------------------------------

    def open_epochs(self, scope: str) -> tuple[JournalRecord, ...]:
        """Every epoch opened and neither closed cleanly nor reconciled, oldest first."""
        target = self._file_for(scope)
        if not target.exists():
            return ()
        with self._lock_for(scope):
            descriptor = os.open(target, os.O_RDONLY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH)
                records = self._read_locked(scope, descriptor)
            finally:
                os.close(descriptor)
        closed = {item.epoch_id for item in records if item.record != "epoch_open"}
        return tuple(
            item for item in records if item.record == "epoch_open" and item.epoch_id not in closed
        )

    def records(self, scope: str) -> tuple[JournalRecord, ...]:
        target = self._file_for(scope)
        if not target.exists():
            return ()
        with self._lock_for(scope):
            descriptor = os.open(target, os.O_RDONLY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH)
                return self._read_locked(scope, descriptor)
            finally:
                os.close(descriptor)

    def _read_locked(self, scope: str, descriptor: int) -> tuple[JournalRecord, ...]:
        size = os.lseek(descriptor, 0, os.SEEK_END)
        raw = os.pread(descriptor, size, 0) if size else b""
        complete, _, _ = raw.rpartition(b"\n")
        lines = complete.split(b"\n") if complete else []
        records: list[JournalRecord] = []
        for index, line in enumerate(lines):
            try:
                document = json.loads(line)
                if (
                    not isinstance(document, dict)
                    or document.get("journal_version") != JOURNAL_VERSION
                ):
                    raise ValueError("no supported journal version")
                if index == 0:
                    header = document.get("header")
                    if not isinstance(header, dict) or header.get("scope") != scope:
                        raise ValueError("the header names another scope")
                    continue
                records.append(_read_record(document, scope, len(records) + 1))
            except (ValueError, KeyError, TypeError) as error:
                raise RecoveryJournalUnavailable(
                    f"scope {scope!r}: journal line {index + 1} is not a usable record: {error}"
                ) from error
        return tuple(records)

    def recover(self, scope: str) -> int:
        """Quarantine a torn final suffix now; answer how many bytes were dropped."""
        target = self._file_for(scope)
        with self._lock_for(scope):
            if not target.exists():
                return 0
            descriptor = os.open(target, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                size = os.lseek(descriptor, 0, os.SEEK_END)
                if size == 0 or os.pread(descriptor, 1, size - 1) == b"\n":
                    return 0
                window = min(size, _LINE_BOUND + 1)
                tail = os.pread(descriptor, window, size - window)
                keep = size - window + tail.rindex(b"\n") + 1 if b"\n" in tail else 0
                os.ftruncate(descriptor, keep)
                os.fsync(descriptor)
                return size - keep
            finally:
                os.close(descriptor)

    def scopes_present(self) -> frozenset[str]:
        if not self._directory.is_dir():
            return frozenset()
        return frozenset(
            entry.stem
            for entry in self._directory.iterdir()
            if entry.suffix == ".jsonl" and scope_matches_contract(entry.stem)
        )

    def location(self) -> StoreLocation:
        return StoreLocation(kind="file", root=self._directory, retention=RETENTION)


def _read_record(document: dict, scope: str, expected_position: int) -> JournalRecord:
    if document.get("scope") != scope:
        raise ValueError("a record names another scope")
    record = document.get("record")
    if record not in RECORDS:
        raise ValueError("a record names no known kind")
    position = document.get("position")
    if position != expected_position:
        raise ValueError(f"position {position!r} where {expected_position} was expected")
    epoch_id = document.get("epoch_id")
    if not isinstance(epoch_id, str) or not epoch_id:
        raise ValueError("a record names no epoch")
    store_id = document.get("store_id")
    from_sequence = document.get("from_sequence")
    marker_sequence = document.get("marker_sequence")
    marker_hash = document.get("marker_hash")
    for name, value in (("from_sequence", from_sequence), ("marker_sequence", marker_sequence)):
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 1
        ):
            raise ValueError(f"{name} must be a positive integer or null")
    if record == "epoch_open" and from_sequence is None:
        raise ValueError("an epoch_open record names where the epoch begins")
    return JournalRecord(
        scope,
        int(position),
        str(record),
        epoch_id,
        store_id if isinstance(store_id, str) else None,
        from_sequence,
        marker_sequence,
        marker_hash if isinstance(marker_hash, str) else None,
    )


def _open(target: Path) -> int:
    try:
        descriptor = os.open(target, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return os.open(target, os.O_RDWR | os.O_APPEND)
    try:
        os.fchmod(descriptor, 0o600)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
