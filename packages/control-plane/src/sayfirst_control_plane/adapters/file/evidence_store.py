# SPDX-License-Identifier: Apache-2.0
"""One locked, append-only JSON-lines evidence chain per scope."""

from __future__ import annotations

import fcntl
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Final

from sayfirst_control_plane.domain.evidence_chain import (
    DAEMON_CONNECTION,
    EvidenceEntry,
    EvidenceRecord,
    Principal,
    canonical_json,
    chained,
    chained_after_break,
    entry_from_document,
    entry_to_document,
    entry_verifies,
)
from sayfirst_control_plane.domain.scope import scope_matches_contract, validate_scope
from sayfirst_control_plane.ports.clock import Clock
from sayfirst_control_plane.ports.evidence_store import StoreLocation

_ENTRY_BOUND: Final = 524_288
_TAIL_BOUND: Final = _ENTRY_BOUND + 1
_RECOVERY_PRINCIPAL: Final = Principal("service", "daemon")


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FileEvidenceStore:
    def __init__(self, root: Path, *, clock: Clock | None = None) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._clock = clock or _SystemClock()
        self._locks_guard = Lock()
        self._locks: dict[str, Lock] = {}

    def _lock_for(self, scope: str) -> Lock:
        with self._locks_guard:
            return self._locks.setdefault(scope, Lock())

    def _file_for(self, scope: str) -> Path:
        validate_scope(scope)
        return self._root / f"{scope}.jsonl"

    def chains_present(self) -> frozenset[str]:
        """The scope of every chain already in the root, named or not by any rule.

        A chain is named by its scope, so an entry whose name is not a scope's
        is not a chain: no request can name it and no record is ever owed to
        it, and the daemon says nothing about it. What is listed is what the
        daemon owes a proof for at start (rule L2a): a chain that is there and
        cannot be appended to is one the daemon would be owed a record on the
        first time a caller names its scope.
        """
        return frozenset(
            entry.stem
            for entry in self._root.iterdir()
            if entry.suffix == ".jsonl" and scope_matches_contract(entry.stem)
        )

    def prepare_chain(self, scope: str) -> Path:
        """Create the scope's chain if absent, then reopen it; the daemon's start check.

        One append through a creation descriptor proves less than the daemon
        claims by serving (article 2): not that the file can be opened again —
        a permissive umask once left the first chain at mode 000, appendable
        through the descriptor that created it and through nothing else — not
        that a chain can be created for another scope, and not that a chain
        already there is one this account can append to. Each is proved here
        as this process, and refused with the file it is about; none of the
        three repairs itself, so none is left to a later retry (article 10).
        """
        target = self._file_for(scope)
        with self._lock_for(scope):
            existed = os.path.lexists(target)
            doing = "opening the existing chain" if existed else "creating the chain"
            try:
                os.close(self._open_chain(target))
            except OSError as error:
                raise _while(doing, target, error) from error
            try:
                os.close(os.open(target, os.O_RDWR | os.O_APPEND))
            except OSError as error:
                raise _while("reopening the chain for append", target, error) from error
        return target

    def _open_chain(self, target: Path) -> int:
        """Open the chain for append, creating it at 0600 — a mode held, not asked for.

        `O_CREAT` applies its mode through the umask, so the mode is set on
        the descriptor of a file this call itself created (`O_EXCL` says which)
        and on nothing that was already there: an existing chain keeps whatever
        an operator gave it, and the spec's "created at 0600" is the daemon's
        own claim about its own files (rule L2a, article 7).
        """
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

    def append(self, record: EvidenceRecord) -> EvidenceEntry:
        target = self._file_for(record.scope)
        with self._lock_for(record.scope):
            descriptor = self._open_chain(target)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                torn = self._recover_torn_tail(descriptor)
                previous = self._last_entry(descriptor)
                if torn:
                    previous = self._write(descriptor, self._torn_gap(record.scope, previous))
                entry = self._place(record, previous)
                self._write(descriptor, entry)
                return entry
            finally:
                os.close(descriptor)

    def _place(self, record: EvidenceRecord, previous: EvidenceEntry | None) -> EvidenceEntry:
        """Place the record, and leave a predecessor that does not verify visible.

        Refusing to record anything more because one stored line does not
        recompute would let a single flipped byte stop a scope's evidence for
        good. Article 10 declares the damage instead: the entry names the
        stored predecessor as it stands and the verifier reports `broken_at`
        there, so the recorder keeps recording and the reader keeps being told.
        """
        if previous is not None and not entry_verifies(previous):
            return chained_after_break(record, previous)
        return chained(record, previous)

    def _write(self, descriptor: int, entry: EvidenceEntry) -> EvidenceEntry:
        payload = canonical_json(entry_to_document(entry)) + b"\n"
        if len(payload) > _ENTRY_BOUND:
            raise ValueError("evidence entry exceeds the byte bound")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        return entry

    def _recover_torn_tail(self, descriptor: int) -> bool:
        """Drop the trailing bytes that never became an entry; keep every entry.

        A process that died mid-append leaves bytes after the last newline.
        They are not an entry: no append completed for them, nothing links to
        them, and no reader has ever seen them. Removing them is not removing a
        record (article 3) — and leaving them would refuse every further append
        to this scope for good, which is a denial of evidence, not a protection.
        The loss is declared by the caller of this method as a `torn` gap.
        """
        size = os.lseek(descriptor, 0, os.SEEK_END)
        if size == 0 or os.pread(descriptor, 1, size - 1) == b"\n":
            return False
        keep = 0
        window = min(size, _TAIL_BOUND)
        tail = os.pread(descriptor, window, size - window)
        if b"\n" in tail:
            keep = size - window + tail.rindex(b"\n") + 1
        elif window < size:
            raise ValueError("the incomplete evidence entry exceeds the bounded tail")
        os.ftruncate(descriptor, keep)
        os.lseek(descriptor, 0, os.SEEK_END)
        os.fsync(descriptor)
        return True

    def _torn_gap(self, scope: str, previous: EvidenceEntry | None) -> EvidenceEntry:
        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return an offset-aware instant")
        instant = now.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        gap = EvidenceRecord(
            scope,
            "gap",
            now,
            DAEMON_CONNECTION,
            _RECOVERY_PRINCIPAL,
            {
                "reason": "torn",
                "count": 1,
                "first_at": instant,
                "last_at": instant,
                "kinds": {},
            },
        )
        return self._place(gap, previous)

    def _last_entry(self, descriptor: int) -> EvidenceEntry | None:
        size = os.lseek(descriptor, 0, os.SEEK_END)
        if size == 0:
            return None
        amount = min(size, 4096)
        while amount <= min(size, _TAIL_BOUND):
            os.lseek(descriptor, size - amount, os.SEEK_SET)
            tail = os.read(descriptor, amount)
            if tail.endswith(b"\n"):
                complete = tail[:-1]
            elif b"\n" in tail:
                complete = tail.rsplit(b"\n", 1)[0]
            else:
                complete = b""
            if complete and (size == amount or b"\n" in complete):
                line = complete.rsplit(b"\n", 1)[-1]
                document = json.loads(line)
                if not isinstance(document, dict):
                    raise ValueError("stored evidence entry is not an object")
                return entry_from_document(document)
            if amount in (size, _TAIL_BOUND):
                break
            amount = min(size, _TAIL_BOUND, amount * 2)
        raise ValueError("stored evidence entry exceeds the bounded tail")

    def read_range(
        self, scope: str, *, from_sequence: int, to_sequence: int | None = None
    ) -> tuple[EvidenceEntry, ...]:
        _validate_range(scope, from_sequence, to_sequence)
        target = self._file_for(scope)
        if not target.exists():
            return ()
        with self._lock_for(scope), target.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            raw = stream.read()
        lines = raw.splitlines() if raw.endswith(b"\n") else raw.splitlines()[:-1]
        entries = []
        for line in lines:
            document = json.loads(line)
            if not isinstance(document, dict):
                raise ValueError("stored evidence entry is not an object")
            entry = entry_from_document(document)
            if entry.sequence >= from_sequence and (
                to_sequence is None or entry.sequence <= to_sequence
            ):
                entries.append(entry)
        return tuple(entries)

    def latest_sequence(self, scope: str) -> int | None:
        target = self._file_for(scope)
        if not target.exists():
            return None
        with self._lock_for(scope):
            descriptor = os.open(target, os.O_RDONLY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH)
                entry = self._last_entry(descriptor)
            finally:
                os.close(descriptor)
        return entry.sequence if entry is not None else None

    def location(self) -> StoreLocation:
        return StoreLocation(
            kind="file",
            root=self._root,
            retention=(
                "kept until an operator removes the file; there is no purge command in this "
                "version and a partial removal is an undeclared gap the verifier refuses"
            ),
        )


def _while(doing: str, target: Path, error: OSError) -> OSError:
    """The same refusal the host gave, saying what the store was doing to which file."""
    return OSError(error.errno, f"{doing}: {error.strerror}", str(target))


def _validate_range(scope: str, start: int, end: int | None) -> None:
    validate_scope(scope)
    if start < 1 or (end is not None and end < start):
        raise ValueError("evidence range is invalid")
