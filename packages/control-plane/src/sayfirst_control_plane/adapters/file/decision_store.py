# SPDX-License-Identifier: Apache-2.0
"""One locked, append-only JSON-lines decision file per scope, the durable authority.

The file is authoritative; the in-memory `(scope, decision_ref) -> offset`
index is a rebuildable projection of it (article 3). What the file holds is
the storage envelope, not the wire decision: a header line that establishes
the scope's opaque store identifier, then one envelope per committed decision
carrying its strictly increasing position, the recording epoch it was written
in, and the complete published decision record inside it (R3).

Durability is the protocol of C2: under the scope's lock the next position is
allocated, the whole line is written with short-write handling, the descriptor
is synced — and, for a file this append created, its directory — and only then
is the index entry published and the position answered. An error before the
first byte is a known refusal; anything after the write began is
indeterminate: no usable answer, and the scope is fenced until its tail is
recovered. A torn final suffix is quarantined and its byte count reported; a
malformed complete line or a duplicate identity is never discarded and never
chosen between, it makes the scope unavailable (R4). No operation updates or
deletes a committed decision.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Final
from uuid import uuid4

from sayfirst_contract.decisions import Decision

from sayfirst_control_plane.domain.evidence_chain import canonical_json
from sayfirst_control_plane.domain.scope import scope_matches_contract, validate_scope
from sayfirst_control_plane.ports.decision_store import (
    DecisionAlreadyExists,
    DecisionAppendIndeterminate,
    DecisionPosition,
    DecisionStoreUnavailable,
    ScopeRequired,
)
from sayfirst_control_plane.ports.evidence_store import StoreLocation

STORAGE_VERSION: Final = 1
DIRECTORY: Final = "decisions"
_LOCK_FILE: Final = ".writer.lock"
_LINE_BOUND: Final = 8 * 1024 * 1024
RETENTION: Final = (
    "indefinite, with no automatic expiry and no purge command; a decision removed by hand "
    "is disclosed by reconciliation as a missing authority, never recreated"
)


class RootHeldByAnotherWriter(RuntimeError):
    """A second writer on one root would allocate the first writer's positions."""


@dataclass(frozen=True)
class Envelope:
    """One committed record as stored: its store, its position, its epoch, its decision."""

    scope: str
    store_id: str
    position: int
    recording_epoch: str
    decision: Decision


@dataclass
class _ScopeState:
    store_id: str
    next_position: int
    offsets: dict[str, int]
    positions: dict[str, DecisionPosition]
    unusable: str | None = None
    fenced: bool = False


class FileDecisionStore:
    VERSION = 1

    def __init__(
        self, root: Path, *, exclusive: bool = False, recording_epoch: str | None = None
    ) -> None:
        self._root = Path(root)
        self._directory = self._root / DIRECTORY
        self._exclusive = exclusive
        self._epoch = recording_epoch or f"epoch:{uuid4()}"
        self._states: dict[str, _ScopeState] = {}
        self._locks_guard = Lock()
        self._locks: dict[str, Lock] = {}
        self._writer_descriptor: int | None = None
        self.recovered_bytes: dict[str, int] = {}

    # -- locks and layout ------------------------------------------------------

    def _lock_for(self, scope: str) -> Lock:
        with self._locks_guard:
            return self._locks.setdefault(scope, Lock())

    def _file_for(self, scope: str) -> Path:
        validate_scope(scope)
        return self._directory / f"{scope}.jsonl"

    def _ensure_directory(self) -> None:
        if self._directory.is_dir():
            return
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self._directory, 0o700)
        _sync_directory(self._root)

    def hold_root(self) -> None:
        """Take the one-writer lock of this root, refusing a second writer by name."""
        if self._writer_descriptor is not None:
            return
        self._ensure_directory()
        descriptor = os.open(self._directory / _LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            raise RootHeldByAnotherWriter(
                f"{self._directory}: another writer holds this decision root"
            ) from None
        self._writer_descriptor = descriptor

    def close(self) -> None:
        if self._writer_descriptor is not None:
            os.close(self._writer_descriptor)
            self._writer_descriptor = None

    # -- the authority -----------------------------------------------------------

    def append(self, decision: Decision) -> DecisionPosition:
        scope = decision.scope
        target = self._file_for(scope)
        with self._lock_for(scope):
            if self._exclusive:
                self.hold_root()
            self._ensure_directory()
            state = self._state_locked(scope, target)
            if state.unusable is not None:
                raise DecisionStoreUnavailable(f"scope {scope!r}: {state.unusable}")
            if decision.decision_ref in state.offsets:
                raise DecisionAlreadyExists((scope, decision.decision_ref))
            created = not target.exists()
            descriptor = self._open(target)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                if state.fenced:
                    self._recover_tail(scope, descriptor)
                    state = self._state_locked(scope, target, rescan=True)
                    if decision.decision_ref in state.offsets:
                        raise DecisionAlreadyExists((scope, decision.decision_ref))
                if created or os.fstat(descriptor).st_size == 0:
                    self._write_header(descriptor, scope, state.store_id)
                position = state.next_position
                envelope = {
                    "storage_version": STORAGE_VERSION,
                    "scope": scope,
                    "store_id": state.store_id,
                    "position": position,
                    "recording_epoch": self._epoch,
                    "decision": decision.to_document(),
                }
                payload = canonical_json(envelope) + b"\n"
                if len(payload) > _LINE_BOUND:
                    raise DecisionStoreUnavailable("a decision record exceeds the byte bound")
                offset = os.lseek(descriptor, 0, os.SEEK_END)
                self._write_all(scope, state, descriptor, payload)
                if created:
                    _sync_directory(self._directory)
            finally:
                os.close(descriptor)
            placed = DecisionPosition(state.store_id, position)
            state.offsets[decision.decision_ref] = offset
            state.positions[decision.decision_ref] = placed
            state.next_position = position + 1
            return placed

    def _write_all(self, scope: str, state: _ScopeState, descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        try:
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        except OSError as error:
            # The first byte may be on disk: the scope is fenced until its
            # tail is examined, and no usable answer leaves here (C2).
            state.fenced = True
            raise DecisionAppendIndeterminate(
                f"scope {scope!r}: the append began and its completion could not be "
                f"established ({error})"
            ) from error

    def _write_header(self, descriptor: int, scope: str, store_id: str) -> None:
        header = {
            "storage_version": STORAGE_VERSION,
            "header": {"scope": scope, "store_id": store_id},
        }
        payload = canonical_json(header) + b"\n"
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)

    def get(self, scope: str, decision_ref: str) -> Decision | None:
        if not scope:
            raise ScopeRequired("a decision read must name a scope")
        target = self._file_for(scope)
        with self._lock_for(scope):
            if not target.exists():
                return None
            state = self._state_locked(scope, target)
            if state.unusable is not None:
                raise DecisionStoreUnavailable(f"scope {scope!r}: {state.unusable}")
            offset = state.offsets.get(decision_ref)
            if offset is None:
                return None
            with target.open("rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
                stream.seek(offset)
                line = stream.readline()
            try:
                return _read_envelope(json.loads(line), scope).decision
            except (ValueError, KeyError, TypeError) as error:
                state.unusable = f"the record at offset {offset} is malformed: {error}"
                raise DecisionStoreUnavailable(f"scope {scope!r}: {state.unusable}") from error

    def position_of(self, scope: str, decision_ref: str) -> DecisionPosition | None:
        if not scope:
            raise ScopeRequired("a decision read must name a scope")
        target = self._file_for(scope)
        with self._lock_for(scope):
            if not target.exists():
                return None
            state = self._state_locked(scope, target)
            if state.unusable is not None:
                raise DecisionStoreUnavailable(f"scope {scope!r}: {state.unusable}")
            return state.positions.get(decision_ref)

    def scan(self, scope: str) -> Iterator[Envelope]:
        """Every committed envelope of a scope in position order, read from the file itself.

        Not a public read: reconciliation walks the authority as stored, never
        through the index. A malformed complete line stops the walk with the
        scope's unavailability, never by skipping the line (R4).
        """
        validate_scope(scope)
        target = self._file_for(scope)
        if not target.exists():
            return
        with self._lock_for(scope):
            state = self._state_locked(scope, target)
            if state.unusable is not None:
                raise DecisionStoreUnavailable(f"scope {scope!r}: {state.unusable}")
            with target.open("rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
                raw = stream.read()
        # The same reading the index makes of the file: a suffix without its
        # newline is torn whether or not its bytes parse, and is no record.
        lines, _ = _complete_lines(raw)
        for line in lines[1:]:
            yield _read_envelope(json.loads(line), scope)

    def store_id_of(self, scope: str) -> str | None:
        """The opaque identifier of a scope's store, or `None` before its first append."""
        target = self._file_for(scope)
        with self._lock_for(scope):
            if not target.exists():
                return None
            state = self._state_locked(scope, target)
            return state.store_id or None

    def scopes_present(self) -> frozenset[str]:
        if not self._directory.is_dir():
            return frozenset()
        return frozenset(
            entry.stem
            for entry in self._directory.iterdir()
            if entry.suffix == ".jsonl" and scope_matches_contract(entry.stem)
        )

    def recover(self, scope: str) -> int:
        """Quarantine a torn final suffix now, and answer how many bytes were dropped (R4).

        A torn suffix is bytes an append never acknowledged: nothing links to
        them and no caller received a position for them. Removing them is not
        removing a record; leaving them would refuse every further append.
        """
        target = self._file_for(scope)
        with self._lock_for(scope):
            if not target.exists():
                return 0
            descriptor = os.open(target, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                dropped = self._recover_tail(scope, descriptor)
            finally:
                os.close(descriptor)
            self._state_locked(scope, target, rescan=True)
            return dropped

    def location(self) -> StoreLocation:
        return StoreLocation(kind="file", root=self._directory, retention=RETENTION)

    # -- the projection: an index rebuilt from the file -------------------------

    def _state_locked(self, scope: str, target: Path, *, rescan: bool = False) -> _ScopeState:
        state = self._states.get(scope)
        if state is not None and not rescan:
            return state
        if not target.exists():
            state = _ScopeState(f"store:{uuid4()}", 1, {}, {})
            self._states[scope] = state
            return state
        with target.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            raw = stream.read()
        state = self._rebuild(scope, raw)
        self._states[scope] = state
        return state

    def _rebuild(self, scope: str, raw: bytes) -> _ScopeState:
        lines, tail = _complete_lines(raw)
        offsets: dict[str, int] = {}
        positions: dict[str, DecisionPosition] = {}
        store_id: str | None = None
        next_position = 1
        offset = 0
        unusable: str | None = None
        for index, line in enumerate(lines):
            try:
                document = json.loads(line)
                if index == 0:
                    store_id = _read_header(document, scope)
                else:
                    assert store_id is not None
                    envelope = _read_envelope(document, scope)
                    if envelope.store_id != store_id:
                        raise ValueError("an envelope names another store")
                    if envelope.position != next_position:
                        raise ValueError(
                            f"position {envelope.position} where {next_position} was expected"
                        )
                    reference = envelope.decision.decision_ref
                    if reference in offsets:
                        raise ValueError(f"decision {reference!r} is recorded twice")
                    offsets[reference] = offset
                    positions[reference] = DecisionPosition(store_id, envelope.position)
                    next_position = envelope.position + 1
            except (ValueError, KeyError, TypeError, AssertionError) as error:
                unusable = f"line {index + 1} is not a usable record: {error}"
                break
            offset += len(line) + 1
        if store_id is None and unusable is None:
            if lines:
                unusable = "the header line is missing"
            else:
                store_id = f"store:{uuid4()}"
        return _ScopeState(
            store_id or "", next_position, offsets, positions, unusable, fenced=bool(tail)
        )

    def _recover_tail(self, scope: str, descriptor: int) -> int:
        size = os.lseek(descriptor, 0, os.SEEK_END)
        if size == 0 or os.pread(descriptor, 1, size - 1) == b"\n":
            if scope in self._states:
                self._states[scope].fenced = False
            return 0
        window = min(size, _LINE_BOUND + 1)
        tail = os.pread(descriptor, window, size - window)
        keep = size - window + tail.rindex(b"\n") + 1 if b"\n" in tail else 0
        os.ftruncate(descriptor, keep)
        os.fsync(descriptor)
        dropped = size - keep
        self.recovered_bytes[scope] = self.recovered_bytes.get(scope, 0) + dropped
        state = self._states.get(scope)
        if state is not None:
            state.fenced = False
        return dropped

    @staticmethod
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


def _complete_lines(raw: bytes) -> tuple[list[bytes], bytes]:
    """The lines an append finished, and the suffix one did not (R4).

    A record is complete when its newline is on disk: the newline is the last
    byte an append writes, and canonical JSON carries no newline of its own,
    so a suffix after the last newline was never acknowledged, whatever its
    bytes happen to parse as. Every reader of the file makes this one cut.
    """
    complete, _, tail = raw.rpartition(b"\n")
    return (complete.split(b"\n") if complete else []), tail


def _read_header(document: object, scope: str) -> str:
    if not isinstance(document, dict) or document.get("storage_version") != STORAGE_VERSION:
        raise ValueError("the header names no supported storage version")
    header = document.get("header")
    if not isinstance(header, dict) or header.get("scope") != scope:
        raise ValueError("the header names another scope")
    store_id = header.get("store_id")
    if not isinstance(store_id, str) or not store_id:
        raise ValueError("the header names no store")
    return store_id


def _read_envelope(document: object, scope: str) -> Envelope:
    if not isinstance(document, dict) or document.get("storage_version") != STORAGE_VERSION:
        raise ValueError("an envelope names no supported storage version")
    if document.get("scope") != scope:
        raise ValueError("an envelope names another scope")
    position = document.get("position")
    if not isinstance(position, int) or isinstance(position, bool) or position < 1:
        raise ValueError("an envelope's position must be a positive integer")
    store_id = document.get("store_id")
    epoch = document.get("recording_epoch")
    if not isinstance(store_id, str) or not store_id or not isinstance(epoch, str) or not epoch:
        raise ValueError("an envelope names no store or no epoch")
    decision = document.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("an envelope carries no decision")
    read = Decision.from_document(decision)
    if read.scope != scope:
        raise ValueError("the decision names another scope than its envelope")
    return Envelope(scope, store_id, position, epoch, read)


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
