# SPDX-License-Identifier: Apache-2.0
"""One immutable file per policy version, named by the digest of its bytes."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from threading import Lock
from typing import Final

from sayfirst_control_plane.ports.evidence_store import StoreLocation
from sayfirst_control_plane.ports.policy_archive import ArchivedPolicy, ArchiveState

_VERSION: Final = re.compile(r"^sha256:([0-9a-f]{64})$")
_TEMPORARY_PREFIX: Final = "."
_TEMPORARY_SUFFIX_MARK: Final = ".tmp-"
DIRECTORY: Final = "policy"
RETENTION: Final = (
    "indefinite, with no automatic expiry and no purge command: a version outlives every "
    "decision and effect that names it, and bytes removed by hand are disclosed as absent, "
    "never repaired from the current policy"
)


def version_of(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class FilePolicyArchive:
    """`<root>/policy/<hex>.toml`, written once through a temporary file and never rewritten.

    Publication is atomic and durable (C1): the bytes go to a unique temporary
    in the same directory, the file is synced, it is linked into place by a
    rename that overwrites no final file, and the directory is synced. A
    crash before the rename leaves an orphan temporary that `recover` removes
    without ever reading it as a version; a crash after leaves a version
    nobody has named yet, which is harmless and kept.
    """

    VERSION = 1

    def __init__(self, root: Path) -> None:
        self._directory = Path(root) / DIRECTORY
        self._lock = Lock()

    def _path_of(self, version: str) -> Path:
        found = _VERSION.fullmatch(version)
        if found is None:
            raise ValueError("a policy version is sha256: and sixty-four lowercase hex digits")
        return self._directory / f"{found.group(1)}.toml"

    def _ensure_directory(self) -> None:
        if self._directory.is_dir():
            return
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._directory, 0o700)
        _sync_directory(self._directory.parent)

    def keep(self, version: str, content: bytes) -> ArchivedPolicy:
        """Keep `content` under `version`; refuse a mismatch; rewrite nothing that is there."""
        target = self._path_of(version)
        if version_of(content) != version:
            raise ValueError("the bytes do not hash to the version they were offered under")
        with self._lock:
            existing = self._read_locked(version, target)
            if existing.state is not ArchiveState.absent:
                return existing
            self._ensure_directory()
            temporary = self._directory / (
                f"{_TEMPORARY_PREFIX}{target.stem}{_TEMPORARY_SUFFIX_MARK}{os.getpid()}-{id(self)}"
            )
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                view = memoryview(content)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                # `link` then `unlink` rather than `rename`: a final file that
                # appeared in the meantime is never overwritten (A2, A4).
                os.link(temporary, target)
            except FileExistsError:
                os.unlink(temporary)
                _sync_directory(self._directory)
                return self._read_locked(version, target)
            os.unlink(temporary)
            _sync_directory(self._directory)
            return ArchivedPolicy(version, ArchiveState.present, bytes(content))

    def read(self, version: str) -> ArchivedPolicy:
        target = self._path_of(version)
        with self._lock:
            return self._read_locked(version, target)

    def _read_locked(self, version: str, target: Path) -> ArchivedPolicy:
        try:
            content = target.read_bytes()
        except FileNotFoundError:
            return ArchivedPolicy(version, ArchiveState.absent, None)
        if version_of(content) != version:
            return ArchivedPolicy(version, ArchiveState.damaged, None)
        return ArchivedPolicy(version, ArchiveState.present, content)

    def recover(self) -> tuple[str, ...]:
        """Remove the orphan temporaries a crash before publication left; name them.

        A temporary is bytes nobody published: no version names it and no
        decision was taken on the strength of it, so removing it removes no
        record (article 3). It is never read as a version.
        """
        if not self._directory.is_dir():
            return ()
        removed = []
        with self._lock:
            for entry in sorted(self._directory.iterdir()):
                if (
                    entry.name.startswith(_TEMPORARY_PREFIX)
                    and _TEMPORARY_SUFFIX_MARK in entry.name
                ):
                    entry.unlink()
                    removed.append(entry.name)
            if removed:
                _sync_directory(self._directory)
        return tuple(removed)

    def location(self) -> StoreLocation:
        return StoreLocation(kind="file", root=self._directory, retention=RETENTION)


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
