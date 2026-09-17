# SPDX-License-Identifier: Apache-2.0
"""The immutable, content-addressed archive of every policy version a decision names.

Article 3 makes the policy file the authority for a decision and article 10
wants an export a reader can check; a version is a digest, and a digest does
not recover its bytes. The archive keeps the exact bytes the authority read,
under the version their digest names, so that a reader holding an export and
the contract wheel can re-derive the recorded answer from the bytes the daemon
actually decided on (article 13). It records historical authoritative inputs;
it is never a writable policy authority, and nothing here promotes a kept copy
to the source of live policy (A4).

The archive carries no scope: a policy file is one administrator-owned file
whose rules each carry their own scope, so no single scope is true of its
bytes. That is its own article 5 exception, entry 3 of `docs/exceptions.md`,
with a restoration condition of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .evidence_store import StoreLocation


class ArchiveState(StrEnum):
    present = "present"
    absent = "absent"
    damaged = "damaged"


@dataclass(frozen=True)
class ArchivedPolicy:
    """One version as the archive answers it: the bytes, or why there are none.

    `content` is present only for `present`. `absent` is for bytes that are
    not there; `damaged` for bytes that no longer hash to their name; storage
    the archive could not read is an `OSError`, never an absence (article 2).
    """

    version: str
    state: ArchiveState
    content: bytes | None


class PolicyArchive(Protocol):
    VERSION = 1

    def keep(self, version: str, content: bytes) -> ArchivedPolicy: ...

    def read(self, version: str) -> ArchivedPolicy: ...

    def location(self) -> StoreLocation: ...
