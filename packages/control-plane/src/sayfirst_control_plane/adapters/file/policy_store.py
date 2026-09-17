# SPDX-License-Identifier: Apache-2.0
"""A read-only TOML policy authority on the daemon host."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from ...access.effective_access import protection, write_access
from ...domain.policy import PolicyInvalid, Principal, parse_policy, policy_version
from ...ports.policy_store import (
    AccessState,
    AccessVerdict,
    LoadedPolicy,
    PolicyUnavailable,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

MAX_POLICY_BYTES = 1_048_576


def _read_from(descriptor: int, limit: int) -> bytes:
    """Up to `limit` bytes from the start of `descriptor`, whatever its offset.

    `pread` and not `read`: the descriptor a start check judged has never been
    read, but nothing here should depend on that, and a file offset is state a
    second caller could have moved.
    """
    chunks: list[bytes] = []
    read = 0
    while read < limit:
        chunk = os.pread(descriptor, limit - read, read)
        if not chunk:
            break
        chunks.append(chunk)
        read += len(chunk)
    return b"".join(chunks)


class FilePolicyStore:
    """Read an administrator-owned file without ever creating or changing it."""

    VERSION = 1

    def __init__(
        self,
        path: Path,
        *,
        max_lifetime_seconds: int = 3600,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.max_lifetime_seconds = max_lifetime_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._judged_at_start: int | None = None

    def load(self) -> LoadedPolicy | PolicyUnavailable:
        """The bytes this name reaches, or why none can be claimed for it.

        Opened once, and the name read again while that descriptor is still
        open: the bytes answered here are the bytes of the file the name
        reached, or this says it does not know which file they came from. A
        second open would be a second file, and holding the first is what stops
        the inode number in the comparison from being handed to a file created
        in between (article 3, article 8).

        When a start check has just run, the descriptor it judged is the one
        read here rather than a second open of the name — see
        `protection_at_start`.
        """
        judged, self._judged_at_start = self._judged_at_start, None
        if judged is not None:
            try:
                return self._policy_from(judged)
            finally:
                os.close(judged)
        try:
            descriptor = os.open(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return PolicyUnavailable(
                "absent",
                f"policy file {self.path} is absent; an empty rule list denies everything",
            )
        except OSError as exc:
            return PolicyUnavailable("unreadable", f"policy file {self.path} is unreadable: {exc}")
        try:
            return self._policy_from(descriptor)
        finally:
            os.close(descriptor)

    def _policy_from(self, descriptor: int) -> LoadedPolicy | PolicyUnavailable:
        """The policy of the file `descriptor` names, if the name still reaches it."""
        try:
            raw = _read_from(descriptor, MAX_POLICY_BYTES + 1)
            opened = os.fstat(descriptor)
            named = os.stat(self.path)
        except FileNotFoundError:
            return PolicyUnavailable(
                "absent",
                f"policy file {self.path} is absent; an empty rule list denies everything",
            )
        except OSError as exc:
            return PolicyUnavailable("unreadable", f"policy file {self.path} is unreadable: {exc}")
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            return PolicyUnavailable(
                "changed_while_read",
                f"policy file {self.path} named another file while it was being read",
            )
        if len(raw) > MAX_POLICY_BYTES:
            return PolicyUnavailable(
                "too_large", f"policy file {self.path} exceeds {MAX_POLICY_BYTES} bytes"
            )
        parsed = parse_policy(raw, max_lifetime_seconds=self.max_lifetime_seconds)
        if isinstance(parsed, PolicyInvalid):
            return PolicyUnavailable(parsed.reason, parsed.message)
        return LoadedPolicy(parsed, policy_version(raw), self._clock(), len(raw), raw)

    def protection_at_start(self, expectation: ProtectionExpectation) -> ProtectionVerdict:
        """Whether the whole name is protected, bound to the file the start will read.

        The binding within this call is the descriptor held across the walk.
        The binding *across* the start sequence is this: a `protected` verdict
        keeps that descriptor open, and the `load` that follows reads it rather
        than opening the name a second time. Two opens were two files — a name
        retargeted between them gave a verdict about one and bytes from
        another, each call internally consistent and the pair about nothing
        (article 8, article 3).

        Only a `protected` verdict keeps it, because only a `protected` verdict
        is followed by a load; a second start check releases whatever the last
        one held, and so does collection, so at most one descriptor is ever
        open for this reason and none outlives the store.

        The binding is the start's and nothing else's: a start runs once,
        before this daemon serves anyone, so the one descriptor is never
        reached by two threads. The same two-call gap exists per decision in
        system mode, between `write_access_of` and the load that follows it,
        and it is *not* closed here — instance state cannot bind a pair of
        calls that concurrent handler threads are making at once. Closing it
        needs a binding passed through the port, which is its own change.
        """
        self._release()
        descriptor = self._held()
        keep = False
        try:
            verdict = protection(
                self.path,
                allowed_owner_uids=expectation.allowed_owner_uids,
                allowed_write_gids=expectation.allowed_write_gids,
            )
            if descriptor is not None and not self._name_still_reaches(descriptor):
                return ProtectionVerdict(
                    ProtectionState.UNKNOWN, self.path, "changed_while_checked"
                )
            keep = descriptor is not None and verdict.kind is ProtectionState.PROTECTED
        finally:
            if descriptor is not None and not keep:
                os.close(descriptor)
            self._judged_at_start = descriptor if keep else None
        return verdict

    def _release(self) -> None:
        """Drop a descriptor a start check kept that no load ever came for."""
        judged, self._judged_at_start = self._judged_at_start, None
        if judged is not None:
            os.close(judged)

    def __del__(self) -> None:
        """A store that is collected between the two calls keeps nothing open."""
        with contextlib.suppress(Exception):  # interpreter shutdown
            self._release()

    def write_access_of(self, principal: Principal) -> AccessVerdict:
        """What this principal could do to the policy this name reaches.

        The walk answers about names. This binds the answer to a file: a
        descriptor of what the name reached is held open for the whole of the
        walk, and the name is read again at the end of it. A name that moved
        under the check is an unknown, never the `not_writable` the walk
        happened to compute about a file nobody is going to open (article 3).
        """
        descriptor = self._held()
        try:
            verdict = write_access(self.path, principal.uid, principal.gids)
            if descriptor is not None and not self._name_still_reaches(descriptor):
                return AccessVerdict(AccessState.UNKNOWN, self.path, "changed_while_checked")
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return verdict

    def _held(self) -> int | None:
        """A read descriptor of what this name reaches, or `None` when it reaches nothing.

        `None` leaves the walk to say what it finds and why, which is what it
        already says about an absent, looping or unreadable name.
        """
        try:
            return os.open(self.path, os.O_RDONLY)
        except OSError:
            return None

    def _name_still_reaches(self, descriptor: int) -> bool:
        """Whether the configured name still reaches the file that descriptor names."""
        try:
            named = os.stat(self.path)
            held = os.fstat(descriptor)
        except OSError:
            return False
        return (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)
