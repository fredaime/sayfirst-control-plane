# SPDX-License-Identifier: Apache-2.0
"""The operating system's record of the peer of a connected local stream.

One adapter per operating system, no generic adapter and no fallback: a
process that cannot read the kernel's record has no identity to offer
(article 6, article 3).
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol, runtime_checkable

NO_ID: Final[int] = 2**32 - 1
"""The kernel's "no identity" marker; never an account."""

_SOL_LOCAL: Final[int] = 0
_LOCAL_PEERCRED: Final[int] = 1
_LOCAL_PEERPID: Final[int] = 2
_XUCRED_VERSION: Final[int] = 0
_UCRED = struct.Struct("@iII")
_XUCRED_HEAD = struct.Struct("@IIh")
_XUCRED_FIRST_GROUP_OFFSET: Final[int] = 12
_XUCRED_NGROUPS: Final[int] = 16
_XUCRED = struct.Struct(f"@IIh{_XUCRED_NGROUPS}I")
"""Darwin's `struct xucred` as its kernel lays it out: `cr_version`, `cr_uid`,
`cr_ngroups`, `cr_groups[NGROUPS]`, and nothing after the group list — which is
why the peer's process id needs a second sockopt here. Other kernels spell the
structure differently (FreeBSD's ends in a union twelve bytes wider); this is
the Darwin adapter, so it reads Darwin's, and a platform without an adapter
gets no layout by resemblance (article 3).

Its size is the only length a record of this option may have; a shorter one has
been cut and a longer one is not this structure, and neither is an identity
(rule P6)."""
_GID = struct.Struct("@I")
_INT = struct.Struct("@i")


class PeerCredentialUnavailable(Exception):
    """The operating system delivered no record for this connection."""


class PeerIdentityUnsupported(Exception):
    """This platform has no adapter, so it has no identity to read."""


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class PeerCredential:
    """What the kernel said about the process that called connect()."""

    uid: int
    gid: int
    pid: int | None
    captured_at: str

    def to_document(self) -> dict[str, object]:
        return {
            "uid": self.uid,
            "gid": self.gid,
            "pid": self.pid,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_document(cls, document: dict[str, object]) -> PeerCredential:
        pid = document.get("pid")
        return cls(
            uid=int(document["uid"]),  # type: ignore[arg-type]
            gid=int(document["gid"]),  # type: ignore[arg-type]
            pid=int(pid) if isinstance(pid, int) else None,
            captured_at=str(document["captured_at"]),
        )


@runtime_checkable
class PeerIdentity(Protocol):
    """One adapter per operating system, established before the first byte."""

    VERSION: int

    def establish(self, connection: socket.socket) -> PeerCredential: ...


def _reject_non_identity(uid: int, gid: int) -> None:
    if uid == NO_ID or gid == NO_ID:
        raise PeerCredentialUnavailable("the kernel reported no identity for the peer")


class LinuxPeerIdentity:
    """SO_PEERCRED: the struct ucred the kernel recorded at connect().

    Both numbers come from `socket`, which carries them from the platform's own
    headers: `17` is the `asm-generic` value for `SO_PEERCRED` and not the value
    on every Linux port, and `SOL_SOCKET` differs on some of them too. A number
    written out by hand is not a clean failure when it is wrong — if the option
    it names on another port answers a record of the same twelve bytes, the
    length check below passes and this builds a `PeerCredential` out of bytes
    that are not a credential, which is the one thing article 6 exists to
    prevent. The Darwin constants above have no standard-library spelling,
    which is why that adapter defines them and this one does not.
    """

    VERSION: Final[int] = 1

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or _now

    def establish(self, connection: socket.socket) -> PeerCredential:
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
        except OSError as error:
            raise PeerCredentialUnavailable(str(error)) from error
        if len(raw) != _UCRED.size:
            raise PeerCredentialUnavailable("the credential record has an unexpected length")
        pid, uid, gid = _UCRED.unpack(raw)
        _reject_non_identity(uid, gid)
        return PeerCredential(
            uid=uid,
            gid=gid,
            pid=pid if pid != 0 else None,
            captured_at=self._clock().isoformat(),
        )


class DarwinPeerIdentity:
    """LOCAL_PEERCRED and LOCAL_PEERPID: the struct xucred and the peer's pid.

    Both options are read at the SOL_LOCAL level, and a record whose
    cr_version is not XUCRED_VERSION is no identity (rule P6).

    getpeereid(3) reads the same kernel record and would add a foreign-function
    binding for nothing, so it is not used.
    """

    VERSION: Final[int] = 1

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or _now

    def establish(self, connection: socket.socket) -> PeerCredential:
        try:
            raw = connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, _XUCRED.size)
        except OSError as error:
            raise PeerCredentialUnavailable(str(error)) from error
        if len(raw) != _XUCRED.size:
            raise PeerCredentialUnavailable(
                f"the credential record is {len(raw)} bytes, the structure is {_XUCRED.size}"
            )
        version, uid, group_count = _XUCRED_HEAD.unpack_from(raw, 0)
        if version != _XUCRED_VERSION:
            raise PeerCredentialUnavailable(f"credential record version {version} is not readable")
        if not 1 <= group_count <= _XUCRED_NGROUPS:
            raise PeerCredentialUnavailable(
                f"the credential record counts {group_count} groups, the structure holds "
                f"1 to {_XUCRED_NGROUPS}"
            )
        (gid,) = _GID.unpack_from(raw, _XUCRED_FIRST_GROUP_OFFSET)
        _reject_non_identity(uid, gid)
        return PeerCredential(
            uid=uid,
            gid=gid,
            pid=self._peer_pid(connection),
            captured_at=self._clock().isoformat(),
        )

    def _peer_pid(self, connection: socket.socket) -> int | None:
        """The peer's process id, or `None` when the kernel reports none.

        A sockopt that failed, or a record of the wrong length, is not "no
        process id": it is a record the adapter could not read, and a
        credential it could not read whole is unavailable (rule P6).
        """
        try:
            raw = connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, _INT.size)
        except OSError as error:
            raise PeerCredentialUnavailable(
                f"the peer's process id is unreadable: {error}"
            ) from error
        if len(raw) != _INT.size:
            raise PeerCredentialUnavailable("the process-id record has an unexpected length")
        (pid,) = _INT.unpack(raw)
        return pid if pid > 0 else None


_ADAPTERS: Final[dict[str, type]] = {"linux": LinuxPeerIdentity, "darwin": DarwinPeerIdentity}


def supported_platforms() -> tuple[str, ...]:
    """The platforms an adapter exists for, in a stable order."""
    return tuple(sorted(_ADAPTERS))


def select_peer_identity(
    platform: str, *, clock: Callable[[], datetime] | None = None
) -> PeerIdentity:
    """Return the adapter for a platform; there is no generic adapter."""
    adapter = _ADAPTERS.get(platform)
    if adapter is None:
        raise PeerIdentityUnsupported(f"no peer-credential adapter for platform {platform!r}")
    return adapter(clock)  # type: ignore[no-any-return]
