# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import dataclasses
import socket
import struct
import sys
from pathlib import Path
from typing import Final

import pytest
from sayfirst_contract.transport import peer as peer_module
from sayfirst_contract.transport.peer import (
    DarwinPeerIdentity,
    LinuxPeerIdentity,
    PeerCredential,
    PeerCredentialUnavailable,
    PeerIdentity,
    PeerIdentityUnsupported,
    select_peer_identity,
    supported_platforms,
)
from sayfirst_testing.peer_identity_contract import run_the_peer_identity_contract
from sayfirst_testing.platforms import requires_platform

pytestmark = pytest.mark.identity


@requires_platform("linux")
def test_peer_credentials_are_read_through_the_platform_adapter(tmp_path: Path) -> None:
    """Article 6: the peer credential comes from the operating system's own record."""
    run_the_peer_identity_contract(
        select_peer_identity(sys.platform), bound_at=tmp_path / "listener.sock"
    )


@requires_platform("darwin")
def test_peer_credentials_are_read_through_the_darwin_adapter(tmp_path: Path) -> None:
    """Article 6: the same conformance suite binds the second operating system.

    This is the only guard that reads a real `struct xucred` off a real kernel,
    so it is the only proof that the Darwin layout is Darwin's. No host but a
    macOS runner can hold it; the CI matrix must run it there, and the gate
    check refuses a run in which it skipped instead
    (`scripts/require_platform_guards.py`). On every other host it is reported
    as not runnable, never counted as held.
    """
    run_the_peer_identity_contract(
        select_peer_identity("darwin"), bound_at=tmp_path / "listener.sock"
    )


def test_the_darwin_adapter_is_an_interface_on_every_platform() -> None:
    """Article 6: the second adapter exists as an interface wherever it cannot run."""
    adapter = select_peer_identity("darwin")
    assert isinstance(adapter, DarwinPeerIdentity)
    assert isinstance(adapter, PeerIdentity)
    assert adapter.VERSION == 1
    assert isinstance(select_peer_identity("linux"), LinuxPeerIdentity)


def test_the_adapter_selector_has_no_generic_adapter() -> None:
    """Article 6 and article 3: no adapter means no identity, so no fallback."""
    for platform in ("win32", "freebsd14", "sunos5", ""):
        with pytest.raises(PeerIdentityUnsupported):
            select_peer_identity(platform)


@requires_platform("linux")
def test_a_credential_the_os_did_not_deliver_is_unavailable() -> None:
    """Article 2: absence of a credential is an unknown, not an identity."""
    adapter = select_peer_identity("linux")
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as inet,
        pytest.raises(PeerCredentialUnavailable),
    ):
        adapter.establish(inet)


def test_a_credential_is_immutable_and_renders_its_absent_pid_as_null() -> None:
    """Article 6, rule P4: a pid the kernel does not report is null, never zero."""
    credential = PeerCredential(uid=1000, gid=1000, pid=None, captured_at="2026-09-04T00:00:00Z")
    with pytest.raises(dataclasses.FrozenInstanceError):
        credential.uid = 0  # type: ignore[misc]
    assert credential.to_document()["pid"] is None


DARWIN_XUCRED_SIZE: Final[int] = 76
"""`sizeof(struct xucred)` on Darwin: `cr_version` (4), `cr_uid` (4),
`cr_ngroups` (2), two bytes of padding, `cr_groups[16]` (64). Apple's
`sys/ucred.h` ends the structure there."""

FREEBSD_XUCRED_SIZE: Final[int] = 88
"""The same five fields plus FreeBSD's trailing `union { void *; pid_t; }`,
which Darwin does not have. A record of this length is not what macOS
delivers, and this adapter is Darwin's."""


def _xucred(
    *,
    version: int = 0,
    uid: int = 501,
    group_count: int = 1,
    gid: int = 20,
    size: int = DARWIN_XUCRED_SIZE,
) -> bytes:
    """One Darwin `struct xucred`, with the fields a test sets.

    `cr_version`, `cr_uid`, `cr_ngroups`, then `cr_groups[16]` from offset 12:
    76 bytes, and nothing after the group list.
    """
    import struct

    record = bytearray(DARWIN_XUCRED_SIZE)
    struct.pack_into("@IIh", record, 0, version, uid, group_count)
    struct.pack_into("@I", record, 12, gid)
    if size <= DARWIN_XUCRED_SIZE:
        return bytes(record[:size])
    return bytes(record) + bytes(size - DARWIN_XUCRED_SIZE)


class _Kernel:
    """A far end that answers the two sockopts the Darwin adapter reads.

    `pid_answer` is the process id the second sockopt reports, or the bytes it
    answers with, or the error it raises.
    """

    def __init__(self, credential_record: bytes, pid_answer: object = 4242) -> None:
        self.credential_record = credential_record
        self.pid_answer = pid_answer

    def getsockopt(self, level: int, option: int, size: int) -> bytes:
        import struct

        if option == 1:
            return self.credential_record
        if isinstance(self.pid_answer, OSError):
            raise self.pid_answer
        if isinstance(self.pid_answer, int):
            return struct.pack("@i", self.pid_answer)
        return self.pid_answer  # type: ignore[return-value]


def test_a_darwin_credential_record_of_the_wrong_length_is_unavailable() -> None:
    """Article 6, rule P6: "the buffer had the wrong length" is not an identity."""
    whole = DarwinPeerIdentity().establish(_Kernel(_xucred()))  # type: ignore[arg-type]
    assert (whole.uid, whole.gid, whole.pid) == (501, 20, 4242)
    for size in (0, 12, 16, 75, 77, FREEBSD_XUCRED_SIZE, 128):
        with pytest.raises(PeerCredentialUnavailable):
            DarwinPeerIdentity().establish(_Kernel(_xucred(size=size)))  # type: ignore[arg-type]


def test_a_malformed_darwin_credential_record_is_unavailable() -> None:
    """Article 6, rule P6, and article 3: a record read only in part is refused."""
    for record in (
        _xucred(version=1),
        _xucred(group_count=0),
        _xucred(group_count=-1),
        _xucred(group_count=17),
        _xucred(uid=2**32 - 1),
        _xucred(gid=2**32 - 1),
    ):
        with pytest.raises(PeerCredentialUnavailable):
            DarwinPeerIdentity().establish(_Kernel(record))  # type: ignore[arg-type]


def test_a_darwin_credential_without_a_readable_process_id_is_unavailable() -> None:
    """Article 6, rule P6: a sockopt that failed is an unknown, not an identity."""
    good = DarwinPeerIdentity().establish(_Kernel(_xucred()))  # type: ignore[arg-type]
    assert good == PeerCredential(uid=501, gid=20, pid=4242, captured_at=good.captured_at)
    for answer in (OSError(22, "Invalid argument"), b"\0", b"\0" * 9):
        with pytest.raises(PeerCredentialUnavailable):
            DarwinPeerIdentity().establish(_Kernel(_xucred(), answer))  # type: ignore[arg-type]


def test_a_darwin_process_id_of_zero_is_null_and_not_a_refusal() -> None:
    """Article 6, rule P4: a pid the kernel does not report is null, never zero."""
    assert DarwinPeerIdentity().establish(_Kernel(_xucred(), 0)).pid is None  # type: ignore[arg-type]


def test_the_darwin_adapter_reads_the_layout_darwin_publishes() -> None:
    """Article 6, rule P6: the adapter reads macOS's record, not another kernel's.

    Apple's `struct xucred` ends at `cr_groups[NGROUPS]`; FreeBSD's carries a
    trailing union and is twelve bytes longer. An adapter that demands the
    FreeBSD length refuses every credential macOS delivers, so a daemon on
    macOS refuses every peer and the client's verification never completes.
    This lane is Linux, so the record is played back through a scripted
    kernel; the OS-real proof is
    `test_peer_credentials_are_read_through_the_darwin_adapter`, which only a
    macOS runner can hold.
    """
    darwin_record = _xucred(uid=501, gid=20)
    assert len(darwin_record) == DARWIN_XUCRED_SIZE
    credential = DarwinPeerIdentity().establish(_Kernel(darwin_record))  # type: ignore[arg-type]
    assert (credential.uid, credential.gid) == (501, 20)
    with pytest.raises(PeerCredentialUnavailable):
        DarwinPeerIdentity().establish(  # type: ignore[arg-type]
            _Kernel(_xucred(size=FREEBSD_XUCRED_SIZE))
        )


def test_no_adapter_reads_a_layout_no_platform_it_serves_publishes() -> None:
    """Article 3: a layout is chosen by platform, never guessed.

    The selector has one adapter per platform and no generic one, so every
    structure the transport unpacks belongs to a platform it names. FreeBSD is
    not one of those platforms, and no FreeBSD layout is carried "just in
    case": a record it alone produces is refused, not read.
    """
    assert supported_platforms() == ("darwin", "linux")
    with pytest.raises(PeerIdentityUnsupported):
        select_peer_identity("freebsd14")
    layouts = {
        name: value for name, value in vars(peer_module).items() if isinstance(value, struct.Struct)
    }
    assert layouts, "the transport unpacks no structure at all"
    assert FREEBSD_XUCRED_SIZE not in {layout.size for layout in layouts.values()}, layouts
    assert peer_module._XUCRED.size == DARWIN_XUCRED_SIZE


class _RecordingKernel:
    """A far end that records which socket option it was asked for."""

    def __init__(self, record: bytes) -> None:
        self.record = record
        self.asked: list[tuple[int, int]] = []

    def getsockopt(self, level: int, option: int, size: int) -> bytes:
        self.asked.append((level, option))
        return self.record[:size]


@requires_platform("linux")
def test_the_linux_adapter_asks_for_the_option_number_the_platform_defines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Article 6: identity is the operating system's, and so is the number that carries it.

    `_SO_PEERCRED = 17` was the `asm-generic` value written out by hand. It is
    not the value on every Linux port, and `SOL_SOCKET` differs on some of
    them; the spec pins the mechanism — `getsockopt(SOL_SOCKET, SO_PEERCRED)` —
    and CPython already carries both numbers from the platform's own headers.
    The bad case is not a clean failure: if the option that carries a
    hand-written number on another port answers a record of the same twelve
    bytes, the length check passes and the daemon builds a `PeerCredential` out
    of bytes that are not a credential — the one thing article 6 exists to
    prevent. This moves the platform's number and requires the adapter's to
    move with it.
    """
    import struct

    monkeypatch.setattr(socket, "SO_PEERCRED", 4217, raising=True)
    monkeypatch.setattr(socket, "SOL_SOCKET", 4201, raising=True)
    kernel = _RecordingKernel(struct.pack("@iII", 4242, 1000, 1000))
    credential = LinuxPeerIdentity().establish(kernel)  # type: ignore[arg-type]
    assert (credential.uid, credential.gid, credential.pid) == (1000, 1000, 4242)
    assert kernel.asked == [(4201, 4217)], kernel.asked
