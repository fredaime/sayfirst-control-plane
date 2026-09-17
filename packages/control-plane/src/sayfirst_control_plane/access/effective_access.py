# SPDX-License-Identifier: Apache-2.0
"""Conservative write and replacement access over a whole naming path."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import stat
import struct
import sys
from pathlib import Path
from typing import Final

from ..domain.write_reach import write_reaches_the_entry_below
from ..ports.policy_store import (
    AccessState,
    AccessVerdict,
    ProtectionState,
    ProtectionVerdict,
)

_ACL_VERSION = 2
_ACL_USER = 0x02
_ACL_GROUP = 0x08
_ACL_MASK = 0x10
_ACL_WRITE = 0x02
_NO_ACL_ERRNOS = {
    value
    for value in (
        getattr(errno, "ENODATA", None),
        getattr(errno, "ENOATTR", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
}


class _AclUnreadable(OSError):
    pass


#: How many links deep a naming path may go before it is called a loop. The
#: number the kernel uses for the same question on Linux.
_MAX_LINKS: Final[int] = 40


def _naming_chains(path: Path) -> tuple[tuple[Path, ...], ...]:
    """Every name that decides which file `path` reaches, deepest first per chain.

    This resolved the path and then walked the components of the *resolved*
    one, which is the whole of the defect: the store opens the configured name,
    and every name between the configured one and the resolved one — a symlink
    and the directories that hold it — was inspected by nobody. Control of a
    name is control of which file is opened, so a link in a directory others
    can write let a foreign principal choose the policy while this reported
    `not_writable` for that same principal (article 8).

    A path is therefore walked component by component, and it produces a chain
    per segment: the components up to and including a symlink, then the
    components of what that link names, and so on to the file the name reaches.
    Each chain is deepest first — the entry, then the directories above it —
    because that is the order the replacement question is asked in, and every
    component above depth zero in a chain is a directory that is not itself a
    link, so its own `parents` are the real directories above it.

    The name is made absolute *without* being normalised, because `normpath`
    is not how a path is read. `os.path.abspath` is `normpath` of a join, and
    `normpath` collapses `link/..` to nothing before any component is looked
    at: a `..` written after a symlink deleted the one component that decided
    the answer, and the walk judged a file the kernel never opens. `Path.cwd()
    / path` joins and keeps every component, and `_extend` walks `..` the way
    the kernel does.
    """
    chains: list[tuple[Path, ...]] = []
    _extend(Path.cwd() / path, chains, 0)
    return tuple(chains)


def _extend(absolute: Path, chains: list[tuple[Path, ...]], links: int) -> None:
    """Walk one segment of the name, a chain per link, `..` as the kernel takes it.

    `..` is a lookup like any other: the kernel resolves the components before
    it, and *then* steps back over the one it arrives at. So the component a
    `..` pops is a name that decides which file is reached — replace it with a
    link and the `..` lands somewhere else — and it is walked as its own chain
    before it is popped. Popping cannot skip a link, because a link is split
    off into a recursion the moment it is reached, so `current` here is never
    one; at the root, stepping back stays at the root, as it does in the
    kernel.
    """
    if links > _MAX_LINKS:
        raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), str(absolute))
    current = Path(absolute.anchor or "/")
    parts = absolute.parts[1:]
    for index, part in enumerate(parts):
        if part == "..":
            chains.append((current, *current.parents))
            current = current.parent
            continue
        current = current / part
        if current.is_symlink():
            chains.append((current, *current.parents))
            target = Path(os.readlink(current))
            base = target if target.is_absolute() else current.parent / target
            _extend(base.joinpath(*parts[index + 1 :]), chains, links + 1)
            return
    chains.append((current, *current.parents))


def _acl(path: Path) -> tuple[tuple[int, int, int], ...]:
    if sys.platform == "darwin":
        if _macos_acl_present(path):
            raise _AclUnreadable("macOS access-control list presence cannot be evaluated")
        return ()
    try:
        raw = os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
    except OSError as exc:
        if exc.errno in _NO_ACL_ERRNOS:
            return ()
        raise _AclUnreadable(str(exc)) from exc
    if len(raw) < 4 or (len(raw) - 4) % 8:
        raise _AclUnreadable("access-control list has an invalid length")
    version = struct.unpack_from("<I", raw)[0]
    if version != _ACL_VERSION:
        raise _AclUnreadable("access-control list has an unknown version")
    return tuple(struct.unpack_from("<HHI", raw, offset) for offset in range(4, len(raw), 8))


def _macos_acl_present(path: Path) -> bool:
    library_name = ctypes.util.find_library("c")
    if library_name is None:
        raise _AclUnreadable("C library cannot be found for access-control-list inspection")
    library = ctypes.CDLL(library_name, use_errno=True)
    library.acl_get_file.argtypes = (ctypes.c_char_p, ctypes.c_int)
    library.acl_get_file.restype = ctypes.c_void_p
    library.acl_get_entry.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    )
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_free.argtypes = (ctypes.c_void_p,)
    acl = library.acl_get_file(os.fsencode(path), 0x00000100)
    if not acl:
        raise _AclUnreadable("macOS access-control list cannot be inspected")
    try:
        entry = ctypes.c_void_p()
        return library.acl_get_entry(acl, 0, ctypes.byref(entry)) == 0
    finally:
        library.acl_free(acl)


def _acl_writers(
    entries: tuple[tuple[int, int, int], ...],
) -> tuple[frozenset[int], frozenset[int]]:
    mask = next((permissions for tag, permissions, _ in entries if tag == _ACL_MASK), 7)
    users = frozenset(
        identifier
        for tag, permissions, identifier in entries
        if tag == _ACL_USER and permissions & mask & _ACL_WRITE
    )
    groups = frozenset(
        identifier
        for tag, permissions, identifier in entries
        if tag == _ACL_GROUP and permissions & mask & _ACL_WRITE
    )
    return users, groups


def write_access(path: Path, uid: int, gids: tuple[int, ...]) -> AccessVerdict:
    """Say whether a principal can mutate the file or replace it through any name.

    Through *any parent* is what the walk is for, and it is also where a
    directory's write permission stops being the same thing as write access to
    what is under it: a sticky ancestor grants the creating and withholds the
    unlinking (`domain/write_reach.py`). Without that reading this answered that
    every principal on a host with a sticky directory on the path could replace
    the file — and article 8 refuses a decision to a principal that could write
    the authority, so in system mode that answer serves nobody.

    Through *any name* is the other half. Every chain of the naming path is
    walked, so a link this principal can retarget is write access to what the
    name reaches, whatever the bits on the file at the end of it say.
    """
    try:
        chains = _naming_chains(path)
    except OSError as exc:
        return AccessVerdict(AccessState.UNKNOWN, path, f"stat_failed: {exc}")
    unknown: AccessVerdict | None = None
    for chain in chains:
        verdict = _write_access_along(chain, uid, gids)
        if verdict.kind is AccessState.WRITABLE:
            return verdict
        if verdict.kind is AccessState.UNKNOWN and unknown is None:
            unknown = verdict
    return unknown or AccessVerdict(AccessState.NOT_WRITABLE)


def _write_access_along(
    components: tuple[Path, ...], uid: int, gids: tuple[int, ...]
) -> AccessVerdict:
    """One chain of the naming path, from the entry it ends at up to the root."""
    entry_uid: int | None = None
    for depth, component in enumerate(components):
        try:
            metadata = component.lstat()
            entries = _acl(component)
        except OSError as exc:
            reason = "acl_unreadable" if isinstance(exc, _AclUnreadable) else "stat_failed"
            return AccessVerdict(AccessState.UNKNOWN, component, f"{reason}: {exc}")
        if uid == 0:
            return AccessVerdict(AccessState.WRITABLE, component, "root")
        owns = uid == metadata.st_uid
        reaches = depth == 0 or write_reaches_the_entry_below(
            mode=metadata.st_mode,
            is_directory=stat.S_ISDIR(metadata.st_mode),
            writer_owns_the_directory=owns,
            writer_owns_the_entry=uid == entry_uid,
        )
        # A symlink's own mode is `0o777` on every POSIX system and its owner
        # cannot rewrite it in place: what a link grants is granted by the
        # directory that holds it, one component up, and by the chain its
        # target begins. Reading its bits would call every link on every host
        # world-writable, which is not a finding, it is noise.
        if reaches and not stat.S_ISLNK(metadata.st_mode):
            if owns:
                return AccessVerdict(AccessState.WRITABLE, component, "owner")
            acl_users, acl_groups = _acl_writers(entries)
            if uid in acl_users or acl_groups.intersection(gids):
                return AccessVerdict(AccessState.WRITABLE, component, "acl_write")
            if metadata.st_gid in gids and metadata.st_mode & stat.S_IWGRP:
                return AccessVerdict(AccessState.WRITABLE, component, "group_write")
            if metadata.st_mode & stat.S_IWOTH:
                return AccessVerdict(AccessState.WRITABLE, component, "other_write")
        entry_uid = metadata.st_uid
    return AccessVerdict(AccessState.NOT_WRITABLE)


def protection(
    path: Path,
    *,
    allowed_owner_uids: frozenset[int],
    allowed_write_gids: frozenset[int],
) -> ProtectionVerdict:
    """Prove that every possible effective writer, on every name, is an administrator."""
    try:
        chains = _naming_chains(path)
    except OSError as exc:
        return ProtectionVerdict(ProtectionState.UNKNOWN, path, f"stat_failed: {exc}")
    unknown: ProtectionVerdict | None = None
    for chain in chains:
        verdict = _protection_along(
            chain,
            allowed_owner_uids=allowed_owner_uids,
            allowed_write_gids=allowed_write_gids,
        )
        if verdict.kind is ProtectionState.EXPOSED:
            return verdict
        if verdict.kind is ProtectionState.UNKNOWN and unknown is None:
            unknown = verdict
    return unknown or ProtectionVerdict(ProtectionState.PROTECTED)


def _protection_along(
    components: tuple[Path, ...],
    *,
    allowed_owner_uids: frozenset[int],
    allowed_write_gids: frozenset[int],
) -> ProtectionVerdict:
    """One chain of the naming path, judged against the expected administrators."""
    for depth, component in enumerate(components):
        try:
            metadata = component.lstat()
            entries = _acl(component)
        except OSError as exc:
            reason = "acl_unreadable" if isinstance(exc, _AclUnreadable) else "stat_failed"
            return ProtectionVerdict(ProtectionState.UNKNOWN, component, reason)
        if metadata.st_uid not in allowed_owner_uids:
            return ProtectionVerdict(ProtectionState.EXPOSED, component, "owner")
        if stat.S_ISLNK(metadata.st_mode):
            # As in `_write_access_along`: a link's own bits grant nothing. Its
            # owner has already been required to be an administrator above, and
            # what could replace it is the directory one component up.
            continue
        if _entries_are_replaceable(metadata, depth):
            acl_users, acl_groups = _acl_writers(entries)
            if not acl_users.issubset(allowed_owner_uids) or not acl_groups.issubset(
                allowed_write_gids
            ):
                return ProtectionVerdict(ProtectionState.EXPOSED, component, "acl_write")
            if metadata.st_mode & stat.S_IWGRP and metadata.st_gid not in allowed_write_gids:
                return ProtectionVerdict(ProtectionState.EXPOSED, component, "group_write")
            if metadata.st_mode & stat.S_IWOTH:
                return ProtectionVerdict(ProtectionState.EXPOSED, component, "other_write")
    return ProtectionVerdict(ProtectionState.PROTECTED)


def _entries_are_replaceable(metadata: os.stat_result, depth: int) -> bool:
    """Whether writing this component lets somebody replace what is under it.

    On the authority file itself — depth zero — write access *is* the exposure,
    and no bit excuses it. On a directory above it the question is the shared
    one (`domain/write_reach.py`), asked about every principal outside
    `allowed_owner_uids`: this component and the one below it were both
    required to be owned by a uid inside that set, so such a principal owns
    neither, and a sticky ancestor leaves the authority where it is however the
    write on it was granted — by a mode bit or by an access control list. That
    is why this is asked before the three grants rather than as an exception to
    one of them.
    """
    if depth == 0:
        return True
    return write_reaches_the_entry_below(
        mode=metadata.st_mode,
        is_directory=stat.S_ISDIR(metadata.st_mode),
        writer_owns_the_directory=False,
        writer_owns_the_entry=False,
    )
