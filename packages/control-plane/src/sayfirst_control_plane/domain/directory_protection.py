# SPDX-License-Identifier: Apache-2.0
"""Whether the directory holding the local address may be trusted to hold it.

Article 6 says it plainly: whoever can write that directory can unlink the
name and bind an impostor in its place. So "writable by the daemon's
principal and root only" is read literally — a group-writable directory is
refused even when the group has one member today, because the daemon cannot
prove it will have one tomorrow.

Write is write however it was granted: the mode's group bit, the mode's other
bit and an access control list are three ways of saying the same thing, and the
directory and every ancestor of it are held to all three. The one exemption is
the sticky bit on an ancestor, which bars the rename the ancestor rule exists to
stop (rule S4).

Pure: a function over what `stat` said, so every ownership case can be held
by a guard on a host with one account (rule S5). The walk over the ancestors
is its own function because it is one rule with two callers: the socket's
directory here, and the evidence root (rule L2a), which article 7 grades by
the same parents.
"""

from __future__ import annotations

import stat as stat_module
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from .write_reach import write_reaches_the_entry_below

SOCKET_DIRECTORY_UNPROTECTED: Final[str] = "socket_directory_unprotected"


@dataclass(frozen=True)
class DirectoryFacts:
    """What one `stat` (and, on Linux, one extended-attribute read) said."""

    name: str
    mode: int
    uid: int
    is_directory: bool
    has_access_acl: bool | None
    """True, False, or None where the answer was not obtained.

    On a platform with a reader, None means the read failed, which is not
    proof that no list exists; on a platform without one it means no reader
    exists (rule S6). Which of the two it is follows from `platform`.
    """


CHECKED: Final[str] = "checked"
UNVERIFIED: Final[str] = "unverified"
NOT_ON_THIS_PLATFORM: Final[str] = "not checked on this platform"


@dataclass(frozen=True)
class Verdict:
    """Protected, or refused with the reason and the name it is about."""

    refusal: str | None
    detail: str
    acl: str
    """Three values, article 2: checked, unverified, or no reader here."""

    @property
    def protected(self) -> bool:
        return self.refusal is None

    @property
    def acl_checked(self) -> bool:
        return self.acl == CHECKED


def _refused(detail: str, *, acl: str) -> Verdict:
    return Verdict(SOCKET_DIRECTORY_UNPROTECTED, detail, acl)


def directory_protection(
    *,
    st: DirectoryFacts,
    ancestors: Sequence[DirectoryFacts],
    daemon_uid: int,
    platform: str,
) -> Verdict:
    """Whether nobody but the daemon's principal and root can write the place.

    `ancestors` are the directories above it, nearest first. Each is held to
    the same three grants of write as the directory itself — group, other, and
    an access control list — because renaming the directory away needs only
    write access on its parent, and a grant is a grant however it was made. The
    one difference is rule S4's sticky exemption: a sticky ancestor bars
    everyone but an entry's owner, the directory's owner and root from
    unlinking or renaming what is under it, so write on it does not reach the
    name below.
    """
    has_reader = platform == "linux"
    if not has_reader:
        acl = NOT_ON_THIS_PLATFORM
    elif st.has_access_acl is None:
        acl = UNVERIFIED
    else:
        acl = CHECKED
    if not st.is_directory:
        return _refused(f"not a directory: {st.name}", acl=acl)
    if st.uid not in (0, daemon_uid):
        return _refused(f"owned by uid {st.uid}: {st.name}", acl=acl)
    if st.mode & (stat_module.S_IWGRP | stat_module.S_IWOTH):
        return _refused(f"writable by others: {st.name}", acl=acl)
    if has_reader:
        if st.has_access_acl is None:
            # A check that could not run is not a check that passed: the
            # directory's true reach is unverified, so the daemon fails
            # closed (article 2, article 3).
            return _refused(f"the access control list could not be read: {st.name}", acl=acl)
        if st.has_access_acl:
            return _refused(f"carries an access control list: {st.name}", acl=acl)
    replaceable = ancestors_protection(ancestors, daemon_uid=daemon_uid, platform=platform)
    if replaceable is not None:
        return _refused(replaceable, acl=acl)
    return Verdict(None, f"acl: {acl}", acl)


def ancestors_protection(
    ancestors: Sequence[DirectoryFacts], *, daemon_uid: int, platform: str
) -> str | None:
    """The first ancestor through which the place below can be replaced, named; or None.

    One rule for every directory the daemon must be able to trust to stay
    where it is: the socket's, whose name an ancestor's writer can rename away
    and bind an impostor at (article 6, rule S4), and the evidence store's,
    which article 7 grades by "every parent directory that would allow it to
    be replaced". `ancestors` are nearest first, and the caller has already
    required the directory below them to be owned by the daemon's principal or
    by root — which is what makes "anybody else" the principal each grant of
    write is read for.
    """
    has_reader = platform == "linux"
    for ancestor in ancestors:
        if ancestor.uid not in (0, daemon_uid):
            return f"an ancestor is owned by uid {ancestor.uid}: {ancestor.name}"
        if not write_reaches_the_entry_below(
            mode=ancestor.mode,
            is_directory=True,
            # Every level below this one was required by the caller to be owned
            # by the daemon's principal or by root, so the principal this asks
            # about — anybody else — owns neither this directory nor the name
            # under it (`domain/write_reach.py`).
            writer_owns_the_directory=False,
            writer_owns_the_entry=False,
        ):
            continue
        if ancestor.mode & stat_module.S_IWOTH:
            return f"an ancestor is writable by anyone and not sticky: {ancestor.name}"
        if ancestor.mode & stat_module.S_IWGRP:
            # The same sentence as rule S3, one level up: the daemon cannot
            # prove the group's membership will stay at one, and a member of it
            # renames the whole directory away rather than unlinking the socket.
            return f"an ancestor is writable by a group and not sticky: {ancestor.name}"
        if has_reader:
            if ancestor.has_access_acl is None:
                return f"an ancestor's access control list could not be read: {ancestor.name}"
            if ancestor.has_access_acl:
                return (
                    f"an ancestor carries an access control list and is not sticky: {ancestor.name}"
                )
    return None
