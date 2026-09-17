# SPDX-License-Identifier: Apache-2.0
"""The account directory of the host: the same name service `login` consults.

It is where an administrator revokes a membership, which is why it, and not
the group list a peer's processes happen to hold, is what this daemon reads
(article 6, rule G1).
"""

from __future__ import annotations

import grp
import os
import pwd
from typing import Final

from ..ports.account_directory import Account


class NssAccountDirectory:
    """`pwd`, `os.getgrouplist` and `grp`, behind the port's three questions."""

    VERSION: Final[int] = 1

    def account(self, uid: int) -> Account | None:
        try:
            entry = pwd.getpwuid(uid)
        except KeyError:
            return None
        return Account(entry.pw_name, entry.pw_gid)

    def group_ids(self, name: str, primary_gid: int) -> tuple[int, ...]:
        return tuple(dict.fromkeys(os.getgrouplist(name, primary_gid)))

    def group_name(self, gid: int) -> str | None:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None


def group_id(name: str) -> int | None:
    """The id of a named group, or None when the host has no such group."""
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def account_uid(name: str) -> int | None:
    """The id of a named account, or None when the host has no such account."""
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def account_primary_gid(name: str) -> int | None:
    """The account's own group, or None when the host has no such account.

    The group the directory records for the account itself, which is what the
    daemon drops to: not the admission list, which belongs to the principals
    the daemon governs (article 7).
    """
    try:
        return pwd.getpwnam(name).pw_gid
    except KeyError:
        return None
