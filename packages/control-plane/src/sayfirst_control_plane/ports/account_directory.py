# SPDX-License-Identifier: Apache-2.0
"""The port that answers what an id is called and which groups it belongs to.

It exists so that a revocation can be tested without a directory service, and
so that the one blocking call this daemon makes sits behind a seam with a
bound (article 8: a port, one version, adapters behind it).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from ..domain.foreign import core_owned


@dataclass(frozen=True)
class Account:
    """What the directory knows an id by."""

    name: str
    primary_gid: int


@runtime_checkable
class AccountDirectory(Protocol):
    """Resolves ids to names and memberships."""

    VERSION: int

    def account(self, uid: int) -> Account | None:
        """The account of a user id, or None when the id has none."""
        ...

    def group_ids(self, name: str, primary_gid: int) -> tuple[int, ...]:
        """Every group id the account belongs to, the primary one included."""
        ...

    def group_name(self, gid: int) -> str | None:
        """The name of a group id, or None when the id has no entry."""
        ...


ACCOUNT_DIRECTORY_VERSION: Final[int] = 1


def account_of(directory: AccountDirectory, uid: int) -> Account | None:
    """Who the directory says a uid is, as the core's own value (rule G1).

    The account decides three things in sequence — whether the peer is admitted,
    what kind the configuration gives it, and what name the principal records —
    and each of those is a separate read of the same object. A directory that
    answered one name to the admission check and another to the record would be
    admitted as one account and recorded as another (articles 3 and 6).
    """
    answer = directory.account(uid)
    return None if answer is None else core_owned(Account, answer, name=str, primary_gid=int)


def group_ids_of(directory: AccountDirectory, name: str, primary_gid: int) -> tuple[int, ...]:
    """The memberships the directory answers, as numbers the core owns."""
    return tuple(int(gid) for gid in directory.group_ids(name, primary_gid))


def group_name_of(directory: AccountDirectory, gid: int) -> str | None:
    """The name the directory gives a group id, as text the core owns."""
    answer = directory.group_name(gid)
    return None if answer is None else str(answer)
