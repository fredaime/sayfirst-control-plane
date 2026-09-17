# SPDX-License-Identifier: Apache-2.0
"""Building the principal the daemon serves from what the host says about a uid.

Article 6: identity is the operating system's. A uid is an account, and an
account is what the operating system calls a user whether a person or a job
holds it — so a principal established from a peer credential is of kind
`user` unless the configuration says otherwise.

The kinds form an open registry, never a closed enumeration: a value outside
the documented four is recorded exactly as given. Group names likewise are
used exactly as the directory returned them; canonicalising them across
directory services is the administrator's responsibility.

Pure: this module names instants but never reads a clock.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Final

from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import (
    ESTABLISHED_BY_PEER_CREDENTIAL,
    WELL_KNOWN_KINDS,
    GroupsStatus,
    Principal,
)

from ..ports.account_directory import (
    Account,
    AccountDirectory,
    account_of,
    group_ids_of,
    group_name_of,
)

KIND_USER: Final[str] = "user"
RESOLVED: Final[GroupsStatus] = GroupsStatus.RESOLVED
PARTIAL: Final[GroupsStatus] = GroupsStatus.PARTIAL
UNKNOWN: Final[GroupsStatus] = GroupsStatus.UNKNOWN

__all__ = [
    "KIND_USER",
    "PARTIAL",
    "RESOLVED",
    "UNKNOWN",
    "WELL_KNOWN_KINDS",
    "GroupResolution",
    "GroupsStatus",
    "build_principal",
    "differs_beyond_establishment",
    "kind_for",
    "resolve_identity",
    "unknown_resolution",
]


@dataclass(frozen=True)
class GroupResolution:
    """What the directory answered about a membership, and how completely."""

    groups: tuple[str, ...] | None
    status: GroupsStatus
    unnamed_group_ids: tuple[int, ...]


def unknown_resolution() -> GroupResolution:
    """The membership of a peer whose directory could not be consulted."""
    return GroupResolution(None, UNKNOWN, ())


def resolve_identity(
    directory: AccountDirectory, uid: int, primary_gid: int
) -> tuple[Account | None, GroupResolution]:
    """Ask the directory who a uid is and which groups it belongs to.

    A uid with no account keeps its primary group: no account is not no
    identity (rule G1). Whatever the directory raises travels to the caller,
    which turns it into the connection's `unknown` state (rule G5).

    The account handed back is the core's own (`account_of`), because the
    caller reads its name again — for the kind the configuration gives it and
    for the name the principal records — and a directory that answers a name
    twice is a directory that may answer two names (article 3).
    """
    account = account_of(directory, uid)
    gids = (
        group_ids_of(directory, account.name, account.primary_gid)
        if account is not None
        else (primary_gid,)
    )
    names: list[str] = []
    unnamed: list[int] = []
    for gid in gids:
        name = group_name_of(directory, gid)
        if name is None:
            unnamed.append(gid)
        else:
            names.append(name)
    status = PARTIAL if unnamed else RESOLVED
    return account, GroupResolution(tuple(names), status, tuple(unnamed))


def kind_for(account: Account | None, account_kinds: Mapping[str, str]) -> str:
    """The kind the configuration gives an account, or the one a uid always has."""
    if account is None:
        return KIND_USER
    return account_kinds.get(account.name, KIND_USER)


def build_principal(
    credential: PeerCredential,
    account: Account | None,
    resolution: GroupResolution,
    *,
    kind: str,
    at: str,
) -> Principal:
    """The identity a decision is evaluated against. It carries no process id."""
    return Principal(
        kind=kind,
        uid=credential.uid,
        gid=credential.gid,
        name=None if account is None else account.name,
        groups=resolution.groups,
        groups_status=resolution.status,
        unnamed_group_ids=resolution.unnamed_group_ids,
        established_by=ESTABLISHED_BY_PEER_CREDENTIAL,
        established_at=at,
    )


def differs_beyond_establishment(before: Principal, after: Principal) -> bool:
    """Whether two resolutions of one connection differ in anything that matters.

    Every member but `established_at` decides: re-resolving an unchanged
    account produces a new instant and nothing else, and evidence that
    claimed an identity had changed then would be claiming something that
    did not happen (rule G3, article 2).
    """
    return replace(before, established_at=after.established_at) != after
