# SPDX-License-Identifier: Apache-2.0
"""Scripted doubles of the ports, mutable between calls so a test can revoke.

These are doubles of the conformance kit, never providers a configuration may
name (article 8: the kit is the contract of a port, not an implementation of
it that a deployment could accidentally activate).
"""

from __future__ import annotations

import socket
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

from sayfirst_contract.transport.peer import PeerCredential, PeerCredentialUnavailable
from sayfirst_control_plane.ports.account_directory import Account


class FixedClock:
    """A clock a test moves by hand."""

    VERSION: Final[int] = 1

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 9, 4, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


class StaticPeerIdentity:
    """A scripted credential, or a scripted absence of one."""

    VERSION: Final[int] = 1

    def __init__(
        self,
        credential: PeerCredential | None = None,
        *,
        unavailable: bool = False,
        by_socket: Mapping[int, PeerCredential] | None = None,
    ) -> None:
        self.credential = credential
        self.unavailable = unavailable
        self.by_socket = dict(by_socket or {})
        self.calls = 0

    def establish(self, connection: socket.socket) -> PeerCredential:
        self.calls += 1
        if self.unavailable:
            raise PeerCredentialUnavailable("scripted absence of a credential")
        scripted = self.by_socket.get(id(connection))
        if scripted is not None:
            return scripted
        if self.credential is None:
            raise PeerCredentialUnavailable("scripted absence of a credential")
        return self.credential


class DirectoryOutage(Exception):
    """The scripted directory cannot be consulted."""


class StaticAccountDirectory:
    """A scripted table of accounts and memberships, mutable between calls."""

    VERSION: Final[int] = 1

    def __init__(
        self,
        accounts: Mapping[int, tuple[str, int]] | None = None,
        memberships: Mapping[str, Sequence[int]] | None = None,
        group_names: Mapping[int, str] | None = None,
        *,
        outage: bool = False,
        delay_seconds: float = 0.0,
    ) -> None:
        self.accounts = dict(accounts or {})
        self.memberships = {name: tuple(gids) for name, gids in (memberships or {}).items()}
        self.group_names = dict(group_names or {})
        self.outage = outage
        self.delay_seconds = delay_seconds
        self.calls: list[tuple[str, object]] = []

    def _consult(self, call: str, argument: object) -> None:
        self.calls.append((call, argument))
        if self.delay_seconds:
            import time

            time.sleep(self.delay_seconds)
        if self.outage:
            raise DirectoryOutage("the scripted directory cannot be consulted")

    def account(self, uid: int) -> Account | None:
        self._consult("account", uid)
        entry = self.accounts.get(uid)
        return None if entry is None else Account(entry[0], entry[1])

    def group_ids(self, name: str, primary_gid: int) -> tuple[int, ...]:
        self._consult("group_ids", name)
        listed = self.memberships.get(name)
        if listed is None:
            return (primary_gid,)
        return tuple(dict.fromkeys((primary_gid, *listed)))

    def group_name(self, gid: int) -> str | None:
        self._consult("group_name", gid)
        return self.group_names.get(gid)

    def revoke(self, name: str, gid: int) -> None:
        """Take a membership away between two calls, as an administrator would."""
        self.memberships[name] = tuple(
            item for item in self.memberships.get(name, ()) if item != gid
        )

    def grant(self, name: str, gid: int) -> None:
        self.memberships[name] = (*self.memberships.get(name, ()), gid)
