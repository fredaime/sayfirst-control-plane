# SPDX-License-Identifier: Apache-2.0
"""Who this daemon serves, decided from the credential and the directory alone.

The kernel already enforced the admission list when the peer connected; this
restates it so the evidence says who was admitted and on what basis, and so a
revocation in the directory takes effect within the identity's lifetime
rather than at the peer's next login (article 6, rules A1 to A6).

Pure: nothing here reads a clock, a process name, an environment variable or
a request. A process id is not a parameter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sayfirst_contract.transport.peer import PeerCredential

from ..ports.account_directory import AccountDirectory, account_of, group_ids_of

PEER_NOT_ADMITTED: Final[str] = "peer_not_admitted"
PER_USER: Final[str] = "per_user"
SYSTEM: Final[str] = "system"
MODES: Final[tuple[str, ...]] = (PER_USER, SYSTEM)


@dataclass(frozen=True)
class Admission:
    """Admitted, or refused with the one code that says why."""

    refusal: str | None

    @property
    def admitted(self) -> bool:
        return self.refusal is None


ADMITTED: Final[Admission] = Admission(None)
REFUSED: Final[Admission] = Admission(PEER_NOT_ADMITTED)


def is_unmapped(credential: PeerCredential, *, overflow_uid: int, overflow_gid: int) -> bool:
    """Whether the kernel reported the overflow id, which is not an identity.

    An id from another user namespace with no mapping here is refused before
    anything is asked of the directory: it is never mapped to an account,
    never admitted "as the overflow user", never read as root's or the
    daemon's (rule P5).
    """
    return credential.uid == overflow_uid or credential.gid == overflow_gid


def admit(
    *,
    credential: PeerCredential,
    mode: str,
    daemon_uid: int,
    socket_gid: int | None,
    directory: AccountDirectory,
) -> Admission:
    """Whether this daemon serves this peer, and the one code when it does not."""
    if mode == PER_USER:
        return ADMITTED if credential.uid == daemon_uid else REFUSED
    if mode == SYSTEM:
        if credential.uid == 0 or credential.uid == daemon_uid:
            return ADMITTED
        if socket_gid is None:
            return REFUSED
        if credential.gid == socket_gid:
            return ADMITTED
        account = account_of(directory, credential.uid)
        if account is None:
            return REFUSED
        gids = group_ids_of(directory, account.name, account.primary_gid)
        return ADMITTED if socket_gid in gids else REFUSED
    raise ValueError(f"admission has no rule for mode {mode!r}")
