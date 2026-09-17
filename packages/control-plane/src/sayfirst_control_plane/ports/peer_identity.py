# SPDX-License-Identifier: Apache-2.0
"""The daemon's side of the peer-credential port.

The port and its adapters live in the contract distribution because both
sides of the boundary verify each other with the same code (article 14); the
daemon registers them and refuses to run where none exists (rule L6).
"""

from __future__ import annotations

import socket
from typing import Final

from sayfirst_contract.transport.peer import (
    NO_ID,
    DarwinPeerIdentity,
    LinuxPeerIdentity,
    PeerCredential,
    PeerCredentialUnavailable,
    PeerIdentity,
    PeerIdentityUnsupported,
    select_peer_identity,
    supported_platforms,
)

from ..domain.foreign import core_owned

PEER_IDENTITY_VERSION: Final[int] = 1


def credential_of(identity: PeerIdentity, connection: socket.socket) -> PeerCredential:
    """The kernel's record of a peer, read once and held as the core's own value.

    The credential is established at accept and then read for the life of the
    connection — by the unmapped-id check, by admission, and by the principal
    every record carries — so an adapter that answered one uid to the check and
    another to the record would be admitted as one account and recorded as
    another (article 6, rules P2 and P6).
    """
    return core_owned(
        PeerCredential,
        identity.establish(connection),
        uid=int,
        gid=int,
        pid=lambda value: None if value is None else int(value),
        captured_at=str,
    )


__all__ = [
    "NO_ID",
    "PEER_IDENTITY_VERSION",
    "DarwinPeerIdentity",
    "LinuxPeerIdentity",
    "PeerCredential",
    "PeerCredentialUnavailable",
    "PeerIdentity",
    "PeerIdentityUnsupported",
    "credential_of",
    "select_peer_identity",
    "supported_platforms",
]
