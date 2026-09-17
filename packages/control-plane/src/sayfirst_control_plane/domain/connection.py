# SPDX-License-Identifier: Apache-2.0
"""The identity a connection carries, from accept until close.

Read once per connection and reused by every request on it: keep-alive
reuses the connection and therefore the credential (rule P2). No request
handler runs on a connection that has none.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import ConnectionStatus, Peer, Principal, WhoAmI

ESTABLISHED = ConnectionStatus.ESTABLISHED
UNKNOWN = ConnectionStatus.UNKNOWN
REFUSED = ConnectionStatus.REFUSED


@dataclass
class ConnectionIdentity:
    """What the daemon knows about one connection, and when it must ask again."""

    connection_id: str
    accepted_at: str
    socket_path: str
    mode: str
    peer: PeerCredential | None
    """What the kernel said, or nothing when it said nothing (rule P6)."""
    status: ConnectionStatus = UNKNOWN
    principal: Principal | None = None
    refusal: str | None = None
    resolved_at: datetime | None = None
    refresh_due_at: datetime | None = None
    requests_begun: int = 0
    """Requests begun on this connection, counted before the request is served.

    An outage is noted against the request it happened in; at accept that is
    request zero, which is no request at all."""
    unknown_since_request: int | None = None
    """The request the last outage was noted in, or `None` when there is none."""
    touched_scopes: set[str] = field(default_factory=set)

    def bind(self, principal: Principal, at: datetime, lifetime_seconds: int) -> None:
        """Bind a resolved principal and set when it must be resolved again."""
        self.principal = principal
        self.status = ESTABLISHED
        self.refusal = None
        self.resolved_at = at
        self.refresh_due_at = at + timedelta(seconds=lifetime_seconds)
        self.unknown_since_request = None

    def mark_unknown(self, at: datetime, lifetime_seconds: int) -> None:
        """The directory could not be consulted; the principal stays as it was.

        The attempt is repeated on the next request that arrives, and in any
        case no later than the documented lifetime, so an outage that ends is
        noticed within that bound and not one request sooner (rule G5).

        "The next request" is counted from the request the outage was noted in.
        An outage at accept is noted in request zero — inside no request at all
        — so the next request is the first one, and it repeats the attempt.
        """
        self.status = UNKNOWN
        self.resolved_at = at
        self.refresh_due_at = at + timedelta(seconds=lifetime_seconds)
        self.unknown_since_request = self.requests_begun

    def refuse(self, code: str) -> None:
        """Refuse the connection with the one code that says why."""
        self.status = REFUSED
        self.refusal = code
        self.principal = None

    def begin_request(self) -> None:
        """One more request begun on this connection.

        Counted before the request is served, so a lookup this request owes is
        a lookup that belongs to this request and not to the next one.
        """
        self.requests_begun += 1

    def is_due(self, now: datetime) -> bool:
        return self.refresh_due_at is not None and now >= self.refresh_due_at

    def needs_lookup(self, now: datetime) -> bool:
        """Whether the directory must be consulted before this request is served."""
        if self.status == UNKNOWN and self.unknown_since_request is not None:
            return self.requests_begun > self.unknown_since_request or self.is_due(now)
        return self.is_due(now)

    def peer_document(self) -> dict[str, object] | None:
        """The record as evidence carries it, or null when there is none."""
        return None if self.peer is None else self._peer().to_document()

    def _peer(self) -> Peer:
        if self.peer is None:
            raise ValueError("this connection carries no peer record")
        return Peer(
            uid=self.peer.uid,
            gid=self.peer.gid,
            pid=self.peer.pid,
            captured_at=self.peer.captured_at,
        )

    def whoami(self, *, generation: int, group_lifetime_seconds: int) -> WhoAmI:
        """What this connection reports about itself, looked up no further."""
        return WhoAmI(
            contract_generation=generation,
            connection_id=self.connection_id,
            socket_path=self.socket_path,
            mode=self.mode,
            peer=self._peer(),
            principal=self.principal,
            status=self.status,
            refresh_due_at=None if self.refresh_due_at is None else self.refresh_due_at.isoformat(),
            group_lifetime_seconds=group_lifetime_seconds,
            delegation=None,
            extra={},
        )
