# SPDX-License-Identifier: Apache-2.0
"""Bounded issuing connections, heartbeats, and terminal grant signals."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock

from ..domain.foreign import core_owned_instant
from ..domain.grant import Grant
from .events import Events, NullEvents


class SignalKind(StrEnum):
    HEARTBEAT = "heartbeat"
    GRANT_ENDED = "grant_ended"


class GrantEndReason(StrEnum):
    POLICY_VERSION_CHANGED = "policy_version_changed"
    EXPIRED = "expired"
    DAEMON_STOPPING = "daemon_stopping"
    CONNECTION_LOST = "connection_lost"


@dataclass(frozen=True)
class GrantSignal:
    kind: SignalKind
    grant_id: str
    policy_version: str
    at: datetime
    reason: GrantEndReason | None = None


class GrantConnection:
    """The sole connection on which one grant was delivered."""

    def __init__(
        self,
        grant: Grant,
        principal_uid: int,
        lost: Callable[[GrantConnection, str], None],
        signal_writer: Callable[[GrantSignal], None] | None = None,
        expired: Callable[[GrantConnection], None] | None = None,
    ) -> None:
        self.grant = grant
        self.principal_uid = principal_uid
        self.live = True
        self.last_signal_at = grant.issued_at
        self._signals: list[GrantSignal] = []
        self._lost = lost
        self._expired = expired
        self._signal_writer = signal_writer

    def drain(self) -> tuple[GrantSignal, ...]:
        signals = tuple(self._signals)
        self._signals.clear()
        return signals

    def peer_closed(self) -> None:
        """End this grant because the boundary it was delivered on went away."""
        if self.live:
            self._lost(self, "connection_lost")

    def peer_wrote(self) -> None:
        """End this grant because its peer wrote where the stream defines nothing.

        The two are one event to `select` and two different things to a reader
        of the record (article 2). A peer that closed is gone; a peer that wrote
        is still there, and it is this daemon that is about to close on it,
        because the stream answer published `Connection: close` and the binding
        defines no second operation on it. Recording both as a connection lost
        said the boundary went away when it had not.
        """
        if self.live:
            self._lost(self, "peer_wrote_on_the_stream")

    def reached_its_lifetime(self) -> None:
        """End this grant because the lifetime it was issued with has run out.

        The registry's `tick` ends every grant that has expired, and nothing
        calls it yet. The connection that carries one grant does know when that
        grant's lifetime is spent, and article 10 already binds the two: "a
        boundary that ... has not heard from it within the grant's lifetime
        treats its grants as expired". Ending it here rather than closing the
        connection under an unexpired grant is what keeps the reason recorded
        equal to the reason it happened (article 2).
        """
        if self.live and self._expired is not None:
            self._expired(self)

    def _write(self, signal: GrantSignal) -> None:
        if self._signal_writer is not None:
            try:
                self._signal_writer(signal)
            except Exception:
                self._lost(self, "connection_lost")
                return
        self._signals.append(signal)
        self.last_signal_at = signal.at


class GrantReservation:
    """One atomically admitted slot that can be opened after decision append."""

    def __init__(self, connections: GrantConnections, principal_uid: int) -> None:
        self._connections = connections
        self.principal_uid = principal_uid
        self._active = True

    def open(
        self,
        grant: Grant,
        signal_writer: Callable[[GrantSignal], None] | None = None,
    ) -> GrantConnection:
        if not self._active:
            raise RuntimeError("grant reservation is no longer active")
        self._active = False
        return self._connections._open_reserved(grant, self.principal_uid, signal_writer)

    def cancel(self) -> None:
        if self._active:
            self._active = False
            self._connections._cancel_reservation(self.principal_uid)


class GrantConnections:
    def __init__(
        self,
        *,
        max_connections_per_principal: int = 64,
        max_connections: int = 1024,
        events: Events | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 0 <= max_connections_per_principal <= 4096:
            raise ValueError("per-principal grant connection limit is out of range")
        if not 0 <= max_connections <= 65536:
            raise ValueError("total grant connection limit is out of range")
        self.max_connections_per_principal = max_connections_per_principal
        self.max_connections = max_connections
        self.events = events or NullEvents()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._connections: dict[str, GrantConnection] = {}
        self._reserved_total = 0
        self._reserved_by_principal: dict[int, int] = {}
        #: Set by `shutdown` and never cleared: the stop is a state of this
        #: registry, not a moment it once fanned out at, so a grant that
        #: registers after it is ended on arrival rather than held live by a
        #: daemon that has already told every other boundary it is stopping.
        self._stopping = False
        self._lock = RLock()

    @property
    def connection_count(self) -> int:
        with self._lock:
            return len(self._connections)

    def has_capacity(self, principal_uid: int) -> bool:
        with self._lock:
            per_principal = sum(
                connection.principal_uid == principal_uid
                for connection in self._connections.values()
            ) + self._reserved_by_principal.get(principal_uid, 0)
            return (
                len(self._connections) + self._reserved_total < self.max_connections
                and per_principal < self.max_connections_per_principal
            )

    def reserve(self, principal_uid: int) -> GrantReservation | None:
        with self._lock:
            if not self.has_capacity(principal_uid):
                return None
            self._reserved_total += 1
            self._reserved_by_principal[principal_uid] = (
                self._reserved_by_principal.get(principal_uid, 0) + 1
            )
        return GrantReservation(self, principal_uid)

    def open(
        self,
        grant: Grant,
        *,
        principal_uid: int,
        signal_writer: Callable[[GrantSignal], None] | None = None,
    ) -> GrantConnection | None:
        reservation = self.reserve(principal_uid)
        if reservation is None:
            return None
        return reservation.open(grant, signal_writer)

    def _open_reserved(
        self,
        grant: Grant,
        principal_uid: int,
        signal_writer: Callable[[GrantSignal], None] | None,
    ) -> GrantConnection:
        with self._lock:
            self._release_reservation(principal_uid)
            connection = GrantConnection(
                grant, principal_uid, self._peer_lost, signal_writer, self._reached_its_lifetime
            )
            self._connections[grant.grant_id] = connection
            stopping = self._stopping
        self.events.record(
            "grant.issued",
            {
                "grant_id": grant.grant_id,
                "decision_ref": grant.decision_ref,
                "lifetime_seconds": grant.lifetime_seconds,
                "policy_version": grant.policy_version,
            },
            at=grant.issued_at,
        )
        if stopping:
            # The answer is delivered before its grant is registered (article
            # 10), and the stop landed between the two. The boundary holds
            # the frame, so it is told on that channel that the daemon is
            # stopping (S5): the grant is issued and ended, in that order, on
            # the record, and the hold on its connection ends at once.
            self._end(connection, GrantEndReason.DAEMON_STOPPING, grant.policy_version, self._now())
        return connection

    def _cancel_reservation(self, principal_uid: int) -> None:
        with self._lock:
            self._release_reservation(principal_uid)

    def _release_reservation(self, principal_uid: int) -> None:
        self._reserved_total -= 1
        remaining = self._reserved_by_principal[principal_uid] - 1
        if remaining:
            self._reserved_by_principal[principal_uid] = remaining
        else:
            del self._reserved_by_principal[principal_uid]

    def policy_version_changed(self, policy_version: str) -> None:
        for connection in self._snapshot():
            if connection.grant.policy_version != policy_version:
                self._end(
                    connection,
                    GrantEndReason.POLICY_VERSION_CHANGED,
                    policy_version,
                    self._now(),
                )

    def tick(self, now: datetime, *, current_policy_version: str) -> None:
        for connection in self._snapshot():
            if now >= connection.grant.expires_at:
                self._end(
                    connection,
                    GrantEndReason.EXPIRED,
                    current_policy_version,
                    now,
                )
            elif now - connection.last_signal_at >= timedelta(
                seconds=connection.grant.heartbeat_seconds
            ):
                connection._write(
                    GrantSignal(
                        SignalKind.HEARTBEAT,
                        connection.grant.grant_id,
                        current_policy_version,
                        now,
                    )
                )

    def shutdown(self) -> None:
        """End every grant as `daemon_stopping`, those held now and any that registers later.

        The flag is raised under the lock that registration takes, so a grant
        is either in the snapshot ended here or sees the flag when it
        registers; there is no instant in which it is neither.
        """
        with self._lock:
            self._stopping = True
        for connection in self._snapshot():
            self._end(
                connection,
                GrantEndReason.DAEMON_STOPPING,
                connection.grant.policy_version,
                self._now(),
            )

    def _now(self) -> datetime:
        """One instant from the composed clock, as a value this service owns.

        The clock is a seam like any other (`domain/foreign.py`): an instant is
        written into a record and compared against another, and both live on the
        type, so a `datetime` subclass answers them itself.
        """
        return core_owned_instant(self._clock())

    def _snapshot(self) -> tuple[GrantConnection, ...]:
        with self._lock:
            return tuple(self._connections.values())

    def _reached_its_lifetime(self, connection: GrantConnection) -> None:
        """One grant ended because its own lifetime is spent, with that reason."""
        self._end(
            connection,
            GrantEndReason.EXPIRED,
            connection.grant.policy_version,
            self._now(),
        )

    def _peer_lost(self, connection: GrantConnection, reason: str) -> None:
        """Release a grant whose connection has ended, recording why it ended.

        No `GrantSignal` is written: this reason is the daemon's own record of
        a channel that is over, and the published reasons of the signal
        (`grant-signal.schema.json`) are the ones a boundary is told over a
        channel that still carries. `reason` is therefore not one of them.
        """
        with self._lock:
            if self._connections.pop(connection.grant.grant_id, None) is None:
                return
            connection.live = False
        self.events.record(
            "grant.ended",
            {"grant_id": connection.grant.grant_id, "reason": reason},
            at=self._now(),
        )

    def _end(
        self,
        connection: GrantConnection,
        reason: GrantEndReason,
        policy_version: str,
        at: datetime,
    ) -> None:
        with self._lock:
            if self._connections.pop(connection.grant.grant_id, None) is None:
                return
            connection.live = False
            connection._write(
                GrantSignal(
                    SignalKind.GRANT_ENDED,
                    connection.grant.grant_id,
                    policy_version,
                    at,
                    reason,
                )
            )
        self.events.record(
            "grant.ended",
            {"grant_id": connection.grant.grant_id, "reason": reason.value},
            at=at,
        )
