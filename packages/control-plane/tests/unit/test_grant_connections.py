# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import (
    GrantConnections,
    GrantEndReason,
    SignalKind,
)
from sayfirst_control_plane.domain.grant import mint_grant

NOW = datetime(2026, 9, 4, tzinfo=UTC)


def _grant(index: int = 1, *, lifetime: int = 30):  # type: ignore[no-untyped-def]
    decision = Decision(
        f"decision-{index}",
        "local",
        "mail.send",
        Outcome.ALLOW,
        Reason.POLICY_ALLOWS,
        "sha256:" + "a" * 64,
        None,
        NOW.isoformat(),
        None,
        1,
        {
            "principal": {"kind": "process", "uid": 1001, "name": "build"},
            "arguments_digest": "sha256:" + "1" * 64,
        },
    )
    return mint_grant(
        decision,
        NOW,
        lifetime_seconds=lifetime,
        policy_version=decision.policy_version or "",
        heartbeat_seconds=5,
    )


def test_a_version_change_ends_every_grant_connection() -> None:
    """Article 10: the authority signal fans out to every issuing connection."""
    connections = GrantConnections(clock=lambda: NOW)
    opened = [connections.open(_grant(index), principal_uid=1001) for index in (1, 2)]
    connections.policy_version_changed("sha256:" + "b" * 64)
    for connection in opened:
        assert connection is not None
        signal = connection.drain()[0]
        assert signal.kind is SignalKind.GRANT_ENDED
        assert signal.reason is GrantEndReason.POLICY_VERSION_CHANGED
        assert connection.live is False


def test_one_broken_signal_writer_does_not_stop_terminal_fanout() -> None:
    """Article 10: every grant is ended even when one signal writer fails."""
    events = MemoryEvents()
    received = []

    def broken(signal):  # type: ignore[no-untyped-def]
        raise RuntimeError("stream headers are not ready")

    connections = GrantConnections(events=events, clock=lambda: NOW)
    first = connections.open(_grant(1), principal_uid=1001, signal_writer=broken)
    second = connections.open(_grant(2), principal_uid=1001, signal_writer=received.append)
    connections.policy_version_changed("sha256:" + "b" * 64)
    assert first is not None and first.live is False
    assert second is not None and second.live is False
    assert received[0].reason is GrantEndReason.POLICY_VERSION_CHANGED
    assert connections.connection_count == 0
    assert len(events.of_kind("grant.ended")) == 2


def test_a_grant_connection_is_closed_at_expiry() -> None:
    """Article 10: the server signals expiry at the lifetime boundary."""
    connections = GrantConnections(clock=lambda: NOW)
    connection = connections.open(_grant(lifetime=10), principal_uid=1001)
    assert connection is not None
    connections.tick(NOW + timedelta(seconds=10), current_policy_version="sha256:" + "a" * 64)
    assert connection.drain()[0].reason is GrantEndReason.EXPIRED
    assert connection.live is False


def test_a_lost_grant_connection_is_recorded() -> None:
    """Article 10: peer loss is an explicit grant ending."""
    events = MemoryEvents()
    connections = GrantConnections(events=events, clock=lambda: NOW)
    connection = connections.open(_grant(), principal_uid=1001)
    assert connection is not None
    connection.peer_closed()
    ended = events.of_kind("grant.ended")
    assert len(ended) == 1
    assert ended[0].details["reason"] == "connection_lost"


def test_the_grant_connection_bound_answers_without_a_grant_never_refuses() -> None:
    """Article 10: capacity only controls caching, not decisions."""
    connections = GrantConnections(max_connections=1, max_connections_per_principal=1)
    assert connections.open(_grant(1), principal_uid=1001) is not None
    assert not connections.has_capacity(1001)
    assert connections.open(_grant(2), principal_uid=1001) is None


def test_a_live_connection_receives_heartbeats() -> None:
    """Article 10: silence can be bounded independently of policy changes."""
    connections = GrantConnections(clock=lambda: NOW)
    connection = connections.open(_grant(), principal_uid=1001)
    assert connection is not None
    connections.tick(NOW + timedelta(seconds=5), current_policy_version="sha256:" + "a" * 64)
    signal = connection.drain()[0]
    assert signal.kind is SignalKind.HEARTBEAT
    assert signal.at == NOW + timedelta(seconds=5)


def test_a_grant_opened_after_shutdown_is_ended_as_daemon_stopping_on_its_channel() -> None:
    """Article 10, S5: a stop is a state of the registry, not a moment it once had.

    The route writes the decision frame before the grant is registered, so a
    graceful stop can land between the two. A registry that only fanned out to
    what it held at that moment would let the late grant register live and
    never tell its boundary the daemon was stopping; the boundary would hold
    a grant nobody would ever end.
    """
    events = MemoryEvents()
    received = []
    connections = GrantConnections(events=events, clock=lambda: NOW)
    connections.shutdown()
    late = connections.open(_grant(), principal_uid=1001, signal_writer=received.append)
    assert late is not None
    assert late.live is False
    assert connections.connection_count == 0
    assert [signal.kind for signal in received] == [SignalKind.GRANT_ENDED]
    assert received[0].reason is GrantEndReason.DAEMON_STOPPING
    assert received[0].grant_id == late.grant.grant_id
    assert events.of_kind("grant.ended")[0].details["reason"] == "daemon_stopping"
