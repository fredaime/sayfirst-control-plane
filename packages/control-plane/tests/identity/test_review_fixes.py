# SPDX-License-Identifier: Apache-2.0
"""The daemon-side defects the review of block 2.2 named, each with its guard."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import ConnectionStatus
from sayfirst_control_plane.adapters import socket_server
from sayfirst_control_plane.adapters.socket_server import Daemon, has_access_acl
from sayfirst_control_plane.domain.directory_protection import (
    DirectoryFacts,
    directory_protection,
)
from sayfirst_control_plane.domain.evidence import RecordCollector
from sayfirst_control_plane.settings import StartRefused, read_settings
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory, StaticPeerIdentity
from sayfirst_testing.platforms import requires_platform
from sayfirst_testing.privileges import requires_unprivileged

_AT = "2026-09-04T00:00:00+00:00"
ME = os.geteuid()
MY_GID = os.getegid()


def _credential(uid: int = ME, gid: int = MY_GID) -> PeerCredential:
    return PeerCredential(uid=uid, gid=gid, pid=4242, captured_at=_AT)


def alice_directory(**kwargs: object) -> StaticAccountDirectory:
    return StaticAccountDirectory(
        accounts={ME: ("alice", MY_GID)},
        memberships={"alice": (MY_GID, 90000)},
        group_names={MY_GID: "alice", 90000: "operators"},
        **kwargs,  # type: ignore[arg-type]
    )


def _daemon(tmp_path: Path, **kwargs: object) -> Daemon:
    settings = read_settings(
        {"socket": {"mode": "per_user", "path": str(tmp_path / "daemon.sock")}},
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=kwargs.pop("directory", None) or alice_directory(),  # type: ignore[arg-type]
        peer_identity=StaticPeerIdentity(_credential()),
        clock=kwargs.pop("clock", None) or FixedClock(),  # type: ignore[arg-type]
        evidence=RecordCollector(),
        daemon_uid=ME,
        overflow_ids=(65534, 65534),
        **kwargs,  # type: ignore[arg-type]
    )
    return daemon


# -- P1.2 -------------------------------------------------------------------


def _facts(**overrides: object) -> DirectoryFacts:
    members: dict[str, object] = {
        "name": "/run/sayfirst",
        "mode": 0o755,
        "uid": 0,
        "is_directory": True,
        "has_access_acl": False,
    }
    members.update(overrides)
    return DirectoryFacts(**members)  # type: ignore[arg-type]


def test_an_unreadable_access_control_list_is_never_proof_that_none_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Articles 2 and 3: a check that could not run is not a check that passed."""
    for failure in (
        PermissionError(errno.EACCES, "Permission denied"),
        OSError(errno.EIO, "Input/output error"),
        PermissionError(errno.EPERM, "Operation not permitted"),
    ):

        def raising(*_: object, error: OSError = failure) -> bytes:
            raise error

        monkeypatch.setattr(socket_server.os, "getxattr", raising, raising=False)
        assert has_access_acl(tmp_path, "linux") is None

    for absent in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):

        def missing(*_: object, number: int = absent) -> bytes:
            raise OSError(number, "no attribute")

        monkeypatch.setattr(socket_server.os, "getxattr", missing, raising=False)
        assert has_access_acl(tmp_path, "linux") is False


def test_an_unread_access_control_list_refuses_the_start_on_linux() -> None:
    """Article 6, rule S3: refused on any failure of the check, not only on a finding."""
    verdict = directory_protection(
        st=_facts(has_access_acl=None), ancestors=(), daemon_uid=1000, platform="linux"
    )
    assert verdict.refusal == "socket_directory_unprotected"
    assert "could not be read" in verdict.detail
    assert verdict.acl == "unverified"
    assert (
        directory_protection(
            st=_facts(has_access_acl=False), ancestors=(), daemon_uid=1000, platform="linux"
        ).acl
        == "checked"
    )
    darwin = directory_protection(
        st=_facts(has_access_acl=None), ancestors=(), daemon_uid=1000, platform="darwin"
    )
    assert darwin.protected
    assert darwin.acl == "not checked on this platform"


# -- P1.3 -------------------------------------------------------------------


def test_an_unknown_connection_retries_its_lookup_within_the_lifetime(tmp_path: Path) -> None:
    """Article 6, rule G5: the attempt is repeated until a later one succeeds."""
    clock = FixedClock()
    directory = alice_directory(outage=True)
    daemon = _daemon(tmp_path, directory=directory, clock=clock)
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    assert identity.status == ConnectionStatus.UNKNOWN
    assert identity.principal is None
    assert identity.refresh_due_at is not None
    assert identity.refresh_due_at <= clock.now() + __import__("datetime").timedelta(
        seconds=daemon.settings.group_lifetime_seconds
    )
    directory.outage = False
    directory.calls.clear()
    # The outage was noted at accept, so the next request is the first one.
    identity.begin_request()
    assert daemon.refresh_if_due(identity) is None
    assert directory.calls, "the recovered directory was never consulted again"
    assert identity.status == ConnectionStatus.ESTABLISHED
    assert identity.principal is not None
    assert identity.principal.name == "alice"
    directory.calls.clear()
    assert daemon.refresh_if_due(identity) is None
    assert directory.calls == [], "the same request asked the directory twice"


def test_an_unknown_connection_recovers_on_one_live_connection(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule G5, over the wire, on the connection that went unknown."""
    directory = alice_directory(outage=True)
    session = make_session(credential=_credential(), directory=directory)
    connection = session.connect()
    status, first = session.request("GET", "/whoami", connection=connection)
    assert status == 200
    assert first["status"] == "unknown"
    directory.outage = False
    status, second = session.request("GET", "/whoami", connection=connection)
    connection.close()
    assert status == 200
    assert second["connection_id"] == first["connection_id"]
    assert second["status"] == "established"
    assert second["principal"]["name"] == "alice"


# -- P1.4 -------------------------------------------------------------------


def test_a_refresh_that_changed_nothing_records_no_change(tmp_path: Path) -> None:
    """Article 6, rule G3: every member but `established_at` decides a change."""
    clock = FixedClock()
    daemon = _daemon(tmp_path, clock=clock)
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    first = identity.principal
    clock.advance(daemon.settings.group_lifetime_seconds)
    assert daemon.refresh_if_due(identity) is None
    assert [record.kind for record in daemon.evidence.records] == ["connection_opened"]
    assert identity.principal is not None
    assert identity.principal.established_at != first.established_at  # type: ignore[union-attr]
    assert identity.principal.groups == first.groups  # type: ignore[union-attr]


def test_a_refresh_that_changed_a_group_records_the_change(tmp_path: Path) -> None:
    """Article 6, rule G3: a real change is recorded, and the connection stays."""
    clock = FixedClock()
    directory = alice_directory()
    daemon = _daemon(tmp_path, directory=directory, clock=clock)
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    directory.group_names[90001] = "release"
    directory.grant("alice", 90001)
    clock.advance(daemon.settings.group_lifetime_seconds)
    assert daemon.refresh_if_due(identity) is None
    assert [record.kind for record in daemon.evidence.records] == [
        "connection_opened",
        "principal_changed",
    ]


# -- P1.5 -------------------------------------------------------------------


def test_a_missing_credential_is_never_invented(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2 and rule P6: absence of a credential is not an identity."""
    session = make_session(unavailable=True, directory=alice_directory())
    status, document = session.request("GET", "/whoami")
    assert status == 503
    assert document["code"] == "peer_credential_unavailable"
    assert document["retryable"] is True
    assert "not admitted" not in document["message"]
    assert "denied" not in document["message"]
    assert "operating system" in document["message"]
    opened = next(r for r in session.evidence.records if r.kind == "connection_opened")
    assert opened.members["peer"] is None
    assert opened.members["principal"] is None
    assert opened.members["refusal"] == "peer_credential_unavailable"


def test_each_refusal_states_its_own_fact(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2: one fact each, and a could-not-ask is never written as a denial."""
    messages = {}
    for name, session in (
        ("peer_uid_unmapped", make_session(credential=_credential(uid=65534))),
        ("peer_not_admitted", make_session(credential=_credential(uid=ME + 1))),
        ("peer_credential_unavailable", make_session(unavailable=True)),
    ):
        _, document = session.request("GET", "/whoami")
        assert document["code"] == name
        messages[name] = document["message"]
    assert len(set(messages.values())) == 3
    assert "namespace" in messages["peer_uid_unmapped"]
    assert "admission list" in messages["peer_not_admitted"]


# -- P2.3 -------------------------------------------------------------------


@requires_unprivileged()
def test_the_directory_check_uses_the_account_the_daemon_will_run_as(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 6, rule M2: the daemon's principal is the owner the check accepts.

    Gated to an unprivileged tester because its refusal is the tester's own
    lack of privilege: `chown root:group` is what fails here, and under root
    nothing fails — `start()` runs to completion and `_drop_privileges` calls
    the irreversible `setuid` in the test process, which ends that process's
    privilege for the whole session. Executed in a root container, this one
    guard turned a run of 1080 passes into 902 passes and 179 errors.

    The claim itself is held under root by
    `test_root_system_mode.py`, which starts the daemon in a forked child.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    seen: list[int] = []
    monkeypatch.setattr(
        socket_server,
        "protect_directory",
        lambda directory, *, daemon_uid, platform: seen.append(daemon_uid) or "acl: checked",
    )
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: 4242
    )
    # The daemon resolves its own group beside its own uid, and drops to that
    # group rather than to the admission list (article 7), so the seam that
    # scripts the account directory scripts both answers.
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: 4242
    )
    settings = read_settings(
        {
            "socket": {
                "mode": "system",
                "group": "operators",
                "run_as": "sayfirst",
                "path": str(root / "daemon.sock"),
            }
        },
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=alice_directory(),
        peer_identity=StaticPeerIdentity(_credential()),
        daemon_uid=0,
        socket_gid=90000,
        overflow_ids=(65534, 65534),
    )
    with pytest.raises((StartRefused, OSError)):
        daemon.start()  # the chown to root needs privilege this account lacks
    assert seen == [4242], "the check ran against root, not the configured principal"


def test_an_unknown_run_as_account_stops_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 6, rule M2: an account the host does not have is not a principal."""
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: None
    )
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: None
    )
    settings = read_settings(
        {
            "socket": {
                "mode": "system",
                "group": "operators",
                "run_as": "absent",
                "path": str(tmp_path / "daemon.sock"),
            }
        },
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=alice_directory(),
        peer_identity=StaticPeerIdentity(_credential()),
        daemon_uid=0,
        socket_gid=90000,
        overflow_ids=(65534, 65534),
    )
    with pytest.raises(StartRefused) as refusal:
        daemon.start()
    assert refusal.value.reason == "run_as_unknown"


# -- P2.4 -------------------------------------------------------------------


def test_every_refused_peer_gets_the_configured_resolution_timeout() -> None:
    """Article 6, rule A5: the bound belongs to the refusal, not to one of its causes."""
    from sayfirst_control_plane.adapters.http_surface import (
        _KEEP_ALIVE_SECONDS,
        connection_timeout,
    )

    settings = read_settings(
        {
            "socket": {"mode": "per_user", "path": "/tmp/d.sock"},
            "identity": {"resolution_timeout_seconds": 7},
        },
        platform="linux",
    )
    assert connection_timeout(ConnectionStatus.REFUSED, settings) == 7.0
    for status in (ConnectionStatus.ESTABLISHED, ConnectionStatus.UNKNOWN, None):
        assert connection_timeout(status, settings) == _KEEP_ALIVE_SECONDS


def test_a_refused_peer_that_never_asks_is_closed_on_that_bound(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule A5: whichever check refused it, the same bound applies."""
    import socket as socket_module
    import time

    for credential, unavailable in (
        (_credential(uid=ME + 1), False),
        (_credential(uid=65534), False),
        (None, True),
    ):
        session = make_session(
            credential=credential,
            unavailable=unavailable,
            directory=alice_directory(),
            overrides={"identity": {"resolution_timeout_seconds": 1}},
        )
        stream = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
        stream.settimeout(10)
        stream.connect(session.daemon.settings.socket_path)
        try:
            started = time.monotonic()
            assert stream.recv(4096) == b"", "the daemon kept a refused connection open"
            elapsed = time.monotonic() - started
            assert elapsed < 5, f"closed after {elapsed:.1f}s, not the configured bound"
        finally:
            stream.close()


# -- P2.6 -------------------------------------------------------------------


# The Linux kernel's own credential path: the peer is read with SO_PEERCRED over a
# real socket pair, which only that kernel offers; macOS is a different identity.
@requires_platform("linux")
def test_the_captured_instant_comes_from_the_clock_port(tmp_path: Path) -> None:
    """Article 6: the Clock port supplies every instant this block records."""
    import socket as socket_module

    clock = FixedClock()
    settings = read_settings(
        {"socket": {"mode": "per_user", "path": str(tmp_path / "daemon.sock")}},
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=alice_directory(),
        clock=clock,
        evidence=RecordCollector(),
        daemon_uid=ME,
        overflow_ids=(65534, 65534),
    )
    left, right = socket_module.socketpair(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    with left, right:
        identity = daemon.establish(left)
    assert identity.peer is not None
    assert identity.peer.captured_at == clock.now().isoformat()
    assert identity.accepted_at == clock.now().isoformat()
