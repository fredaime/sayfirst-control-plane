# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os

from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory
from sayfirst_testing.platforms import requires_platform
from sayfirst_testing.privileges import requires_unprivileged
from sayfirst_testing.schemas import validate_document

_AT = "2026-09-04T00:00:00+00:00"
ME = os.geteuid()
MY_GID = os.getegid()
STRANGER = ME + 1
OPERATORS = 90000


def _credential(uid: int = ME, gid: int = MY_GID, pid: int | None = 4242) -> PeerCredential:
    return PeerCredential(uid=uid, gid=gid, pid=pid, captured_at=_AT)


def alice_directory(**kwargs: object) -> StaticAccountDirectory:
    return StaticAccountDirectory(
        accounts={ME: ("alice", MY_GID)},
        memberships={"alice": (MY_GID, OPERATORS)},
        group_names={MY_GID: "alice", OPERATORS: "operators"},
        **kwargs,  # type: ignore[arg-type]
    )


def test_whoami_reports_the_principal_the_daemon_bound_at_accept(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule W1: it reads the connection and looks nothing up itself."""
    session = make_session(credential=_credential(), directory=alice_directory())
    status, document = session.request("GET", "/whoami")
    assert status == 200
    validate_document(document, "whoami-result")
    assert document["peer"] == {"uid": ME, "gid": MY_GID, "pid": 4242, "captured_at": _AT}
    assert document["principal"]["name"] == "alice"
    assert document["principal"]["groups"] == ["alice", "operators"]
    assert document["principal"]["reference"] == f"user:{ME}"
    assert document["status"] == "established"
    assert document["mode"] == "per_user"
    assert document["delegation"] is None
    assert document["group_lifetime_seconds"] == 60


def test_an_unmapped_uid_is_refused(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule P5: the overflow id is never mapped to an account."""
    directory = alice_directory()
    session = make_session(credential=_credential(uid=65534), directory=directory)
    status, document = session.request("GET", "/whoami")
    assert status == 403
    assert document["code"] == "peer_uid_unmapped"
    assert document["retryable"] is False
    assert directory.calls == []
    opened = next(r for r in session.evidence.records if r.kind == "connection_opened")
    assert opened.scope == "local"
    assert opened.members["principal"] is None
    assert opened.members["peer"]["uid"] == 65534
    assert opened.members["refusal"] == "peer_uid_unmapped"


def test_a_credential_the_os_did_not_deliver_is_unknown_not_refused(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 2: absence of a credential is neither an identity nor a denial."""
    session = make_session(unavailable=True, directory=alice_directory())
    status, document = session.request("GET", "/whoami")
    assert status == 503
    assert document["code"] == "peer_credential_unavailable"
    assert document["retryable"] is True


# The Linux kernel's own credential path: the peer is read with SO_PEERCRED over a
# real socket pair, which only that kernel offers; macOS is a different identity.
@requires_platform("linux")
def test_a_kernel_no_identity_uid_is_unavailable(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule P6: 2**32-1 is the kernel's "no id", never an account."""
    from sayfirst_contract.transport.peer import (
        NO_ID,
        LinuxPeerIdentity,
        PeerCredentialUnavailable,
    )

    class _Kernel:
        def getsockopt(self, *_: object) -> bytes:
            import struct

            return struct.pack("@iII", 7, NO_ID, MY_GID)

    try:
        LinuxPeerIdentity().establish(_Kernel())  # type: ignore[arg-type]
    except PeerCredentialUnavailable:
        return
    raise AssertionError("the kernel's no-identity marker must be unavailable")


def test_a_refused_connection_answers_a_problem_document_not_eof(make_session) -> None:  # type: ignore[no-untyped-def]
    """Articles 1 and 2: a caller can always tell a refusal from an absent answer.

    "The first HTTP request on it is answered with that problem document" is
    read for the request the caller actually sent, whichever method it names:
    an answer only five verbs receive is a bare 501 for the sixth, and a
    caller cannot tell that from "could not ask".
    """
    from sayfirst_contract.binding.http_unix_socket.routes import ROUTES

    unlisted = {"OPTIONS", "HEAD", "TRACE", "FROBNICATE"}
    methods = sorted({route.method for route in ROUTES} | unlisted)
    for method in methods:
        session = make_session(credential=_credential(uid=STRANGER), directory=alice_directory())
        connection = session.connect()
        status, document = session.request(method, "/whoami", connection=connection)
        assert status == 403, method
        if method != "HEAD":
            # A HEAD response carries the headers of the answer and none of
            # its body; the status is the whole of what a caller reads.
            assert document["code"] == "peer_not_admitted", method
            assert document["message"], method
        connection.close()


def test_an_admitted_connection_answers_every_method_in_the_contract(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 1, article 2: a method the binding does not define still gets an answer.

    Only that: three undefined verbs are answered as `operation_unknown`
    documents rather than the base handler's bare 501 page. Whether the served
    surface *is* the published one is a different claim, and
    `test_served_surface.py` is where it is held.
    """
    session = make_session(credential=_credential(), directory=alice_directory())
    for method in ("OPTIONS", "TRACE", "FROBNICATE"):
        status, document = session.request(method, "/whoami")
        assert status == 404, method
        assert document["code"] == "operation_unknown", method
        assert document["contract_generation"] == 1, method


@requires_unprivileged()
def test_the_per_user_daemon_refuses_root_over_the_wire(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule A2: one principal is read literally.

    Gated to an unprivileged tester because "root is refused" is only true
    when root is not the account the daemon runs as. Rule A2 reads the one
    principal literally, so a per-user daemon started by root has uid 0 as its
    principal and admits it — executed in a root container, this guard read
    `200` where it asserts `403`, and the daemon was right. What the guard is
    for is that root gets no *extra* admission; the case where root is a
    stranger needs a tester that is not root.
    """
    session = make_session(credential=_credential(uid=0, gid=0), directory=alice_directory())
    status, document = session.request("GET", "/whoami")
    assert status == 403
    assert document["code"] == "peer_not_admitted"


def test_the_connection_identity_is_bound_once_per_connection(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule P2: keep-alive reuses the connection and its credential."""
    session = make_session(credential=_credential(), directory=alice_directory())
    connection = session.connect()
    _, first = session.request("GET", "/whoami", connection=connection)
    _, second = session.request("GET", "/whoami", connection=connection)
    connection.close()
    assert first["connection_id"] == second["connection_id"]
    assert first["peer"]["captured_at"] == second["peer"]["captured_at"]
    _, third = session.request("GET", "/whoami")
    assert third["connection_id"] != first["connection_id"]


def test_a_directory_outage_makes_the_identity_unknown_not_a_verdict(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 3: fail-closed, and article 2: unknown is not a negative fact."""
    directory = alice_directory(outage=True)
    session = make_session(credential=_credential(), directory=directory)
    status, document = session.request("GET", "/whoami")
    assert status == 200
    assert document["principal"] is None
    assert document["status"] == "unknown"
    # The next attempt is due at once, so a request that follows repeats it
    # and an outage that ends is noticed within the documented lifetime.
    assert document["refresh_due_at"] is not None
    status, document = session.request(
        "POST", "/decisions", {"contract_generation": 1, "capability": "example.effect"}
    )
    assert status == 503
    assert document["code"] == "principal_groups_unavailable"
    assert document["retryable"] is True
    directory.outage = False
    status, document = session.request("GET", "/whoami")
    assert status == 200
    assert document["status"] == "established"
    assert document["principal"]["name"] == "alice"


def test_a_directory_lookup_is_bounded_by_the_timeout(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule G4: a slow name service never stalls another connection."""
    import threading
    import time

    slow = alice_directory(delay_seconds=6.0)
    session = make_session(
        credential=_credential(),
        directory=slow,
        overrides={"identity": {"resolution_timeout_seconds": 1}},
    )
    outcome: dict[str, object] = {}

    def ask() -> None:
        outcome["first"] = session.request("GET", "/whoami")

    thread = threading.Thread(target=ask)
    thread.start()
    deadline = time.monotonic() + 5
    while not slow.calls and time.monotonic() < deadline:
        time.sleep(0.01)
    assert slow.calls, "the first connection never reached the directory"
    started = time.monotonic()
    status, document = session.request("GET", "/whoami")
    elapsed = time.monotonic() - started
    # This connection pays its own bounded attempts and nobody else's: one at
    # accept and one inside the request that follows it (rule G5), so two
    # `resolution_timeout_seconds` at most. Waiting on the other connection's
    # lookup would cost the directory's six.
    assert elapsed < 4, "a slow lookup stalled another connection"
    assert status == 200
    # Its own lookup was bounded too, so it is served with an unknown identity
    # rather than waiting for the directory.
    assert document["status"] == "unknown"
    thread.join(timeout=10)
    first_status, first_document = outcome["first"]  # type: ignore[misc]
    assert first_status == 200
    assert first_document["status"] == "unknown"


def test_group_membership_is_re_resolved_within_the_documented_lifetime(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rules G2 and A6: the revocation latency is the lifetime, no longer."""
    from sayfirst_control_plane.adapters.socket_server import Daemon
    from sayfirst_control_plane.domain.evidence import RecordCollector
    from sayfirst_control_plane.settings import read_settings
    from sayfirst_testing.doubles import StaticPeerIdentity

    clock = FixedClock()
    directory = StaticAccountDirectory(
        accounts={STRANGER: ("alice", 901)},
        memberships={"alice": (901, OPERATORS)},
        group_names={901: "alice", OPERATORS: "operators"},
    )
    credential = _credential(uid=STRANGER, gid=901)
    settings = read_settings(
        {"socket": {"mode": "system", "group": "operators", "path": str(tmp_path / "d.sock")}},
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=directory,
        peer_identity=StaticPeerIdentity(credential),
        clock=clock,
        evidence=RecordCollector(),
        daemon_uid=ME,
        socket_gid=OPERATORS,
        overflow_ids=(65534, 65534),
    )
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    assert identity.status == "established"
    assert identity.principal is not None
    assert identity.principal.groups == ("alice", "operators")
    directory.revoke("alice", OPERATORS)
    clock.advance(59)
    assert daemon.refresh_if_due(identity) is None
    assert identity.status == "established"
    clock.advance(1)
    assert daemon.refresh_if_due(identity) == "peer_not_admitted"
    assert identity.status == "refused"
    assert [record.kind for record in daemon.evidence.records] == [
        "connection_opened",
        "principal_changed",
    ]


def test_a_principal_change_keeps_the_connection_open(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule G3: a change that still passes admission is recorded, not closed."""
    clock = FixedClock()
    directory = alice_directory()
    session = make_session(credential=_credential(), directory=directory, clock=clock)
    connection = session.connect()
    _, first = session.request("GET", "/whoami", connection=connection)
    directory.group_names[90001] = "release"
    directory.grant("alice", 90001)
    clock.advance(60)
    status, second = session.request("GET", "/whoami", connection=connection)
    assert status == 200
    assert second["connection_id"] == first["connection_id"]
    assert second["principal"]["groups"] == ["alice", "operators", "release"]
    changes = [r for r in session.evidence.records if r.kind == "principal_changed"]
    assert len(changes) == 1
    assert changes[0].members["before"]["groups"] == ["alice", "operators"]
    assert changes[0].members["after"]["groups"] == ["alice", "operators", "release"]
    status, third = session.request("GET", "/whoami", connection=connection)
    assert status == 200
    connection.close()


def test_the_first_record_of_a_connection_on_a_chain_is_its_identity(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 11, rule E1: the identity precedes anything the connection causes."""
    session = make_session(credential=_credential(), directory=alice_directory())
    connection = session.connect()
    for scope in ("s1", "s2"):
        session.request(
            "POST",
            "/decisions",
            {"contract_generation": 1, "capability": "example.effect", "scope": scope},
            connection=connection,
        )
    connection.close()
    for scope in ("local", "s1", "s2"):
        chain = [r for r in session.evidence.records if r.scope == scope]
        assert chain, scope
        assert chain[0].kind == "connection_opened", scope
    import time

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        closed = [r for r in session.evidence.records if r.kind == "connection_closed"]
        if len(closed) == 3:
            break
        time.sleep(0.01)
    assert {record.scope for record in closed} == {"local", "s1", "s2"}


def test_a_delegation_outside_its_bounds_is_refused(make_session) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule D3: a declaration outside its bounds takes no decision."""
    session = make_session(credential=_credential(), directory=alice_directory())
    link = {"kind": "user", "name": "alice", "uid": 1001, "via": "privilege_tool"}
    for delegation in (
        {"chain": [link] * 5},
        {"chain": [{**link, "via": "v" * 65}]},
        {"chain": [{**link, "issuer": "somewhere"}]},
        {"chain": []},
        {"chain": [link], "verified": True},
    ):
        status, document = session.request(
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "delegation": delegation,
            },
        )
        assert status == 400, delegation
        assert document["code"] == "delegation_invalid", delegation


def test_a_delegation_is_recorded_as_evidence_and_never_collapses_the_principal() -> None:
    """Article 6, rule D1: nothing the peer declares changes who it is."""
    from sayfirst_contract.whoami import Delegation
    from sayfirst_control_plane.domain.evidence import actor_members, principal_for_evaluation
    from sayfirst_control_plane.domain.principal import build_principal, resolve_identity

    directory = alice_directory()
    account, resolution = resolve_identity(directory, ME, MY_GID)
    bob = build_principal(_credential(), account, resolution, kind="user", at=_AT)
    declared = Delegation.from_request_member(
        {"chain": [{"kind": "user", "name": "carol", "uid": 1002, "via": "privilege_tool"}]}
    )
    members = actor_members(bob, declared)
    assert members["principal"]["name"] == "alice"
    assert "delegation" not in members["principal"]
    assert members["delegation"]["status"] == "declared"
    assert members["delegation"]["chain"][0]["name"] == "carol"
    assert principal_for_evaluation(bob, declared) is bob


def test_a_request_without_a_delegation_renders_null() -> None:
    """Article 2: absence is a present null, never a missing member."""
    from sayfirst_control_plane.domain.evidence import actor_members

    members = actor_members(None, None)
    assert members["delegation"] is None
    assert "delegation" in members
