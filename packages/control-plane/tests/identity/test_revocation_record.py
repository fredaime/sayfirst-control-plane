# SPDX-License-Identifier: Apache-2.0
"""Article 6, rules G3 and A6: what a revocation records, and in what shape."""

from __future__ import annotations

import os
from pathlib import Path

from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.domain.evidence import RecordCollector
from sayfirst_control_plane.settings import read_settings
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory, StaticPeerIdentity
from sayfirst_testing.schemas import validate_document

ME = os.geteuid()
STRANGER = ME + 1
OPERATORS = 90000
_AT = "2026-09-04T00:00:00+00:00"


def _daemon(tmp_path: Path, directory: StaticAccountDirectory, clock: FixedClock) -> Daemon:
    settings = read_settings(
        {
            "socket": {
                "mode": "system",
                "group": "operators",
                "path": str(tmp_path / "daemon.sock"),
            }
        },
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=directory,
        peer_identity=StaticPeerIdentity(
            PeerCredential(uid=STRANGER, gid=901, pid=4242, captured_at=_AT)
        ),
        clock=clock,
        evidence=RecordCollector(),
        daemon_uid=ME,
        socket_gid=OPERATORS,
        overflow_ids=(65534, 65534),
    )
    return daemon


def test_a_revocation_records_the_principal_it_revoked_and_the_one_it_found(
    tmp_path: Path,
) -> None:
    """Rule G3: `principal_changed` carries a principal on both sides."""
    clock = FixedClock()
    directory = StaticAccountDirectory(
        accounts={STRANGER: ("alice", 901)},
        memberships={"alice": (901, OPERATORS)},
        group_names={901: "alice", OPERATORS: "operators"},
    )
    daemon = _daemon(tmp_path, directory, clock)
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    assert identity.status == "established"

    directory.revoke("alice", OPERATORS)
    identity.begin_request()
    clock.advance(daemon.settings.group_lifetime_seconds)
    assert daemon.refresh_if_due(identity) == "peer_not_admitted"

    changes = [record for record in daemon.evidence.records if record.kind == "principal_changed"]
    assert len(changes) == 1
    members = changes[0].members
    assert set(members) == {"connection_id", "at", "before", "after"}
    assert members["connection_id"] == identity.connection_id
    assert members["at"] == clock.now().isoformat()
    before, after = members["before"], members["after"]
    assert before is not None, "the principal that was revoked is not recorded"
    assert after is not None, "the principal the directory now reports is not recorded"
    validate_document(before, "principal")
    validate_document(after, "principal")
    assert before["groups"] == ["alice", "operators"]
    assert after["groups"] == ["alice"], "the change that caused the refusal is not recorded"
    assert after["name"] == "alice"
    assert after["uid"] == STRANGER


def test_the_connection_is_refused_and_closed_after_the_change_is_recorded(
    tmp_path: Path,
) -> None:
    """Rule A6: refused from that point, with the change recorded first."""
    clock = FixedClock()
    directory = StaticAccountDirectory(
        accounts={STRANGER: ("alice", 901)},
        memberships={"alice": (901, OPERATORS)},
        group_names={901: "alice", OPERATORS: "operators"},
    )
    daemon = _daemon(tmp_path, directory, clock)
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    directory.revoke("alice", OPERATORS)
    identity.begin_request()
    clock.advance(daemon.settings.group_lifetime_seconds)
    daemon.refresh_if_due(identity)
    assert [record.kind for record in daemon.evidence.records] == [
        "connection_opened",
        "principal_changed",
    ]
    assert identity.status == "refused"
    assert identity.refusal == "peer_not_admitted"
    assert identity.principal is None


def test_a_connection_refused_at_accept_records_no_principal(tmp_path: Path) -> None:
    """Rule E4: a refused connection never carries one, because none was established."""
    clock = FixedClock()
    directory = StaticAccountDirectory(
        accounts={STRANGER: ("alice", 901)},
        memberships={"alice": (901,)},
        group_names={901: "alice"},
    )
    daemon = _daemon(tmp_path, directory, clock)
    identity = daemon.establish(object())  # type: ignore[arg-type]
    daemon.on_connection(identity)
    assert identity.status == "refused"
    kinds = [record.kind for record in daemon.evidence.records]
    assert kinds == ["connection_opened"], "a first refusal is not an identity change"
    opened = daemon.evidence.records[0]
    assert opened.members["principal"] is None
    assert opened.members["refusal"] == "peer_not_admitted"
