# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import dataclasses
import inspect

import pytest
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import Principal
from sayfirst_control_plane.domain.admission import ADMITTED, admit, is_unmapped
from sayfirst_control_plane.domain.principal import build_principal, resolve_identity
from sayfirst_testing.doubles import StaticAccountDirectory

_AT = "2026-09-04T00:00:00+00:00"


def _credential(uid: int, gid: int, pid: int | None = 4242) -> PeerCredential:
    return PeerCredential(uid=uid, gid=gid, pid=pid, captured_at=_AT)


def test_admission_reads_nothing_but_the_credential_and_the_directory() -> None:
    """Article 6, rule A4: not the pid, not a name, not a header, not a body."""
    parameters = set(inspect.signature(admit).parameters)
    assert parameters == {"credential", "mode", "daemon_uid", "socket_gid", "directory"}


def test_a_process_id_is_diagnostic_and_never_decisional() -> None:
    """Article 6, rule P4: a pid is stored, rendered, and used for nothing else.

    Three claims, one guard: the identity a decision is evaluated against
    cannot carry a process id, the admission rule cannot be handed one, and
    two credentials that differ only in their pid produce the same verdict and
    the same principal — so a reused pid can decide nothing.
    """
    assert "pid" not in {field.name for field in dataclasses.fields(Principal)}
    assert "pid" not in inspect.signature(admit).parameters
    directory = StaticAccountDirectory(
        accounts={1000: ("alice", 1000)}, group_names={1000: "alice"}
    )
    verdicts = []
    principals = []
    for pid in (1, None):
        credential = _credential(1000, 1000, pid)
        verdicts.append(
            admit(
                credential=credential,
                mode="per_user",
                daemon_uid=1000,
                socket_gid=None,
                directory=directory,
            )
        )
        account, resolution = resolve_identity(directory, credential.uid, credential.gid)
        principals.append(build_principal(credential, account, resolution, kind="user", at=_AT))
    assert verdicts[0] == verdicts[1] == ADMITTED
    assert principals[0] == principals[1]
    assert principals[0].to_document() == principals[1].to_document()


def test_the_per_user_daemon_admits_one_principal() -> None:
    """Article 6, rule A2: one principal is read literally; root has no side door."""
    directory = StaticAccountDirectory()
    for uid, expected in (
        (1000, ADMITTED.refusal),
        (1001, "peer_not_admitted"),
        (0, "peer_not_admitted"),
    ):
        verdict = admit(
            credential=_credential(uid, 1000),
            mode="per_user",
            daemon_uid=1000,
            socket_gid=None,
            directory=directory,
        )
        assert verdict.refusal == expected, uid


def test_the_system_daemon_admits_root_the_owner_and_the_socket_group() -> None:
    """Article 6, rule A3: this is where authorisation does real work."""
    directory = StaticAccountDirectory(
        accounts={1000: ("alice", 1000), 1001: ("bob", 1001), 1002: ("carol", 1002)},
        memberships={"alice": (1000, 900), "bob": (1001,)},
        group_names={900: "operators", 1000: "alice", 1001: "bob", 1002: "carol"},
    )
    table = {
        (0, 0): None,
        (1000, 1000): None,
        (1001, 1001): "peer_not_admitted",
        (1002, 900): None,
        (1002, 1002): "peer_not_admitted",
    }
    for (uid, gid), expected in table.items():
        verdict = admit(
            credential=_credential(uid, gid),
            mode="system",
            daemon_uid=1000,
            socket_gid=900,
            directory=directory,
        )
        assert verdict.refusal == expected, (uid, gid)


def test_an_unmapped_uid_is_refused() -> None:
    """Article 6, rule P5: the overflow id is a non-identity, never an account."""
    directory = StaticAccountDirectory()
    for credential in (_credential(65534, 1000), _credential(1000, 65534)):
        assert is_unmapped(credential, overflow_uid=65534, overflow_gid=65534)
    assert not is_unmapped(_credential(1000, 1000), overflow_uid=65534, overflow_gid=65534)
    assert directory.calls == []


def test_a_mode_the_daemon_does_not_know_is_a_programming_error() -> None:
    """Article 3: an unreadable mode never falls through to admitted."""
    with pytest.raises(ValueError):
        admit(
            credential=_credential(1000, 1000),
            mode="zz-synthetic-mode",
            daemon_uid=1000,
            socket_gid=None,
            directory=StaticAccountDirectory(),
        )
