# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import WELL_KNOWN_KINDS
from sayfirst_control_plane.domain.admission import admit
from sayfirst_control_plane.domain.principal import (
    KIND_USER,
    build_principal,
    kind_for,
    resolve_identity,
    unknown_resolution,
)
from sayfirst_testing.doubles import DirectoryOutage, StaticAccountDirectory

_AT = "2026-09-04T00:00:00+00:00"
SERVER = Path(__file__).resolve().parents[2] / "src" / "sayfirst_control_plane"


def _credential(uid: int = 1000, gid: int = 1000) -> PeerCredential:
    return PeerCredential(uid=uid, gid=gid, pid=4242, captured_at=_AT)


def _directory(**kwargs: object) -> StaticAccountDirectory:
    return StaticAccountDirectory(
        accounts={1000: ("alice", 1000)},
        memberships={"alice": (1000, 900)},
        group_names={900: "operators", 1000: "alice"},
        **kwargs,  # type: ignore[arg-type]
    )


def test_group_names_are_not_canonicalised() -> None:
    """Article 6, rule G6: canonicalising them is the administrator's business."""
    directory = StaticAccountDirectory(
        accounts={1000: ("alice", 1000)},
        memberships={"alice": (1000, 900, 901)},
        group_names={1000: "Ops", 900: "ops ", 901: "DOMAIN\\ops"},
    )
    account, resolution = resolve_identity(directory, 1000, 1000)
    principal = build_principal(_credential(), account, resolution, kind=KIND_USER, at=_AT)
    assert principal.groups == ("Ops", "ops ", "DOMAIN\\ops")
    assert principal.groups_status == "resolved"


def test_a_uid_without_an_account_is_named_null() -> None:
    """Article 6, rule G1: no account is not no identity; the primary group remains."""
    directory = StaticAccountDirectory(group_names={1000: "alice"})
    account, resolution = resolve_identity(directory, 1000, 1000)
    principal = build_principal(_credential(), account, resolution, kind=KIND_USER, at=_AT)
    assert principal.name is None
    assert principal.groups == ("alice",)
    assert principal.groups_status == "resolved"
    assert principal.reference == "user:1000"


def test_a_group_id_with_no_entry_makes_the_resolution_partial() -> None:
    """Article 2: partial is its own value, and the unnamed ids are listed."""
    directory = StaticAccountDirectory(
        accounts={1000: ("alice", 1000)},
        memberships={"alice": (1000, 900)},
        group_names={1000: "alice"},
    )
    _, resolution = resolve_identity(directory, 1000, 1000)
    assert resolution.status == "partial"
    assert resolution.groups == ("alice",)
    assert resolution.unnamed_group_ids == (900,)


def test_a_directory_outage_is_an_unknown_and_never_an_empty_membership() -> None:
    """Article 2 and article 3: unknown is not a negative fact."""
    with pytest.raises(DirectoryOutage):
        resolve_identity(_directory(outage=True), 1000, 1000)
    resolution = unknown_resolution()
    assert resolution.status == "unknown"
    assert resolution.groups is None
    assert resolution.unnamed_group_ids == ()


def test_a_configured_account_kind_changes_evidence_and_nothing_else() -> None:
    """Article 6, rule K3: kind is vocabulary for evidence, not a decisional term."""
    directory = StaticAccountDirectory(accounts={1000: ("svc", 1000)}, group_names={1000: "svc"})
    account, resolution = resolve_identity(directory, 1000, 1000)
    mapping = {"svc": "service"}
    plain = build_principal(_credential(), account, resolution, kind=KIND_USER, at=_AT)
    mapped = build_principal(
        _credential(), account, resolution, kind=kind_for(account, mapping), at=_AT
    )
    assert plain.kind == "user" and plain.reference == "user:1000"
    assert mapped.kind == "service" and mapped.reference == "service:1000"
    verdicts = {
        admit(
            credential=_credential(),
            mode="per_user",
            daemon_uid=1000,
            socket_gid=None,
            directory=directory,
        )
    }
    assert len(verdicts) == 1
    assert kind_for(account, {}) == KIND_USER
    assert kind_for(None, mapping) == KIND_USER


def test_a_kind_outside_the_documented_four_is_recorded_as_given() -> None:
    """Article 6, rule K1: the registry is open, and nothing in the server closes it."""
    account, resolution = resolve_identity(_directory(), 1000, 1000)
    principal = build_principal(_credential(), account, resolution, kind="janitor", at=_AT)
    assert principal.kind == "janitor"
    assert principal.reference == "janitor:1000"
    assert kind_for(account, {"alice": "zz-synthetic-kind"}) == "zz-synthetic-kind"


def test_no_enumeration_in_the_server_closes_the_kind_registry() -> None:
    """Article 6, rule K1: never a closed enumeration, anywhere in this package."""
    documented = set(WELL_KNOWN_KINDS)
    inspected = 0
    for source in SERVER.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            inspected += 1
            bases = {
                base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
                for base in node.bases
            }
            if not bases & {"Enum", "StrEnum", "IntEnum"}:
                continue
            values = {
                item.value.value
                for item in node.body
                if isinstance(item, ast.Assign)
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, str)
            }
            assert not values & documented, f"{source}:{node.name}"
    assert WELL_KNOWN_KINDS == ("user", "service", "workload", "process")
    assert inspected >= 5
