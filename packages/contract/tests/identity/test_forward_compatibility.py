# SPDX-License-Identifier: Apache-2.0
"""Article 13: an unknown enum value is read as unknown, never as a known one."""

from __future__ import annotations

import pytest
from sayfirst_contract.values import Unknown
from sayfirst_contract.whoami import (
    ConnectionStatus,
    GroupsStatus,
    Mode,
    Principal,
    WhoAmI,
)

_AT = "2026-09-04T00:00:00+00:00"


def _principal_document(**overrides: object) -> dict[str, object]:
    document = {
        "kind": "user",
        "uid": 1000,
        "gid": 1000,
        "name": "alice",
        "groups": ["alice"],
        "groups_status": "resolved",
        "unnamed_group_ids": [],
        "established_by": "peer_credential",
        "established_at": _AT,
        "reference": "user:1000",
    }
    document.update(overrides)
    return document


def _whoami_document(**overrides: object) -> dict[str, object]:
    document = {
        "contract_generation": 1,
        "connection_id": "connection-1",
        "socket_path": "/run/d.sock",
        "mode": "per_user",
        "peer": {"uid": 1000, "gid": 1000, "pid": 7, "captured_at": _AT},
        "principal": _principal_document(),
        "status": "established",
        "refresh_due_at": None,
        "group_lifetime_seconds": 60,
        "delegation": None,
    }
    document.update(overrides)
    return document


def test_a_fourth_groups_status_is_read_as_unknown() -> None:
    """Article 13: the reader retains the value and never interprets it."""
    principal = Principal.from_document(_principal_document(groups_status="zz-synthetic-status"))
    assert isinstance(principal.groups_status, Unknown)
    assert principal.groups_status.raw == "zz-synthetic-status"
    assert principal.groups_status is not GroupsStatus.RESOLVED
    assert principal.groups_are_unknown
    assert principal.to_document()["groups_status"] == "zz-synthetic-status"
    assert Principal.from_document(principal.to_document()) == principal


def test_the_three_named_group_statuses_are_read_as_themselves() -> None:
    """Article 2: the three values the contract names keep their meaning."""
    for value in ("resolved", "partial", "unknown"):
        principal = Principal.from_document(_principal_document(groups_status=value))
        assert principal.groups_status is GroupsStatus(value)
    assert not Principal.from_document(_principal_document()).groups_are_unknown
    assert Principal.from_document(_principal_document(groups_status="unknown")).groups_are_unknown


def test_a_fourth_connection_status_or_mode_is_read_as_unknown() -> None:
    """Article 13: a future connection state is never read as established."""
    result = WhoAmI.from_document(
        _whoami_document(status="zz-synthetic-state", mode="zz-synthetic-mode")
    )
    assert isinstance(result.status, Unknown)
    assert isinstance(result.mode, Unknown)
    assert result.status is not ConnectionStatus.ESTABLISHED
    assert not result.is_established
    assert result.to_document()["status"] == "zz-synthetic-state"
    assert result.to_document()["mode"] == "zz-synthetic-mode"
    assert WhoAmI.from_document(result.to_document()) == result
    known = WhoAmI.from_document(_whoami_document())
    assert known.status is ConnectionStatus.ESTABLISHED
    assert known.mode is Mode.PER_USER
    assert known.is_established


def test_a_value_written_as_a_plain_string_is_normalised_on_construction() -> None:
    """Article 13: one representation, whichever side built the value."""
    written = Principal(
        kind="user",
        uid=1000,
        gid=1000,
        name="alice",
        groups=("alice",),
        groups_status="resolved",
        unnamed_group_ids=(),
        established_by="peer_credential",
        established_at=_AT,
    )
    assert written.groups_status is GroupsStatus.RESOLVED
    assert written == Principal.from_document(_principal_document())


def test_the_published_delegation_bounds_are_counted_in_bytes() -> None:
    """Article 13, rule D3: the contract and the daemon hold one bound."""
    from sayfirst_contract.artifacts import domain_schema
    from sayfirst_contract.whoami import (
        MAX_KIND_BYTES,
        MAX_NAME_BYTES,
        MAX_VIA_BYTES,
        Delegation,
        DelegationOutOfBounds,
    )
    from sayfirst_testing.schemas import document_is_valid

    entry = domain_schema("delegation")["properties"]["chain"]["items"]["properties"]
    assert entry["kind"]["x-max-bytes"] == MAX_KIND_BYTES
    assert entry["name"]["x-max-bytes"] == MAX_NAME_BYTES
    assert entry["via"]["x-max-bytes"] == MAX_VIA_BYTES
    for member, limit in (("kind", MAX_KIND_BYTES), ("via", MAX_VIA_BYTES)):
        assert entry[member]["maxLength"] == limit

    # Sixty-four characters of three bytes each: inside the code-point bound
    # a generic validator can see, outside the bound the contract states.
    wide = "é" * MAX_VIA_BYTES
    assert len(wide) == MAX_VIA_BYTES
    assert len(wide.encode()) > MAX_VIA_BYTES
    document = {"chain": [{"kind": "user", "name": "alice", "uid": 1, "via": wide}]}
    with pytest.raises(DelegationOutOfBounds):
        Delegation.from_request_member(document)
    assert not document_is_valid(document, "delegation")
    document["chain"][0]["via"] = "privilege_tool"  # type: ignore[index]
    assert document_is_valid(document, "delegation")
