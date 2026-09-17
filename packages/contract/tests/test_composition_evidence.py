# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sayfirst_contract.plugins import (
    ComposedProvider,
    read_composition_evidence,
)

PROVIDER: dict[str, object] = {
    "interface": "PrivacyRedactor",
    "version": 1,
    "provider": "none",
    "distribution": "sayfirst-control-plane",
    "distribution_version": "0.1.0",
    "entry_point": "sayfirst_control_plane.plugins.defaults:registration",
    "content_digest": "unknown",
}


def _entry(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "scope": "local",
        "kind": "composition",
        "recorded_at": "2026-09-04T00:00:00+00:00",
        "connection_id": "daemon",
        "principal": {"kind": "service", "id": "daemon"},
        "body": {"providers": [dict(PROVIDER)]},
        "sequence": 1,
        "previous_hash": None,
        "entry_hash": "0" * 64,
        "preimage_version": "sayfirst-control-plane/evidence/v1",
    }
    entry.update(overrides)
    return entry


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "composition.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_complete_chain_entry_reads_back_as_the_composition_it_records(
    tmp_path: Path,
) -> None:
    composed = read_composition_evidence(_write(tmp_path, _entry()))

    assert composed == (
        ComposedProvider(
            interface="PrivacyRedactor",
            version=1,
            provider="none",
            distribution="sayfirst-control-plane",
            distribution_version="0.1.0",
            entry_point="sayfirst_control_plane.plugins.defaults:registration",
            content_digest="unknown",
        ),
    )


def test_a_bare_kind_and_body_is_not_a_recorded_composition(tmp_path: Path) -> None:
    """Article 2: an envelope with no chain in it is not evidence of one."""
    path = _write(tmp_path, {"kind": "composition", "body": {"providers": []}})

    with pytest.raises(ValueError, match="missing members: connection_id, entry_hash"):
        read_composition_evidence(path)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        pytest.param({"scope": 7}, "scope", id="numeric-scope"),
        pytest.param({"scope": ""}, "scope", id="empty-scope"),
        pytest.param({"connection_id": 7}, "connection_id", id="numeric-connection"),
        pytest.param({"principal": "daemon"}, "principal", id="untyped-principal"),
        pytest.param({"principal": {"kind": "service"}}, "principal", id="principal-without-id"),
        pytest.param(
            {"principal": {"kind": "service", "id": "daemon", "via": "someone"}},
            "delegation",
            id="unstructured-delegation",
        ),
        pytest.param(
            {"principal": {"kind": "service", "id": "daemon", "via": [{"kind": "person"}]}},
            "principal",
            id="delegation-without-id",
        ),
        pytest.param({"recorded_at": 1757030400}, "instant", id="numeric-instant"),
        pytest.param({"recorded_at": "2026-09-04T00:00:00"}, "instant", id="naive-instant"),
        pytest.param({"sequence": True}, "sequence", id="boolean-sequence"),
        pytest.param({"sequence": 0}, "sequence", id="zero-sequence"),
        pytest.param({"sequence": "1"}, "sequence", id="textual-sequence"),
        pytest.param({"previous_hash": "0" * 64}, "previous hash", id="first-entry-with-parent"),
        pytest.param({"sequence": 2, "previous_hash": None}, "previous hash", id="orphan-entry"),
        pytest.param({"sequence": 2, "previous_hash": "nope"}, "previous hash", id="short-parent"),
        pytest.param({"entry_hash": "0" * 63}, "entry hash", id="short-entry-hash"),
        pytest.param({"entry_hash": None}, "entry hash", id="absent-entry-hash"),
        pytest.param({"preimage_version": 1}, "preimage_version", id="numeric-preimage"),
        pytest.param({"preimage_version": ""}, "preimage_version", id="empty-preimage"),
        pytest.param({"body": "providers"}, "body", id="textual-body"),
    ],
)
def test_an_entry_without_the_chain_shape_is_refused(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    """Article 2: the reader validates the whole typed envelope, not two members."""
    with pytest.raises(ValueError, match=message):
        read_composition_evidence(_write(tmp_path, _entry(**overrides)))


def test_an_entry_carrying_a_member_the_reader_cannot_name_is_refused(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="unknown members"):
        read_composition_evidence(_write(tmp_path, _entry(signature="trust-me")))


def test_an_entry_of_another_kind_is_still_named_as_such(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a composition"):
        read_composition_evidence(_write(tmp_path, _entry(kind="decision")))


def test_a_delegated_principal_is_accepted_when_every_link_is_typed(
    tmp_path: Path,
) -> None:
    entry = _entry(
        principal={
            "kind": "service",
            "id": "daemon",
            "via": [{"kind": "person", "id": "uid:1000", "via": []}],
        }
    )

    assert len(read_composition_evidence(_write(tmp_path, entry))) == 1


def test_a_missing_member_and_an_unknown_one_are_named_apart(tmp_path: Path) -> None:
    """Article 2: a refusal that names the opposite fact sends the reader astray."""
    entry = _entry()
    del entry["preimage_version"]

    with pytest.raises(ValueError, match="is missing members: preimage_version"):
        read_composition_evidence(_write(tmp_path, entry))

    with pytest.raises(ValueError, match="has unknown members: signature"):
        read_composition_evidence(_write(tmp_path, _entry(signature="trust-me")))
