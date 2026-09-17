# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import inspect
import json
import tomllib
from collections import UserDict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_control_plane.domain.evidence_chain import (
    PREIMAGE_VERSION,
    EvidenceRecord,
    Principal,
    chained,
    preimage,
)

#: The single normative copy of the preimage vectors is the contract's
#: (`_contracts/domain/evidence-preimage-v1.json`), read from the installed
#: wheel: the server and the contract each recompute every vector on their
#: own, and neither reads the other's implementation (article 13). The
#: server's older fixture stays where the evidence design cites it, as a
#: pointer held identical to the normative copy below.
VECTORS = "evidence-preimage-v1.json"
POINTER = Path(__file__).parents[1] / "fixtures" / "evidence" / "preimage-v1.json"


def _principal(document: dict[str, object]) -> Principal:
    via = document["via"]
    assert isinstance(via, list)
    return Principal(
        str(document["kind"]),
        str(document["id"]),
        tuple(_principal(item) for item in via),  # type: ignore[arg-type]
    )


def test_the_preimage_recipe_is_pinned_by_the_published_vectors() -> None:
    """Article 13: the server recomputes the contract's normative vectors on its own."""
    document = load_json("domain", VECTORS)
    assert isinstance(document, dict) and len(document["vectors"]) >= 2
    pointer = json.loads(POINTER.read_text(encoding="utf-8"))
    assert pointer["vectors"] == document["vectors"], "the pointer drifted from the normative copy"
    for vector in document["vectors"]:
        raw = preimage(
            scope=vector["scope"],
            sequence=vector["sequence"],
            kind=vector["kind"],
            recorded_at=datetime.fromisoformat(vector["recorded_at"].replace("Z", "+00:00")),
            connection_id=vector["connection_id"],
            principal=_principal(vector["principal"]),
            body=vector["body"],
            previous_hash=vector["previous_hash"],
        )
        assert raw.hex() == vector["preimage_hex"]
        assert hashlib.sha256(raw).hexdigest() == vector["digest"]


def test_the_version_tag_names_this_server_distribution() -> None:
    project = tomllib.loads(
        (Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    assert PREIMAGE_VERSION.split("/") == [project["name"], "evidence", "v1"]


def test_chained_accepts_no_version_of_the_callers_choosing() -> None:
    assert "version" not in inspect.signature(chained).parameters


def test_a_non_serialisable_body_refuses() -> None:
    with pytest.raises(TypeError, match="JSON serializable"):
        EvidenceRecord(
            "local",
            "gap",
            datetime.fromisoformat("2026-09-04T10:00:00+00:00"),
            "daemon",
            Principal("service", "daemon"),
            {
                "reason": "dropped",
                "count": 1,
                "first_at": "2026-09-04T10:00:00Z",
                "last_at": "2026-09-04T10:00:00Z",
                "kinds": UserDict({"effect": 1}),
            },
        )


def test_every_component_is_load_bearing() -> None:
    now = datetime(2026, 9, 4, tzinfo=UTC)
    principal = Principal("user", "example")
    body = {"providers": []}
    base = {
        "scope": "local",
        "sequence": 2,
        "kind": "composition",
        "recorded_at": now,
        "connection_id": "daemon",
        "principal": principal,
        "body": body,
        "previous_hash": "0" * 64,
    }
    mutations = (
        {"scope": "other"},
        {"sequence": 3},
        {"kind": "grade"},
        {"recorded_at": now + timedelta(seconds=1)},
        {"connection_id": "other"},
        {"principal": Principal("service", "example")},
        {"body": {"providers": [{"interface": "x", "version": 1, "provider": "y"}]}},
        {"previous_hash": "1" * 64},
    )
    raw = preimage(**base)
    assert all(preimage(**{**base, **mutation}) != raw for mutation in mutations)


def test_an_absent_previous_hash_is_not_an_empty_one() -> None:
    arguments = {
        "scope": "local",
        "sequence": 1,
        "kind": "composition",
        "recorded_at": datetime(2026, 9, 4, tzinfo=UTC),
        "connection_id": "daemon",
        "principal": Principal("service", "daemon"),
        "body": {"providers": []},
    }
    assert preimage(**arguments, previous_hash=None) != preimage(**arguments, previous_hash="")


def test_length_prefixing_leaves_no_two_fields_colliding() -> None:
    common = {
        "sequence": 1,
        "kind": "composition",
        "recorded_at": datetime(2026, 9, 4, tzinfo=UTC),
        "principal": Principal("service", "daemon"),
        "body": {"providers": []},
        "previous_hash": None,
    }
    left = preimage(scope="a", connection_id="bc", **common)
    right = preimage(scope="ab", connection_id="c", **common)
    assert left != right
