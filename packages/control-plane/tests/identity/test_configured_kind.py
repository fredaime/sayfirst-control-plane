# SPDX-License-Identifier: Apache-2.0
"""Article 13: every response is a contract shape, whatever a deployment says."""

from __future__ import annotations

import os

import pytest
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.whoami import MAX_KIND_BYTES
from sayfirst_control_plane.domain.principal import build_principal, kind_for, resolve_identity
from sayfirst_control_plane.settings import StartRefused, read_settings
from sayfirst_testing.doubles import StaticAccountDirectory
from sayfirst_testing.schemas import document_is_valid, validate_document

ME = os.geteuid()
MY_GID = os.getegid()
_AT = "2026-09-04T00:00:00+00:00"


def _settings(kind: object):  # type: ignore[no-untyped-def]
    return read_settings(
        {
            "socket": {"mode": "system", "group": "operators", "path": "/tmp/d.sock"},
            "identity": {"accounts": {"svc-build": {"kind": kind}}},
        },
        platform="linux",
    )


def _directory() -> StaticAccountDirectory:
    return StaticAccountDirectory(
        accounts={ME: ("svc-build", MY_GID)}, group_names={MY_GID: "builders"}
    )


def test_a_configured_kind_outside_the_published_shape_stops_the_start() -> None:
    """Article 13: a deployment cannot ask the daemon to answer off-contract."""
    for planted in ("", " ", "k" * (MAX_KIND_BYTES + 1), "é" * MAX_KIND_BYTES, 7, True, None, []):
        with pytest.raises(StartRefused) as refusal:
            _settings(planted)
        assert refusal.value.reason == "mode_invalid", planted
        assert "kind" in refusal.value.detail, planted


def test_a_configured_kind_inside_the_published_shape_is_kept_as_given() -> None:
    """Article 6, rule K1: the registry is open above the contract's bounds."""
    for accepted in ("service", "workload", "janitor", "k" * MAX_KIND_BYTES, "é" * 32):
        assert _settings(accepted).account_kinds == {"svc-build": accepted}


def test_a_configured_kind_never_makes_the_daemon_answer_outside_its_contract() -> None:
    """Article 13: what the daemon records and serves satisfies the published shape."""
    directory = _directory()
    account, resolution = resolve_identity(directory, ME, MY_GID)
    credential = PeerCredential(uid=ME, gid=MY_GID, pid=7, captured_at=_AT)
    for accepted in ("service", "janitor", "k" * MAX_KIND_BYTES):
        settings = _settings(accepted)
        principal = build_principal(
            credential,
            account,
            resolution,
            kind=kind_for(account, settings.account_kinds),
            at=_AT,
        )
        assert principal.kind == accepted
        assert principal.reference == f"{accepted}:{ME}"
        validate_document(principal.to_document(), "principal")

    # The bound is the contract's, so a kind the reader would refuse is one the
    # configuration refuses first.
    off_contract = build_principal(credential, account, resolution, kind="", at=_AT).to_document()
    assert not document_is_valid(off_contract, "principal")


def test_an_account_kinds_table_that_is_not_a_table_of_kinds_stops_the_start() -> None:
    """Article 8: a configuration the daemon cannot read is not a configuration."""
    for planted in ({"svc": "service"}, {"svc": {"kind": "service", "uid": 7}}, {"svc": []}):
        with pytest.raises(StartRefused) as refusal:
            read_settings(
                {
                    "socket": {"mode": "system", "group": "operators", "path": "/tmp/d.sock"},
                    "identity": {"accounts": planted},
                },
                platform="linux",
            )
        assert refusal.value.reason == "mode_invalid", planted
