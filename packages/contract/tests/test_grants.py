# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.grants import Grant, GrantConditions, GrantUse, grant_use

NOW = datetime(2026, 9, 4, tzinfo=UTC)
DIGEST = "sha256:" + "0" * 64
OTHER = "sha256:" + "1" * 64


def _grant(*, arguments_digest: str | None = DIGEST, lifetime: int = 300) -> Grant:
    return Grant(
        "grant-1",
        "decision-1",
        "sha256:" + "a" * 64,
        NOW.isoformat(),
        lifetime,
        (NOW + timedelta(seconds=lifetime)).isoformat(),
        5,
        GrantConditions("local", "example.effect", "user:build", arguments_digest),
    )


def _ask(**changes: object) -> DecisionAsk:
    return replace(DecisionAsk("example.effect", "local", DIGEST), **changes)  # type: ignore[arg-type]


def test_a_held_grant_covers_the_same_ask_inside_its_lifetime() -> None:
    """Article 10: a grant exists so its holder acts again without asking."""
    verdict = grant_use(
        _grant(), _ask(), "user:build", now=NOW + timedelta(seconds=1), connection_live=True
    )
    assert verdict is GrantUse.HIT


def test_a_lost_connection_voids_a_grant_before_anything_else_is_read() -> None:
    """Article 10: a grant is bound to the connection that carries its signals."""
    verdict = grant_use(_grant(), _ask(), "user:build", now=NOW, connection_live=False)
    assert verdict is GrantUse.CONNECTION_LOST


def test_a_grant_stops_covering_at_its_published_expiry() -> None:
    """Article 10: a grant has a bounded lifetime and no grace after it."""
    grant = _grant(lifetime=30)
    at_expiry = NOW + timedelta(seconds=30)
    assert grant_use(grant, _ask(), "user:build", now=at_expiry, connection_live=True) is (
        GrantUse.EXPIRED
    )
    assert (
        grant_use(
            grant, _ask(), "user:build", now=at_expiry - timedelta(seconds=1), connection_live=True
        )
        is GrantUse.HIT
    )


def test_a_pinned_arguments_digest_is_never_satisfied_by_another_or_by_none() -> None:
    """Article 3: a changed input is not the input the grant was issued for."""
    for digest in (OTHER, None):
        verdict = grant_use(
            _grant(),
            _ask(arguments_digest=digest),
            "user:build",
            now=NOW,
            connection_live=True,
        )
        assert verdict is GrantUse.ARGUMENTS_CHANGED, digest


@pytest.mark.parametrize(
    ("ask_changes", "principal"),
    [
        ({"scope": "other"}, "user:build"),
        ({"capability": "example.other"}, "user:build"),
        ({}, "user:other"),
    ],
)
def test_every_other_closed_condition_is_matched_exactly(
    ask_changes: dict[str, object], principal: str
) -> None:
    """Article 10: the four conditions a grant pins are matched, never approximated."""
    verdict = grant_use(_grant(), _ask(**ask_changes), principal, now=NOW, connection_live=True)
    assert verdict is GrantUse.CONDITIONS_DIFFER


def test_a_naive_instant_is_refused_rather_than_read_as_utc() -> None:
    """Article 2: an instant without an offset is unreadable, not assumed."""
    grant = replace(_grant(), expires_at="2026-09-04T00:05:00")
    with pytest.raises(ValueError, match="offset"):
        grant_use(grant, _ask(), "user:build", now=NOW, connection_live=True)
