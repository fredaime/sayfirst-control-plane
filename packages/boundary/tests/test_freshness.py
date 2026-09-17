# SPDX-License-Identifier: Apache-2.0
"""The four things that end a grant, and the published rule that decides three.

Article 10 binds a grant to the connection that delivered it, to its lifetime,
to the policy version it was issued under, and to having heard from the control
plane within that lifetime. `grant_use` in the contract distribution decides the
connection, the lifetime and the pinned conditions; it takes no version argument
(a holder cannot know the current version — a change arrives as a signal) and no
silence argument. This module adds those two and delegates the rest.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sayfirst_boundary.freshness import Ending, Held, ending
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.grants import Grant, GrantConditions, GrantEndReason

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64
PRINCIPAL = "user:build"


def _grant(*, lifetime: int = 300, heartbeat: int = 10) -> Grant:
    return Grant(
        grant_id="g-1",
        decision_ref="dec-1",
        policy_version="sha256:" + "a" * 64,
        issued_at=NOW.isoformat(),
        lifetime_seconds=lifetime,
        expires_at=(NOW + timedelta(seconds=lifetime)).isoformat(),
        heartbeat_seconds=heartbeat,
        conditions=GrantConditions(
            scope="local",
            capability="example.effect",
            principal_reference=PRINCIPAL,
            arguments_digest=DIGEST,
        ),
    )


def _held(**overrides: object) -> Held:
    fields: dict[str, object] = {
        "grant": _grant(),
        "last_heard_at": NOW,
        "connection_live": True,
        "ended_by": None,
    }
    fields.update(overrides)
    return Held(**fields)  # type: ignore[arg-type]


def _ask(*, digest: str | None = DIGEST, capability: str = "example.effect") -> DecisionAsk:
    return DecisionAsk(capability=capability, scope="local", arguments_digest=digest)


def test_a_fresh_grant_covering_the_same_ask_is_live() -> None:
    assert ending(_held(), _ask(), PRINCIPAL, now=NOW + timedelta(seconds=1)) is Ending.LIVE


def test_a_lost_connection_ends_it_whatever_the_lifetime_says() -> None:
    held = _held(connection_live=False)
    assert ending(held, _ask(), PRINCIPAL, now=NOW) is Ending.CONNECTION_LOST


def test_the_lifetime_running_out_ends_it() -> None:
    at_expiry = NOW + timedelta(seconds=300)
    assert ending(_held(), _ask(), PRINCIPAL, now=at_expiry) is Ending.EXPIRED


def test_silence_for_a_lifetime_ends_it_although_the_connection_is_open() -> None:
    """The clause `grant_use` cannot express, and the reason this module exists."""
    held = _held(last_heard_at=NOW - timedelta(seconds=300))
    assert ending(held, _ask(), PRINCIPAL, now=NOW + timedelta(seconds=1)) is Ending.SILENT


def test_silence_is_measured_against_the_lifetime_not_the_heartbeat() -> None:
    held = _held(last_heard_at=NOW - timedelta(seconds=11))
    assert ending(held, _ask(), PRINCIPAL, now=NOW + timedelta(seconds=1)) is Ending.LIVE


def test_a_read_signal_that_ended_the_grant_is_final() -> None:
    held = _held(ended_by=GrantEndReason.POLICY_VERSION_CHANGED)
    assert (
        ending(held, _ask(), PRINCIPAL, now=NOW + timedelta(seconds=1))
        is Ending.POLICY_VERSION_CHANGED
    )


def test_a_different_capability_is_not_this_grant() -> None:
    assert (
        ending(_held(), _ask(capability="other.effect"), PRINCIPAL, now=NOW)
        is Ending.CONDITIONS_DIFFER
    )


def test_a_different_principal_is_not_this_grant() -> None:
    assert ending(_held(), _ask(), "user:someone-else", now=NOW) is Ending.CONDITIONS_DIFFER


def test_different_arguments_are_not_this_grant() -> None:
    other = "sha256:" + "2" * 64
    assert ending(_held(), _ask(digest=other), PRINCIPAL, now=NOW) is Ending.ARGUMENTS_CHANGED


def test_an_ask_carrying_no_digest_does_not_satisfy_a_pinned_one() -> None:
    """Article 3: an unknown input is never the more permissive reading."""
    assert ending(_held(), _ask(digest=None), PRINCIPAL, now=NOW) is Ending.ARGUMENTS_CHANGED


def test_a_lost_connection_outranks_every_other_ending() -> None:
    """Precedence is the constitutional order, and this pins it."""
    held = _held(
        connection_live=False,
        last_heard_at=NOW - timedelta(seconds=900),
        ended_by=GrantEndReason.EXPIRED,
    )
    assert ending(held, _ask(digest=None), PRINCIPAL, now=NOW + timedelta(days=1)) is (
        Ending.CONNECTION_LOST
    )


def test_only_live_lets_a_caller_act() -> None:
    """The whole set is checked, so a member added later cannot default to acting."""
    acting = {member for member in Ending if member is Ending.LIVE}
    assert acting == {Ending.LIVE}
    assert len(Ending) == 7


def test_exactly_one_lifetime_of_silence_ends_it() -> None:
    """The threshold itself, which the test above does not reach.

    That one uses 301 seconds against a 300-second lifetime, so it passes under
    `>` as well as `>=` and therefore says nothing about the boundary. This one
    is at exactly one lifetime and the grant has NOT yet expired (it was issued
    at `NOW` and runs to `NOW + 300`), so it isolates the comparison: under `>`
    it reads `LIVE` and a grant the control plane has not spoken about for its
    whole lifetime would be honoured.
    """
    held = _held(last_heard_at=NOW - timedelta(seconds=300))
    assert ending(held, _ask(), PRINCIPAL, now=NOW) is Ending.SILENT


def test_expiry_outranks_silence_at_the_instant_both_are_true() -> None:
    """The defect this module was first written with, pinned so it cannot return.

    At `NOW + 300` the default grant is expired AND has been unheard-from for
    exactly its lifetime. The control plane's own `grant_state` tests expiry
    first, and so must this: telling a caller the plane went quiet, when the
    grant had simply run out, names the wrong cause for the right refusal.
    """
    both_true = NOW + timedelta(seconds=300)
    held = _held(last_heard_at=NOW)
    assert (both_true - held.last_heard_at) == timedelta(seconds=held.grant.lifetime_seconds)
    assert ending(held, _ask(), PRINCIPAL, now=both_true) is Ending.EXPIRED
