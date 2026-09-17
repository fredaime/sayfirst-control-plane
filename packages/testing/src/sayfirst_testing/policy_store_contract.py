# SPDX-License-Identifier: Apache-2.0
"""Reusable contract suite for the read-only policy authority port."""

from __future__ import annotations

from sayfirst_control_plane.domain.policy import Principal
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    LoadedPolicy,
    PolicyStore,
    PolicyUnavailable,
    ProtectionExpectation,
    ProtectionState,
)


def assert_policy_store_contract(
    available: PolicyStore,
    unavailable: PolicyStore,
    exposed: PolicyStore,
    *,
    expectation: ProtectionExpectation,
    principal: Principal,
) -> None:
    """Prove whole-load, classified absence, and both access verdicts."""
    assert available.VERSION == unavailable.VERSION == exposed.VERSION == 1
    first = available.load()
    second = available.load()
    assert isinstance(first, LoadedPolicy)
    assert second == first
    absent = unavailable.load()
    assert isinstance(absent, PolicyUnavailable)
    assert absent.reason == "absent"
    assert not hasattr(absent, "outcome")
    # Both arms are asserted: an adapter answering one fixed verdict for every
    # path fails one of them, whichever verdict it fixes (articles 2 and 8).
    assert available.protection_at_start(expectation).kind is ProtectionState.PROTECTED
    assert available.write_access_of(principal).kind is AccessState.NOT_WRITABLE
    assert exposed.protection_at_start(expectation).kind is ProtectionState.EXPOSED
    assert exposed.write_access_of(principal).kind is AccessState.WRITABLE
