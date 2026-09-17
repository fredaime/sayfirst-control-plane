# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from sayfirst_control_plane.architecture.information_contract import (
    INFORMATION_CONTRACT,
    Plane,
    Structure,
)


def test_the_information_contract_declares_the_policy_projection_as_a_projection() -> None:
    """Article 3: persistence metadata cannot silently promote the projection."""
    structure = INFORMATION_CONTRACT["policy_projection"]
    assert structure.plane is Plane.PROJECTION
    assert structure.role == "definition"
    assert structure.role not in {"source_of_truth", "human_authority"}


@pytest.mark.parametrize("role", ["source_of_truth", "human_authority"])
def test_a_projection_refuses_authority_roles_by_construction(role) -> None:  # type: ignore[no-untyped-def]
    """Article 3: invalid projection authority roles cannot be represented."""
    with pytest.raises(ValueError, match="projection"):
        Structure(Plane.PROJECTION, role, "test_proof")  # type: ignore[arg-type]


@pytest.mark.parametrize("role", ["source_of_truth", "human_authority"])
def test_an_observation_refuses_authority_roles_by_construction(role) -> None:  # type: ignore[no-untyped-def]
    """Article 3: an observation can be absent or stale, so it owns no invariant."""
    with pytest.raises(ValueError, match="observation"):
        Structure(Plane.OBSERVATION, role, "test_proof")  # type: ignore[arg-type]


def test_an_authority_refuses_the_trace_role_by_construction() -> None:
    """Article 3: the mirror of the clause above — a trace is not what a system owns.

    An authority accepts writes and owns invariants; a trace is what the system
    saw and may be absent or stale. Without this clause the register would
    accept an authority declaring itself a trace of itself, which is the
    silent promotion in the other direction.
    """
    with pytest.raises(ValueError, match="trace"):
        Structure(Plane.AUTHORITY, "trace", "test_proof")


def test_the_daemon_event_sink_is_declared_an_observation() -> None:
    """Article 3: the sink an operator reads says what plane it is on, and owns nothing.

    It is the first observation this register holds, and the reason to declare
    it is the reason article 3 exists: a reader who took it for the evidence
    chain would be reading a bounded, restart-emptied window as the authority
    for what the daemon decided.
    """
    structure = INFORMATION_CONTRACT["daemon_events"]
    assert structure.plane is Plane.OBSERVATION
    assert structure.surfaces == (), "an in-memory sink outlives no process"


def test_policy_and_decision_are_declared_as_authorities() -> None:
    """Article 3: the write-owning structures say that they own invariants."""
    assert INFORMATION_CONTRACT["policy_file"].plane is Plane.AUTHORITY
    assert INFORMATION_CONTRACT["decision"].plane is Plane.AUTHORITY
