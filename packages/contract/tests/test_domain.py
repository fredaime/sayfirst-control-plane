# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import date

import pytest
from sayfirst_contract.approvals import Approval
from sayfirst_contract.decisions import DecisionAsk, Outcome, Reason, read_decision
from sayfirst_contract.generation import (
    CONTRACT_GENERATION,
    DeprecatedGeneration,
    GenerationMarker,
    generation_is_supported,
    negotiate_generation,
    supported_generations,
)
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.status import Status
from sayfirst_contract.values import Unknown, read_enum


def test_the_outcome_vocabulary_is_closed_at_three() -> None:
    """Article 1: a fourth decision outcome is not part of the domain."""
    assert {item.value for item in Outcome} == {"allow", "deny", "suspend"}
    assert len(Outcome) == 3


def test_an_unknown_enum_value_reads_as_unknown() -> None:
    """Article 13: an enum value outside this generation is preserved, not guessed."""
    assert read_enum(Outcome, "allow") is Outcome.ALLOW
    assert read_enum(Outcome, "zz-synthetic-outcome-4e1f") == Unknown("zz-synthetic-outcome-4e1f")
    assert read_enum(Outcome, 7) == Unknown("7")


def test_a_request_writer_never_omits_the_generation() -> None:
    """Article 13: every emitted request pins the generation."""
    digest = "sha256:" + "0" * 64
    document = DecisionAsk("example.effect", arguments_digest=digest).to_document(
        CONTRACT_GENERATION
    )
    assert document == {
        "contract_generation": CONTRACT_GENERATION,
        "capability": "example.effect",
        "scope": "local",
        "arguments_digest": digest,
    }


def test_an_unknown_outcome_is_could_not_ask_and_reported_unknown() -> None:
    """Articles 1, 2 and 13: an unknown outcome never becomes a denial."""
    result = read_decision(
        {
            "contract_generation": 1,
            "authority": "authoritative",
            "decision_ref": "decision-1",
            "scope": "local",
            "capability": "example.effect",
            "outcome": "zz-synthetic-outcome-4e1f",
            "reason": "policy_allows",
            "policy_version": "sha256:" + "0" * 64,
            "approval_ref": None,
            "decided_at": "2026-09-04T00:00:00+00:00",
            "correlation": None,
        }
    )
    from sayfirst_contract.client import CouldNotAsk

    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.OUTCOME_UNKNOWN
    assert result.reported_outcome == "unknown"


def test_a_deprecated_generation_is_still_supported_inside_its_window() -> None:
    """Articles 8 and 13: either side of the deprecation window keeps support."""
    marker = GenerationMarker(
        2,
        (DeprecatedGeneration(1, date(2026, 1, 1), "0.2.0"),),
    )
    assert supported_generations(marker, on=date(2026, 7, 2), release="0.3.0") == (2, 1)
    assert supported_generations(marker, on=date(2026, 6, 1), release="0.4.0") == (2, 1)


def test_a_generation_past_its_window_is_not_supported() -> None:
    """Articles 8 and 13: support ends only after both minimum windows pass."""
    marker = GenerationMarker(
        2,
        (DeprecatedGeneration(1, date(2026, 1, 1), "0.2.0"),),
    )
    assert supported_generations(marker, on=date(2026, 7, 2), release="0.4.0") == (2,)


def test_generation_negotiation_is_a_pure_membership_rule() -> None:
    """Article 13: negotiation has no ambient state and distinguishes unsupported input."""
    supported = (2, 1)
    assert generation_is_supported(supported, 1)
    assert not generation_is_supported(supported, True)
    assert negotiate_generation(supported, 1) is None
    refusal = negotiate_generation(supported, 3)
    assert refusal is not None
    assert refusal.code is ProblemCode.GENERATION_UNSUPPORTED
    assert refusal.contract_generation == 3


def test_a_request_writer_rejects_a_non_positive_generation() -> None:
    """Article 13: request writers cannot emit an invalid generation."""
    with pytest.raises(ValueError, match="positive"):
        DecisionAsk("example.effect", arguments_digest="sha256:" + "0" * 64).to_document(0)


def test_reason_reading_does_not_change_a_known_outcome() -> None:
    """Article 13: an unknown reason remains data while the known outcome governs."""
    assert read_enum(Reason, "zz-synthetic-reason") == Unknown("zz-synthetic-reason")


def test_supported_generations_contains_the_status_generation() -> None:
    """Article 13: a status document cannot omit its own generation from support."""
    document = {
        "contract_generation": 1,
        "supported_generations": [2],
        "integrity_grade": {
            "grade": "unverified",
            "basis": "access_not_established",
            "evaluated_at": "2026-09-04T10:00:00Z",
            "store": "file",
            "reevaluation_interval_seconds": 30,
        },
        "privacy_provider": "none",
        "principal": {"kind": "user", "uid": 1000, "name": None},
        "store": {"authority": "authoritative", "kind": "file"},
    }
    with pytest.raises(ValueError, match="must contain contract_generation"):
        Status.from_document(document)


def _approval_document(**members: object) -> dict[str, object]:
    """The published `approval-result` of one ended wait, with whatever a case adds."""
    document: dict[str, object] = {
        "contract_generation": CONTRACT_GENERATION,
        "authority": "authoritative",
        "approval_ref": "approval-1",
        "decision_ref": "decision-1",
        "scope": "local",
        "capability": "example.effect",
        "state": "approved",
        "requested_at": "2026-09-15T12:00:00Z",
        "deadline": "2026-09-15T12:05:00Z",
        "resolved_at": "2026-09-15T12:00:10Z",
        "resolution_reason": None,
    }
    document.update(members)
    return document


def test_the_reader_reads_the_person_and_keeps_an_unknown_member_in_extra() -> None:
    """Both readers, so the member is not a server-only fact (article 13)."""
    document = _approval_document(person="user:1000", later_member="kept")

    approval = Approval.from_document(document)

    assert approval.person == "user:1000"
    assert approval.extra == {"later_member": "kept"}
    assert approval.to_document()["person"] == "user:1000"


def test_a_wait_no_document_names_a_person_on_reads_and_renders_none() -> None:
    """Article 2: absent is absent — a reader invents no person and renders no null one."""
    approval = Approval.from_document(_approval_document(state="expired", resolution_reason=None))

    assert approval.person is None
    assert "person" not in approval.to_document()
