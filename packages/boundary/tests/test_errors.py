# SPDX-License-Identifier: Apache-2.0
"""The outcomes a caller catches, held apart from one another.

Article 1 closes the outcome set at allow, deny and suspend, and article 2 adds
the fourth thing that is not an outcome: the question could not be asked. A
caller that caught one type for all four would have lost the distinction the
constitution insists on, so each is its own type and none is a subclass of
another.
"""

from __future__ import annotations

import pytest
from sayfirst_boundary.errors import (
    AskRefused,
    BoundaryError,
    CouldNotAsk,
    Denied,
    Suspended,
)


def test_every_outcome_is_a_boundary_error() -> None:
    for error in (Denied, Suspended, AskRefused, CouldNotAsk):
        assert issubclass(error, BoundaryError)


def test_no_outcome_is_a_subclass_of_another() -> None:
    outcomes = (Denied, Suspended, AskRefused, CouldNotAsk)
    for one in outcomes:
        for other in outcomes:
            if one is not other:
                assert not issubclass(one, other), f"{one.__name__} catches {other.__name__}"


def test_a_denial_carries_what_denied_it() -> None:
    error = Denied(decision_ref="dec-1", capability="example.effect", reason="policy_denies")
    assert (error.decision_ref, error.capability, error.reason) == (
        "dec-1",
        "example.effect",
        "policy_denies",
    )


def test_a_suspension_carries_the_approval_a_person_will_answer() -> None:
    error = Suspended(approval_ref="apr-1", decision_ref="dec-1", capability="example.effect")
    assert error.approval_ref == "apr-1"


def test_could_not_ask_says_whether_asking_again_could_help() -> None:
    assert CouldNotAsk(detail="no such file", retryable=True).retryable is True
    assert CouldNotAsk(detail="unreadable answer", retryable=False).retryable is False


def test_catching_a_denial_does_not_catch_an_unanswerable_question() -> None:
    with pytest.raises(CouldNotAsk):
        try:
            raise CouldNotAsk(detail="unreachable", retryable=True)
        except Denied:  # pragma: no cover - the point is that this does not match
            pytest.fail("CouldNotAsk was caught as Denied")
