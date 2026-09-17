# SPDX-License-Identifier: Apache-2.0
"""Article 13: the contract's retrospective evaluator passes the one fixture arbiter.

Two implementations of `sayfirst/policy-evaluation/v1` exist — the server's
live evaluator and this wheel's retrospective one — and they are held apart by
one vector set, `policy-evaluation-v1.json`, which each runs independently. The
retrospective one consumes recorded inputs and archived policy bytes, performs
no I/O, reaches no daemon, and mints nothing (article 1: a boundary deciding
locally is what is forbidden, and re-deriving a recorded decision after the
fact is not that).
"""

from __future__ import annotations

import inspect

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.retrospective_policy import (
    RECIPE,
    PolicyUnparseable,
    RecordedDecision,
    Rederivation,
    evaluate_recorded_inputs,
    rederive_recorded_decision,
)

VECTORS = load_json("domain", "policy-evaluation-v1.json")


def _cases(member: str) -> list[object]:
    assert isinstance(VECTORS, dict)
    cases = VECTORS[member]
    assert isinstance(cases, list) and len(cases) >= 8
    return cases


@pytest.mark.parametrize("vector", _cases("vectors"), ids=lambda item: item["name"])
def test_contract_evaluator_runs_every_policy_evaluation_vector(vector: dict) -> None:
    """Article 13: every published vector, through the contract's own evaluator."""
    assert VECTORS["recipe"] == RECIPE  # type: ignore[index]
    answer = evaluate_recorded_inputs(
        vector["policy"].encode("utf-8"),
        scope=vector["scope"],
        capability=vector["capability"],
        principal_references=tuple(vector["principal_references"]),
        arguments_digest=vector["arguments_digest"],
    )
    expected = vector["expected"]
    if expected.get("unparseable"):
        assert isinstance(answer, PolicyUnparseable), answer
    else:
        assert answer == (expected["outcome"], expected["reason"], expected["rule_id"])


@pytest.mark.parametrize("case", _cases("rederivations"), ids=lambda item: item["name"])
def test_a_recorded_decision_is_rederived_as_the_vector_says(case: dict) -> None:
    """Articles 2 and 13: confirmed, differs or unverifiable, with the published cause."""
    recorded = case["recorded"]
    references = recorded["principal_references"]
    result = rederive_recorded_decision(
        RecordedDecision(
            scope=recorded["scope"],
            capability=recorded["capability"],
            principal_references=None if references is None else tuple(references),
            arguments_digest=recorded["arguments_digest"],
            outcome=recorded["outcome"],
            reason=recorded["reason"],
            rule_id=recorded["rule_id"],
            evaluation_recipe=recorded["evaluation_recipe"],
        ),
        case["policy"].encode("utf-8"),
    )
    expected = case["expected"]
    assert result.verdict is Rederivation(expected["verdict"])
    assert result.cause == expected["cause"]
    assert result.expected == (
        None if expected["expected"] is None else tuple(expected["expected"])
    )


def test_the_vectors_cover_both_disagreement_and_the_reason_outside_the_recipe() -> None:
    """Anti-vacuity: the arbiter carries a differs, a confirmed and an out-of-recipe case."""
    verdicts = {case["expected"]["verdict"] for case in _cases("rederivations")}  # type: ignore[index]
    assert verdicts == {"confirmed", "differs", "unverifiable"}
    causes = {case["expected"]["cause"] for case in _cases("rederivations")}  # type: ignore[index]
    assert "reason_outside_recipe" in causes
    assert "evaluation_recipe_unsupported" in causes
    assert any(vector["expected"].get("unparseable") for vector in _cases("vectors"))  # type: ignore[index]
    assert any("live_acceptance" in vector for vector in _cases("vectors"))  # type: ignore[operator]


def test_the_evaluator_is_pure_and_is_not_reexported_from_the_package_root() -> None:
    """Article 1's mitigation: named for audit, documented as such, and not the root's.

    An importable evaluator in the wheel every boundary installs is the shortest
    path to a second control plane without evidence. The module says what it is
    for, opens no file, socket or clock, and the package root does not offer it.
    """
    import sayfirst_contract
    from sayfirst_contract import retrospective_policy

    assert "historical audit only; never authorize an effect" in (
        retrospective_policy.__doc__ or ""
    )
    assert not hasattr(sayfirst_contract, "retrospective_policy") or (
        "retrospective_policy" not in getattr(sayfirst_contract, "__all__", ())
    )
    source = inspect.getsource(retrospective_policy)
    for forbidden in ("import os", "import socket", "import time", "datetime", "open(", "Path("):
        assert forbidden not in source, forbidden
