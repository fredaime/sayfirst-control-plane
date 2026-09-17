# SPDX-License-Identifier: Apache-2.0
"""Article 13: the live evaluator runs the same vectors as the contract's, independently.

Two implementations of `sayfirst/policy-evaluation/v1` — `domain/policy.py`,
which decides live, and the contract wheel's retrospective module, which
re-derives after the fact — and one fixture arbiter between them,
`policy-evaluation-v1.json`. Neither imports the other; each runs every vector
on its own, and a vector one passes and the other fails is a defect in one of
the two. This is the live side.
"""

from __future__ import annotations

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_control_plane.domain.policy import (
    DecisionQuestion,
    PolicyInvalid,
    Principal,
    evaluate,
    parse_policy,
)

VECTORS = load_json("domain", "policy-evaluation-v1.json")


def _vectors() -> list[dict]:
    assert isinstance(VECTORS, dict)
    cases = VECTORS["vectors"]
    assert isinstance(cases, list) and len(cases) >= 8
    return cases


def _question(vector: dict) -> DecisionQuestion:
    """The live question the recorded references describe.

    The recorded references are what the daemon read for the decision: the
    caller's own user reference and the group references the relevant rules
    named. A live principal is rebuilt from them, so the live evaluator sees the
    same identity the retrospective one is handed.
    """
    references = [str(item) for item in vector["principal_references"]]
    users = [item.removeprefix("user:") for item in references if item.startswith("user:")]
    groups = tuple(item.removeprefix("group:") for item in references if item.startswith("group:"))
    return DecisionQuestion(
        DecisionAsk(
            vector["capability"], scope=vector["scope"], arguments_digest=vector["arguments_digest"]
        ),
        Principal("process", 1001, users[0] if users else "nobody", (2001,), groups),
    )


@pytest.mark.parametrize("vector", _vectors(), ids=lambda item: item["name"])
def test_the_live_evaluator_runs_every_policy_evaluation_vector(vector: dict) -> None:
    """Article 13: the live evaluator agrees with the published arbiter, on its own."""
    acceptance = vector.get("live_acceptance")
    cap = 3600 if acceptance is None else int(acceptance["max_lifetime_seconds"])
    parsed = parse_policy(vector["policy"].encode("utf-8"), max_lifetime_seconds=cap)
    expected = vector["expected"]
    if expected.get("unparseable") or (acceptance is not None and not acceptance["accepted"]):
        assert isinstance(parsed, PolicyInvalid), parsed
        return
    assert not isinstance(parsed, PolicyInvalid), parsed
    verdict = evaluate(parsed, _question(vector))
    assert (verdict.outcome.value, verdict.reason.value, verdict.rule_id) == (
        expected["outcome"],
        expected["reason"],
        expected["rule_id"],
    )


def test_the_acceptance_only_vector_is_refused_live_and_yields_a_triple_retrospectively() -> None:
    """Article 2: the narrower retrospective claim is labelled where the two differ.

    A lifetime above the deployment cap is refused by live acceptance and is not
    the outcome triple's business; the vector says so, and this holds both halves
    on the live side: refused under the cap, accepted without it.
    """
    vector = next(
        item
        for item in _vectors()
        if "live_acceptance" in item and not item["live_acceptance"]["accepted"]
    )
    cap = int(vector["live_acceptance"]["max_lifetime_seconds"])
    assert isinstance(
        parse_policy(vector["policy"].encode("utf-8"), max_lifetime_seconds=cap), PolicyInvalid
    )
    uncapped = parse_policy(vector["policy"].encode("utf-8"), max_lifetime_seconds=86400)
    assert not isinstance(uncapped, PolicyInvalid)
    verdict = evaluate(uncapped, _question(vector))
    assert verdict.rule_id == vector["expected"]["rule_id"]
