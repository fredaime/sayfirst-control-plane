# SPDX-License-Identifier: Apache-2.0 OR MIT-0
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_contract.approvals import ApprovalResolution, ApprovalState, Resolution
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.client import Answered, CouldNotAsk, Refused
from sayfirst_contract.evidence import ChainCondition, entry_verifies, verify_chain
from sayfirst_contract.golden import Expect, load_scenarios
from sayfirst_contract.problems import ProblemCode, problem_class
from sayfirst_contract.replay import Side, Verdict, replay
from sayfirst_contract_stub.stub import _PAGE_BOUND, Stub, StubHarness


def test_the_stub_answers_only_outcomes_of_this_generation() -> None:
    """Articles 1 and 13: the server fake emits only defined server values."""
    registry = load_json("domain", "problem-codes.json")["codes"]
    for scenario in load_scenarios().values():
        if scenario.given.server is not None:
            with pytest.raises(ValueError, match="scripts a server this fake is not"):
                Stub(scenario.name)
            continue
        stub = Stub(scenario.name)
        result = stub.ask_decision(scenario.ask)
        if scenario.given.policy_unavailable:
            assert isinstance(result, CouldNotAsk)
            assert result.problem.code is ProblemCode.POLICY_UNAVAILABLE
            continue
        assert isinstance(result, Answered)
        assert result.contract_generation == 1
        assert result.value.contract_generation == 1
        assert result.value.outcome.value in {"allow", "deny", "suspend"}
        if result.value.approval_ref is not None:
            approval = stub.read_approval(result.value.scope, result.value.approval_ref)
            assert isinstance(approval, Answered)
            assert approval.value.contract_generation == 1
            assert approval.value.state is not ApprovalState.UNKNOWN
    status = Stub("allow").read_status()
    assert isinstance(status, Answered)
    assert status.value.contract_generation == 1
    refusal = Stub("allow").read_approval("local", "not-present")
    assert isinstance(refusal, Refused)
    assert registry[refusal.problem.code.value]["origin"] == "server"


def test_a_fake_that_decided_nothing_claims_no_entry_and_no_verdict() -> None:
    """Article 2: an empty chain establishes nothing, and says so.

    The verdict is the published verifier's over a range with nothing in it,
    not one this fake writes for itself — which is what it used to answer for
    every range, entries or no entries.
    """
    stub = Stub("allow")
    page = stub.read_evidence("local", 1)
    bundle = stub.export_evidence("local", 1)
    assert isinstance(page, Answered)
    assert isinstance(bundle, Answered)
    assert page.value["verification"]["condition"] == "unverifiable"
    assert page.value["verification"]["covers_an_entry"] is False
    assert bundle.value["entry_count"] == 0


def test_a_decision_the_fake_took_is_on_a_chain_the_published_verifier_reads() -> None:
    """Article 13: one recipe places the entry, and one verifier judges the range.

    Both faces of this fake answer from the same chain, so a consumer that
    exercises it in process sees what the socket face serves.
    """
    stub = Stub("allow")
    decision = stub.ask_decision(load_scenarios()["allow"].ask)
    assert isinstance(decision, Answered)
    page = stub.read_evidence("local", 1)
    assert isinstance(page, Answered)
    entries = page.value["entries"]
    assert [entry["kind"] for entry in entries] == ["grade", "effect"]
    assert entries[1]["body"]["decision_id"] == decision.value.decision_ref
    assert all(entry_verifies(entry) for entry in entries), entries
    assert verify_chain(entries, scope="local", from_sequence=1).condition is ChainCondition.intact


def test_a_range_outside_the_published_bounds_is_refused_by_name() -> None:
    """Articles 1 and 2: the in-process face answers a result, never an exception.

    The socket face refuses these before the object below is reached, which is
    exactly why the object needs its own case: it is published too, and a
    caller that asks it for a range it cannot serve is owed the code the daemon
    answers and not a raise out of a verifier.
    """
    stub = Stub("allow")
    for asked in (
        lambda: stub.read_evidence("local", 0),
        lambda: stub.read_evidence("local", 1, 0),
        lambda: stub.read_evidence("local", 1, _PAGE_BOUND + 1),
        lambda: stub.export_evidence("local", 2, 1),
    ):
        refusal = asked()
        assert isinstance(refusal, Refused), refusal
        assert refusal.problem.code is ProblemCode.EVIDENCE_RANGE_INVALID


def test_a_scope_the_contract_rejects_is_refused_as_a_malformed_scope() -> None:
    """The code the daemon answers for the same input, and not the range code.

    A scope that fails the contract's pattern is a malformed request; answering
    the range code would tell a caller its range was out of bounds, which is a
    statement about something never read.
    """
    stub = Stub("allow")
    for refusal in (stub.read_evidence("bad scope!", 1), stub.export_evidence("bad scope!", 1)):
        assert isinstance(refusal, Refused), refusal
        assert refusal.problem.code is ProblemCode.SCOPE_INVALID


def test_an_entry_the_published_reader_cannot_read_is_this_fakes_own_defect() -> None:
    """Article 2: a chain this fake broke is not a complaint about the caller's scope.

    The scope and the range are held before the verifier is called, so what is
    left for it to refuse is an entry this fake placed and the published reader
    cannot read. Answering `scope_invalid` for that would report a defect of
    the fake as a fault of the request — and rule P1 already names the answer a
    defect gets. Broken by hand here, because nothing this fake writes is
    unreadable and the arm would otherwise be reasoning with no case under it.
    """
    stub = Stub("allow")
    assert isinstance(stub.ask_decision(load_scenarios()["allow"].ask), Answered)
    del stub._entries["local"][0]["previous_hash"]

    result = stub.read_evidence("local", 1)
    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.INTERNAL
    assert "previous_hash" in result.problem.message, result.problem.message


def test_the_fake_reads_back_a_decision_it_took_and_refuses_one_it_did_not() -> None:
    """Article 13: the pair a published read exists for, answered by the fake too."""
    stub = Stub("allow")
    decision = stub.ask_decision(load_scenarios()["allow"].ask)
    assert isinstance(decision, Answered)
    read = stub.read_decision("local", decision.value.decision_ref)
    assert isinstance(read, Answered)
    assert read.value == decision.value
    # A scope nobody decided in is not a scope this fake decided in.
    elsewhere = stub.read_decision("elsewhere", decision.value.decision_ref)
    assert isinstance(elsewhere, Refused)
    assert elsewhere.problem.code is ProblemCode.DECISION_NOT_FOUND


def test_the_stub_pairs_outcome_and_reason() -> None:
    """Article 1: each fake decision uses an allowed outcome/reason pair."""
    allowed = {
        # The two approval reasons are the pairing article 12 fixes for a
        # re-ask of a question one person has already answered: an allow or a
        # deny, never a fourth outcome. `review_approve` and `review_reject`
        # now script that re-ask, so both are reached by a shipped fixture and
        # not only published (article 13); the loop below takes one ask per
        # scenario, which is the first one, so what it walks is the pairing of
        # the scripted outcome.
        "allow": {"policy_allows", "approval_granted"},
        "deny": {"policy_denies", "policy_absent", "capability_unknown", "approval_rejected"},
        "suspend": {"policy_requires_review"},
    }
    for scenario in load_scenarios().values():
        if scenario.binds_server() and not scenario.given.policy_unavailable:
            result = Stub(scenario.name).ask_decision(scenario.ask)
            assert isinstance(result, Answered)
            assert result.value.reason.value in allowed[result.value.outcome.value]
            assert (result.value.approval_ref is not None) is (
                result.value.outcome.value == "suspend"
            )


def test_the_stub_replays_every_scenario_that_binds_the_server() -> None:
    """Article 13: the fake passes precisely the server-bound authoritative set."""
    report = replay(load_scenarios(), StubHarness(), Side.SERVER)
    assert report.failures() == ()
    assert {item.name for item in report.bound()} == {
        name for name, scenario in load_scenarios().items() if scenario.binds_server()
    }
    not_applicable = {
        item.name for item in report.scenarios if item.verdict is Verdict.NOT_APPLICABLE
    }
    assert not_applicable == {
        name for name, scenario in load_scenarios().items() if not scenario.binds_server()
    }
    assert not_applicable == {
        "grant_expired_by_lifetime",
        "grant_hit_within_lifetime",
        "grant_void_on_arguments_change",
        "grant_void_on_connection_loss",
        "unknown_outcome",
        "unreachable",
    }


def test_a_second_resolution_is_refused() -> None:
    """Articles 3 and 12: one resolution creates one terminal record."""
    stub = Stub("review_approve")
    decision = stub.ask_decision(load_scenarios()["review_approve"].ask)
    assert isinstance(decision, Answered)
    resolution = ApprovalResolution(
        "local",
        decision.value.approval_ref,
        Resolution.APPROVE,  # type: ignore[arg-type]
    )
    assert isinstance(stub.resolve_approval(resolution), Answered)
    second = stub.resolve_approval(resolution)
    assert isinstance(second, Refused)
    assert second.problem.code is ProblemCode.APPROVAL_RESOLVED
    assert len(stub.approval_records) == 2


def test_a_resolution_after_the_deadline_is_refused() -> None:
    """Article 12: expiry is terminal and cannot be resolved afterward."""
    now = datetime(2026, 9, 4, tzinfo=UTC)
    stub = Stub("review_expire", clock=lambda: now)
    decision = stub.ask_decision(load_scenarios()["review_expire"].ask)
    assert isinstance(decision, Answered)
    now += timedelta(seconds=61)
    result = stub.resolve_approval(
        ApprovalResolution("local", decision.value.approval_ref, Resolution.APPROVE)  # type: ignore[arg-type]
    )
    assert isinstance(result, Refused)
    assert result.problem.code is ProblemCode.APPROVAL_RESOLVED
    approval = stub.read_approval("local", decision.value.approval_ref)  # type: ignore[arg-type]
    assert isinstance(approval, Answered)
    assert approval.value.state is ApprovalState.EXPIRED


def test_the_document_the_fake_serves_names_a_person_exactly_where_one_acted() -> None:
    """Articles 12 and 13: a conformance claim is proven by a test, or it is not made.

    The fake's own answer is the fixture here — what a third party building
    against this distribution reads is `to_document`, which is what `stub_http`
    writes on the wire — so the member is asserted on that document and never on
    a field of the fake. The rule it must serve is the server's: exactly one
    person behind an act, and no such member at all on a wait nobody acted on,
    absent rather than null. The lapse is the fake's own — the deadline passes on
    its clock and it expires the wait when the wait is read — so an expired
    document is proven here rather than assumed to follow from the pending one,
    and the instant that document ends at is asserted in the same breath: one
    read proves both, and a lapse is the one state whose instant a server's own
    record allows exactly one value for.
    """
    now = datetime(2026, 9, 4, tzinfo=UTC)
    acted = Stub("review_approve", clock=lambda: now)
    decision = acted.ask_decision(load_scenarios()["review_approve"].ask)
    assert isinstance(decision, Answered)
    reference = decision.value.approval_ref
    assert reference is not None

    waiting = acted.read_approval("local", reference)
    assert isinstance(waiting, Answered), waiting
    assert waiting.value.state is ApprovalState.PENDING
    assert "person" not in waiting.value.to_document(), "nobody has acted, so nobody is named"

    assert isinstance(
        acted.resolve_approval(ApprovalResolution("local", reference, Resolution.APPROVE)), Answered
    )
    resolved = acted.read_approval("local", reference)
    assert isinstance(resolved, Answered), resolved
    document = resolved.value.to_document()
    assert document["state"] == "approved"
    person = document.get("person")
    assert isinstance(person, str) and person, f"an act names the person who took it: {document}"

    lapsing = Stub("review_expire", clock=lambda: now)
    lapsed_decision = lapsing.ask_decision(load_scenarios()["review_expire"].ask)
    assert isinstance(lapsed_decision, Answered)
    lapsed_reference = lapsed_decision.value.approval_ref
    assert lapsed_reference is not None
    now += timedelta(seconds=61)

    lapsed = lapsing.read_approval("local", lapsed_reference)
    assert isinstance(lapsed, Answered), lapsed
    assert lapsed.value.state is ApprovalState.EXPIRED
    lapse = lapsed.value.to_document()
    assert "person" not in lapse, "a wait that ran out attributes nothing"
    # A lapse ended when it ran out, which is its deadline and no other
    # instant: the server's record refuses any other value, so a fake serving
    # `expired` with a null instant would serve a document no daemon can
    # (articles 2 and 13).
    assert lapse["resolved_at"] == lapse["deadline"], lapse


def _internal_failure() -> Refused | CouldNotAsk:
    """The one answer this fake gives for a scenario that states no decision."""
    scenario = replace(load_scenarios()["allow"], expect=Expect())
    result = Stub(scenario.name, scenarios={scenario.name: scenario}).ask_decision(scenario.ask)
    assert isinstance(result, Refused | CouldNotAsk), result
    return result


def test_the_stub_uses_the_registered_retryability_for_internal_failures() -> None:
    """Article 2: an unclassified server failure does not claim non-retryability."""
    result = _internal_failure()
    assert result.problem.code is ProblemCode.INTERNAL
    assert result.problem.retryable is None


def test_the_stub_classes_a_published_problem_as_the_registry_classes_it() -> None:
    """Article 13: the fake answers the class a daemon answers, or it proves nothing.

    Retryability was always read from the registry here; the class is the other
    column of the same row. A fake that decided it for itself would let a
    consumer's governed program pass against this distribution and fail against
    a daemon on the same code — the one outcome a conformance fake must not
    produce.

    Both sides of the column are walked through the fake's own operations:
    `internal` is a « could not ask » (a server that cannot say why it failed
    has not refused the question), and `approval_resolved` is a refusal (the
    act reached the daemon and the daemon rejected it). Asserted against
    `problem_class` rather than spelled out, so a class that moves in the
    registry moves here.
    """
    internal = _internal_failure()
    assert internal.problem.code is ProblemCode.INTERNAL
    assert problem_class(ProblemCode.INTERNAL) == "could_not_ask"
    assert type(internal) is CouldNotAsk, internal

    stub = Stub("review_approve")
    decision = stub.ask_decision(load_scenarios()["review_approve"].ask)
    assert isinstance(decision, Answered)
    resolution = ApprovalResolution(
        "local",
        decision.value.approval_ref,  # type: ignore[arg-type]
        Resolution.APPROVE,
    )
    assert isinstance(stub.resolve_approval(resolution), Answered)
    spent = stub.resolve_approval(resolution)
    assert spent.problem.code is ProblemCode.APPROVAL_RESOLVED  # type: ignore[union-attr]
    assert problem_class(ProblemCode.APPROVAL_RESOLVED) == "refused"
    assert type(spent) is Refused, spent
    # A refusal is a control plane's to give, so a refused result carries a
    # problem that says one answered — here the fake is that control plane.
    assert spent.problem.control_plane_answered is True
    assert internal.problem.control_plane_answered is True
