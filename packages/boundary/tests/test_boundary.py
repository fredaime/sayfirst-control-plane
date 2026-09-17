# SPDX-License-Identifier: Apache-2.0
"""The one shape: ask, then act, or do not act.

What is under test is the integration — that a miss asks, that a hit does not,
that each outcome leaves as its own exception, that nothing but an allow is
cached, and that the body does not run unless the control plane said it may. The
client is a scripted double: a real socket is exercised by the end-to-end suites
that start a daemon, and what matters here is the decision path.

The last case is the exception to "scripted": it walks the published registry
rather than a chosen code, so every published code is carried through
`ProblemCode` and `problem_retryable` on its way to the outcome its class names.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sayfirst_boundary import AskRefused, CouldNotAsk, Denied, Suspended
from sayfirst_boundary.boundary import Boundary
from sayfirst_boundary.digest import arguments_digest
from sayfirst_boundary.evidence import OutcomeLog, Record
from sayfirst_contract.client import Answered, Refused
from sayfirst_contract.client import CouldNotAsk as CouldNotAskResult
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_contract.grants import Grant, GrantConditions, GrantSignal
from sayfirst_contract.problems import (
    Problem,
    ProblemCode,
    classes_by_code,
    problem_class,
    problem_retryable,
)

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
VERSION = "sha256:" + "a" * 64
PRINCIPAL = "user:build"
ARGUMENTS = {"to": "someone@example.test"}


def _decision(outcome: Outcome, *, approval_ref: str | None = None) -> Decision:
    return Decision(
        decision_ref="dec-1",
        scope="local",
        capability="example.effect",
        outcome=outcome,
        reason=Reason.POLICY_ALLOWS if outcome is Outcome.ALLOW else Reason.POLICY_DENIES,
        policy_version=VERSION,
        approval_ref=approval_ref,
        decided_at=NOW.isoformat(),
        correlation=None,
        contract_generation=1,
        extra={},
    )


def _grant() -> Grant:
    return Grant(
        grant_id="g-1",
        decision_ref="dec-1",
        policy_version=VERSION,
        issued_at=NOW.isoformat(),
        lifetime_seconds=300,
        expires_at=(NOW + timedelta(seconds=300)).isoformat(),
        heartbeat_seconds=10,
        conditions=GrantConditions(
            "local", "example.effect", PRINCIPAL, arguments_digest(ARGUMENTS)
        ),
    )


class _Stream:
    def __init__(self, grant: Grant | None) -> None:
        self.grant = grant
        self.closed = False
        self._queue: list[GrantSignal] = []
        self._arrived = threading.Condition()
        self._finished = False

    def deliver(self, signal: GrantSignal) -> None:
        with self._arrived:
            self._queue.append(signal)
            self._arrived.notify_all()

    def finish(self) -> None:
        with self._arrived:
            self._finished = True
            self._arrived.notify_all()

    def signals(self) -> Iterator[GrantSignal]:
        while True:
            with self._arrived:
                while not self._queue and not self._finished:
                    self._arrived.wait()
                if self._queue:
                    yield self._queue.pop(0)
                    continue
                return

    def close(self) -> None:
        self.closed = True
        self.finish()


class _Client:
    """Answer each ask from a script, and count how often it was asked."""

    def __init__(self, answers: list[tuple[object, _Stream | None]]) -> None:
        self._answers = answers
        self.asks: list[DecisionAsk] = []

    def hold_decision(self, ask: DecisionAsk) -> tuple[object, _Stream | None]:
        self.asks.append(ask)
        return self._answers.pop(0)


def _boundary(client: _Client, written: list[Record] | None = None) -> Boundary:
    # `written or []` would build a NEW list whenever `written` is empty — which
    # is every time a test passes a fresh one — so the sink would append to a
    # throwaway and both log assertions would hold against an empty list for
    # ever. `is None` is the test that was meant.
    collected = [] if written is None else written
    log = OutcomeLog(capacity=8, sink=collected.append, clock=lambda: NOW)
    return Boundary(client=client, principal_reference=PRINCIPAL, log=log, clock=lambda: NOW)


@pytest.fixture
def client() -> _Client:
    return _Client([])


@pytest.fixture
def written() -> list[Record]:
    return []


@pytest.fixture
def boundary(client: _Client, written: list[Record]) -> Iterator[Boundary]:
    held = _boundary(client, written)
    try:
        yield held
    finally:
        held.close()


def test_an_allow_runs_the_body(client: _Client, boundary: Boundary) -> None:
    client._answers = [(Answered(_decision(Outcome.ALLOW), 1), _Stream(_grant()))]
    ran = False
    with boundary.request("example.effect", ARGUMENTS):
        ran = True
    assert ran is True


def test_the_ask_carries_a_digest_and_not_the_arguments(
    client: _Client, boundary: Boundary
) -> None:
    client._answers = [(Answered(_decision(Outcome.ALLOW), 1), _Stream(_grant()))]
    with boundary.request("example.effect", ARGUMENTS):
        pass
    assert client.asks[0].arguments_digest == arguments_digest(ARGUMENTS)
    assert "someone@example.test" not in repr(client.asks[0])


def test_a_second_identical_act_does_not_ask_again(client: _Client, boundary: Boundary) -> None:
    client._answers = [(Answered(_decision(Outcome.ALLOW), 1), _Stream(_grant()))]
    for _ in range(2):
        with boundary.request("example.effect", ARGUMENTS):
            pass
    assert len(client.asks) == 1


def test_different_arguments_ask_again(client: _Client, boundary: Boundary) -> None:
    client._answers = [
        (Answered(_decision(Outcome.ALLOW), 1), _Stream(_grant())),
        (Answered(_decision(Outcome.ALLOW), 1), _Stream(None)),
    ]
    with boundary.request("example.effect", ARGUMENTS):
        pass
    with boundary.request("example.effect", {"to": "other@example.test"}):
        pass
    assert len(client.asks) == 2


def test_a_deny_raises_and_the_body_does_not_run(client: _Client, boundary: Boundary) -> None:
    client._answers = [(Answered(_decision(Outcome.DENY), 1), _Stream(None))]
    ran = False
    with pytest.raises(Denied) as raised, boundary.request("example.effect", ARGUMENTS):
        ran = True  # pragma: no cover - the point is that this is unreachable
    assert ran is False
    assert raised.value.capability == "example.effect"


def test_a_suspend_raises_carrying_the_approval_and_does_not_park(
    client: _Client, boundary: Boundary
) -> None:
    client._answers = [
        (Answered(_decision(Outcome.SUSPEND, approval_ref="apr-1"), 1), _Stream(None))
    ]
    with pytest.raises(Suspended) as raised, boundary.request("example.effect", ARGUMENTS):
        pass  # pragma: no cover
    assert raised.value.approval_ref == "apr-1"


def test_a_refusal_is_not_a_denial(client: _Client, boundary: Boundary) -> None:
    problem = Problem(
        code=ProblemCode.OPERATION_UNKNOWN,
        message="no such capability",
        retryable=False,
        contract_generation=1,
    )
    client._answers = [(Refused(problem), None)]
    with pytest.raises(AskRefused), boundary.request("example.effect", ARGUMENTS):
        pass  # pragma: no cover


def test_an_unanswerable_question_fails_closed_and_is_not_a_denial(
    client: _Client, boundary: Boundary
) -> None:
    problem = Problem(
        code=ProblemCode.UNREACHABLE,
        message="no such file",
        retryable=True,
        contract_generation=1,
    )
    client._answers = [(CouldNotAskResult(problem), None)]
    ran = False
    with pytest.raises(CouldNotAsk), boundary.request("example.effect", ARGUMENTS):
        ran = True  # pragma: no cover
    assert ran is False


@pytest.mark.parametrize(
    ("outcome", "error"), [(Outcome.DENY, Denied), (Outcome.SUSPEND, Suspended)]
)
def test_nothing_but_an_allow_is_ever_cached(
    client: _Client, boundary: Boundary, outcome: Outcome, error: type[Exception]
) -> None:
    """Two asks for the same question, because the first answer was not cacheable."""
    client._answers = [
        (Answered(_decision(outcome), 1), _Stream(None)),
        (Answered(_decision(outcome), 1), _Stream(None)),
    ]
    for _ in range(2):
        with pytest.raises(error), boundary.request("example.effect", ARGUMENTS):
            pass  # pragma: no cover
    assert len(client.asks) == 2


def test_an_allow_that_minted_no_grant_is_not_cached_either(
    client: _Client, boundary: Boundary
) -> None:
    client._answers = [
        (Answered(_decision(Outcome.ALLOW), 1), _Stream(None)),
        (Answered(_decision(Outcome.ALLOW), 1), _Stream(None)),
    ]
    for _ in range(2):
        with boundary.request("example.effect", ARGUMENTS):
            pass
    assert len(client.asks) == 2


def test_the_outcome_a_caller_records_reaches_the_log(
    client: _Client, boundary: Boundary, written: list[Record]
) -> None:
    client._answers = [(Answered(_decision(Outcome.ALLOW), 1), _Stream(_grant()))]
    with boundary.request("example.effect", ARGUMENTS) as grant:
        grant.record_outcome("sha256:" + "5" * 64)
    boundary.flush()
    assert [record.outcome_digest for record in written] == ["sha256:" + "5" * 64]


def test_a_body_that_raised_still_records_that_it_was_permitted(
    client: _Client, boundary: Boundary, written: list[Record]
) -> None:
    """The decision happened; a record that vanished with the exception would lose it."""
    client._answers = [(Answered(_decision(Outcome.ALLOW), 1), _Stream(_grant()))]
    with pytest.raises(RuntimeError), boundary.request("example.effect", ARGUMENTS):
        raise RuntimeError("the effect failed")
    boundary.flush()
    assert [record.decision_ref for record in written] == ["dec-1"]
    assert written[0].outcome_digest is None


class _ClientAnswering:
    """One scripted answer, to whatever is asked of it."""

    def __init__(self, result: object) -> None:
        self._result = result

    def hold_decision(self, ask: DecisionAsk) -> tuple[object, None]:
        return self._result, None


@pytest.mark.parametrize("code", sorted(name for name in classes_by_code()))
def test_every_published_code_reaches_the_outcome_its_class_names(code: str) -> None:
    """A governed program sees `AskRefused` for a refusal and `CouldNotAsk` for the rest.

    Article 2: the absence of a refusal is not a refusal and is not an
    allowance. The boundary does not classify — it maps the result the contract
    already classed — so this walks the registry rather than a list.
    """
    problem = Problem(ProblemCode(code), "as published", problem_retryable(ProblemCode(code)), 1)
    result = Refused(problem) if problem_class(code) == "refused" else CouldNotAskResult(problem)
    boundary = Boundary(client=_ClientAnswering(result), principal_reference="user:test")
    expected = AskRefused if problem_class(code) == "refused" else CouldNotAsk
    with pytest.raises(expected), boundary.request("example.effect", {}):
        pytest.fail("the body ran on a non-allow")
