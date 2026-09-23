# SPDX-License-Identifier: Apache-2.0
"""The one shape a governed program uses, and the only way into the body.

    with boundary.request(capability, arguments) as grant:
        result = do_the_effect(**arguments)
        grant.record_outcome(digest(result))

There is no path into that body that skips the ask, which is the whole design:
the decision is not a check the body could forget to make, it is the thing that
opens the body at all. A hit on a held grant does not ask; a miss asks; anything
other than an allow raises before the body, and `could not ask` raises too,
because the absence of a refusal is not permission (doctrine D4).

Only an allow is cached, and only an allow that arrived with a grant. The
control plane mints a grant for exactly one question, and an allow served
without one is an allow that is not to be reused.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sayfirst_contract.client import Answered, Refused
from sayfirst_contract.client import CouldNotAsk as CouldNotAskResult
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome

from .cache import GrantStore
from .digest import arguments_digest
from .errors import AskRefused, CouldNotAsk, Denied, Suspended
from .evidence import OutcomeLog
from .signals import SignalReader


class _Client(Protocol):
    def hold_decision(self, ask: DecisionAsk) -> tuple[object, object]: ...


@dataclass
class GrantHandle:
    """What the body may say about what it did."""

    decision_ref: str
    capability: str
    _log: OutcomeLog
    recorded: bool = False

    def record_outcome(self, digest: str) -> None:
        self._log.record(
            capability=self.capability,
            decision_ref=self.decision_ref,
            outcome_digest=digest,
        )
        self.recorded = True


class Boundary:
    """Ask the control plane before an effect, and hold what it grants."""

    def __init__(
        self,
        *,
        client: _Client,
        principal_reference: str,
        correlation: str | None = None,
        log: OutcomeLog | None = None,
        clock: Callable[[], datetime] | None = None,
        hold_grants: bool = True,
    ) -> None:
        self._client = client
        self._principal = principal_reference
        # Article 10's cache: an allow minted a grant, and an identical later act
        # is answered by it without a round trip. A boundary that holds none asks
        # for every act instead — what a verifier needs, since its proof is one
        # recorded decision for each effect it saw and a grant hit records
        # nothing. Asking more often is always allowed; never asking less is the
        # rule the cache itself keeps.
        self._hold_grants = hold_grants
        # One boundary is one execution, so a correlation set here is stamped on
        # every ask this boundary puts, and the plane records it on the effect
        # (`correlation_source: boundary_supplied`). It is how a later reader —
        # the verifier above all — tells THIS run's records from another
        # execution's of the same principal, without trusting the boundary for a
        # connection identity. It is not part of a grant's key (a grant matches
        # on scope, principal, capability and digest), so a constant correlation
        # across a run leaves the cache exactly as it was.
        self._correlation = correlation
        self._clock = clock or (lambda: datetime.now(UTC))
        self._store = GrantStore()
        self._log = log or OutcomeLog(capacity=1024, sink=lambda record: None, clock=self._clock)

    @contextmanager
    def request(
        self,
        capability: str,
        arguments: Mapping[str, object],
        *,
        scope: str = "local",
    ) -> Iterator[GrantHandle]:
        try:
            digest = arguments_digest(arguments)
        except (TypeError, ValueError, RecursionError) as error:
            # UnicodeEncodeError is a ValueError: a path that is not UTF-8, which
            # `os.fsdecode` leaves as a lone surrogate. The digest is how the
            # question is put, so arguments it cannot describe are a question
            # that was not asked — one of this boundary's four outcomes, and the
            # body does not run.
            raise CouldNotAsk(
                detail=f"the effect's arguments cannot be described to the control plane: {error}",
                retryable=False,
            ) from error
        ask = DecisionAsk(
            capability=capability,
            scope=scope,
            arguments_digest=digest,
            correlation=self._correlation,
        )
        now = self._clock()
        held = self._store.take(ask, self._principal, now=now) if self._hold_grants else None
        decision_ref = held.held().grant.decision_ref if held is not None else self._ask(ask)
        handle = GrantHandle(decision_ref=decision_ref, capability=capability, _log=self._log)
        try:
            yield handle
        finally:
            if not handle.recorded:
                self._log.record(
                    capability=capability,
                    decision_ref=decision_ref,
                    outcome_digest=None,
                )

    def _ask(self, ask: DecisionAsk) -> str:
        """Put the question, raise anything that is not an allow, cache what is."""
        result, stream = self._client.hold_decision(ask)
        if isinstance(result, Refused):
            raise AskRefused(
                problem_code=str(result.problem.code),
                detail=str(result.problem.message),
            )
        if isinstance(result, CouldNotAskResult):
            # The contract already says whether asking again could help, so the
            # boundary reports that rather than deciding for itself.
            raise CouldNotAsk(
                detail=str(result.problem.message),
                retryable=result.problem.retryable,
            )
        if not isinstance(result, Answered):
            raise CouldNotAsk(detail="the answer could not be read", retryable=False)
        decision: Decision = result.value
        if decision.outcome is Outcome.DENY:
            self._close(stream)
            raise Denied(
                decision_ref=decision.decision_ref,
                capability=decision.capability,
                reason=str(decision.reason),
            )
        if decision.outcome is Outcome.SUSPEND:
            self._close(stream)
            raise Suspended(
                approval_ref=str(decision.approval_ref),
                decision_ref=decision.decision_ref,
                capability=decision.capability,
            )
        if self._hold_grants and stream is not None and getattr(stream, "grant", None) is not None:
            try:
                reader = SignalReader(stream, clock=self._clock)
            except Exception:
                # The allow was answered and recorded, and this act runs on it.
                # A grant that cannot be held only means the next identical act
                # asks again; keeping the connection with nothing reading it
                # would be the leak.
                self._close(stream)
            else:
                self._store.put(reader)
        else:
            self._close(stream)
        return decision.decision_ref

    @staticmethod
    def _close(stream: object) -> None:
        closer = getattr(stream, "close", None)
        if callable(closer):
            closer()

    def flush(self) -> None:
        """Hand held records to the sink. Called by a caller, never on the hot path."""
        self._log.flush()

    def close(self) -> None:
        """Give up every held grant and flush what is recorded."""
        self._store.close()
        self._log.flush()
