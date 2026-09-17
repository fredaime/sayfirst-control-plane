# SPDX-License-Identifier: Apache-2.0
"""Bounded asynchronous evidence emission with declared loss."""

from __future__ import annotations

import base64
import os
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Condition, Lock, Thread
from time import monotonic
from typing import Final
from uuid import uuid4

from sayfirst_control_plane.domain.evidence_chain import (
    DAEMON_CONNECTION,
    EvidenceRecord,
    Principal,
)
from sayfirst_control_plane.domain.foreign import core_owned, core_owned_instant
from sayfirst_control_plane.domain.integrity_grade import (
    CallerAccess,
    Grade,
    GradeEvaluation,
    evaluate_grade,
)
from sayfirst_control_plane.plugins.interfaces import PrivacyRedactor, Redaction
from sayfirst_control_plane.plugins.privacy.none import NoRedaction
from sayfirst_control_plane.ports.clock import Clock
from sayfirst_control_plane.ports.decision_store import DecisionPosition
from sayfirst_control_plane.ports.evidence_store import EvidenceStore, StoreLocation
from sayfirst_control_plane.ports.path_access import PathAccess, PathFacts

EVIDENCE_QUEUE_CAPACITY: Final = 4096
CAPTURE_HARD_CEILING: Final = 65_536
GRADE_REEVALUATION_INTERVAL_SECONDS: Final = 30

#: A store that refuses an append is retried, never spun on: the first retry is
#: soon enough to ride out a momentary refusal, and the delay doubles to a
#: ceiling so a store that is down for the daemon's life costs one wakeup every
#: few seconds rather than a core (article 10 bounds the pipeline).
RETRY_INITIAL_SECONDS: Final = 0.05
RETRY_MAX_SECONDS: Final = 5.0


@dataclass(frozen=True)
class CaptureRule:
    capability: str
    max_bytes: int

    def __post_init__(self) -> None:
        if not self.capability or self.capability == "*":
            raise ValueError("a capture rule must name one capability")
        if not 1 <= self.max_bytes <= CAPTURE_HARD_CEILING:
            raise ValueError("max_bytes is outside the capture bound")


class CapturePolicy:
    def __init__(self, rules: Iterable[CaptureRule] = ()) -> None:
        values = tuple(rules)
        if len({item.capability for item in values}) != len(values):
            raise ValueError("a capability has more than one capture rule")
        self._rules = {item.capability: item for item in values}

    def for_capability(self, capability: str) -> CaptureRule | None:
        return self._rules.get(capability)


@dataclass(frozen=True)
class EvidenceConnection:
    connection_id: str
    access: CallerAccess

    def __post_init__(self) -> None:
        if not self.connection_id or self.connection_id == DAEMON_CONNECTION:
            raise ValueError("connection_id is required and reserved from the daemon")


@dataclass(frozen=True)
class EffectDecision:
    """The decision an effect records, with the facts a new writer copies beside it (M1).

    The five historical members stand alone for a writer that has none of the
    rest; a writer that supplies `evaluation_recipe` supplies the whole set,
    and the body carries them together with `correlation_source` derived from
    whether a correlation was supplied.
    """

    decision_id: str
    outcome: str
    decided_at: datetime
    policy_version: str
    reason: str | None = None
    rule_id: str | None = None
    arguments_digest: str | None = None
    correlation: str | None = None
    principal_references: tuple[str, ...] | None = None
    evaluation_recipe: str | None = None
    position: DecisionPosition | None = None


@dataclass(frozen=True)
class _Loss:
    """What a gap says about one record, read from the record by the core.

    Article 11: a gap claims which kinds were dropped and when, and a record
    that has been handed to a store is memory that store can write. Reading
    these two members off the record *before* the store sees it is what keeps
    the claim about the emission rather than about the refusal — a store that
    rewrote the `kind` of a record it then refused made the gap name a kind
    nothing emitted, and, because the chain admits only the four kinds it
    publishes, made the gap record unbuildable and the loss unrecorded.
    """

    kind: str
    recorded_at: datetime


def _losses(records: tuple[EvidenceRecord, ...]) -> tuple[_Loss, ...]:
    """The core's own reading of what a gap over these records would say."""
    return tuple(_Loss(record.kind, record.recorded_at) for record in records)


@dataclass
class _PendingGap:
    count: int
    first_at: datetime
    last_at: datetime
    kinds: Counter[str]

    @classmethod
    def from_losses(cls, losses: tuple[_Loss, ...]) -> _PendingGap:
        instants = [item.recorded_at for item in losses]
        return cls(
            len(losses),
            min(instants),
            max(instants),
            Counter(item.kind for item in losses),
        )

    def include(self, losses: tuple[_Loss, ...]) -> None:
        self.count += len(losses)
        self.first_at = min(self.first_at, *(item.recorded_at for item in losses))
        self.last_at = max(self.last_at, *(item.recorded_at for item in losses))
        self.kinds.update(item.kind for item in losses)


@dataclass(frozen=True)
class _Unit:
    scope: str
    records: tuple[EvidenceRecord, ...]
    gap_before: _PendingGap | None = None


@dataclass(frozen=True)
class _GradeState:
    evaluation: GradeEvaluation


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class EvidenceEmitter:
    """Return from emission without waiting for the evidence authority."""

    def __init__(
        self,
        store: EvidenceStore,
        *,
        clock: Clock | None = None,
        path_access: PathAccess | None = None,
        privacy_redactor: PrivacyRedactor | None = None,
        capture_policy: CapturePolicy | None = None,
        queue_capacity: int = EVIDENCE_QUEUE_CAPACITY,
        grade_reevaluation_seconds: int = GRADE_REEVALUATION_INTERVAL_SECONDS,
        daemon_access: CallerAccess | None = None,
        daemon_principal: Principal | None = None,
        also_inspected: Iterable[Callable[[], StoreLocation]] = (),
        recording_epoch: str | None = None,
        before_first_event: Callable[[str], None] | None = None,
    ) -> None:
        if queue_capacity < 1:
            raise ValueError("queue_capacity must be positive")
        if not 1 <= grade_reevaluation_seconds <= 300:
            raise ValueError("grade_reevaluation_seconds must be in [1, 300]")
        self._store = store
        self._clock = clock or _SystemClock()
        self._path_access = path_access
        #: The other stores a grade must read (R6): the decision authority,
        #: the policy archive, the recovery journal. A caller who can write
        #: any of them can forge what the chain would then confirm, so each is
        #: inspected with its parents and its actual files, and the grade is
        #: the weakest claim any of them supports (article 7).
        self._also_inspected = tuple(also_inspected)
        #: The recording epoch every body this emitter writes names (C3): an
        #: opaque identifier of this process's run, never a clock, so a reader
        #: can tell which entries an epoch that did not close cleanly covers.
        self.recording_epoch = recording_epoch or f"epoch:{uuid4()}"
        #: Called once per scope before the first event of it is accepted, so
        #: the recovery journal can open the scope's epoch first (C3).
        self.before_first_event = before_first_event
        self._scopes_seen: set[str] = set()
        self._scopes_seen_lock = Lock()
        self._redactor = privacy_redactor or NoRedaction()
        #: Read once, at composition, and held: the name in a capture record is
        #: the provider this daemon composed, not one a later answer names.
        self._redactor_name = str(self._redactor.name)
        self._capture_policy = capture_policy or CapturePolicy()
        self._capacity = queue_capacity
        self._grade_interval = grade_reevaluation_seconds
        uid = os.getuid()
        self._daemon_access = daemon_access or CallerAccess(uid, frozenset(os.getgroups()))
        self._daemon_principal = daemon_principal or Principal("service", "daemon")
        self._condition = Condition()
        self._queue: deque[_Unit] = deque()
        self._queued_records = 0
        self._pending: dict[str, _PendingGap] = {}
        self._flush_requests: Counter[str] = Counter()
        self._flush_completed: Counter[str] = Counter()
        self._retry_at: dict[str, float] = {}
        self._retry_backoff: dict[str, float] = {}
        self._final_attempt: set[str] = set()
        self._delivering = True
        self._inflight: _Unit | None = None
        self._closing = False
        self._grade_lock = Lock()
        self._grades: dict[tuple[str, str], _GradeState] = {}
        self._worker = Thread(target=self._drain, name="evidence-emitter", daemon=True)
        self._worker.start()

    @property
    def privacy_provider(self) -> str:
        return self._redactor_name

    @property
    def grade_reevaluation_seconds(self) -> int:
        return self._grade_interval

    @property
    def store_location(self) -> StoreLocation:
        return self._core_owned_location()

    def _core_owned_location(self) -> StoreLocation:
        """Where the store says it keeps evidence, as the core's own value."""
        return core_owned(
            StoreLocation,
            self._store.location(),
            kind=str,
            root=lambda root: None if root is None else Path(root),
            retention=str,
        )

    @property
    def pending_flush_requests(self) -> tuple[str, ...]:
        """The scopes a caller is still waiting on; a timed-out request is gone."""
        with self._condition:
            return tuple(sorted(self._flush_requests))

    @property
    def worker_is_alive(self) -> bool:
        return self._worker.is_alive()

    @property
    def emission_status(self) -> dict[str, object]:
        """Whether the pipeline is delivering, and what it is holding if not.

        Article 10 makes the pipeline declare its gaps. A store that refuses
        every append holds those gaps in memory, where no reader can see them,
        so the emitter says here that it is not delivering and how many records
        it is holding — an unrecorded record is never silently unrecorded.
        """
        with self._condition:
            holding: Counter[str] = Counter()
            for scope, gap in self._pending.items():
                holding[scope] += gap.count
            for unit in (*self._queue, *((self._inflight,) if self._inflight else ())):
                holding[unit.scope] += len(unit.records)
                if unit.gap_before is not None:
                    holding[unit.scope] += unit.gap_before.count
            return {
                "delivering": self._delivering,
                "undelivered_records": sum(holding.values()),
                "scopes_undelivered": sorted(scope for scope, held in holding.items() if held),
            }

    def emit(self, record: EvidenceRecord) -> bool:
        """Enqueue one record; `False` when the pipeline is not recording it.

        `True` means the record was accepted *and* the store is accepting
        appends. It is `False` when the queue could not hold the record — the
        loss is declared as a gap — and `False` while the store is refusing
        writes, because a record handed to a stalled pipeline is not evidence
        yet and article 2 forbids reporting it as though it were.
        """
        return self._submit((record,))

    def emit_effect(
        self,
        *,
        scope: str | None,
        connection: EvidenceConnection,
        principal: Principal,
        capability: str,
        decision: EffectDecision,
        payload: bytes | None = None,
    ) -> bool:
        actual_scope = scope or "local"
        body: dict[str, object] = {
            "capability": capability,
            "decision_id": decision.decision_id,
            "outcome": _value(decision.outcome),
            "decided_at": _instant(decision.decided_at),
            "policy_version": decision.policy_version,
            "recording_epoch": self.recording_epoch,
        }
        if decision.evaluation_recipe is not None:
            # Inside the body, so the preimage recipe hashes them (M1); the
            # nulls are recorded as nulls, never synthesised (article 2).
            body.update(
                {
                    "reason": None if decision.reason is None else _value(decision.reason),
                    "rule_id": decision.rule_id,
                    "arguments_digest": decision.arguments_digest,
                    "correlation": decision.correlation,
                    "correlation_source": (
                        "absent" if decision.correlation is None else "boundary_supplied"
                    ),
                    "principal_references": list(decision.principal_references or ()),
                    "evaluation_recipe": decision.evaluation_recipe,
                    "decision_position": (
                        None
                        if decision.position is None
                        else {
                            "store_id": decision.position.store_id,
                            "position": decision.position.position,
                        }
                    ),
                }
            )
        rule = self._capture_policy.for_capability(capability)
        if rule is not None and payload is not None:
            body["capture"] = self._capture(actual_scope, capability, payload, rule)
        grade = self._grade_record_if_needed(
            actual_scope, connection.connection_id, connection.access, principal
        )
        effect = EvidenceRecord(
            actual_scope,
            "effect",
            self._aware_now(),
            connection.connection_id,
            principal,
            body,
        )
        return self._submit((grade, effect) if grade is not None else (effect,))

    def evaluation_for(
        self,
        scope: str,
        connection: EvidenceConnection,
        principal: Principal,
        *,
        force: bool = False,
    ) -> GradeEvaluation:
        record = self._grade_record_if_needed(
            scope,
            connection.connection_id,
            connection.access,
            principal,
            force=force,
        )
        if record is not None:
            self._submit((record,))
        with self._grade_lock:
            return self._grades[(connection.connection_id, scope)].evaluation

    def before_verdict(
        self,
        scope: str,
        connection: EvidenceConnection,
        principal: Principal,
        *,
        timeout: float = 5,
    ) -> bool:
        self.evaluation_for(scope, connection, principal, force=True)
        return self.flush(scope, timeout=timeout)

    def flush(self, scope: str | None = None, timeout: float = 5) -> bool:
        deadline = monotonic() + timeout
        if scope is None:
            with self._condition:
                scopes = {
                    *self._pending,
                    *(unit.scope for unit in self._queue),
                    *(item[1] for item in self._grades),
                }
                if self._inflight is not None:
                    scopes.add(self._inflight.scope)
            return all(
                self.flush(item, timeout=max(0, deadline - monotonic())) for item in sorted(scopes)
            )
        if not scope:
            raise ValueError("scope is required")
        with self._condition:
            target = self._flush_completed[scope] + 1
            self._flush_requests[scope] += 1
            self._condition.notify_all()
            try:
                while self._flush_completed[scope] < target:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        return False
                    self._condition.wait(remaining)
                return True
            finally:
                # A request nobody is waiting on any more is discarded, so a
                # timed-out flush does not keep the drain retrying for ever.
                self._flush_requests[scope] -= 1
                if self._flush_requests[scope] <= 0:
                    del self._flush_requests[scope]

    def close(self, timeout: float = 5) -> bool:
        flushed = self.flush(timeout=timeout)
        with self._condition:
            self._closing = True
            self._condition.notify_all()
        self._worker.join(timeout=max(0, timeout))
        return flushed and not self._worker.is_alive()

    def daemon_grade_record(self, scope: str) -> EvidenceRecord | None:
        """The daemon's own grade on a scope, if one is due, for a synchronous writer.

        The recovery markers are appended outside this pipeline, on the daemon's
        connection; a marker recorded before its grade would be graded
        `unverified`, so the writer asks here first and the grade state stays
        one (article 7).
        """
        return self._grade_record_if_needed(
            scope, DAEMON_CONNECTION, self._daemon_access, self._daemon_principal
        )

    def _submit(self, records: tuple[EvidenceRecord, ...]) -> bool:
        if not records:
            return True
        scope = records[0].scope
        if any(record.scope != scope for record in records):
            raise ValueError("an emission unit must belong to one scope")
        self._open_scope(scope)
        with self._condition:
            if self._closing:
                self._count_loss(scope, _losses(records))
                return False
            over_capacity = (
                len(records) > self._capacity
                or self._queued_records + len(records) > self._capacity
            )
            if over_capacity:
                self._count_loss(scope, _losses(records))
                self._condition.notify_all()
                return False
            gap = self._pending.pop(scope, None)
            self._queue.append(_Unit(scope, records, gap))
            self._queued_records += len(records)
            self._condition.notify_all()
            return self._delivering

    def _open_scope(self, scope: str) -> None:
        """Open the scope's epoch before its first event, outside the queue's lock."""
        if self.before_first_event is None:
            return
        with self._scopes_seen_lock:
            if scope in self._scopes_seen:
                return
            self.before_first_event(scope)
            self._scopes_seen.add(scope)

    def _count_loss(self, scope: str, losses: tuple[_Loss, ...]) -> None:
        pending = self._pending.get(scope)
        if pending is None:
            self._pending[scope] = _PendingGap.from_losses(losses)
        else:
            pending.include(losses)

    def _drain(self) -> None:
        while True:
            with self._condition:
                unit = self._next_unit()
                while unit is None:
                    if self._closing and not self._retryable_pending():
                        return
                    self._condition.wait(self._idle_timeout())
                    unit = self._next_unit()
                self._inflight = unit
            completed = 0
            gap_written = False
            failed = False
            # Read before the store is handed anything: what a gap over this
            # unit would claim is a fact about what the core emitted, and the
            # records are about to become memory the store can write.
            losses = _losses(unit.records)
            try:
                if unit.gap_before is not None:
                    self._append_gap(unit.scope, unit.gap_before)
                    gap_written = True
                for record in unit.records:
                    self._store.append(record)
                    completed += 1
            except Exception:
                failed = True
            with self._condition:
                if failed:
                    self._delivering = False
                    if unit.gap_before is not None and not gap_written:
                        self._restore_gap(unit.scope, unit.gap_before)
                    remaining = losses[completed:]
                    if remaining:
                        self._count_loss(unit.scope, remaining)
                    self._back_off(unit.scope)
                else:
                    self._delivering = True
                    self._retry_at.pop(unit.scope, None)
                    self._retry_backoff.pop(unit.scope, None)
                self._inflight = None
                self._condition.notify_all()

    def _next_unit(self) -> _Unit | None:
        if self._queue:
            unit = self._queue.popleft()
            self._queued_records -= len(unit.records)
            return unit
        now = monotonic()
        requested = sorted(self._flush_requests)
        if self._closing:
            requested = sorted({*requested, *self._pending})
        for scope in requested:
            if scope in self._pending:
                if self._closing:
                    # Closing gets one last attempt per scope, then gives up:
                    # a store that will not accept must not hold the daemon.
                    if scope in self._final_attempt:
                        continue
                    self._final_attempt.add(scope)
                elif self._retry_at.get(scope, 0.0) > now:
                    continue
                return _Unit(scope, (), self._pending.pop(scope))
            self._complete_flush(scope)
        return None

    def _complete_flush(self, scope: str) -> None:
        self._flush_completed[scope] += 1
        self._retry_at.pop(scope, None)
        self._retry_backoff.pop(scope, None)
        self._condition.notify_all()

    def _retryable_pending(self) -> bool:
        return any(scope not in self._final_attempt for scope in self._pending)

    def _idle_timeout(self) -> float | None:
        deadlines = [
            self._retry_at[scope]
            for scope in self._flush_requests
            if scope in self._pending and scope in self._retry_at
        ]
        if not deadlines:
            return None
        return max(0.0, min(deadlines) - monotonic())

    def _back_off(self, scope: str) -> None:
        previous = self._retry_backoff.get(scope, 0.0)
        delay = RETRY_INITIAL_SECONDS if previous <= 0 else min(previous * 2, RETRY_MAX_SECONDS)
        self._retry_backoff[scope] = delay
        self._retry_at[scope] = monotonic() + delay

    def _restore_gap(self, scope: str, gap: _PendingGap) -> None:
        present = self._pending.get(scope)
        if present is None:
            self._pending[scope] = gap
            return
        gap.count += present.count
        gap.first_at = min(gap.first_at, present.first_at)
        gap.last_at = max(gap.last_at, present.last_at)
        gap.kinds.update(present.kinds)
        self._pending[scope] = gap

    def _append_gap(self, scope: str, pending: _PendingGap) -> None:
        grade = self._grade_record_if_needed(
            scope,
            DAEMON_CONNECTION,
            self._daemon_access,
            self._daemon_principal,
        )
        if grade is not None:
            self._store.append(grade)
        self._store.append(
            EvidenceRecord(
                scope,
                "gap",
                pending.last_at,
                DAEMON_CONNECTION,
                self._daemon_principal,
                {
                    "reason": "dropped",
                    "count": pending.count,
                    "first_at": _instant(pending.first_at),
                    "last_at": _instant(pending.last_at),
                    "kinds": dict(sorted(pending.kinds.items())),
                    "accounting": "event",
                    "recording_epoch": self.recording_epoch,
                },
            )
        )

    def _capture(
        self, scope: str, capability: str, payload: bytes, rule: CaptureRule
    ) -> dict[str, object]:
        limited = payload[: rule.max_bytes]
        truncated = len(payload) > rule.max_bytes
        try:
            # Article 11: what is written into evidence is what the core read
            # once, not memory the redactor still owns. A provider that answered
            # `applied` and then handed back the payload on the next read of
            # `content` would write the payload the record calls redacted.
            result = core_owned(
                Redaction,
                self._redactor.redact(scope=scope, capability=capability, content=limited),
                content=bytes,
                status=str,
                provider=str,
            )
        except Exception:
            return {
                "captured": False,
                "provider": self._redactor_name,
                "withheld": "redaction_failed",
            }
        if result.status not in {"applied", "not_applicable"}:
            return {
                "captured": False,
                "provider": self._redactor_name,
                "withheld": "redaction_failed",
            }
        content = result.content[: rule.max_bytes]
        truncated = truncated or len(result.content) > rule.max_bytes
        capture: dict[str, object] = {
            # The provider named is the one this daemon composed, which the core
            # read at composition and holds: a name the record takes from the
            # answer is a name the answer chooses (articles 2 and 8).
            "captured": True,
            "provider": self._redactor_name,
            "bytes": len(content),
            "truncated": truncated,
        }
        try:
            capture["content"] = content.decode("utf-8")
        except UnicodeDecodeError:
            capture["content"] = base64.b64encode(content).decode("ascii")
            capture["encoding"] = "base64"
        return capture

    def _grade_record_if_needed(
        self,
        scope: str,
        connection_id: str,
        caller: CallerAccess,
        principal: Principal,
        *,
        force: bool = False,
    ) -> EvidenceRecord | None:
        with self._grade_lock:
            key = (connection_id, scope)
            previous = self._grades.get(key)
            now = self._aware_now()
            if (
                not force
                and previous is not None
                and (now - previous.evaluation.evaluated_at).total_seconds() < self._grade_interval
            ):
                return None
            evaluation = self._evaluate(scope, caller, now)
            self._grades[key] = _GradeState(evaluation)
            if previous is not None and previous.evaluation.grade is evaluation.grade:
                return None
            return EvidenceRecord(
                scope,
                "grade",
                now,
                connection_id,
                principal,
                {
                    "grade": evaluation.grade.value,
                    "basis": evaluation.basis,
                    "evaluated_at": _instant(evaluation.evaluated_at),
                    "paths_inspected": evaluation.paths_inspected,
                    "recording_epoch": self.recording_epoch,
                },
            )

    def _evaluate(self, scope: str, caller: CallerAccess, now: datetime) -> GradeEvaluation:
        location = self._core_owned_location()
        if location.root is None or self._path_access is None:
            return evaluate_grade(caller, (), at=now)
        try:
            # Article 7: a grade is a claim about facts, so the facts are the
            # core's own copies. `evaluate_grade` reads a mode five times.
            chains = [self._chain(location, scope)]
            for read_location in self._also_inspected:
                other = core_owned(
                    StoreLocation,
                    read_location(),
                    kind=str,
                    root=lambda root: None if root is None else Path(root),
                    retention=str,
                )
                if other.root is not None:
                    chains.extend(self._chains_of(other, scope))
        except Exception:
            return GradeEvaluation(Grade.unverified, "access_not_established", now, 0)
        return _weakest_claim([evaluate_grade(caller, facts, at=now) for facts in chains], at=now)

    def _chain(self, location: StoreLocation, scope: str) -> list[PathFacts]:
        """The root, its parents, and the scope's own file when there is one."""
        facts = [self._inspect(path) for path in _paths(location)]
        scope_path = location.scope_path(scope)
        if scope_path is not None:
            scope_fact = self._inspect(scope_path.absolute())
            if scope_fact.exists:
                facts.append(scope_fact)
        return facts

    def _chains_of(self, location: StoreLocation, scope: str) -> list[list[PathFacts]]:
        """One chain per actual file under another store's root, and one for the root alone.

        Inspecting the parent alone is no proof about a child (A5): a version
        file an operator loosened sits under a directory nobody else can enter
        only until that directory is entered, and a scope's decision file can
        be more open than the directory it sits in.
        """
        assert location.root is not None
        root = location.root.absolute()
        parents = [self._inspect(path) for path in _paths(location)]
        chains = [parents]
        leaves = sorted(item for item in root.iterdir() if item.is_file()) if root.is_dir() else []
        for leaf in leaves:
            fact = self._inspect(leaf)
            if fact.exists:
                chains.append([*parents, fact])
        return chains

    def _inspect(self, path: Path) -> PathFacts:
        """One inspection of one path, taken into the core before it is graded."""
        assert self._path_access is not None
        return core_owned(PathFacts, self._path_access.inspect(path), path=Path)

    def _aware_now(self) -> datetime:
        """The core's own instant, so a recorded time is the time that was read."""
        return core_owned_instant(self._clock.now())


def _paths(location: StoreLocation):  # type: ignore[no-untyped-def]
    assert location.root is not None
    root = location.root.absolute()
    return [*reversed(root.parents), root]


def _weakest_claim(evaluations: list[GradeEvaluation], *, at: datetime) -> GradeEvaluation:
    """The one grade several inspected stores support between them (article 7).

    A caller who can write any of them is at observability grade whatever the
    others say; otherwise an inspection that could not be established leaves
    the grade unverified for that reason; only when every store was read and
    none is writable is the caller not a writer. The count of paths is the
    count over every inspection, so a reader can see how much was looked at.
    """
    inspected = sum(item.paths_inspected for item in evaluations)
    for basis in ("caller_can_write", "access_not_established", "caller_cannot_write"):
        for item in evaluations:
            if item.basis == basis:
                return GradeEvaluation(item.grade, basis, at, inspected)
    return GradeEvaluation(Grade.unverified, "access_not_established", at, inspected)


def _instant(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("instant must be offset-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _value(value: object) -> str:
    return str(getattr(value, "value", value))
