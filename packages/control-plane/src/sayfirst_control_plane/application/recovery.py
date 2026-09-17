# SPDX-License-Identifier: Apache-2.0
"""The synchronous recovery writer: epochs, their closure, and the losses it can name (C3, C4, S8).

The asynchronous emitter keeps the evidence authority off the hot path
(article 10), so a process that dies may lose events it had accepted. This
writer bounds what that can hide. Before the emitter accepts any event in a
scope, the scope's epoch is opened in the journal. On a graceful stop, after
the queues drain, a `clean_stop` marker is appended over the epoch's span and
the journal records it. At the next start, an epoch still open is declared
`unclean_stop` over its span, with an unknown loss count and every kind it
may have lost — a vanished grade downgrade, a composition — so a verifier
lowers every connection of that epoch and reports the coverage unknown. Then
the durable decision positions of the epoch are compared with the effect
positions that survived, and each committed decision without an effect is
declared in an `unflushed` gap by identity and position, bounded and split,
never id-less. Every marker is written synchronously, on the daemon's own
connection, after the daemon's own grade. Recovery converges: what is already
declared is reused, and a second start over the same journal appends nothing.

Reconciliation compares contents, not just identities (S8): an effect whose
decision the authority does not hold, and a shared fact the two copies
disagree on, are each counted and reported, and neither copy is repaired from
the other.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sayfirst_contract.decisions import Decision

from ..adapters.file.decision_store import FileDecisionStore
from ..domain.evidence_chain import (
    DAEMON_CONNECTION,
    EvidenceEntry,
    EvidenceRecord,
    Principal,
    core_owned_entry,
)
from ..domain.foreign import core_owned, core_owned_instant
from ..ports.decision_store import DecisionStoreUnavailable
from ..ports.evidence_store import EvidenceStore
from ..ports.policy_archive import ArchiveState, PolicyArchive
from ..ports.recovery_journal import JournalRecord, RecoveryJournal

GAP_ID_BOUND: Final = 8192
"""At most this many decisions per marker; a larger loss is several markers."""

POSSIBLY_LOST_KINDS: Final = ("effect", "grade", "composition", "gap")
RECOVERY_PRINCIPAL: Final = Principal("service", "daemon")
_SHARED_FACTS: Final = (
    "capability",
    "outcome",
    "policy_version",
    "reason",
    "rule_id",
    "arguments_digest",
    "correlation",
    "correlation_source",
    "principal_references",
    "evaluation_recipe",
)


@dataclass(frozen=True)
class ReconciliationReport:
    """What one reconciliation of one scope found; rendered into the status result.

    Every count and cursor is `None` when the comparison did not run — a
    scope none ran on, or an authority that could not be read — and an
    integer only when it did (article 2): a null is an absence said so, a
    zero is a count.
    """

    scope: str
    checked_at: datetime | None
    through_sequence: int | None
    through_decision_position: int | None
    state: str
    effects_without_decision: int | None
    contradictory_decisions: int | None
    unflushed_declared: int | None
    unknown_event_coverage: bool | None
    policy_versions_absent: int | None
    policy_versions_damaged: int | None

    @classmethod
    def not_run(cls, scope: str) -> ReconciliationReport:
        """The one rendering of a comparison that did not happen: nulls, never zeros."""
        return cls(scope, None, None, None, "not_run", None, None, None, None, None, None)

    def to_document(self) -> dict[str, object]:
        return {
            "scope": self.scope,
            "checked_at": None
            if self.checked_at is None
            else self.checked_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "through_sequence": self.through_sequence,
            "through_decision_position": self.through_decision_position,
            "state": self.state,
            # S7's once-only baseline is not established on this base: the
            # history before the durable store is unknown coverage, said so.
            "baseline": {
                "state": "not_established",
                "store_id": None,
                "first_covered_sequence": None,
                "legacy_effects_without_authority": None,
            },
            "effects_without_decision": self.effects_without_decision,
            "contradictory_decisions": self.contradictory_decisions,
            "unflushed_declared": self.unflushed_declared,
            "unknown_event_coverage": self.unknown_event_coverage,
            "policy_versions_absent": self.policy_versions_absent,
            "policy_versions_damaged": self.policy_versions_damaged,
        }


class RecoveryWriter:
    def __init__(
        self,
        chain: EvidenceStore,
        decisions: FileDecisionStore,
        journal: RecoveryJournal,
        *,
        recording_epoch: str,
        clock: Callable[[], datetime] | None = None,
        daemon_grade: Callable[[str], EvidenceRecord | None] | None = None,
        archive: PolicyArchive | None = None,
    ) -> None:
        self.chain = chain
        self.decisions = decisions
        self.journal = journal
        self.recording_epoch = recording_epoch
        self._clock = clock or (lambda: datetime.now(UTC))
        self._daemon_grade = daemon_grade
        self._archive = archive
        self._opened: set[str] = set()
        self.reports: dict[str, ReconciliationReport] = {}

    @property
    def opened_scopes(self) -> frozenset[str]:
        """The scopes whose epoch this life opened and has not yet closed."""
        return frozenset(self._opened)

    def _open_records(self, scope: str) -> tuple[JournalRecord, ...]:
        """What the journal says is open, as the core's own values (article 3)."""
        return tuple(
            core_owned(
                JournalRecord,
                item,
                scope=str,
                position=int,
                record=str,
                epoch_id=str,
                store_id=lambda value: None if value is None else str(value),
                from_sequence=lambda value: None if value is None else int(value),
                marker_sequence=lambda value: None if value is None else int(value),
                marker_hash=lambda value: None if value is None else str(value),
            )
            for item in self.journal.open_epochs(scope)
        )

    # -- epochs --------------------------------------------------------------------

    def open_epoch(self, scope: str) -> None:
        """Open this process's epoch for `scope`, once, before any event of it is accepted."""
        if scope in self._opened:
            return
        head = self.chain.latest_sequence(scope)
        self.journal.open_epoch(
            scope,
            self.recording_epoch,
            store_id=self.decisions.store_id_of(scope),
            from_sequence=(0 if head is None else int(head)) + 1,
        )
        self._opened.add(scope)

    def close_clean(self, scope: str) -> bool:
        """After the emitter drained: the clean marker over the span, then the journal."""
        if scope not in self._opened:
            return False
        opened = [
            item
            for item in self.journal.open_epochs(scope)
            if item.epoch_id == self.recording_epoch
        ]
        if not opened:
            return False
        record = opened[-1]
        assert record.from_sequence is not None
        # The daemon's own grade first, inside the span the marker closes: a
        # grade outside every clean span would be unknown coverage for good.
        self._grade_first(scope)
        head = self.chain.latest_sequence(scope)
        through = None if head is None else int(head)
        if through is None or through < record.from_sequence:
            # The epoch produced nothing on the chain; there is no span to mark.
            self.journal.epoch_clean(
                scope, self.recording_epoch, marker_sequence=None, marker_hash=None
            )
            self._opened.discard(scope)
            return True
        marker = self._append(
            scope,
            "recovery",
            {
                "event": "clean_stop",
                "epoch_id": self.recording_epoch,
                "from_sequence": record.from_sequence,
                "through_sequence": through,
                "recording_epoch": f"recovery:{self.recording_epoch}",
            },
        )
        self.journal.epoch_clean(
            scope,
            self.recording_epoch,
            marker_sequence=marker.sequence,
            marker_hash=marker.entry_hash,
        )
        self._opened.discard(scope)
        return True

    # -- the next start ----------------------------------------------------------------

    def reconcile_at_start(self, scope: str) -> ReconciliationReport:
        """Close every epoch the journal left open, declare its losses, then compare contents.

        An authority that cannot be read for this scope ends the reconciliation
        as `not_run` with every count null (article 2): an unreadable store is
        no evidence that a decision is missing, and an epoch whose losses could
        not be declared stays open in the journal for the next start to
        declare. The status result carries the scope as that `not_run`
        reconciliation, and a read on it answers `decision_store_unavailable`.
        """
        entries = list(self._read_all(scope))
        try:
            for record in self._open_records(scope):
                if record.epoch_id == self.recording_epoch:
                    continue  # this life's own epoch, open on purpose
                entries = self._reconcile_epoch(scope, record, entries)
            report = self._compare(scope, entries)
        except DecisionStoreUnavailable:
            report = ReconciliationReport.not_run(scope)
        self.reports[scope] = report
        return report

    def _reconcile_epoch(
        self, scope: str, record: JournalRecord, entries: list[EvidenceEntry]
    ) -> list[EvidenceEntry]:
        assert record.from_sequence is not None
        marker = next(
            (
                item
                for item in entries
                if item.kind == "recovery"
                and item.body.get("event") == "unclean_stop"
                and item.body.get("epoch_id") == record.epoch_id
            ),
            None,
        )
        # The span is the producer's own entries: what this recovery writes
        # over it is not evidence the dead process produced, and counting it
        # would make a second recovery mark what the first already marked.
        produced = [
            item.sequence
            for item in entries
            if item.sequence >= record.from_sequence
            and not _written_by_recovery(item)
            and item.body.get("recording_epoch", record.epoch_id) == record.epoch_id
        ]
        head = max(produced) if produced else 0
        if marker is None and head >= record.from_sequence:
            self._grade_first(scope)
            marker = self._append(
                scope,
                "recovery",
                {
                    "event": "unclean_stop",
                    "epoch_id": record.epoch_id,
                    "from_sequence": record.from_sequence,
                    "through_sequence": head,
                    "lost_event_count": None,
                    "possibly_lost_kinds": list(POSSIBLY_LOST_KINDS),
                    "coverage": "unknown",
                    "recording_epoch": f"recovery:{record.epoch_id}",
                },
            )
            entries.append(marker)
        entries = self._declare_unflushed(scope, record.epoch_id, entries)
        self.journal.epoch_reconciled(
            scope,
            record.epoch_id,
            marker_sequence=None if marker is None else marker.sequence,
            marker_hash=None if marker is None else marker.entry_hash,
        )
        return entries

    def _declare_unflushed(
        self, scope: str, epoch_id: str, entries: list[EvidenceEntry]
    ) -> list[EvidenceEntry]:
        """C4: every committed decision of the epoch without a surviving effect, by identity."""
        surviving = {
            (
                str(item.body["decision_position"]["store_id"]),
                int(item.body["decision_position"]["position"]),
            )  # type: ignore[index]
            for item in entries
            if item.kind == "effect" and isinstance(item.body.get("decision_position"), dict)
        }
        named = {
            str(identifier)
            for item in entries
            if item.kind == "gap" and isinstance(item.body.get("decision_ids"), list)
            for identifier in item.body["decision_ids"]  # type: ignore[union-attr]
        }
        # A scope the authority cannot serve declares nothing it cannot read:
        # the unavailability ends the reconciliation before the epoch is
        # journaled as reconciled, so the next start declares it.
        envelopes = list(self.decisions.scan(scope))
        missing = sorted(
            (
                envelope
                for envelope in envelopes
                if envelope.recording_epoch == epoch_id
                and (envelope.store_id, envelope.position) not in surviving
                and envelope.decision.decision_ref not in named
            ),
            key=lambda envelope: envelope.position,
        )
        for start in range(0, len(missing), GAP_ID_BOUND):
            chunk = missing[start : start + GAP_ID_BOUND]
            instants = sorted(item.decision.decided_at for item in chunk)
            self._grade_first(scope)
            gap = self._append(
                scope,
                "gap",
                {
                    "reason": "unflushed",
                    "count": len(chunk),
                    "first_at": _render(instants[0]),
                    "last_at": _render(instants[-1]),
                    "kinds": {"effect": len(chunk)},
                    "decision_ids": [item.decision.decision_ref for item in chunk],
                    "decision_positions": [
                        {"store_id": item.store_id, "position": item.position} for item in chunk
                    ],
                    "accounting": "decision",
                    "recording_epoch": epoch_id,
                },
            )
            entries.append(gap)
        return entries

    # -- compare contents (S8) -----------------------------------------------------------

    def _compare(self, scope: str, entries: Sequence[EvidenceEntry]) -> ReconciliationReport:
        # The authority is walked once, before any count exists, so a scope it
        # cannot serve raises here whether the chain holds one effect or none;
        # a count is only ever of what was read (article 2).
        held_by_reference = {
            envelope.decision.decision_ref: envelope.decision
            for envelope in self.decisions.scan(scope)
        }
        effects_without_decision = 0
        contradictory = 0
        versions: set[str] = set()
        last_position: int | None = None
        for entry in entries:
            if entry.kind != "effect":
                continue
            body = entry.body
            versions.add(str(body["policy_version"]))
            position = body.get("decision_position")
            if isinstance(position, dict):
                last_position = max(last_position or 0, int(position["position"]))
            held = held_by_reference.get(str(body["decision_id"]))
            if held is None:
                effects_without_decision += 1
                continue
            if _contradicts(body, held):
                contradictory += 1
        unflushed = sum(
            len(entry.body["decision_ids"])  # type: ignore[arg-type]
            for entry in entries
            if entry.kind == "gap"
            and entry.body.get("reason") == "unflushed"
            and isinstance(entry.body.get("decision_ids"), list)
        )
        unknown = any(
            entry.kind == "recovery" and entry.body.get("event") == "unclean_stop"
            for entry in entries
        )
        absent = damaged = 0
        if self._archive is not None:
            for version in sorted(versions):
                state = self._archive.read(version).state
                absent += state is ArchiveState.absent
                damaged += state is ArchiveState.damaged
        state = (
            "contradicts"
            if contradictory
            else "disagrees"
            if effects_without_decision
            else "agrees"
        )
        return ReconciliationReport(
            scope,
            core_owned_instant(self._clock()),
            entries[-1].sequence if entries else None,
            last_position,
            state,
            effects_without_decision,
            contradictory,
            unflushed,
            unknown,
            absent,
            damaged,
        )

    # -- appending on the daemon's own connection --------------------------------------

    def _grade_first(self, scope: str) -> None:
        if self._daemon_grade is None:
            return
        record = self._daemon_grade(scope)
        if record is not None:
            self.chain.append(record)

    def _append(self, scope: str, kind: str, body: dict[str, object]) -> EvidenceEntry:
        record = EvidenceRecord(
            scope,
            kind,
            core_owned_instant(self._clock()),
            DAEMON_CONNECTION,
            RECOVERY_PRINCIPAL,
            body,
        )
        return core_owned_entry(self.chain.append(record))

    def _read_all(self, scope: str) -> tuple[EvidenceEntry, ...]:
        return tuple(
            core_owned_entry(item) for item in self.chain.read_range(scope, from_sequence=1)
        )


def _written_by_recovery(entry: EvidenceEntry) -> bool:
    """A marker or an unflushed gap: written after the fact, never by the producer."""
    return entry.kind == "recovery" or (
        entry.kind == "gap" and entry.body.get("reason") == "unflushed"
    )


def _contradicts(body: object, held: Decision) -> bool:
    """Whether a shared fact the effect copied differs from the authority's record."""
    assert isinstance(body, dict)
    document = held.to_document()
    for fact in _SHARED_FACTS:
        if fact not in body:
            continue  # a historical body: unknown, never unequal to null (S8)
        recorded = document.get(fact) if fact != "outcome" else document["outcome"]
        if body[fact] != recorded:
            return True
    return False


def _render(instant: str) -> str:
    parsed = datetime.fromisoformat(instant.replace("Z", "+00:00"))
    return parsed.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
