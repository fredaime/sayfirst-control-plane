# SPDX-License-Identifier: Apache-2.0
"""The append-only evidence record, chain recipe, and verifier."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from itertools import pairwise
from typing import Final

from .foreign import core_owned, core_owned_instant
from .integrity_grade import Grade, weakest

FIRST_SEQUENCE: Final = 1
PREIMAGE_VERSION: Final = "sayfirst-control-plane/evidence/v1"
ENTRY_KINDS: Final = ("effect", "grade", "gap", "composition", "recovery")
#: Why a chain declares a gap: the queue could not hold the record, a retention
#: purge removed it (article 11; no path emits this yet), a process died
#: mid-append and the bytes that never became an entry were dropped, or a
#: committed decision has no surviving effect entry after recovery (C4).
GAP_REASONS: Final = ("dropped", "purged", "torn", "unflushed")
#: The three recovery markers: the once-only baseline and the closure of a
#: producer epoch, clean or unclean (C3, S7).
RECOVERY_EVENTS: Final = ("baseline", "clean_stop", "unclean_stop")
GAP_ACCOUNTING: Final = ("physical_record", "decision", "event")
DAEMON_CONNECTION: Final = "daemon"
#: The identifier of the evaluation recipe a new writer records on every
#: effect. It is the server's own spelling of the recipe the contract
#: publishes, held equal by the shared vector set, never imported from it.
EVALUATION_RECIPE: Final = "sayfirst/policy-evaluation/v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_POLICY_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^(?:user|group):.+$")
#: Every reason the contract publishes, spelled here rather than imported, the
#: way the evaluation recipe above is; `tests/unit/test_evidence_chain.py`
#: holds the two equal, because a reason the daemon can decide and this
#: validator does not know is a decision that cannot be written onto its chain.
_REASONS: Final = frozenset(
    {
        "policy_allows",
        "policy_denies",
        "policy_absent",
        "policy_requires_review",
        "capability_unknown",
        "approval_granted",
        "approval_rejected",
    }
)
#: The members a new writer copies into an effect body beside the historical
#: five (M1); they come together, and a body that carries some is refused.
EFFECT_DECISION_MEMBERS: Final = frozenset(
    {
        "reason",
        "rule_id",
        "arguments_digest",
        "correlation",
        "correlation_source",
        "principal_references",
        "evaluation_recipe",
        "decision_position",
    }
)
_BODY_MEMBERS: Final = {
    "effect": {
        "capability",
        "decision_id",
        "outcome",
        "decided_at",
        "policy_version",
        "capture",
        "recording_epoch",
        *EFFECT_DECISION_MEMBERS,
    },
    "grade": {"grade", "basis", "evaluated_at", "paths_inspected", "recording_epoch"},
    "gap": {
        "reason",
        "count",
        "first_at",
        "last_at",
        "kinds",
        "decision_ids",
        "decision_positions",
        "accounting",
        "recording_epoch",
    },
    "composition": {"providers", "recording_epoch"},
    "recovery": {
        "event",
        "epoch_id",
        "from_sequence",
        "through_sequence",
        "lost_event_count",
        "possibly_lost_kinds",
        "coverage",
        "store_id",
        "first_decision_position",
        "first_covered_sequence",
        "legacy_effects_without_authority",
        "established_at",
        "recording_epoch",
    },
}
_BODY_REQUIRED: Final = {
    "effect": {"capability", "decision_id", "outcome", "decided_at", "policy_version"},
    "grade": {"grade", "basis", "evaluated_at", "paths_inspected"},
    "gap": {"reason", "count", "first_at", "last_at", "kinds"},
    "composition": {"providers"},
    "recovery": {"event", "recording_epoch"},
}
_RECOVERY_REQUIRED: Final = {
    "baseline": {
        "store_id",
        "first_decision_position",
        "first_covered_sequence",
        "legacy_effects_without_authority",
        "established_at",
    },
    "clean_stop": {"epoch_id", "from_sequence", "through_sequence"},
    "unclean_stop": {
        "epoch_id",
        "from_sequence",
        "through_sequence",
        "lost_event_count",
        "possibly_lost_kinds",
        "coverage",
    },
}


class InvalidEvidence(ValueError):
    """The supplied entries cannot belong to the requested chain."""


@dataclass(frozen=True)
class Principal:
    kind: str
    id: str
    via: tuple[Principal, ...] = ()

    def __post_init__(self) -> None:
        if not self.kind or not self.id:
            raise ValueError("principal kind and id are required")
        if not all(isinstance(item, Principal) for item in self.via):
            raise TypeError("principal delegation must contain principals")


@dataclass(frozen=True)
class EvidenceRecord:
    scope: str
    kind: str
    recorded_at: datetime
    connection_id: str
    principal: Principal
    body: Mapping[str, object]

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError("scope is required")
        if self.kind not in ENTRY_KINDS:
            raise ValueError(f"unknown evidence kind {self.kind!r}")
        if self.recorded_at.tzinfo is None or self.recorded_at.utcoffset() is None:
            raise ValueError("recorded_at must be an offset-aware instant")
        if not self.connection_id:
            raise ValueError("connection_id is required")
        members = set(self.body)
        if members - _BODY_MEMBERS[self.kind]:
            raise ValueError("evidence body has an unknown member")
        if not _BODY_REQUIRED[self.kind] <= members:
            raise ValueError("evidence body lacks a required member")
        _validate_body(self.kind, self.body)
        canonical_json(self.body)


@dataclass(frozen=True)
class EvidenceEntry(EvidenceRecord):
    sequence: int
    previous_hash: str | None
    entry_hash: str
    preimage_version: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.sequence < FIRST_SEQUENCE:
            raise ValueError("sequence is before the first sequence")
        if self.sequence == FIRST_SEQUENCE and self.previous_hash is not None:
            raise ValueError("a genesis entry cannot name a predecessor")
        if self.sequence > FIRST_SEQUENCE and self.previous_hash is None:
            raise ValueError("a later entry must name a predecessor")
        if self.previous_hash is not None and not _DIGEST.fullmatch(self.previous_hash):
            raise ValueError("previous_hash is not a lowercase digest")
        if not _DIGEST.fullmatch(self.entry_hash):
            raise ValueError("entry_hash is not a lowercase digest")


class ChainCondition(StrEnum):
    intact = "intact"
    broken_at = "broken_at"
    gap_at = "gap_at"
    unverifiable = "unverifiable"


@dataclass(frozen=True)
class DeclaredGap:
    sequence: int
    reason: str
    count: int


@dataclass(frozen=True)
class ConnectionGrade:
    connection_id: str
    grade: Grade


@dataclass(frozen=True)
class ChainVerdict:
    scope: str
    condition: ChainCondition
    from_sequence: int
    to_sequence: int | None
    up_to: int | None
    sequence: int | None
    expected: str | None
    found: str | None
    version: str | None
    covers_an_entry: bool
    declared_gaps: tuple[DeclaredGap, ...]
    grades: tuple[ConnectionGrade, ...]


def _validate_body(kind: str, body: Mapping[str, object]) -> None:
    epoch = body.get("recording_epoch")
    if "recording_epoch" in body and (not isinstance(epoch, str) or not epoch):
        raise ValueError("recording_epoch must be a non-empty string")
    if kind == "effect":
        for member in ("capability", "decision_id", "decided_at", "policy_version"):
            if not isinstance(body[member], str) or not body[member]:
                raise ValueError(f"effect {member} must be a non-empty string")
        if body["outcome"] not in {"allow", "deny", "suspend"}:
            raise ValueError("effect outcome is unknown")
        if "capture" in body:
            _validate_capture(body["capture"])
        _validate_copied_decision(body)
    elif kind == "recovery":
        _validate_recovery(body)
    elif kind == "grade":
        if body["grade"] not in {item.value for item in Grade}:
            raise ValueError("grade is unknown")
        if body["basis"] not in {
            "caller_can_write",
            "caller_cannot_write",
            "access_not_established",
        }:
            raise ValueError("grade basis is unknown")
        if not isinstance(body["paths_inspected"], int) or body["paths_inspected"] < 0:
            raise ValueError("paths_inspected must be non-negative")
        if not isinstance(body["evaluated_at"], str) or not body["evaluated_at"]:
            raise ValueError("evaluated_at must be a non-empty string")
    elif kind == "gap":
        if body["reason"] not in GAP_REASONS:
            raise ValueError("gap reason is unknown")
        if not isinstance(body["count"], int) or body["count"] < 1:
            raise ValueError("gap count must be positive")
        if not isinstance(body["kinds"], Mapping):
            raise ValueError("gap kinds must be an object")
        kinds = body["kinds"]
        if not all(
            key in ENTRY_KINDS and isinstance(value, int) and value >= 1
            for key, value in kinds.items()
        ):
            raise ValueError("gap kinds must count known evidence kinds")
        if body["reason"] == "torn":
            # A record torn by a crash mid-append never completed, so its kind
            # is not knowable. Naming one would be a claim the bytes do not
            # support (article 2); the count still says one record was lost.
            if kinds:
                raise ValueError("a torn gap names no kind")
        elif sum(kinds.values()) != body["count"]:
            raise ValueError("gap kind counts must equal the total count")
        for member in ("first_at", "last_at"):
            if not isinstance(body[member], str) or not body[member]:
                raise ValueError(f"gap {member} must be a non-empty string")
        _validate_named_losses(body)
    else:
        providers = body["providers"]
        if not isinstance(providers, list):
            raise ValueError("composition providers must be a list")
        for provider in providers:
            if not isinstance(provider, Mapping) or set(provider) != {
                "interface",
                "version",
                "provider",
            }:
                raise ValueError("a composition provider has unknown members")
            if (
                not isinstance(provider["interface"], str)
                or not provider["interface"]
                or not isinstance(provider["provider"], str)
                or not provider["provider"]
                or not isinstance(provider["version"], int)
                or provider["version"] < 1
            ):
                raise ValueError("a composition provider is invalid")


def _validate_copied_decision(body: Mapping[str, object]) -> None:
    """The copied facts come together, each in its published shape (M1, article 13)."""
    present = EFFECT_DECISION_MEMBERS & set(body)
    if not present:
        return
    if present != EFFECT_DECISION_MEMBERS:
        raise ValueError("an effect carries the copied decision facts together or not at all")
    if body["reason"] not in _REASONS:
        raise ValueError("effect reason is outside the published enumeration")
    if body["rule_id"] is not None and (
        not isinstance(body["rule_id"], str) or not body["rule_id"]
    ):
        raise ValueError("effect rule_id must be a non-empty string or null")
    digest = body["arguments_digest"]
    if digest is not None and (not isinstance(digest, str) or not _POLICY_DIGEST.fullmatch(digest)):
        raise ValueError("effect arguments_digest must be a sha256 digest or null")
    correlation = body["correlation"]
    if correlation is not None and (not isinstance(correlation, str) or len(correlation) > 128):
        raise ValueError("effect correlation must be a string of at most 128 characters or null")
    if body["correlation_source"] != ("absent" if correlation is None else "boundary_supplied"):
        raise ValueError("effect correlation_source must say who chose the correlation")
    references = body["principal_references"]
    if (
        not isinstance(references, list)
        or any(
            not isinstance(item, str) or _REFERENCE.fullmatch(item) is None for item in references
        )
        or list(references) != sorted(set(references))
    ):
        raise ValueError("effect principal_references must be sorted unique references")
    recipe = body["evaluation_recipe"]
    if not isinstance(recipe, str) or not recipe:
        raise ValueError("effect evaluation_recipe must be a non-empty string")
    _validate_position(body["decision_position"])


def _validate_position(value: object) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"store_id", "position"}
        or not isinstance(value["store_id"], str)
        or not value["store_id"]
        or not isinstance(value["position"], int)
        or isinstance(value["position"], bool)
        or value["position"] < 1
    ):
        raise ValueError("a decision position names a store and a positive position")


def _validate_named_losses(body: Mapping[str, object]) -> None:
    """A gap that names decisions names them by identity and position, paired (C4)."""
    if "accounting" in body and body["accounting"] not in GAP_ACCOUNTING:
        raise ValueError("gap accounting is unknown")
    named = {"decision_ids", "decision_positions"} & set(body)
    if not named:
        return
    if named != {"decision_ids", "decision_positions"}:
        raise ValueError("a gap names its decisions by identity and by position together")
    identities = body["decision_ids"]
    positions = body["decision_positions"]
    if not isinstance(identities, list) or not isinstance(positions, list):
        raise ValueError("decision_ids and decision_positions must be lists")
    if not 1 <= len(identities) <= 8192 or len(identities) != len(positions):
        raise ValueError("decision_ids and decision_positions pair one to one, bounded")
    if any(not isinstance(item, str) or not item for item in identities):
        raise ValueError("a decision id must be a non-empty string")
    if len(set(identities)) != len(identities):
        raise ValueError("a decision id is named twice")
    for item in positions:
        _validate_position(item)
    ordered = [(str(item["store_id"]), int(item["position"])) for item in positions]  # type: ignore[index]
    if ordered != sorted(ordered):
        raise ValueError("named losses are sorted by position")
    if body.get("accounting") == "decision" and body["count"] != len(identities):
        raise ValueError("a decision-accounted gap counts the decisions it names")


def _validate_recovery(body: Mapping[str, object]) -> None:
    event = body["event"]
    if event not in RECOVERY_EVENTS:
        raise ValueError("recovery event is unknown")
    required = _RECOVERY_REQUIRED[str(event)]
    if not required <= set(body):
        raise ValueError(f"a {event} marker lacks a required member")
    for member in ("from_sequence", "through_sequence", "first_covered_sequence"):
        if member in body and (
            not isinstance(body[member], int) or isinstance(body[member], bool) or body[member] < 1
        ):
            raise ValueError(f"recovery {member} must be a positive integer")
    if event == "unclean_stop":
        if body["lost_event_count"] is not None or body["coverage"] != "unknown":
            raise ValueError("an unclean stop inventories nothing and covers unknown")
        kinds = body["possibly_lost_kinds"]
        if not isinstance(kinds, list) or not {"effect", "grade", "composition", "gap"} <= set(
            kinds
        ):
            raise ValueError("an unclean stop names every kind it may have lost")
    if event == "baseline":
        if body["first_decision_position"] != 1:
            raise ValueError("a baseline begins at position one")
        if not isinstance(body["legacy_effects_without_authority"], int):
            raise ValueError("a baseline counts the legacy effects without authority")


def _validate_capture(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("capture must be an object")
    if value.get("captured") is True:
        required = {"captured", "provider", "bytes", "truncated", "content"}
        allowed = {*required, "encoding"}
        if set(value) - allowed or not required <= set(value):
            raise ValueError("captured content has unknown or missing members")
        if (
            not isinstance(value["provider"], str)
            or not value["provider"]
            or not isinstance(value["bytes"], int)
            or not 0 <= value["bytes"] <= 65_536
            or not isinstance(value["truncated"], bool)
            or not isinstance(value["content"], str)
            or ("encoding" in value and value["encoding"] != "base64")
        ):
            raise ValueError("captured content is invalid")
        return
    if value.get("captured") is False:
        if set(value) != {"captured", "provider", "withheld"} or not isinstance(
            value["provider"], str
        ):
            raise ValueError("withheld capture is invalid")
        if not value["provider"] or value["withheld"] != "redaction_failed":
            raise ValueError("withheld capture is invalid")
        return
    raise ValueError("capture must say whether content was captured")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _instant(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("instant must be offset-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def principal_to_document(principal: Principal) -> dict[str, object]:
    return {
        "kind": principal.kind,
        "id": principal.id,
        "via": [principal_to_document(item) for item in principal.via],
    }


def _component(raw: bytes | None) -> bytes:
    if raw is None:
        return b"-:"
    return str(len(raw)).encode() + b":" + raw


def preimage(
    *,
    scope: str,
    sequence: int,
    kind: str,
    recorded_at: datetime,
    connection_id: str,
    principal: Principal,
    body: Mapping[str, object],
    previous_hash: str | None,
) -> bytes:
    values = (
        PREIMAGE_VERSION.encode(),
        scope.encode(),
        str(sequence).encode(),
        kind.encode(),
        _instant(recorded_at).encode(),
        connection_id.encode(),
        canonical_json(principal_to_document(principal)),
        canonical_json(body),
        previous_hash.encode() if previous_hash is not None else None,
    )
    return b"".join(_component(value) for value in values)


def _hash(record: EvidenceRecord, sequence: int, previous_hash: str | None) -> str:
    return hashlib.sha256(
        preimage(
            scope=record.scope,
            sequence=sequence,
            kind=record.kind,
            recorded_at=record.recorded_at,
            connection_id=record.connection_id,
            principal=record.principal,
            body=record.body,
            previous_hash=previous_hash,
        )
    ).hexdigest()


def _record(entry: EvidenceEntry) -> EvidenceRecord:
    return EvidenceRecord(
        entry.scope,
        entry.kind,
        entry.recorded_at,
        entry.connection_id,
        entry.principal,
        entry.body,
    )


def core_owned_principal(value: object) -> Principal:
    """A principal a store answered with, rebuilt as the core's own value."""
    return core_owned(
        Principal,
        value,
        kind=str,
        id=str,
        via=lambda items: tuple(core_owned_principal(item) for item in items),
    )


def core_owned_body(value: object) -> dict[str, object]:
    """An entry body a store answered with, as plain values the core owns.

    The round trip is through the chain's own canonical form, which is what the
    hash is taken over, so a body the core rebuilt hashes exactly as the stored
    one did: rebuilding an entry never turns an intact chain into a broken one.
    """
    return dict(json.loads(canonical_json(dict(value))))


def core_owned_entry(entry: object) -> EvidenceEntry:
    """One entry a store answered with, read once and rebuilt as the core's own.

    A store is a port (article 8), so the entries it answers a range with are
    memory it owns. They are verified and then rendered for the caller, and
    those are two reads: an entry that answered honestly to `verify` and
    differently to `entry_to_document` would be served under a verdict that was
    reached about something else (articles 2 and 10). The verdict and the
    document are taken from this value, which is read once and is the core's.
    """
    return core_owned(
        EvidenceEntry,
        entry,
        scope=str,
        kind=str,
        recorded_at=core_owned_instant,
        connection_id=str,
        principal=core_owned_principal,
        body=core_owned_body,
        sequence=int,
        previous_hash=lambda value: None if value is None else str(value),
        entry_hash=str,
        preimage_version=str,
    )


#: What an entry the recipe cannot be applied to raises on the way through
#: `_hash`: an instant at the edge of the calendar whose offset pushes it past
#: the edge arrives as an `OverflowError`, an `ArithmeticError` and so outside
#: `ValueError` entirely. The offline verifier in the contract wheel names the
#: same set, because the two implementations answer the same inputs the same
#: way and the published vectors are what hold them apart (article 13).
_UNAPPLIABLE: Final = (InvalidEvidence, KeyError, TypeError, ValueError, OverflowError)


def entry_verifies(entry: EvidenceEntry) -> bool:
    """Whether an entry's own hash recomputes under the recipe it declares.

    A boolean about every entry, including one the recipe cannot be applied to
    at all: a caller asking whether an entry verifies is owed an answer and not
    an exception to classify for itself (article 2).
    """
    if entry.preimage_version != PREIMAGE_VERSION:
        return False
    try:
        return _hash(_record(entry), entry.sequence, entry.previous_hash) == entry.entry_hash
    except _UNAPPLIABLE:
        return False


def chained_after_break(record: EvidenceRecord, previous: EvidenceEntry) -> EvidenceEntry:
    """Continue a chain whose last entry does not verify, leaving the break visible.

    `chained` refuses a predecessor it cannot verify, which is right for a
    writer building a chain. It is wrong as the answer to a chain that is
    already damaged: refusing every further append would stop the recorder on
    one damaged line, and article 10 wants the loss declared, not the recording
    stopped. The new entry names the stored predecessor as it stands, so the
    verifier reports `broken_at` at the entry that does not verify (article 2:
    the damage is stated, never repaired away).
    """
    if previous.scope != record.scope:
        raise ValueError("a chain cannot follow another scope")
    sequence = previous.sequence + 1
    return EvidenceEntry(
        **record.__dict__,
        sequence=sequence,
        previous_hash=previous.entry_hash,
        entry_hash=_hash(record, sequence, previous.entry_hash),
        preimage_version=PREIMAGE_VERSION,
    )


def chained(record: EvidenceRecord, previous: EvidenceEntry | None) -> EvidenceEntry:
    """Place one record after its same-scope predecessor under the pinned recipe."""
    if previous is not None and previous.scope != record.scope:
        raise ValueError("a chain cannot follow another scope")
    if previous is not None and (
        _hash(_record(previous), previous.sequence, previous.previous_hash) != previous.entry_hash
    ):
        raise ValueError("the predecessor hash does not carry its sequence")
    sequence = FIRST_SEQUENCE if previous is None else previous.sequence + 1
    previous_hash = None if previous is None else previous.entry_hash
    return EvidenceEntry(
        **record.__dict__,
        sequence=sequence,
        previous_hash=previous_hash,
        entry_hash=_hash(record, sequence, previous_hash),
        preimage_version=PREIMAGE_VERSION,
    )


def entry_to_document(entry: EvidenceEntry) -> dict[str, object]:
    return {
        "scope": entry.scope,
        "kind": entry.kind,
        "recorded_at": _instant(entry.recorded_at),
        "connection_id": entry.connection_id,
        "principal": principal_to_document(entry.principal),
        "body": dict(entry.body),
        "sequence": entry.sequence,
        "previous_hash": entry.previous_hash,
        "entry_hash": entry.entry_hash,
        "preimage_version": entry.preimage_version,
    }


def _read_principal(document: Mapping[str, object]) -> Principal:
    via = document.get("via", [])
    if not isinstance(via, list) or not all(isinstance(item, Mapping) for item in via):
        raise ValueError("principal via must be a list")
    return Principal(
        str(document["kind"]),
        str(document["id"]),
        tuple(_read_principal(item) for item in via),  # type: ignore[arg-type]
    )


def entry_from_document(document: Mapping[str, object]) -> EvidenceEntry:
    principal = document["principal"]
    body = document["body"]
    if not isinstance(principal, Mapping) or not isinstance(body, Mapping):
        raise ValueError("entry principal and body must be objects")
    return EvidenceEntry(
        scope=str(document["scope"]),
        kind=str(document["kind"]),
        recorded_at=datetime.fromisoformat(str(document["recorded_at"]).replace("Z", "+00:00")),
        connection_id=str(document["connection_id"]),
        principal=_read_principal(principal),
        body=dict(body),
        sequence=int(document["sequence"]),
        previous_hash=(
            str(document["previous_hash"]) if document["previous_hash"] is not None else None
        ),
        entry_hash=str(document["entry_hash"]),
        preimage_version=str(document["preimage_version"]),
    )


def verdict_to_document(verdict: ChainVerdict) -> dict[str, object]:
    """One verdict as it is served, and as `manifest_hash` binds it.

    It lives beside the verdict rather than beside the reads because
    `domain/evidence_export.py` hashes exactly this rendering: a second
    rendering would be a second answer to "what did this export claim", and the
    two would part company at the first member added to one of them.
    """
    return {
        "scope": verdict.scope,
        "condition": verdict.condition.value,
        "from_sequence": verdict.from_sequence,
        "to_sequence": verdict.to_sequence,
        "up_to": verdict.up_to,
        "sequence": verdict.sequence,
        "expected": verdict.expected,
        "found": verdict.found,
        "version": verdict.version,
        "covers_an_entry": verdict.covers_an_entry,
        "declared_gaps": [
            {"sequence": item.sequence, "reason": item.reason, "count": item.count}
            for item in verdict.declared_gaps
        ],
        "grades": [
            {"connection_id": item.connection_id, "grade": item.grade.value}
            for item in verdict.grades
        ],
    }


def _grades(
    entries: Sequence[EvidenceEntry], grades_before: Mapping[str, Grade]
) -> tuple[ConnectionGrade, ...]:
    current = dict(grades_before)
    covered: dict[str, list[Grade]] = {}
    for entry in entries:
        if entry.kind == "grade":
            current[entry.connection_id] = Grade(str(entry.body["grade"]))
        covered.setdefault(entry.connection_id, []).append(
            current.get(entry.connection_id, Grade.unverified)
        )
    return tuple(
        ConnectionGrade(connection_id, weakest(values))
        for connection_id, values in sorted(covered.items())
    )


def _verdict(
    entries: Sequence[EvidenceEntry],
    *,
    scope: str,
    from_sequence: int,
    condition: ChainCondition,
    sequence: int | None = None,
    expected: str | None = None,
    found: str | None = None,
    version: str | None = None,
    grades_before: Mapping[str, Grade],
    graded_entries: Sequence[EvidenceEntry] | None = None,
) -> ChainVerdict:
    intact = condition is ChainCondition.intact
    return ChainVerdict(
        scope=scope,
        condition=condition,
        from_sequence=from_sequence,
        to_sequence=entries[-1].sequence if entries else None,
        up_to=entries[-1].sequence if entries and intact else None,
        sequence=sequence,
        expected=expected,
        found=found,
        version=version,
        covers_an_entry=bool(entries),
        declared_gaps=tuple(
            DeclaredGap(entry.sequence, str(entry.body["reason"]), int(entry.body["count"]))
            for entry in entries
            if entry.kind == "gap"
        ),
        grades=_grades(entries if graded_entries is None else graded_entries, grades_before),
    )


def verify(
    entries: Sequence[EvidenceEntry],
    *,
    scope: str,
    from_sequence: int,
    to_sequence: int | None = None,
    grades_before: Mapping[str, Grade],
) -> ChainVerdict:
    """Verify one requested range and refuse every undeclared absence.

    `to_sequence` is the end the caller asked for and the store claimed to
    hold. A caller that names it asserts the range: entries stopping short of
    it are an undeclared gap, not a shorter clean chain (article 10). A caller
    that names no end asserts none, so a short answer is verified as it stands.

    Two conditions are told apart on purpose. `broken_at` is a negative fact
    this verifier established: it recomputed and the number did not match.
    `unverifiable` is the absence of one — a recipe this daemon holds no reader
    for, or an entry that recipe cannot be applied to — and must not be
    rendered as damage to the chain (article 2).
    """
    if not scope:
        raise InvalidEvidence("scope is required")
    if from_sequence < FIRST_SEQUENCE:
        raise InvalidEvidence("from_sequence is before the first sequence")
    if to_sequence is not None and to_sequence < from_sequence:
        raise InvalidEvidence("to_sequence is before from_sequence")
    if any(entry.scope != scope for entry in entries):
        raise InvalidEvidence("entries from another scope cannot be verified here")
    if any(right.sequence <= left.sequence for left, right in pairwise(entries)):
        raise InvalidEvidence("entries are out of sequence order")
    if not entries:
        if to_sequence is None:
            return _verdict(
                entries,
                scope=scope,
                from_sequence=from_sequence,
                condition=ChainCondition.unverifiable,
                grades_before=grades_before,
            )
        return _verdict(
            entries,
            scope=scope,
            from_sequence=from_sequence,
            condition=ChainCondition.gap_at,
            sequence=from_sequence,
            grades_before=grades_before,
            graded_entries=(),
        )
    if entries[0].sequence != from_sequence:
        return _verdict(
            entries,
            scope=scope,
            from_sequence=from_sequence,
            condition=ChainCondition.gap_at,
            sequence=from_sequence,
            grades_before=grades_before,
            graded_entries=(),
        )
    for index, (left, right) in enumerate(pairwise(entries), start=1):
        if right.sequence != left.sequence + 1:
            return _verdict(
                entries,
                scope=scope,
                from_sequence=from_sequence,
                condition=ChainCondition.gap_at,
                sequence=left.sequence + 1,
                grades_before=grades_before,
                graded_entries=entries[:index],
            )
    if to_sequence is not None and entries[-1].sequence < to_sequence:
        return _verdict(
            entries,
            scope=scope,
            from_sequence=from_sequence,
            condition=ChainCondition.gap_at,
            sequence=entries[-1].sequence + 1,
            grades_before=grades_before,
        )
    for index, entry in enumerate(entries):
        if entry.preimage_version != PREIMAGE_VERSION:
            # Not a break. This verifier holds no recipe for the entry, so it
            # established nothing about it, and `broken_at` would render an
            # absence of capability as damage to the chain (article 2). The
            # version is named so a reader knows which recipe to go and find.
            return _verdict(
                entries,
                scope=scope,
                from_sequence=from_sequence,
                condition=ChainCondition.unverifiable,
                sequence=entry.sequence,
                found=entry.entry_hash,
                version=entry.preimage_version,
                grades_before=grades_before,
                graded_entries=entries[:index],
            )
        try:
            expected_hash = _hash(_record(entry), entry.sequence, entry.previous_hash)
        except _UNAPPLIABLE:
            # An entry the declared recipe cannot be applied to at all. The
            # range stops being checkable here and says so, rather than claiming
            # the chain was found damaged.
            return _verdict(
                entries,
                scope=scope,
                from_sequence=from_sequence,
                condition=ChainCondition.unverifiable,
                sequence=entry.sequence,
                found=entry.entry_hash,
                version=entry.preimage_version,
                grades_before=grades_before,
                graded_entries=entries[:index],
            )
        if expected_hash != entry.entry_hash:
            return _verdict(
                entries,
                scope=scope,
                from_sequence=from_sequence,
                condition=ChainCondition.broken_at,
                sequence=entry.sequence,
                expected=expected_hash,
                found=entry.entry_hash,
                grades_before=grades_before,
                graded_entries=entries[:index],
            )
    for index, (previous, entry) in enumerate(pairwise(entries), start=1):
        if entry.previous_hash != previous.entry_hash:
            return _verdict(
                entries,
                scope=scope,
                from_sequence=from_sequence,
                condition=ChainCondition.broken_at,
                sequence=entry.sequence,
                expected=previous.entry_hash,
                found=entry.previous_hash,
                grades_before=grades_before,
                graded_entries=entries[:index],
            )
    return _verdict(
        entries,
        scope=scope,
        from_sequence=from_sequence,
        condition=ChainCondition.intact,
        grades_before=grades_before,
    )
