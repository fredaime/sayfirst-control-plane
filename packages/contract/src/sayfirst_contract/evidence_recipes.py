# SPDX-License-Identifier: Apache-2.0
"""The evidence recipes, published as executable code, and the chain's verdict.

Article 10 puts the chain and its verdict in the open core, and article 13
publishes the recipes so that a reader holding nothing but a range of entries
and this wheel can check what the range claims. This module is that half:
canonical JSON, the instant rendering, the length-prefixed preimage of
`sayfirst-control-plane/evidence/v1`, entry hashing, chain contiguity and
linking, three export manifest recipes, and `verify_chain`.

It is separate from `evidence` for one reason, and the reason is a rule rather
than a tidiness: `evidence` also holds the offline export verifier, which
re-derives a recorded decision from the archived policy bytes, and re-deriving
a decision is deciding. No boundary and no server may reach that — article 1
forbids a second control plane without evidence, and
`tests/test_retrospective_evaluator_boundaries.py` resolves the import graph of
every boundary, of the operator command, of the shipped fake and of the whole
live server to hold it. The recipes carry no evaluator, so a writer that places
an entry and a reader that checks one reach them here without reaching the
evaluator at all. `evidence` re-exports every name below, so nothing a consumer
imports moves.

It imports no server, opens no file or socket, and reads no clock. A caller
loads bytes outside it and hands it parsed documents.
"""

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

PREIMAGE_VERSION: Final = "sayfirst-control-plane/evidence/v1"
MANIFEST_V1: Final = "sayfirst-control-plane/evidence-export/v1"
MANIFEST_V2: Final = "sayfirst-control-plane/evidence-export/v2"
MANIFEST_V3: Final = "sayfirst-control-plane/evidence-export/v3"
MANIFEST_VERSIONS: Final = (MANIFEST_V1, MANIFEST_V2, MANIFEST_V3)
ENTRY_KINDS: Final = ("effect", "grade", "gap", "composition", "recovery")
GAP_REASONS: Final = ("dropped", "purged", "torn", "unflushed")
RECOVERY_EVENTS: Final = ("clean_stop", "unclean_stop")
GRADES: Final = ("unverified", "observability", "evidence")
_GRADE_RANK: Final = {"unverified": 0, "observability": 1, "evidence": 2}
#: The kinds that are emitted asynchronously and so need an epoch's closure to
#: be counted as covered; a gap or a recovery marker is written synchronously.
_ASYNCHRONOUS_KINDS: Final = frozenset({"effect", "grade", "composition"})

_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
_POLICY_VERSION: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCOPE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENTRY_MEMBERS: Final = (
    "scope",
    "kind",
    "recorded_at",
    "connection_id",
    "principal",
    "body",
    "sequence",
    "previous_hash",
    "entry_hash",
    "preimage_version",
)
_BODY_REQUIRED: Final = {
    "effect": ("capability", "decision_id", "outcome", "decided_at", "policy_version"),
    "grade": ("grade", "basis", "evaluated_at", "paths_inspected"),
    "gap": ("reason", "count", "first_at", "last_at", "kinds"),
    "composition": ("providers",),
    "recovery": ("event", "epoch_id", "from_sequence", "through_sequence"),
}
#: The members a new writer copies into an effect body (block 2.7), each read
#: as recorded and never synthesised for a historical entry that lacks it.
EFFECT_DECISION_MEMBERS: Final = (
    "reason",
    "rule_id",
    "arguments_digest",
    "correlation",
    "correlation_source",
    "principal_references",
    "evaluation_recipe",
    "decision_position",
)


class InvalidBundle(ValueError):
    """The document is not an export this wheel can read."""


# -- recipes ----------------------------------------------------------------


def canonical_json(value: object) -> bytes:
    """The one serialisation every hash is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def render_instant(value: str) -> str:
    """An instant as the preimage renders it: UTC, whole seconds, a trailing `Z`.

    `OverflowError` is an `ArithmeticError`, not a `ValueError`: an instant at
    the edge of the calendar with an offset that pushes it past the edge —
    `0001-01-01T00:00:00+01:00` — raises out of `astimezone` and past every
    clause that names `ValueError`. It is an instant this recipe cannot render,
    which is exactly what `InvalidBundle` says.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise InvalidBundle("an instant must be offset-aware")
        return parsed.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError) as error:
        raise InvalidBundle(f"an instant outside the calendar: {value!r}") from error


def _component(raw: bytes | None) -> bytes:
    return b"-:" if raw is None else str(len(raw)).encode() + b":" + raw


def _principal_document(principal: Mapping[str, object]) -> dict[str, object]:
    """One principal, as the canonical JSON of the preimage renders it.

    A delegation whose item is not an object reached the recursive call and
    raised `AttributeError` — outside every clause that names `ValueError` —
    where it is the same fact as the list check below: a principal this recipe
    cannot render, which is what `InvalidBundle` says (article 6 keeps a
    delegation a chain of principals, never a string).
    """
    if not isinstance(principal, Mapping):
        raise InvalidBundle("a principal must be an object")
    via = principal.get("via", [])
    if not isinstance(via, list):
        raise InvalidBundle("a principal's via must be a list")
    return {
        "kind": str(principal["kind"]),
        "id": str(principal["id"]),
        "via": [_principal_document(item) for item in via],
    }


def preimage(
    *,
    scope: str,
    sequence: int,
    kind: str,
    recorded_at: str,
    connection_id: str,
    principal: Mapping[str, object],
    body: Mapping[str, object],
    previous_hash: str | None,
) -> bytes:
    """The length-prefixed preimage of `sayfirst-control-plane/evidence/v1`."""
    values = (
        PREIMAGE_VERSION.encode(),
        scope.encode(),
        str(sequence).encode(),
        kind.encode(),
        render_instant(recorded_at).encode(),
        connection_id.encode(),
        canonical_json(_principal_document(principal)),
        canonical_json(dict(body)),
        previous_hash.encode() if previous_hash is not None else None,
    )
    return b"".join(_component(value) for value in values)


def entry_hash_of(entry: Mapping[str, object]) -> str:
    """The hash an entry document recomputes to under the recipe it declares."""
    return hashlib.sha256(
        preimage(
            scope=str(entry["scope"]),
            sequence=int(entry["sequence"]),  # type: ignore[call-overload]
            kind=str(entry["kind"]),
            recorded_at=str(entry["recorded_at"]),
            connection_id=str(entry["connection_id"]),
            principal=entry["principal"],  # type: ignore[arg-type]
            body=entry["body"],  # type: ignore[arg-type]
            previous_hash=None if entry["previous_hash"] is None else str(entry["previous_hash"]),
        )
    ).hexdigest()


#: What an entry the recipe cannot be applied to raises on the way through
#: `entry_hash_of`: a member the recipe needs and the document lacks, a member
#: of the wrong shape, or an instant outside the calendar — which arrives as an
#: `OverflowError`, an `ArithmeticError` and so outside `ValueError` entirely.
_UNAPPLIABLE: Final = (InvalidBundle, KeyError, TypeError, ValueError, OverflowError)


def entry_verifies(entry: Mapping[str, object]) -> bool:
    """Whether one entry's own hash recomputes under the recipe it declares.

    A boolean about every entry, including one the recipe cannot be applied to
    at all: a caller asking whether an entry verifies is owed an answer and not
    an exception to classify for itself (article 2).
    """
    if entry.get("preimage_version") != PREIMAGE_VERSION:
        return False
    try:
        return entry_hash_of(entry) == entry.get("entry_hash")
    except _UNAPPLIABLE:
        return False


def chained_document(
    record: Mapping[str, object], previous: Mapping[str, object] | None
) -> dict[str, object]:
    """Place one record after its predecessor, as a writer of the recipe does.

    Published so that a writer — a server, a fixture, a test — builds entries
    from the same recipe the verifier reads; it is not a store and keeps nothing.
    """
    if previous is not None and previous["scope"] != record["scope"]:
        raise ValueError("a chain cannot follow another scope")
    sequence = 1 if previous is None else int(previous["sequence"]) + 1  # type: ignore[call-overload]
    previous_hash = None if previous is None else str(previous["entry_hash"])
    placed = {
        "scope": str(record["scope"]),
        "kind": str(record["kind"]),
        "recorded_at": str(record["recorded_at"]),
        "connection_id": str(record["connection_id"]),
        "principal": _principal_document(record["principal"]),  # type: ignore[arg-type]
        "body": dict(record["body"]),  # type: ignore[call-overload]
        "sequence": sequence,
        "previous_hash": previous_hash,
        "preimage_version": PREIMAGE_VERSION,
    }
    placed["entry_hash"] = entry_hash_of(placed)
    return placed


def manifest_hash(bundle: Mapping[str, object], *, version: str) -> str:
    """An export's manifest digest under one of the three published recipes.

    v1 bound the requested range, the verdict's `condition` and `up_to`, and
    the ordered entry hashes. v2 bound the whole verdict instead of two of its
    members, because the grades an export claims sat outside the number a
    verifier compared. v3 binds every top-level member of the bundle except
    the hash itself, so that the policy attachments and their availability
    states — an `absent` carries no bytes to hash — and the recovery context
    move the digest too (article 10).
    """
    if version == MANIFEST_V3:
        return hashlib.sha256(
            canonical_json({key: value for key, value in bundle.items() if key != "manifest_hash"})
        ).hexdigest()
    entries = bundle.get("entries", ())
    if not isinstance(entries, list):
        raise InvalidBundle("entries must be a list")
    verification = bundle.get("verification")
    if not isinstance(verification, Mapping):
        raise InvalidBundle("verification must be an object")
    document: dict[str, object] = {
        "version": version,
        "scope": bundle.get("scope"),
        "from_sequence": bundle.get("from_sequence"),
        "to_sequence": bundle.get("to_sequence"),
        "contract_version": bundle.get("contract_version"),
        "entry_hashes": [entry["entry_hash"] for entry in entries],
    }
    if version == MANIFEST_V2:
        document["verdict"] = dict(verification)
    elif version == MANIFEST_V1:
        up_to = verification.get("up_to")
        document["condition"] = str(verification.get("condition"))
        document["up_to"] = (
            up_to if isinstance(up_to, int) and not isinstance(up_to, bool) else None
        )
    else:
        raise ValueError(f"unknown manifest recipe {version!r}")
    return hashlib.sha256(canonical_json(document)).hexdigest()


# -- the chain half of the verdict -------------------------------------------


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
    grade: str


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

    def to_document(self) -> dict[str, object]:
        """The published `evidence-verdict` shape, as a server renders it."""
        return {
            "scope": self.scope,
            "condition": self.condition.value,
            "from_sequence": self.from_sequence,
            "to_sequence": self.to_sequence,
            "up_to": self.up_to,
            "sequence": self.sequence,
            "expected": self.expected,
            "found": self.found,
            "version": self.version,
            "covers_an_entry": self.covers_an_entry,
            "declared_gaps": [
                {"sequence": item.sequence, "reason": item.reason, "count": item.count}
                for item in self.declared_gaps
            ],
            "grades": [
                {"connection_id": item.connection_id, "grade": item.grade} for item in self.grades
            ],
        }


def _sequence(entry: Mapping[str, object]) -> int:
    return int(entry["sequence"])  # type: ignore[call-overload]


def _read_entry(entry: object) -> Mapping[str, object]:
    """One entry document, held to the published shape a reader tolerates.

    A member this generation does not define is kept — it is hashed as it
    stands — and a kind this generation does not define is hashed and otherwise
    passed over; a document that lacks a member the recipe needs cannot be
    verified at all and is refused as a bundle (article 13).
    """
    if not isinstance(entry, Mapping):
        raise InvalidBundle("an entry must be an object")
    for member in _ENTRY_MEMBERS:
        if member not in entry:
            raise InvalidBundle(f"an entry lacks {member}")
    sequence = entry["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise InvalidBundle("an entry's sequence must be a positive integer")
    previous = entry["previous_hash"]
    if previous is not None and (not isinstance(previous, str) or not _DIGEST.fullmatch(previous)):
        raise InvalidBundle("an entry's previous_hash must be a lowercase digest or null")
    if sequence == 1 and previous is not None:
        raise InvalidBundle("a genesis entry cannot name a predecessor")
    if sequence > 1 and previous is None:
        raise InvalidBundle("a later entry must name a predecessor")
    if not isinstance(entry["entry_hash"], str) or not _DIGEST.fullmatch(entry["entry_hash"]):
        raise InvalidBundle("an entry's entry_hash must be a lowercase digest")
    for member in ("scope", "kind", "recorded_at", "connection_id", "preimage_version"):
        if not isinstance(entry[member], str) or not entry[member]:
            raise InvalidBundle(f"an entry's {member} must be a non-empty string")
    if not isinstance(entry["principal"], Mapping) or not isinstance(entry["body"], Mapping):
        raise InvalidBundle("an entry's principal and body must be objects")
    for member in ("kind", "id"):
        if not isinstance(entry["principal"].get(member), str):
            raise InvalidBundle(f"a principal's {member} must be a string")
    kind = str(entry["kind"])
    body = entry["body"]
    for member in _BODY_REQUIRED.get(kind, ()):
        if member not in body:
            raise InvalidBundle(f"a {kind} body lacks {member}")
    if kind == "gap" and body["reason"] not in GAP_REASONS:
        raise InvalidBundle("a gap names a reason this generation does not define")
    if kind == "recovery":
        if body["event"] not in RECOVERY_EVENTS:
            raise InvalidBundle("a recovery marker names an event this generation does not define")
        for member in ("from_sequence", "through_sequence"):
            if not isinstance(body[member], int) or isinstance(body[member], bool):
                raise InvalidBundle(f"a recovery marker's {member} must be an integer")
    return entry


def _grades(
    entries: Sequence[Mapping[str, object]], *, lowered: frozenset[str] = frozenset()
) -> tuple[ConnectionGrade, ...]:
    """The weakest grade recorded for each connection over these entries, from nothing.

    An offline range holds no verified prefix, so it carries no grade in from
    before its first entry: a connection whose grade record is not inside the
    range is `unverified` over it, whatever the server asserted (article 7).
    A connection named in `lowered` — one represented in an epoch that did not
    close cleanly — is `unverified` throughout, because a lost downgrade
    cannot leave a stronger historical verdict standing.
    """
    current: dict[str, str] = {}
    covered: dict[str, list[str]] = {}
    for entry in entries:
        connection = str(entry["connection_id"])
        if entry["kind"] == "grade":
            grade = str(entry["body"]["grade"])  # type: ignore[index]
            current[connection] = grade if grade in _GRADE_RANK else "unverified"
        covered.setdefault(connection, []).append(current.get(connection, "unverified"))
    return tuple(
        ConnectionGrade(
            connection,
            "unverified" if connection in lowered else min(values, key=_GRADE_RANK.__getitem__),
        )
        for connection, values in sorted(covered.items())
    )


def _verdict(
    entries: Sequence[Mapping[str, object]],
    *,
    scope: str,
    from_sequence: int,
    condition: ChainCondition,
    sequence: int | None = None,
    expected: str | None = None,
    found: str | None = None,
    version: str | None = None,
    graded: Sequence[Mapping[str, object]] | None = None,
    lowered: frozenset[str] = frozenset(),
) -> ChainVerdict:
    intact = condition is ChainCondition.intact
    return ChainVerdict(
        scope=scope,
        condition=condition,
        from_sequence=from_sequence,
        to_sequence=_sequence(entries[-1]) if entries else None,
        up_to=_sequence(entries[-1]) if entries and intact else None,
        sequence=sequence,
        expected=expected,
        found=found,
        version=version,
        covers_an_entry=bool(entries),
        declared_gaps=tuple(
            DeclaredGap(_sequence(entry), str(entry["body"]["reason"]), int(entry["body"]["count"]))  # type: ignore[index]
            for entry in entries
            if entry["kind"] == "gap"
        ),
        grades=_grades(entries if graded is None else graded, lowered=lowered),
    )


def verify_chain(
    entries: Sequence[Mapping[str, object]],
    *,
    scope: str,
    from_sequence: int,
    to_sequence: int | None = None,
    lowered: frozenset[str] = frozenset(),
) -> ChainVerdict:
    """Verify one range as the server's verifier does, with no prefix carried in.

    Contiguity first, so a missing sequence is a gap before it is anything
    else; then every hash under the recipe each entry declares; then every
    link. The verdict names the first sequence at which the range stops being
    what it claims, and the entries before it are the ones a reader may trust.

    Two conditions are told apart on purpose. `broken_at` is a negative fact
    this verifier established: it recomputed and the number did not match.
    `unverifiable` is the absence of one: a recipe this wheel holds no reader
    for, or an entry that recipe cannot be applied to, establishes nothing
    about the chain and must not be rendered as damage to it (article 2).

    `InvalidBundle` is raised for the CALLER's arguments — a scope that does
    not match the contract, a range that is not a range — and for an entry
    document this generation cannot read as an entry at all. What a bundle's
    content says about the chain is a verdict, never an exception.
    """
    if not _SCOPE.fullmatch(scope):
        raise InvalidBundle("scope does not match the contract")
    if from_sequence < 1 or (to_sequence is not None and to_sequence < from_sequence):
        raise InvalidBundle("the requested range is invalid")
    read = [_read_entry(entry) for entry in entries]
    common = {"scope": scope, "from_sequence": from_sequence, "lowered": lowered}
    # A bundle's CONTENT is never the caller's argument error. A range carrying
    # an entry of another scope, or carrying its entries out of order, is not
    # the range that was asked for and cannot be checked as one — which is a
    # verdict that establishes nothing, not a claim that the chain was found
    # damaged (articles 1 and 2). The two arguments above stay raised.
    if any(entry["scope"] != scope for entry in read):
        return _verdict(read, condition=ChainCondition.unverifiable, graded=(), **common)  # type: ignore[arg-type]
    if any(_sequence(right) <= _sequence(left) for left, right in pairwise(read)):
        return _verdict(read, condition=ChainCondition.unverifiable, graded=(), **common)  # type: ignore[arg-type]
    if not read:
        if to_sequence is None:
            return _verdict(read, condition=ChainCondition.unverifiable, **common)  # type: ignore[arg-type]
        return _verdict(read, condition=ChainCondition.gap_at, sequence=from_sequence, **common)  # type: ignore[arg-type]
    if _sequence(read[0]) != from_sequence:
        return _verdict(
            read,
            condition=ChainCondition.gap_at,
            sequence=from_sequence,
            graded=(),
            **common,  # type: ignore[arg-type]
        )
    for index, (left, right) in enumerate(pairwise(read), start=1):
        if _sequence(right) != _sequence(left) + 1:
            return _verdict(
                read,
                condition=ChainCondition.gap_at,
                sequence=_sequence(left) + 1,
                graded=read[:index],
                **common,  # type: ignore[arg-type]
            )
    if to_sequence is not None and _sequence(read[-1]) < to_sequence:
        return _verdict(
            read,
            condition=ChainCondition.gap_at,
            sequence=_sequence(read[-1]) + 1,
            **common,  # type: ignore[arg-type]
        )
    for index, entry in enumerate(read):
        if entry["preimage_version"] != PREIMAGE_VERSION:
            # Not a break. This verifier holds no recipe for the entry, so it
            # established nothing about it, and `broken_at` would render an
            # absence of capability as damage to the chain (article 2). The
            # version is named so a reader knows which recipe to go and find.
            return _verdict(
                read,
                condition=ChainCondition.unverifiable,
                sequence=_sequence(entry),
                found=str(entry["entry_hash"]),
                version=str(entry["preimage_version"]),
                graded=read[:index],
                **common,  # type: ignore[arg-type]
            )
        try:
            expected_hash = entry_hash_of(entry)
        except _UNAPPLIABLE:
            # An entry the declared recipe cannot be applied to at all — a
            # principal whose delegation is not a chain, an instant outside the
            # calendar. The range stops being checkable here and says so, rather
            # than claiming the chain was found damaged.
            return _verdict(
                read,
                condition=ChainCondition.unverifiable,
                sequence=_sequence(entry),
                found=str(entry["entry_hash"]),
                version=str(entry["preimage_version"]),
                graded=read[:index],
                **common,  # type: ignore[arg-type]
            )
        if expected_hash != entry["entry_hash"]:
            return _verdict(
                read,
                condition=ChainCondition.broken_at,
                sequence=_sequence(entry),
                expected=expected_hash,
                found=str(entry["entry_hash"]),
                graded=read[:index],
                **common,  # type: ignore[arg-type]
            )
    for index, (previous, entry) in enumerate(pairwise(read), start=1):
        if entry["previous_hash"] != previous["entry_hash"]:
            return _verdict(
                read,
                condition=ChainCondition.broken_at,
                sequence=_sequence(entry),
                expected=str(previous["entry_hash"]),
                found=str(entry["previous_hash"]),
                graded=read[:index],
                **common,  # type: ignore[arg-type]
            )
    return _verdict(read, condition=ChainCondition.intact, **common)  # type: ignore[arg-type]
