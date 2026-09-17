# SPDX-License-Identifier: Apache-2.0
"""The complete offline export verifier, over the published evidence recipes.

Article 13 publishes the recipes so that a reader holding nothing but an export
and this wheel can check what the export claims. `evidence_recipes` is the
writing-and-checking half — canonical JSON, the preimage, entry hashing, the
chain verdict, three manifest recipes — and this module is the reading half:
`verify_export`, which puts them together with `retrospective_policy` to
re-derive every trusted decision the export carries. Every name of the recipes
module is re-exported here, so `sayfirst_contract.evidence` remains the one
import a consumer needs. The server keeps its own implementations of every
recipe; the vectors in `_contracts/domain/` are what hold the two apart
(article 13).

The split is a rule and not a tidiness: re-deriving a recorded decision is
deciding, so no boundary and no server may reach this module — which is why a
writer that only places an entry imports the recipes directly.

It imports no server, opens no file or socket, and reads no clock. A caller
loads bytes outside it and hands it a parsed bundle.

What `confirmed` establishes is narrow and is said in `ExportVerdict`: the
named, actually evaluated records are internally consistent with the archived
policy bytes under their recorded recipe and recorded inputs. It establishes
neither historical group membership, nor that the arguments matched a
boundary-supplied digest, nor receipt, execution, grant validity after a
restart, nor integrity against a writer able to replace an observability-grade
store (article 7). The grade is a separate, weakest-grade claim, recomputed
here from the grade records the range itself carries and nothing before it.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from .evidence_recipes import _ASYNCHRONOUS_KINDS, _POLICY_VERSION, _SCOPE, _read_entry, _sequence
from .evidence_recipes import EFFECT_DECISION_MEMBERS as EFFECT_DECISION_MEMBERS
from .evidence_recipes import ENTRY_KINDS as ENTRY_KINDS
from .evidence_recipes import GAP_REASONS as GAP_REASONS
from .evidence_recipes import GRADES as GRADES
from .evidence_recipes import MANIFEST_V1 as MANIFEST_V1
from .evidence_recipes import MANIFEST_V2 as MANIFEST_V2
from .evidence_recipes import MANIFEST_V3 as MANIFEST_V3
from .evidence_recipes import MANIFEST_VERSIONS as MANIFEST_VERSIONS
from .evidence_recipes import PREIMAGE_VERSION as PREIMAGE_VERSION
from .evidence_recipes import RECOVERY_EVENTS as RECOVERY_EVENTS
from .evidence_recipes import ChainCondition as ChainCondition
from .evidence_recipes import ChainVerdict as ChainVerdict
from .evidence_recipes import ConnectionGrade as ConnectionGrade
from .evidence_recipes import DeclaredGap as DeclaredGap
from .evidence_recipes import InvalidBundle as InvalidBundle
from .evidence_recipes import canonical_json as canonical_json
from .evidence_recipes import chained_document as chained_document
from .evidence_recipes import entry_hash_of as entry_hash_of
from .evidence_recipes import entry_verifies as entry_verifies
from .evidence_recipes import manifest_hash as manifest_hash
from .evidence_recipes import preimage as preimage
from .evidence_recipes import render_instant as render_instant
from .evidence_recipes import verify_chain as verify_chain
from .retrospective_policy import (
    RECIPE,
    RecordedDecision,
    Rederivation,
    rederive_recorded_decision,
)

# -- the export verdict -----------------------------------------------------


class ArchiveState(StrEnum):
    present = "present"
    absent = "absent"
    damaged = "damaged"
    unknown = "unknown"


@dataclass(frozen=True)
class EntryRederivation:
    sequence: int
    decision_id: str
    evaluation_recipe: str | None
    verdict: Rederivation
    cause: str | None
    expected: tuple[str, str, str | None] | None

    def to_document(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "decision_id": self.decision_id,
            "evaluation_recipe": self.evaluation_recipe,
            "verdict": self.verdict.value,
            "cause": self.cause,
            "expected": None if self.expected is None else list(self.expected),
        }


@dataclass(frozen=True)
class ExportVerdict:
    """What one export establishes, and exactly how far that reaches (H1 to H3)."""

    scope: str | None
    chain: ChainVerdict | None
    manifest_version: str | None
    manifest_hash_recomputes: bool | None
    policy_versions: Mapping[str, ArchiveState]
    evaluation_recipes: tuple[str, ...]
    rederivations: tuple[EntryRederivation, ...]
    rederived_decision_ids: tuple[str, ...]
    confirmed_decision_ids: tuple[str, ...]
    declared_missing_decision_ids: tuple[str, ...]
    coverage: str
    from_sequence: int | None
    to_sequence: int | None
    next_from: int | None
    issues: tuple[str, ...]
    overall: Rederivation
    #: The grades the server asserted, kept beside the recomputed ones and
    #: never merged into them: a conservative offline grade is not a
    #: disagreement about policy, and an asserted one is not a verification.
    asserted_grades: Mapping[str, str] = field(default_factory=dict)

    def to_document(self) -> dict[str, object]:
        return {
            "scope": self.scope,
            "chain": None if self.chain is None else self.chain.to_document(),
            "manifest_version": self.manifest_version,
            "manifest_hash_recomputes": self.manifest_hash_recomputes,
            "policy_versions": {key: value.value for key, value in self.policy_versions.items()},
            "evaluation_recipes": list(self.evaluation_recipes),
            "rederivations": [item.to_document() for item in self.rederivations],
            "rederived_decision_ids": list(self.rederived_decision_ids),
            "confirmed_decision_ids": list(self.confirmed_decision_ids),
            "declared_missing_decision_ids": list(self.declared_missing_decision_ids),
            "coverage": self.coverage,
            "from_sequence": self.from_sequence,
            "to_sequence": self.to_sequence,
            "next_from": self.next_from,
            "issues": list(self.issues),
            "overall": self.overall.value,
            "asserted_grades": dict(self.asserted_grades),
        }


def _invalid(scope: str | None, reason: str) -> ExportVerdict:
    return ExportVerdict(
        scope=scope,
        chain=None,
        manifest_version=None,
        manifest_hash_recomputes=None,
        policy_versions={},
        evaluation_recipes=(),
        rederivations=(),
        rederived_decision_ids=(),
        confirmed_decision_ids=(),
        declared_missing_decision_ids=(),
        coverage="unknown",
        from_sequence=None,
        to_sequence=None,
        next_from=None,
        issues=("bundle_invalid", reason),
        overall=Rederivation.unverifiable,
    )


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvalidBundle("a sequence member must be a positive integer or null")
    return value


def _policy_bytes(
    state: object,
) -> tuple[ArchiveState, bytes | None]:
    """One attachment, read as its state and — when present and matching — its bytes."""
    if not isinstance(state, Mapping) or state.get("state") not in {
        item.value for item in ArchiveState
    }:
        raise InvalidBundle("a policy attachment must carry a published state")
    kind = ArchiveState(str(state["state"]))
    if kind is not ArchiveState.present:
        return kind, None
    content = state.get("content")
    if not isinstance(content, str):
        raise InvalidBundle("a present policy attachment carries its content")
    try:
        return kind, base64.b64decode(content, validate=True)
    except (ValueError, TypeError) as error:
        raise InvalidBundle("a policy attachment is not base64") from error


def _recorded(body: Mapping[str, object], scope: str) -> RecordedDecision:
    references = body.get("principal_references")
    recipe = body.get("evaluation_recipe")
    return RecordedDecision(
        scope=scope,
        capability=str(body["capability"]),
        principal_references=(
            tuple(str(item) for item in references) if isinstance(references, list) else None
        ),
        arguments_digest=body["arguments_digest"]
        if isinstance(body.get("arguments_digest"), str)
        else None,
        outcome=str(body["outcome"]),
        reason=str(body.get("reason")),
        rule_id=body["rule_id"] if isinstance(body.get("rule_id"), str) else None,
        evaluation_recipe=recipe if isinstance(recipe, str) else None,
    )


def _trusted(entries: Sequence[Mapping[str, object]], chain: ChainVerdict) -> int:
    """How many leading entries the chain verdict lets a reader trust."""
    if chain.condition is ChainCondition.intact:
        return len(entries)
    if chain.sequence is None:
        return 0
    return sum(1 for entry in entries if _sequence(entry) < chain.sequence)


def _verified_context(
    context: object, last: Mapping[str, object] | None, scope: str
) -> tuple[list[Mapping[str, object]], bool]:
    """The recovery context, or nothing, and whether a supplied one failed to verify."""
    if context is None:
        return [], False
    if not isinstance(context, list):
        raise InvalidBundle("recovery_context must be a list")
    if not context:
        return [], False
    if last is None:
        return [], True
    try:
        read = [_read_entry(entry) for entry in context]
    except InvalidBundle:
        return [], True
    if _sequence(read[0]) != _sequence(last) + 1 or read[0]["previous_hash"] != last["entry_hash"]:
        return [], True
    verdict = verify_chain(read, scope=scope, from_sequence=_sequence(read[0]))
    if verdict.condition is not ChainCondition.intact:
        return [], True
    return read, False


def _epochs(
    markers: Sequence[Mapping[str, object]],
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    clean: list[tuple[int, int]] = []
    unclean: list[tuple[int, int]] = []
    for marker in markers:
        body = marker["body"]
        span = (int(body["from_sequence"]), int(body["through_sequence"]))  # type: ignore[index]
        (clean if body["event"] == "clean_stop" else unclean).append(span)  # type: ignore[index]
    return clean, unclean


def _within(sequence: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(start <= sequence <= end for start, end in spans)


def verify_export(bundle: Mapping[str, object]) -> ExportVerdict:
    """Everything an export establishes, from the export and this wheel alone (V3).

    In order: the shape, the chain, its manifest digest under the recipe the bundle
    names, the recovery context, the policy attachments against the versions
    the trusted effects name, the re-derivation of every trusted supported
    effect, the coverage, and the precedence of H3. Structural invalidity is a
    verdict with its issues populated, never an exception and never a boolean.

    What that totality covers, exactly: every document a JSON parser produces.
    A caller that builds a `Mapping` by hand and puts a value in it that the
    canonical serialiser refuses — a set, a `datetime`, an object of its own —
    is outside it, and `manifest_hash` raises on that value here exactly as it
    would anywhere else. The input domain of an export is a parsed document, so
    the guards below name what a document can be wrong about and nothing else.
    """
    if not isinstance(bundle, Mapping):
        return _invalid(None, "the bundle is not an object")
    scope = bundle.get("scope")
    if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
        return _invalid(None, "the bundle names no valid scope")
    try:
        from_sequence = _optional_int(bundle.get("from_sequence"))
        if from_sequence is None:
            raise InvalidBundle("from_sequence is required")
        to_sequence = _optional_int(bundle.get("to_sequence"))
        next_from = _optional_int(bundle.get("next_from"))
        entries_raw = bundle.get("entries")
        verification = bundle.get("verification")
        if not isinstance(entries_raw, list) or not isinstance(verification, Mapping):
            raise InvalidBundle("entries must be a list and verification an object")
        if not isinstance(bundle.get("manifest_hash"), str):
            raise InvalidBundle("manifest_hash is required")
        entries = [_read_entry(entry) for entry in entries_raw]
        if entries and to_sequence != _sequence(entries[-1]):
            raise InvalidBundle("to_sequence must name the last entry the bundle carries")
        attachments = bundle.get("policy_versions")
        if attachments is not None and not isinstance(attachments, Mapping):
            raise InvalidBundle("policy_versions must be an object")
        context, context_unverified = _verified_context(
            bundle.get("recovery_context"), entries[-1] if entries else None, scope
        )
    except InvalidBundle as error:
        return _invalid(scope, str(error))

    issues: list[str] = []
    # The chain, and how much of it a reader may trust. The call is inside the
    # guard because a range this wheel cannot check is a verdict about the
    # bundle and never an exception out of a verifier (articles 1 and 2).
    try:
        provisional = verify_chain(
            entries, scope=scope, from_sequence=from_sequence, to_sequence=to_sequence
        )
    except InvalidBundle as error:
        return _invalid(scope, str(error))
    trusted_count = _trusted(entries, provisional)
    trusted = entries[:trusted_count]
    if provisional.condition is ChainCondition.unverifiable:
        issues.append("chain_unverifiable")
    elif provisional.condition is not ChainCondition.intact:
        issues.append("chain_damaged")

    # Its manifest digest, under the recipe the bundle names or the two it
    # predates; then the same chain again, with the connections an unclean
    # epoch lowered. Both are inside the guard for the reason the first call is.
    manifest_version: str | None = None
    recomputes: bool | None = None
    named = bundle.get("manifest_version")
    try:
        if named is None:
            for candidate in (MANIFEST_V1, MANIFEST_V2):
                if manifest_hash(bundle, version=candidate) == bundle["manifest_hash"]:
                    manifest_version, recomputes = candidate, True
                    break
            else:
                recomputes = False
        elif named in MANIFEST_VERSIONS:
            manifest_version = str(named)
            recomputes = manifest_hash(bundle, version=manifest_version) == bundle["manifest_hash"]
        else:
            issues.append("manifest_recipe_unsupported")
        if recomputes is False:
            issues.append("manifest_mismatch")
        if context_unverified:
            issues.append("recovery_context_unverified")

        # Epoch closure, from the markers the range and its context carry.
        markers = [entry for entry in (*trusted, *context) if entry["kind"] == "recovery"]
        clean_spans, unclean_spans = _epochs(markers)
        lowered = frozenset(
            str(entry["connection_id"])
            for entry in trusted
            if _within(_sequence(entry), unclean_spans)
        )
        chain = verify_chain(
            entries,
            scope=scope,
            from_sequence=from_sequence,
            to_sequence=to_sequence,
            lowered=lowered,
        )
    except InvalidBundle as error:
        return _invalid(scope, str(error))

    # The policy attachments the trusted effects need.
    effects = [entry for entry in trusted if entry["kind"] == "effect"]
    required = sorted({str(entry["body"]["policy_version"]) for entry in effects})  # type: ignore[index]
    states: dict[str, ArchiveState] = {}
    contents: dict[str, bytes] = {}
    causes: dict[str, str] = {}
    for version in required:
        attachment = None if attachments is None else attachments.get(version)
        if attachment is None:
            states[version] = ArchiveState.absent
            causes[version] = "policy_absent"
            if "policy_map_incomplete" not in issues:
                issues.append("policy_map_incomplete")
            continue
        try:
            state, content = _policy_bytes(attachment)
        except InvalidBundle as error:
            return _invalid(scope, str(error))
        if state is ArchiveState.present:
            assert content is not None
            if _POLICY_VERSION.fullmatch(version) is None or (
                "sha256:" + hashlib.sha256(content).hexdigest() != version
            ):
                states[version] = ArchiveState.damaged
                causes[version] = "policy_damaged"
                if "policy_map_incomplete" not in issues:
                    issues.append("policy_map_incomplete")
                continue
            states[version] = state
            contents[version] = content
        else:
            states[version] = state
            causes[version] = {
                ArchiveState.absent: "policy_absent",
                ArchiveState.damaged: "policy_damaged",
                ArchiveState.unknown: "policy_state_unknown",
            }[state]

    # Re-derivation of every trusted effect; untrusted ones are named as such.
    rederivations: list[EntryRederivation] = []
    recipes: set[str] = set()
    for entry in entries:
        if entry["kind"] != "effect":
            continue
        body = entry["body"]
        recipe = body.get("evaluation_recipe")
        recipe_text = recipe if isinstance(recipe, str) else None
        if recipe_text is not None:
            recipes.add(recipe_text)
        decision_id = str(body["decision_id"])
        if _sequence(entry) > (_sequence(trusted[-1]) if trusted else 0):
            rederivations.append(
                EntryRederivation(
                    _sequence(entry),
                    decision_id,
                    recipe_text,
                    Rederivation.unverifiable,
                    "entry_untrusted",
                    None,
                )
            )
            continue
        version = str(body["policy_version"])
        if version not in contents:
            rederivations.append(
                EntryRederivation(
                    _sequence(entry),
                    decision_id,
                    recipe_text,
                    Rederivation.unverifiable,
                    causes[version],
                    None,
                )
            )
            continue
        result = rederive_recorded_decision(_recorded(body, scope), contents[version])
        rederivations.append(
            EntryRederivation(
                _sequence(entry),
                decision_id,
                recipe_text,
                result.verdict,
                result.cause,
                result.expected,
            )
        )

    rederived = tuple(
        item.decision_id
        for item in rederivations
        if item.verdict in (Rederivation.confirmed, Rederivation.differs)
    )
    confirmed = tuple(
        item.decision_id for item in rederivations if item.verdict is Rederivation.confirmed
    )
    declared_missing = tuple(
        str(identifier)
        for entry in trusted
        if entry["kind"] == "gap" and isinstance(entry["body"].get("decision_ids"), list)  # type: ignore[union-attr]
        for identifier in entry["body"]["decision_ids"]  # type: ignore[index]
    )

    # Coverage (H2).
    asynchronous = [entry for entry in trusted if entry["kind"] in _ASYNCHRONOUS_KINDS]
    incomplete = any(entry["kind"] == "gap" for entry in trusted)
    unknown = (
        not trusted
        or trusted_count < len(entries)
        or context_unverified
        or any(_within(_sequence(entry), unclean_spans) for entry in asynchronous)
        or any(not _within(_sequence(entry), clean_spans) for entry in asynchronous)
    )
    coverage = "incomplete" if incomplete else "unknown" if unknown else "complete"
    if incomplete:
        issues.append("coverage_incomplete")
    if unknown:
        issues.append("coverage_unknown")
    if not effects:
        issues.append("no_decisions")

    # Precedence (H3).
    if any(item.verdict is Rederivation.differs for item in rederivations):
        overall = Rederivation.differs
    elif (
        issues
        or coverage != "complete"
        or not rederivations
        or any(item.verdict is not Rederivation.confirmed for item in rederivations)
    ):
        overall = Rederivation.unverifiable
    else:
        overall = Rederivation.confirmed

    # The grades the SERVER asserted, read as defensively as any other member a
    # bundle carries: an item that names no connection, or no grade, names no
    # assertion this reader can keep, and passing over it is not the same as
    # inventing one (article 2). It raised a `KeyError` out of a verifier.
    asserted = verification.get("grades")
    asserted_grades = (
        {
            str(item["connection_id"]): str(item["grade"])
            for item in asserted
            if isinstance(item, Mapping)
            and isinstance(item.get("connection_id"), str)
            and isinstance(item.get("grade"), str)
        }
        if isinstance(asserted, list)
        else {}
    )
    return ExportVerdict(
        scope=scope,
        chain=chain,
        manifest_version=manifest_version,
        manifest_hash_recomputes=recomputes,
        policy_versions=states,
        evaluation_recipes=tuple(sorted(recipes)),
        rederivations=tuple(rederivations),
        rederived_decision_ids=rederived,
        confirmed_decision_ids=confirmed,
        declared_missing_decision_ids=declared_missing,
        coverage=coverage,
        from_sequence=from_sequence,
        to_sequence=to_sequence,
        next_from=next_from,
        issues=tuple(issues),
        overall=overall,
        asserted_grades=asserted_grades,
    )


__all__ = [
    "EFFECT_DECISION_MEMBERS",
    "ENTRY_KINDS",
    "GAP_REASONS",
    "GRADES",
    "MANIFEST_V1",
    "MANIFEST_V2",
    "MANIFEST_V3",
    "MANIFEST_VERSIONS",
    "PREIMAGE_VERSION",
    "RECIPE",
    "RECOVERY_EVENTS",
    "ArchiveState",
    "ChainCondition",
    "ChainVerdict",
    "ConnectionGrade",
    "DeclaredGap",
    "EntryRederivation",
    "ExportVerdict",
    "InvalidBundle",
    "Rederivation",
    "canonical_json",
    "chained_document",
    "entry_hash_of",
    "entry_verifies",
    "manifest_hash",
    "preimage",
    "render_instant",
    "verify_chain",
    "verify_export",
]
