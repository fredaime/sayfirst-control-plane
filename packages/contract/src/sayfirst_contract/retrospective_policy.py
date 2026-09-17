# SPDX-License-Identifier: Apache-2.0
"""The retrospective policy evaluation recipe: historical audit only; never authorize an effect.

This module re-derives a decision that was *already taken and recorded* from
the recorded inputs and the archived bytes of the policy version the record
names, and says whether the recorded answer is the one those inputs and bytes
yield. That is all it does. It performs no I/O, reaches no daemon, holds no
state, and cannot mint a decision, an approval or a grant. A boundary that
called it to decide would be the second control plane without evidence that
article 1 forbids; `tests/test_retrospective_evaluator_boundaries.py` fails
the build if a boundary, the operator command or the live server reaches it.

The recipe is `sayfirst/policy-evaluation/v1`, published in full beside its
vectors in `_contracts/domain/recipes/policy-evaluation-v1.md`. The server
keeps its own live evaluator and does not import this one; the two are held
apart by `policy-evaluation-v1.json`, which each runs independently (article
13). A semantic change mints a new recipe identifier; this identifier never
changes meaning.
"""

from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

RECIPE: Final = "sayfirst/policy-evaluation/v1"
"""The stable identifier of the semantics below; a decision records the one it was taken under."""

RECIPE_REASONS: Final = frozenset(
    {"policy_allows", "policy_denies", "policy_absent", "policy_requires_review"}
)
"""The recipe's own reason vocabulary. The published `reason` enum is wider —
`capability_unknown` is answered before any policy is consulted — and a
recorded reason outside these four is out of this recipe's scope, never a
disagreement (article 2)."""

_IDENTIFIER: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CAPABILITY: Final = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$")
_SCOPE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROOT_MEMBERS: Final = frozenset({"format", "revision", "rule"})
_REVISION_MEMBERS: Final = frozenset({"reason"})
_RULE_MEMBERS: Final = frozenset(
    {
        "id",
        "capability",
        "scope",
        "principals",
        "outcome",
        "reason",
        "grant_lifetime_seconds",
        "review_deadline_seconds",
        "arguments_digest",
    }
)
_OUTCOMES: Final = ("allow", "deny", "suspend")
_STRICTEST_FIRST: Final = (
    ("deny", "policy_denies"),
    ("suspend", "policy_requires_review"),
    ("allow", "policy_allows"),
)


class Rederivation(StrEnum):
    confirmed = "confirmed"
    differs = "differs"
    unverifiable = "unverifiable"


@dataclass(frozen=True)
class PolicyUnparseable:
    """The bytes are not a format-1 policy under this recipe's rules."""

    message: str


@dataclass(frozen=True)
class RecordedDecision:
    """The recorded inputs and the recorded answer of one decision, as an entry carries them.

    A `None` in `principal_references` or `evaluation_recipe` is a historical
    entry that did not record the member; it is reported as such, never
    synthesised (article 2).
    """

    scope: str
    capability: str
    principal_references: tuple[str, ...] | None
    arguments_digest: str | None
    outcome: str
    reason: str
    rule_id: str | None
    evaluation_recipe: str | None


@dataclass(frozen=True)
class Rederived:
    verdict: Rederivation
    cause: str | None
    expected: tuple[str, str, str | None] | None


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    capability: str
    scope: str
    principals: tuple[str, ...]
    outcome: str
    arguments_digest: str | None


class _Invalid(ValueError):
    pass


def _has_control(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _text(value: object, *, member: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or _has_control(value):
        raise _Invalid(f"{member} must be a non-empty string of at most {maximum} characters")
    return value


def _only(document: dict[str, object], allowed: frozenset[str], *, member: str) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise _Invalid(f"{member} has unknown member {unknown[0]}")


def _reference(raw: object, *, member: str) -> str:
    if not isinstance(raw, str) or raw.count(":") != 1:
        raise _Invalid(f"{member} must be user:<name> or group:<name>")
    kind, name = raw.split(":", 1)
    if kind not in {"user", "group"} or not name or len(name) > 256 or _has_control(name):
        raise _Invalid(f"{member} must be user:<name> or group:<name>")
    return raw


def _rule(raw: object, index: int) -> _Rule:
    if not isinstance(raw, dict):
        raise _Invalid(f"rule[{index}] must be a table")
    _only(raw, _RULE_MEMBERS, member=f"rule[{index}]")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or _IDENTIFIER.fullmatch(rule_id) is None:
        raise _Invalid(f"rule[{index}].id is invalid")
    prefix = f"rule {rule_id}"
    capability = raw.get("capability")
    if not isinstance(capability, str) or _CAPABILITY.fullmatch(capability) is None:
        raise _Invalid(f"{prefix}.capability is invalid")
    scope = raw.get("scope", "local")
    if not isinstance(scope, str) or _SCOPE.fullmatch(scope) is None or _has_control(scope):
        raise _Invalid(f"{prefix}.scope is invalid")
    principals_raw = raw.get("principals")
    if not isinstance(principals_raw, list) or not principals_raw:
        raise _Invalid(f"{prefix}.principals must be a non-empty array")
    principals = tuple(_reference(value, member=f"{prefix}.principals") for value in principals_raw)
    outcome = raw.get("outcome")
    if not isinstance(outcome, str) or outcome not in _OUTCOMES:
        raise _Invalid(f"{prefix}.outcome is invalid")
    _text(raw.get("reason"), member=f"{prefix}.reason", maximum=512)
    lifetime = raw.get("grant_lifetime_seconds")
    if lifetime is not None and (
        not isinstance(lifetime, int)
        or isinstance(lifetime, bool)
        or lifetime < 1
        or outcome != "allow"
    ):
        # The deployment-configured upper bound is deliberately not reproduced:
        # it affects live acceptance of a policy, not the triple this recipe
        # checks (rule 2 of the recipe).
        raise _Invalid(f"{prefix}.grant_lifetime_seconds is invalid")
    deadline = raw.get("review_deadline_seconds")
    if deadline is not None and (
        not isinstance(deadline, int)
        or isinstance(deadline, bool)
        or not 1 <= deadline <= 86400
        or outcome != "suspend"
    ):
        # A wait bounds a suspension and is read by no rule of this recipe:
        # rule 2 names it so that a policy carrying it parses, and rules 3 and
        # 4 never look at it, so the triple is the one it would have been
        # without the member.
        raise _Invalid(f"{prefix}.review_deadline_seconds is invalid")
    digest = raw.get("arguments_digest")
    if digest is not None and (not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None):
        raise _Invalid(f"{prefix}.arguments_digest is invalid")
    return _Rule(rule_id, capability, scope, principals, outcome, digest)


def _parse(policy: bytes) -> tuple[_Rule, ...]:
    try:
        document = tomllib.loads(policy.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise _Invalid(str(error)) from error
    _only(document, _ROOT_MEMBERS, member="policy")
    format_value = document.get("format")
    if not isinstance(format_value, int) or isinstance(format_value, bool) or format_value != 1:
        raise _Invalid(f"policy.format {format_value!r} is unsupported")
    revision = document.get("revision")
    if not isinstance(revision, dict):
        raise _Invalid("policy.revision must be a table")
    _only(revision, _REVISION_MEMBERS, member="revision")
    _text(revision.get("reason"), member="revision.reason", maximum=512)
    rules_raw = document.get("rule", [])
    if not isinstance(rules_raw, list):
        raise _Invalid("policy.rule must be an array of tables")
    rules = tuple(_rule(value, index) for index, value in enumerate(rules_raw))
    identifiers = [rule.rule_id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise _Invalid("a rule id is duplicated")
    return rules


def evaluate_recorded_inputs(
    policy: bytes,
    *,
    scope: str,
    capability: str,
    principal_references: tuple[str, ...],
    arguments_digest: str | None,
) -> tuple[str, str, str | None] | PolicyUnparseable:
    """The outcome triple the recipe yields for these recorded inputs and these bytes.

    Recorded inputs, not live ones: the references are the ones the daemon
    recorded as read for the decision, and nothing here consults an account
    directory, a clock or a grant registry. The triple is `(outcome, reason,
    rule_id)`.
    """
    try:
        rules = _parse(policy)
    except _Invalid as error:
        return PolicyUnparseable(str(error))
    recorded = frozenset(principal_references)
    applying = tuple(
        rule
        for rule in rules
        if rule.capability == capability
        and rule.scope == scope
        and any(reference in recorded for reference in rule.principals)
        and (
            rule.arguments_digest is None
            or (arguments_digest is not None and rule.arguments_digest == arguments_digest)
        )
    )
    if not applying:
        return ("deny", "policy_absent", None)
    for outcome, reason in _STRICTEST_FIRST:
        for rule in applying:
            if rule.outcome == outcome:
                return (outcome, reason, rule.rule_id)
    raise AssertionError("every parsed rule carries one of the three outcomes")


def rederive_recorded_decision(recorded: RecordedDecision, policy: bytes) -> Rederived:
    """Compare a recorded answer with what its recorded inputs and bytes yield.

    `confirmed` means equal, `differs` means demonstrably not, and
    `unverifiable` names its cause: a recipe this module does not implement, a
    member the record did not carry, bytes that are not a policy, or a recorded
    reason outside the recipe's four. None of the three is a live decision.
    """
    if recorded.evaluation_recipe is None or recorded.principal_references is None:
        return Rederived(Rederivation.unverifiable, "members_absent", None)
    if recorded.evaluation_recipe != RECIPE:
        return Rederived(Rederivation.unverifiable, "evaluation_recipe_unsupported", None)
    if recorded.reason not in RECIPE_REASONS:
        return Rederived(Rederivation.unverifiable, "reason_outside_recipe", None)
    computed = evaluate_recorded_inputs(
        policy,
        scope=recorded.scope,
        capability=recorded.capability,
        principal_references=recorded.principal_references,
        arguments_digest=recorded.arguments_digest,
    )
    if isinstance(computed, PolicyUnparseable):
        return Rederived(Rederivation.unverifiable, "policy_unparseable", None)
    if computed == (recorded.outcome, recorded.reason, recorded.rule_id):
        return Rederived(Rederivation.confirmed, None, None)
    return Rederived(Rederivation.differs, None, computed)
