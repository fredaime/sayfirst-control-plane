# SPDX-License-Identifier: Apache-2.0
"""The policy file format and its pure evaluation rule."""

from __future__ import annotations

import hashlib
import re
import tomllib
import unicodedata
from dataclasses import dataclass
from typing import Literal

from sayfirst_contract.decisions import DecisionAsk, Outcome, Reason

from .foreign import core_owned

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$")
_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROOT_MEMBERS = frozenset({"format", "revision", "rule"})
_REVISION_MEMBERS = frozenset({"reason"})
_RULE_MEMBERS = frozenset(
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

#: How long a suspended effect waits when the rule that suspended it names no
#: length, and the longest wait a rule may name. The default is applied by the
#: loader rather than read later, so a suspend rule always carries the number
#: it will be measured against and nothing downstream has to infer one
#: (article 2). A day is the ceiling because a wait nobody ends is a decision
#: nobody took, and the store's own sweep ends it at the deadline.
DEFAULT_REVIEW_DEADLINE_SECONDS: int = 300
MAX_REVIEW_DEADLINE_SECONDS: int = 86400


@dataclass(frozen=True)
class Principal:
    """The acting identity already established from a connection."""

    kind: str
    uid: int
    user_name: str
    gids: tuple[int, ...]
    group_names: tuple[str, ...]
    delegated_human: str | None = None

    @property
    def reference(self) -> str:
        return f"user:{self.user_name}"


@dataclass(frozen=True)
class PrincipalReference:
    kind: Literal["user", "group"]
    name: str

    def matches(self, principal: Principal) -> bool:
        if self.kind == "user":
            return self.name == principal.user_name
        return self.name in principal.group_names

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    capability: str
    scope: str
    principals: tuple[PrincipalReference, ...]
    outcome: Outcome
    reason: str
    grant_lifetime_seconds: int | None = None
    arguments_digest: str | None = None
    #: How long this rule's suspension waits, in seconds. A number on every
    #: `suspend` rule and `None` on every other one: only a suspension waits.
    review_deadline_seconds: int | None = None

    def applies(self, question: DecisionQuestion) -> bool:
        return (
            self.capability == question.ask.capability
            and self.scope == question.ask.scope
            and any(reference.matches(question.principal) for reference in self.principals)
            and (
                self.arguments_digest is None
                or self.arguments_digest == question.ask.arguments_digest
            )
        )


@dataclass(frozen=True)
class Policy:
    format: int
    revision_reason: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class PolicyInvalid:
    reason: Literal["malformed", "format_unsupported", "invalid"]
    message: str


@dataclass(frozen=True)
class DecisionQuestion:
    """A generation-one ask plus the principal established from the connection."""

    ask: DecisionAsk
    principal: Principal


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome
    reason: Reason
    rule_id: str | None
    rule: Rule | None


def core_owned_reference(value: object) -> PrincipalReference:
    """One principal reference of a rule, as the core's own value."""
    return core_owned(PrincipalReference, value, name=str)


def core_owned_rule(value: object) -> Rule:
    """One rule of a policy a store answered with, as the core's own value."""
    return core_owned(
        Rule,
        value,
        rule_id=str,
        capability=str,
        scope=str,
        principals=lambda items: tuple(core_owned_reference(item) for item in items),
        reason=str,
    )


def core_owned_policy(value: object) -> Policy:
    """A policy a store answered with, read once and rebuilt as the core's own.

    Article 3: the authority for a decision is the policy this daemon loaded,
    and a store that answered one set of rules to the evaluation and another to
    the version the record names would have decided the effect twice. The rules
    are rebuilt with it, because a rule is what `evaluate` reads.
    """
    return core_owned(
        Policy,
        value,
        format=int,
        revision_reason=str,
        rules=lambda items: tuple(core_owned_rule(item) for item in items),
    )


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


def _principal(raw: object, *, member: str) -> PrincipalReference:
    if not isinstance(raw, str) or raw.count(":") != 1:
        raise _Invalid(f"{member} must be user:<name> or group:<name>")
    kind, name = raw.split(":", 1)
    if kind not in {"user", "group"} or not name or len(name) > 256 or _has_control(name):
        raise _Invalid(f"{member} must be user:<name> or group:<name>")
    return PrincipalReference(kind, name)  # type: ignore[arg-type]


def _rule(raw: object, index: int, max_lifetime_seconds: int) -> Rule:
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
    principals = tuple(_principal(value, member=f"{prefix}.principals") for value in principals_raw)
    outcome_raw = raw.get("outcome")
    try:
        outcome = Outcome(outcome_raw)
    except (TypeError, ValueError):
        raise _Invalid(f"{prefix}.outcome is invalid") from None
    reason = _text(raw.get("reason"), member=f"{prefix}.reason", maximum=512)
    lifetime = raw.get("grant_lifetime_seconds")
    if lifetime is not None and (
        not isinstance(lifetime, int)
        or isinstance(lifetime, bool)
        or not 1 <= lifetime <= max_lifetime_seconds
        or outcome is not Outcome.ALLOW
    ):
        raise _Invalid(f"{prefix}.grant_lifetime_seconds is invalid")
    arguments_digest = raw.get("arguments_digest")
    if arguments_digest is not None and (
        not isinstance(arguments_digest, str) or _DIGEST.fullmatch(arguments_digest) is None
    ):
        raise _Invalid(f"{prefix}.arguments_digest is invalid")
    return Rule(
        rule_id,
        capability,
        scope,
        principals,
        outcome,
        reason,
        lifetime,
        arguments_digest,
        _review_deadline(raw.get("review_deadline_seconds"), outcome, prefix=prefix),
    )


def _review_deadline(raw: object, outcome: Outcome, *, prefix: str) -> int | None:
    """The wait this rule's suspension is measured against, or `None` if it never waits.

    A member on a rule that does not suspend is refused rather than ignored:
    an administrator who wrote it meant something by it, and a wait on an
    `allow` would never be honoured (article 2). A boolean is excluded by hand
    because Python counts one as an integer, and a wait of no length or one
    beyond a day is not a wait.
    """
    if outcome is not Outcome.SUSPEND:
        if raw is not None:
            raise _Invalid(f"{prefix}.review_deadline_seconds is invalid")
        return None
    if raw is None:
        return DEFAULT_REVIEW_DEADLINE_SECONDS
    if (
        not isinstance(raw, int)
        or isinstance(raw, bool)
        or not 1 <= raw <= MAX_REVIEW_DEADLINE_SECONDS
    ):
        raise _Invalid(f"{prefix}.review_deadline_seconds is invalid")
    return raw


def parse_policy(raw: bytes, *, max_lifetime_seconds: int = 3600) -> Policy | PolicyInvalid:
    """Parse format 1 without raising for an administrator-controlled bad file."""
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return PolicyInvalid("malformed", str(exc))
    try:
        _only(document, _ROOT_MEMBERS, member="policy")
        format_value = document.get("format")
        if not isinstance(format_value, int) or isinstance(format_value, bool) or format_value != 1:
            return PolicyInvalid(
                "format_unsupported", f"policy.format {format_value} is unsupported"
            )
        revision = document.get("revision")
        if not isinstance(revision, dict):
            raise _Invalid("policy.revision must be a table")
        _only(revision, _REVISION_MEMBERS, member="revision")
        revision_reason = _text(revision.get("reason"), member="revision.reason", maximum=512)
        rules_raw = document.get("rule", [])
        if not isinstance(rules_raw, list):
            raise _Invalid("policy.rule must be an array of tables")
        rules = tuple(
            _rule(value, index, max_lifetime_seconds) for index, value in enumerate(rules_raw)
        )
        identifiers = [rule.rule_id for rule in rules]
        if len(identifiers) != len(set(identifiers)):
            duplicate = next(
                value for index, value in enumerate(identifiers) if value in identifiers[:index]
            )
            raise _Invalid(f"rule {duplicate}.id is duplicated")
    except _Invalid as exc:
        return PolicyInvalid("invalid", str(exc))
    return Policy(format_value, revision_reason, rules)


def policy_version(raw: bytes) -> str:
    """Return the opaque content identity of the authority bytes."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def references_read(policy: Policy, question: DecisionQuestion) -> tuple[str, ...]:
    """The principal references the evaluation read, sorted and unique (M3).

    The caller's own references intersected with those named by every rule for
    the asked scope and capability — competing rules and rules whose pinned
    digest does not match included, because the retrospective evaluation must
    be able to repeat every membership test the live one made. A group the
    caller holds that only another scope or capability names is not recorded:
    the record says which memberships were read for this question, not which
    the caller has (article 11). Never truncated.
    """
    held = {f"user:{question.principal.user_name}"}
    held.update(f"group:{name}" for name in question.principal.group_names)
    named = {
        str(reference)
        for rule in policy.rules
        if rule.capability == question.ask.capability and rule.scope == question.ask.scope
        for reference in rule.principals
    }
    return tuple(sorted(held & named))


def evaluate(policy: Policy, question: DecisionQuestion) -> Verdict:
    """Apply exact matches and select deny before suspend before allow."""
    applying = tuple(rule for rule in policy.rules if rule.applies(question))
    if not applying:
        return Verdict(Outcome.DENY, Reason.POLICY_ABSENT, None, None)
    for outcome, reason in (
        (Outcome.DENY, Reason.POLICY_DENIES),
        (Outcome.SUSPEND, Reason.POLICY_REQUIRES_REVIEW),
        (Outcome.ALLOW, Reason.POLICY_ALLOWS),
    ):
        for rule in applying:
            if rule.outcome is outcome:
                return Verdict(outcome, reason, rule.rule_id, rule)
    raise AssertionError("Outcome is a closed enum and every rule was parsed from it")
