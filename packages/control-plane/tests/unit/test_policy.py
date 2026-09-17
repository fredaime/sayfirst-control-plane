# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib

from sayfirst_contract.decisions import DecisionAsk, Outcome, Reason
from sayfirst_control_plane.domain.policy import (
    DecisionQuestion,
    PolicyInvalid,
    Principal,
    evaluate,
    parse_policy,
    policy_version,
)

DIGEST = "sha256:" + "1" * 64
OTHER_DIGEST = "sha256:" + "2" * 64


def _policy(*rules: str, extra: str = "") -> bytes:
    joined = "\n".join(rules)
    return (f'format = 1\n[revision]\nreason = "reviewed change"\n{extra}\n{joined}\n').encode()


def _rule(
    rule_id: str,
    outcome: str,
    *,
    principals: str = '["user:build"]',
    arguments_digest: str | None = None,
) -> str:
    pin = "" if arguments_digest is None else f'\narguments_digest = "{arguments_digest}"'
    return (
        "[[rule]]\n"
        f'id = "{rule_id}"\n'
        'capability = "mail.send"\n'
        f"principals = {principals}\n"
        f'outcome = "{outcome}"\n'
        f'reason = "reason for {rule_id}"{pin}'
    )


def _question(*, digest: str = DIGEST, delegated_human: str | None = None) -> DecisionQuestion:
    return DecisionQuestion(
        ask=DecisionAsk("mail.send", arguments_digest=digest),
        principal=Principal(
            kind="process",
            uid=1001,
            user_name="build",
            gids=(2001,),
            group_names=("ci",),
            delegated_human=delegated_human,
        ),
    )


def test_an_absent_rule_denies_and_names_policy_absent() -> None:
    """Article 1: a loaded policy without an applying rule fails closed."""
    parsed = parse_policy(_policy())
    assert not isinstance(parsed, PolicyInvalid)
    verdict = evaluate(parsed, _question())
    assert verdict.outcome is Outcome.DENY
    assert verdict.reason is Reason.POLICY_ABSENT
    assert verdict.rule_id is None


def test_the_strictest_applying_rule_wins() -> None:
    """Article 1: deny wins over suspend and allow, preserving file order."""
    parsed = parse_policy(
        _policy(
            _rule("allow-first", "allow"),
            _rule("suspend-first", "suspend"),
            _rule("deny-first", "deny"),
            _rule("deny-second", "deny"),
        )
    )
    assert not isinstance(parsed, PolicyInvalid)
    verdict = evaluate(parsed, _question())
    assert (verdict.outcome, verdict.reason, verdict.rule_id) == (
        Outcome.DENY,
        Reason.POLICY_DENIES,
        "deny-first",
    )


def test_a_rule_bound_to_a_group_name_applies_to_a_member() -> None:
    """Article 6: resolved acting-principal group names take part in matching."""
    parsed = parse_policy(_policy(_rule("ci", "allow", principals='["group:ci"]')))
    assert not isinstance(parsed, PolicyInvalid)
    assert evaluate(parsed, _question()).outcome is Outcome.ALLOW


def test_a_rule_bound_to_the_delegated_human_does_not_apply_to_the_acting_process() -> None:
    """Article 6: delegation evidence never changes the acting principal."""
    parsed = parse_policy(_policy(_rule("human", "allow", principals='["user:alice"]')))
    assert not isinstance(parsed, PolicyInvalid)
    assert evaluate(parsed, _question(delegated_human="alice")).outcome is Outcome.DENY


def test_a_rule_pinned_to_an_arguments_digest_ignores_another_digest() -> None:
    """Article 3: a change of the pinned boundary digest makes the rule inapplicable."""
    parsed = parse_policy(_policy(_rule("pinned", "allow", arguments_digest=DIGEST)))
    assert not isinstance(parsed, PolicyInvalid)
    assert evaluate(parsed, _question()).outcome is Outcome.ALLOW
    assert evaluate(parsed, _question(digest=OTHER_DIGEST)).outcome is Outcome.DENY


def test_an_unknown_outcome_word_refuses_the_file() -> None:
    """Article 1: the policy cannot extend the three decision outcomes."""
    parsed = parse_policy(_policy(_rule("unknown", "permit")))
    assert isinstance(parsed, PolicyInvalid)
    assert parsed.reason == "invalid"
    assert "unknown.outcome" in parsed.message


def test_an_unknown_key_refuses_the_file() -> None:
    """Article 1: policy members are closed and never silently ignored."""
    parsed = parse_policy(_policy(extra='surprise = "no"'))
    assert isinstance(parsed, PolicyInvalid)
    assert parsed.reason == "invalid"
    assert "surprise" in parsed.message


def test_an_unknown_format_refuses_the_file() -> None:
    """Article 3: an unknown authority format is not interpreted."""
    raw = _policy().replace(b"format = 1", b"format = 2")
    parsed = parse_policy(raw)
    assert isinstance(parsed, PolicyInvalid)
    assert parsed.reason == "format_unsupported"


def test_a_non_integer_format_is_unsupported_not_structurally_invalid() -> None:
    """Article 3: every value other than integer one is an unsupported format."""
    parsed = parse_policy(_policy().replace(b"format = 1", b'format = "1"'))
    assert isinstance(parsed, PolicyInvalid)
    assert parsed.reason == "format_unsupported"


def test_policy_capabilities_and_scopes_share_the_public_question_grammar() -> None:
    """Articles 2 and 13: accepted policy rules can be asked by a governed program."""
    dead_capability = parse_policy(
        _policy(_rule("dead-capability", "allow").replace("mail.send", "mail-send"))
    )
    assert isinstance(dead_capability, PolicyInvalid)
    long_scope = "s" * 128
    live_scope = parse_policy(_policy(_rule("long-scope", "allow") + f'\nscope = "{long_scope}"'))
    assert not isinstance(live_scope, PolicyInvalid)


def test_the_policy_version_is_the_digest_of_the_file_bytes() -> None:
    """Article 10: every byte, including whitespace, participates in the version."""
    raw = _policy(_rule("allow", "allow"))
    assert policy_version(raw) == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert policy_version(raw + b"\n") != policy_version(raw)


def test_the_outcome_vocabulary_is_closed_at_three() -> None:
    """Article 1: evaluation uses only the shapes block 2.1 publishes."""
    assert {item.value for item in Outcome} == {"allow", "deny", "suspend"}


def _suspend_rule(rule_id: str, *, wait: str | None = None) -> str:
    member = "" if wait is None else f"\nreview_deadline_seconds = {wait}"
    return _rule(rule_id, "suspend") + member


def test_a_suspend_rule_carries_the_wait_its_file_names() -> None:
    """Article 12: how long a suspended effect waits is the administrator's to set."""
    parsed = parse_policy(_policy(_suspend_rule("waits", wait="60")))
    assert not isinstance(parsed, PolicyInvalid)
    assert parsed.rules[0].review_deadline_seconds == 60


def test_a_suspend_rule_that_names_no_wait_loads_the_default_rather_than_nothing() -> None:
    """Article 2: a rule carries the number it will use, so nothing infers one later."""
    parsed = parse_policy(_policy(_suspend_rule("silent")))
    assert not isinstance(parsed, PolicyInvalid)
    assert parsed.rules[0].review_deadline_seconds == 300


def test_a_rule_that_does_not_suspend_carries_no_wait_at_all() -> None:
    """Article 12: only a suspension waits, so only a suspend rule holds a wait."""
    parsed = parse_policy(_policy(_rule("allows", "allow"), _rule("denies", "deny")))
    assert not isinstance(parsed, PolicyInvalid)
    assert [rule.review_deadline_seconds for rule in parsed.rules] == [None, None]


def test_a_wait_outside_its_bounds_refuses_the_file() -> None:
    """Article 3: a wait of no length and a wait beyond a day are neither of them waits."""
    for value in ("0", "-1", "86401"):
        parsed = parse_policy(_policy(_suspend_rule("waits", wait=value)))
        assert isinstance(parsed, PolicyInvalid)
        assert parsed.reason == "invalid"
        assert "waits.review_deadline_seconds is invalid" in parsed.message


def test_a_wait_that_is_not_a_whole_number_of_seconds_refuses_the_file() -> None:
    """Article 3: a boolean is an integer to Python and never a length of time."""
    for value in ('"60"', "true", "60.5"):
        parsed = parse_policy(_policy(_suspend_rule("waits", wait=value)))
        assert isinstance(parsed, PolicyInvalid)
        assert "waits.review_deadline_seconds is invalid" in parsed.message


def test_a_wait_on_a_rule_that_does_not_suspend_refuses_the_file() -> None:
    """Article 2: a member that could not be honoured is refused, never ignored."""
    for outcome in ("allow", "deny"):
        parsed = parse_policy(
            _policy(_rule("never-waits", outcome) + "\nreview_deadline_seconds = 60")
        )
        assert isinstance(parsed, PolicyInvalid)
        assert "never-waits.review_deadline_seconds is invalid" in parsed.message


def test_a_grant_lifetime_on_a_suspend_rule_is_refused_as_it_always_was() -> None:
    """Article 10: a lifetime belongs to an allow, and the new member changes nothing."""
    parsed = parse_policy(_policy(_suspend_rule("waits") + "\ngrant_lifetime_seconds = 60"))
    assert isinstance(parsed, PolicyInvalid)
    assert "waits.grant_lifetime_seconds is invalid" in parsed.message
