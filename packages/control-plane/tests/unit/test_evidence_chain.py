# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sayfirst_control_plane.domain.evidence_chain import (
    ChainCondition,
    EvidenceEntry,
    EvidenceRecord,
    Grade,
    InvalidEvidence,
    Principal,
    chained,
    chained_after_break,
    entry_to_document,
    entry_verifies,
    preimage,
    verify,
)

NOW = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)
PRINCIPAL = Principal("user", "example")


def effect(*, connection_id: str = "connection-1") -> EvidenceRecord:
    return EvidenceRecord(
        scope="local",
        kind="effect",
        recorded_at=NOW,
        connection_id=connection_id,
        principal=PRINCIPAL,
        body={
            "capability": "example.effect",
            "decision_id": "decision-1",
            "outcome": "allow",
            "decided_at": "2026-09-04T10:00:00Z",
            "policy_version": "policy-1",
        },
    )


def test_the_verifier_refuses_a_chain_with_an_undeclared_gap() -> None:
    """Article 10: a missing sequence is never presented as a clean chain."""
    first = chained(effect(), None)
    second = chained(effect(), first)
    third = chained(effect(), second)
    fourth = chained(effect(), third)
    verdict = verify(
        (first, second, replace(fourth, previous_hash=second.entry_hash)),
        scope="local",
        from_sequence=1,
        grades_before={},
    )
    assert verdict.condition is ChainCondition.gap_at
    assert verdict.sequence == 3
    assert verdict.up_to is None


def test_a_connection_whose_grade_record_is_missing_renders_unverified() -> None:
    """Article 7: the verifier adds no grade that the chain did not record."""
    entry = chained(effect(), None)
    verdict = verify((entry,), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.intact
    assert [(item.connection_id, item.grade) for item in verdict.grades] == [
        ("connection-1", Grade.unverified)
    ]


def test_a_chain_may_not_follow_another_scopes_entry() -> None:
    """Articles 5 and 10: each scope owns an independent chain."""
    first = chained(effect(), None)
    with pytest.raises(ValueError, match="scope"):
        chained(replace(effect(), scope="other"), first)


def test_a_rewritten_entry_is_broken_at_its_own_sequence() -> None:
    first = chained(effect(), None)
    rewritten = replace(first, body={**first.body, "decision_id": "rewritten"})
    verdict = verify((rewritten,), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.broken_at
    assert verdict.sequence == 1
    assert verdict.expected != verdict.found


def test_an_empty_range_is_unverifiable_and_covers_no_entry() -> None:
    verdict = verify((), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.unverifiable
    assert verdict.covers_an_entry is False
    assert verdict.grades == ()


def test_a_declared_gap_is_not_an_undeclared_gap() -> None:
    first = chained(effect(), None)
    second = chained(effect(), first)
    marker = EvidenceRecord(
        "local",
        "gap",
        NOW,
        "daemon",
        Principal("service", "daemon"),
        {
            "reason": "dropped",
            "count": 2,
            "first_at": "2026-09-04T10:00:00Z",
            "last_at": "2026-09-04T10:00:01Z",
            "kinds": {"effect": 2},
        },
    )
    gap = chained(marker, second)
    after = chained(effect(), gap)
    verdict = verify((first, second, gap, after), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.intact
    assert [(item.sequence, item.reason, item.count) for item in verdict.declared_gaps] == [
        (3, "dropped", 2)
    ]


def test_an_unknown_preimage_version_is_a_refusal_never_a_fallback() -> None:
    """Refused, and named as what it is: a recipe this daemon holds no reader for.

    No fallback, and no claim either. `broken_at` is a negative fact about the
    chain and nothing here established one — the entry may be perfectly sound
    under a recipe published later (article 2) — so the range stops being
    checkable at that sequence, names the version, and offers no expectation to
    compare against. The offline verifier in the contract wheel answers the same
    input the same way, and the published vectors are what hold the two apart
    (article 13).
    """
    entry = replace(chained(effect(), None), preimage_version="future/evidence/v2")
    verdict = verify((entry,), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.unverifiable
    assert verdict.sequence == entry.sequence
    assert verdict.version == "future/evidence/v2"
    assert verdict.expected is None
    assert verdict.found == entry.entry_hash


def test_an_instant_outside_the_calendar_is_a_false_verify_and_not_an_overflow() -> None:
    """`entry_verifies` answers a boolean about every entry this daemon can hold.

    An instant at the edge of the calendar with an offset that pushes it past
    the edge raises `OverflowError` out of `astimezone`, and an `OverflowError`
    is an `ArithmeticError` — outside every clause that named `ValueError`. It
    is an instant this recipe cannot render, so the entry does not verify, and
    the range that carries it stops being checkable rather than being reported
    as damaged.
    """
    edge = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    entry = replace(chained(effect(), None), recorded_at=edge)
    assert entry_verifies(entry) is False
    verdict = verify((entry,), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.unverifiable
    assert verdict.sequence == entry.sequence


def test_a_delegation_is_recorded_in_via_and_never_collapsed() -> None:
    delegated = replace(
        effect(),
        principal=Principal(
            "process",
            "runner",
            (Principal("user", "operator"),),
        ),
    )
    document = entry_to_document(chained(delegated, None))
    assert document["principal"] == {
        "kind": "process",
        "id": "runner",
        "via": [{"kind": "user", "id": "operator", "via": []}],
    }
    assert "pid" not in document["principal"]


def test_an_entry_does_not_verify_its_own_hash_at_construction() -> None:
    rewritten = replace(chained(effect(), None), body={**effect().body, "decision_id": "changed"})
    assert rewritten.body["decision_id"] == "changed"


def test_a_genesis_naming_a_predecessor_is_refused() -> None:
    with pytest.raises(ValueError, match="genesis"):
        replace(chained(effect(), None), previous_hash="0" * 64)


def test_a_later_entry_naming_no_predecessor_is_refused() -> None:
    first = chained(effect(), None)
    with pytest.raises(ValueError, match="predecessor"):
        replace(chained(effect(), first), previous_hash=None)


def test_a_hash_that_is_not_a_lowercase_digest_is_refused() -> None:
    with pytest.raises(ValueError, match="lowercase"):
        replace(chained(effect(), None), entry_hash="A" * 64)


def test_a_predecessor_that_does_not_recompute_is_refused() -> None:
    """G9: a writer cannot continue from an entry whose own hash is not its content.

    Moving an entry past its proper place is one way to produce one: the
    sequence is part of the preimage, so the stored hash no longer recomputes.
    What refuses it is the predecessor-hash check, not a check on the sequence,
    and the message says so.
    """
    first = chained(effect(), None)
    second = chained(effect(), first)
    skipped = replace(second, sequence=second.sequence + 2)
    with pytest.raises(ValueError, match="predecessor hash"):
        chained(effect(), skipped)
    assert entry_verifies(second) is True
    assert entry_verifies(skipped) is False


def test_a_recomputed_hash_breaks_the_link_at_the_next_sequence() -> None:
    first = chained(effect(), None)
    original_second = chained(effect(), first)
    third = chained(effect(), original_second)
    rewritten_second = chained(
        replace(effect(), body={**effect().body, "decision_id": "changed"}),
        first,
    )
    verdict = verify(
        (first, rewritten_second, third),
        scope="local",
        from_sequence=1,
        grades_before={},
    )
    assert verdict.condition is ChainCondition.broken_at
    assert verdict.sequence == 3


def test_sequence_gaps_are_checked_before_entry_hashes() -> None:
    first = chained(effect(), None)
    second = chained(effect(), first)
    third = chained(effect(), second)
    rewritten_first = replace(first, body={**first.body, "decision_id": "rewritten"})
    verdict = verify(
        (rewritten_first, third),
        scope="local",
        from_sequence=1,
        grades_before={},
    )
    assert verdict.condition is ChainCondition.gap_at
    assert verdict.sequence == 2


def test_entry_hashes_are_checked_before_links() -> None:
    first = chained(effect(), None)
    second = chained(effect(), first)
    third = chained(effect(), second)
    wrong_link = "f" * 64
    relinked_second = replace(
        second,
        previous_hash=wrong_link,
        entry_hash=hashlib.sha256(
            preimage(
                scope=second.scope,
                sequence=second.sequence,
                kind=second.kind,
                recorded_at=second.recorded_at,
                connection_id=second.connection_id,
                principal=second.principal,
                body=second.body,
                previous_hash=wrong_link,
            )
        ).hexdigest(),
    )
    rewritten_third = replace(third, body={**third.body, "decision_id": "rewritten"})
    verdict = verify(
        (first, relinked_second, rewritten_third),
        scope="local",
        from_sequence=1,
        grades_before={},
    )
    assert verdict.condition is ChainCondition.broken_at
    assert verdict.sequence == 3


def test_a_deletion_at_the_head_of_the_asked_range_is_a_gap() -> None:
    first = chained(effect(), None)
    second = chained(effect(), first)
    verdict = verify((second,), scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.gap_at
    assert verdict.sequence == 1


def test_a_mixed_scope_range_refuses() -> None:
    first = chained(effect(), None)
    other = replace(first, scope="other")
    with pytest.raises(InvalidEvidence, match="another scope"):
        verify((first, other), scope="local", from_sequence=1, grades_before={})


def test_a_verdict_carries_the_weakest_grade_of_the_period() -> None:
    observed = EvidenceRecord(
        "local",
        "grade",
        NOW,
        "connection-1",
        PRINCIPAL,
        {
            "grade": "observability",
            "basis": "caller_can_write",
            "evaluated_at": "2026-09-04T10:00:00Z",
            "paths_inspected": 2,
        },
    )
    lowered = replace(
        observed,
        body={
            **observed.body,
            "grade": "unverified",
            "basis": "caller_cannot_write",
        },
    )
    first = chained(observed, None)
    second = chained(effect(), first)
    third = chained(lowered, second)
    fourth = chained(effect(), third)
    verdict = verify(
        (first, second, third, fourth),
        scope="local",
        from_sequence=1,
        grades_before={},
    )
    assert verdict.grades[0].grade is Grade.unverified


def test_a_verdict_excludes_grades_past_its_first_failure() -> None:
    first = chained(effect(), None)
    second = chained(effect(connection_id="untrusted-tail"), first)
    rewritten_first = replace(first, body={**first.body, "decision_id": "rewritten"})
    verdict = verify(
        (rewritten_first, second),
        scope="local",
        from_sequence=1,
        grades_before={},
    )
    assert verdict.condition is ChainCondition.broken_at
    assert verdict.sequence == 1
    assert verdict.grades == ()


def _chain(length: int) -> tuple[EvidenceEntry, ...]:
    entries: list[EvidenceEntry] = []
    for _ in range(length):
        entries.append(chained(effect(), entries[-1] if entries else None))
    return tuple(entries)


def test_a_missing_tail_of_the_asked_range_is_a_gap() -> None:
    """Article 10: a gap is declared or the chain is not intact, wherever the hole falls."""
    entries = _chain(3)[:2]
    verdict = verify(
        entries,
        scope="local",
        from_sequence=1,
        to_sequence=3,
        grades_before={},
    )
    assert verdict.condition is ChainCondition.gap_at
    assert verdict.sequence == 3
    assert verdict.up_to is None


def test_an_asked_range_the_store_answers_with_nothing_is_a_gap_not_an_absence() -> None:
    """Article 2: an absence the store cannot explain is never rendered as a clean range."""
    verdict = verify((), scope="local", from_sequence=2, to_sequence=4, grades_before={})
    assert verdict.condition is ChainCondition.gap_at
    assert verdict.sequence == 2
    assert verdict.covers_an_entry is False


def test_a_range_asked_without_an_end_still_verifies_what_it_covers() -> None:
    """Article 10: a caller that names no end asserts no end, so a short answer is intact."""
    verdict = verify(_chain(3)[:2], scope="local", from_sequence=1, grades_before={})
    assert verdict.condition is ChainCondition.intact
    assert verdict.up_to == 2


def test_a_continuation_after_a_break_may_not_cross_a_scope() -> None:
    """Article 5: recovering a damaged chain never merges two scopes."""
    first = chained(effect(), None)
    other = EvidenceRecord(**{**effect().__dict__, "scope": "elsewhere"})
    with pytest.raises(ValueError, match="another scope"):
        chained_after_break(other, first)


def test_a_torn_gap_that_names_a_kind_is_refused() -> None:
    """Article 2: a record that never completed has no kind to claim."""
    body = {
        "reason": "torn",
        "count": 1,
        "first_at": "2026-09-04T10:00:00Z",
        "last_at": "2026-09-04T10:00:00Z",
        "kinds": {"effect": 1},
    }
    with pytest.raises(ValueError, match="torn gap names no kind"):
        EvidenceRecord(
            scope="local",
            kind="gap",
            recorded_at=NOW,
            connection_id="daemon",
            principal=PRINCIPAL,
            body=body,
        )
    EvidenceRecord(
        scope="local",
        kind="gap",
        recorded_at=NOW,
        connection_id="daemon",
        principal=PRINCIPAL,
        body={**body, "kinds": {}},
    )


def test_a_dropped_gap_still_accounts_for_every_record_it_names() -> None:
    """Article 10: the relaxation is for a torn record only, not for a drop."""
    with pytest.raises(ValueError, match="kind counts"):
        EvidenceRecord(
            scope="local",
            kind="gap",
            recorded_at=NOW,
            connection_id="daemon",
            principal=PRINCIPAL,
            body={
                "reason": "dropped",
                "count": 2,
                "first_at": "2026-09-04T10:00:00Z",
                "last_at": "2026-09-04T10:00:00Z",
                "kinds": {"effect": 1},
            },
        )


# -- block 2.7: the copied decision facts, the recovery kind, the named losses --


def _new_writer_effect_body() -> dict[str, object]:
    return {
        "capability": "example.effect",
        "decision_id": "decision-1",
        "outcome": "allow",
        "decided_at": "2026-09-04T00:00:00Z",
        "policy_version": "sha256:" + "a" * 64,
        "reason": "policy_allows",
        "rule_id": "rule-0",
        "arguments_digest": None,
        "correlation": "corr-1",
        "correlation_source": "boundary_supplied",
        "principal_references": ["group:ops", "user:alice"],
        "evaluation_recipe": "sayfirst/policy-evaluation/v1",
        "decision_position": {"store_id": "store-1", "position": 1},
        "recording_epoch": "epoch-1",
    }


def test_an_effect_record_carries_the_copied_decision_facts_inside_its_hashed_body() -> None:
    """M1: the facts sit in the body, so the preimage recipe hashes them."""
    record = EvidenceRecord(
        "local",
        "effect",
        datetime(2026, 9, 4, tzinfo=UTC),
        "connection-1",
        Principal("user", "alice"),
        _new_writer_effect_body(),
    )
    entry = chained(record, None)
    assert entry.body["reason"] == "policy_allows"
    assert entry.body["decision_position"] == {"store_id": "store-1", "position": 1}
    without = {**_new_writer_effect_body(), "rule_id": "rule-9"}
    other = chained(replace(record, body=without), None)
    assert other.entry_hash != entry.entry_hash


@pytest.mark.parametrize(
    "broken",
    [
        {"correlation_source": "guessed"},
        {"principal_references": ["alice"]},
        {"principal_references": ["user:b", "user:a"]},
        {"decision_position": {"store_id": "", "position": 1}},
        {"reason": "policy_hoped"},
        {"arguments_digest": "md5:abc"},
    ],
)
def test_a_copied_fact_outside_its_published_shape_is_refused(broken: dict) -> None:
    with pytest.raises(ValueError):
        EvidenceRecord(
            "local",
            "effect",
            datetime(2026, 9, 4, tzinfo=UTC),
            "connection-1",
            Principal("user", "alice"),
            {**_new_writer_effect_body(), **broken},
        )


def test_a_recovery_marker_is_a_kind_of_its_own() -> None:
    record = EvidenceRecord(
        "local",
        "recovery",
        datetime(2026, 9, 4, tzinfo=UTC),
        "daemon",
        Principal("service", "daemon"),
        {
            "event": "unclean_stop",
            "epoch_id": "epoch-1",
            "from_sequence": 1,
            "through_sequence": 3,
            "lost_event_count": None,
            "possibly_lost_kinds": ["effect", "grade", "composition", "gap"],
            "coverage": "unknown",
            "recording_epoch": "recovery:epoch-1",
        },
    )
    assert chained(record, None).kind == "recovery"
    with pytest.raises(ValueError):
        EvidenceRecord(
            "local",
            "recovery",
            datetime(2026, 9, 4, tzinfo=UTC),
            "daemon",
            Principal("service", "daemon"),
            {"event": "vanished", "epoch_id": "e", "from_sequence": 1, "through_sequence": 1},
        )


def test_an_unflushed_gap_names_its_decisions_by_identity_and_position() -> None:
    """C4: a known-decision loss is declared by identity, paired one to one, sorted by position."""
    body = {
        "reason": "unflushed",
        "count": 2,
        "first_at": "2026-09-04T00:00:00Z",
        "last_at": "2026-09-04T00:00:00Z",
        "kinds": {"effect": 2},
        "decision_ids": ["decision-1", "decision-2"],
        "decision_positions": [
            {"store_id": "store-1", "position": 1},
            {"store_id": "store-1", "position": 2},
        ],
        "accounting": "decision",
        "recording_epoch": "epoch-1",
    }
    record = EvidenceRecord(
        "local",
        "gap",
        datetime(2026, 9, 4, tzinfo=UTC),
        "daemon",
        Principal("service", "daemon"),
        body,
    )
    assert chained(record, None).body["decision_ids"] == ["decision-1", "decision-2"]
    for broken in (
        {"decision_positions": body["decision_positions"][:1]},
        {"count": 1},
        {"decision_positions": list(reversed(body["decision_positions"]))},
    ):
        with pytest.raises(ValueError):
            EvidenceRecord(
                "local",
                "gap",
                datetime(2026, 9, 4, tzinfo=UTC),
                "daemon",
                Principal("service", "daemon"),
                {**body, **broken},
            )


def test_the_reasons_an_effect_may_copy_are_the_reasons_the_contract_publishes() -> None:
    """Article 13: one reason vocabulary, and a second spelling held equal to it.

    This module keeps its own spelling of the published enumeration rather than
    importing one, the way it keeps its own spelling of the evaluation recipe.
    A second spelling drifts unless something holds it, and the drift is not
    cosmetic: a reason the contract publishes and this validator does not know
    is a decision the daemon takes and cannot write onto its own chain.
    """
    from sayfirst_contract.decisions import Reason
    from sayfirst_control_plane.domain.evidence_chain import _REASONS

    assert {item.value for item in Reason} == _REASONS


def test_an_effect_may_copy_the_reason_a_granted_approval_decided() -> None:
    """Article 12: a suspension a person approved is recorded as the allow it became."""
    for reason, outcome in (("approval_granted", "allow"), ("approval_rejected", "deny")):
        body = {**_new_writer_effect_body(), "reason": reason, "outcome": outcome}
        entry = chained(
            EvidenceRecord(
                "local",
                "effect",
                datetime(2026, 9, 4, tzinfo=UTC),
                "connection-1",
                Principal("user", "alice"),
                body,
            ),
            None,
        )
        assert entry.body["reason"] == reason
