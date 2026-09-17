# SPDX-License-Identifier: Apache-2.0
"""Articles 2, 10, 13, 14: the complete offline verifier, from the contract wheel alone.

`verify_export(bundle)` holds only the export and this wheel. It recomputes
every hash, recomputes its manifest digest under the recipe the bundle names, checks
the policy bytes the bundle carries against the versions the effects name,
re-derives every trusted effect through `retrospective_policy`, and says what
it covered. Nothing here imports a server, and the bundles are built by the
recipes this module publishes, so a server that disagrees with one of them has
a defect of its own to find (article 13).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.evidence import (
    MANIFEST_V1,
    MANIFEST_V2,
    MANIFEST_V3,
    ArchiveState,
    ChainCondition,
    Rederivation,
    canonical_json,
    chained_document,
    entry_hash_of,
    entry_verifies,
    manifest_hash,
    preimage,
    verify_chain,
    verify_export,
)

POLICY = (
    b'format = 1\n[revision]\nreason = "verifier"\n'
    b'[[rule]]\nid = "scenario-0"\ncapability = "example.effect"\nscope = "local"\n'
    b'principals = ["user:alice"]\noutcome = "allow"\nreason = "the allow rule"\n'
)
VERSION = "sha256:" + hashlib.sha256(POLICY).hexdigest()
OTHER_POLICY = POLICY.replace(b'outcome = "allow"', b'outcome = "deny"')
OTHER_VERSION = "sha256:" + hashlib.sha256(OTHER_POLICY).hexdigest()
AT = "2026-09-05T10:00:00Z"
PRINCIPAL = {"kind": "user", "id": "alice", "via": []}
DAEMON = {"kind": "service", "id": "daemon", "via": []}


def _record(kind: str, body: Mapping[str, object], *, connection: str = "connection-1") -> dict:
    return {
        "scope": "local",
        "kind": kind,
        "recorded_at": AT,
        "connection_id": connection,
        "principal": DAEMON if connection == "daemon" else PRINCIPAL,
        "body": dict(body),
    }


def _effect(decision_id: str = "decision-1", **overrides: object) -> dict:
    body: dict[str, object] = {
        "capability": "example.effect",
        "decision_id": decision_id,
        "outcome": "allow",
        "decided_at": AT,
        "policy_version": VERSION,
        "reason": "policy_allows",
        "rule_id": "scenario-0",
        "arguments_digest": None,
        "correlation": "gate-1",
        "correlation_source": "boundary_supplied",
        "principal_references": ["user:alice"],
        "evaluation_recipe": "sayfirst/policy-evaluation/v1",
        "decision_position": {"store_id": "store-a", "position": 1},
    }
    body.update(overrides)
    return _record("effect", body)


def _grade(connection: str = "connection-1") -> dict:
    return _record(
        "grade",
        {
            "grade": "observability",
            "basis": "caller_can_write",
            "evaluated_at": AT,
            "paths_inspected": 3,
        },
        connection=connection,
    )


def _composition() -> dict:
    return _record("composition", {"providers": []}, connection="daemon")


def _clean_stop(epoch: str, from_sequence: int, through_sequence: int) -> dict:
    return _record(
        "recovery",
        {
            "event": "clean_stop",
            "epoch_id": epoch,
            "from_sequence": from_sequence,
            "through_sequence": through_sequence,
        },
        connection="daemon",
    )


def _unclean_stop(epoch: str, from_sequence: int, through_sequence: int) -> dict:
    return _record(
        "recovery",
        {
            "event": "unclean_stop",
            "epoch_id": epoch,
            "from_sequence": from_sequence,
            "through_sequence": through_sequence,
            "lost_event_count": None,
            "possibly_lost_kinds": ["effect", "grade", "composition", "gap"],
            "coverage": "unknown",
        },
        connection="daemon",
    )


def _chain(*records: Mapping[str, object]) -> list[dict]:
    entries: list[dict] = []
    for record in records:
        entries.append(chained_document(record, entries[-1] if entries else None))
    return entries


def _bundle(
    entries: list[dict],
    *,
    from_sequence: int = 1,
    to_sequence: int | None = None,
    policies: Mapping[str, Mapping[str, object]] | None = None,
    context: list[dict] | None = None,
    next_from: int | None = None,
) -> dict:
    included = [
        item
        for item in entries
        if item["sequence"] >= from_sequence
        and (to_sequence is None or item["sequence"] <= to_sequence)
    ]
    verdict = verify_chain(
        included,
        scope="local",
        from_sequence=from_sequence,
        to_sequence=to_sequence
        if to_sequence is not None
        else (included[-1]["sequence"] if included else None),
    )
    if policies is None:
        policies = {VERSION: {"state": "present", "content": base64.b64encode(POLICY).decode()}}
    bundle: dict[str, object] = {
        "contract_version": "1",
        "scope": "local",
        "from_sequence": from_sequence,
        "to_sequence": included[-1]["sequence"] if included else None,
        "entry_count": len(included),
        "entries": included,
        "verification": verdict.to_document(),
        "next_from": next_from,
        "manifest_version": MANIFEST_V3,
        "policy_versions": dict(policies),
        "recovery_context": [] if context is None else context,
    }
    bundle["manifest_hash"] = manifest_hash(bundle, version=MANIFEST_V3)
    return bundle


def _closed_epoch() -> list[dict]:
    """One daemon life: composition, a graded effect, then a clean stop."""
    entries = _chain(_composition(), _grade(), _effect())
    return _chain(
        _composition(), _grade(), _effect(), _clean_stop("epoch-1", 1, entries[-1]["sequence"])
    )


def valid_bundle() -> dict:
    """The bundle every malformed one below is a single mutation of."""
    return _bundle(_closed_epoch())


def vector_entries() -> list[dict]:
    """A short chain of three of the published kinds, each verifying as it stands."""
    return _chain(_composition(), _grade(), _effect())


def vector_entry() -> dict:
    return vector_entries()[0]


def _with_entry(bundle: dict, index: int, members: Mapping[str, object]) -> dict:
    """The same bundle with one member replaced on one entry, and nothing else moved."""
    entries = list(bundle["entries"])
    entries[index] = {**entries[index], **members}
    return bundle | {"entries": entries}


def _connections(entries: Sequence[Mapping[str, object]]) -> list[str]:
    """The connections a verdict graded over these entries, in the order it reports them."""
    return sorted({str(entry["connection_id"]) for entry in entries})


# -- recipes ---------------------------------------------------------------


def test_the_preimage_vectors_reproduce_from_the_installed_wheel() -> None:
    """Article 13: the normative preimage vectors are read from the wheel and recompute."""
    document = load_json("domain", "evidence-preimage-v1.json")
    assert isinstance(document, dict) and len(document["vectors"]) >= 2
    for vector in document["vectors"]:
        raw = preimage(
            scope=vector["scope"],
            sequence=vector["sequence"],
            kind=vector["kind"],
            recorded_at=vector["recorded_at"],
            connection_id=vector["connection_id"],
            principal=vector["principal"],
            body=vector["body"],
            previous_hash=vector["previous_hash"],
        )
        assert raw.hex() == vector["preimage_hex"]
        assert hashlib.sha256(raw).hexdigest() == vector["digest"]


def test_every_manifest_recipe_vector_recomputes_and_only_under_its_own_version() -> None:
    """Article 13: v1, v2 and v3 are three recipes, each pinned by vectors."""
    document = load_json("domain", "evidence-export-manifest-vectors.json")
    assert isinstance(document, dict)
    versions = {vector["manifest_version"] for vector in document["vectors"]}
    assert versions == {MANIFEST_V1, MANIFEST_V2, MANIFEST_V3}
    for vector in document["vectors"]:
        bundle = vector["bundle"]
        assert manifest_hash(bundle, version=vector["manifest_version"]) == vector["manifest_hash"]
        others = versions - {vector["manifest_version"]}
        assert all(
            manifest_hash(bundle, version=other) != vector["manifest_hash"] for other in others
        )


def test_the_v3_manifest_binds_the_availability_states_and_the_context() -> None:
    """Article 10: a claim of `absent` moves the digest; v2 left it outside the number."""
    bundle = _bundle(_closed_epoch())
    weakened = dict(bundle)
    weakened["policy_versions"] = {VERSION: {"state": "absent"}}
    assert manifest_hash(weakened, version=MANIFEST_V3) != bundle["manifest_hash"]
    assert manifest_hash(weakened, version=MANIFEST_V2) == manifest_hash(
        bundle, version=MANIFEST_V2
    )
    with_context = {**bundle, "recovery_context": [dict(bundle["entries"][0])]}
    assert manifest_hash(with_context, version=MANIFEST_V3) != bundle["manifest_hash"]


def test_an_entry_hash_recomputes_and_a_changed_body_does_not() -> None:
    entries = _chain(_composition(), _effect())
    assert all(entry_verifies(item) for item in entries)
    forged = {**entries[1], "body": {**entries[1]["body"], "outcome": "deny"}}
    assert entry_hash_of(forged) != forged["entry_hash"]
    assert not entry_verifies(forged)


def test_an_instant_outside_the_calendar_is_a_false_verify_and_not_an_overflow() -> None:
    """`entry_verifies` answers a boolean about every entry, including this one.

    An instant at the edge of the calendar with an offset that pushes it past
    the edge raises `OverflowError` out of `astimezone`, and an `OverflowError`
    is an `ArithmeticError` — outside every clause here that named `ValueError`.
    It is an instant this recipe cannot render, so the entry does not verify.
    """
    entry = dict(vector_entry(), recorded_at="0001-01-01T00:00:00+01:00")
    assert entry_verifies(entry) is False


def test_canonical_json_is_the_published_form() -> None:
    assert canonical_json({"b": 1, "a": [1, "é"]}) == b'{"a":[1,"\\u00e9"],"b":1}'


# -- the chain half of the verdict -------------------------------------------


def test_an_offline_range_beginning_after_one_carries_no_prefix_grade() -> None:
    """Article 7 through V1: the verifier adds nothing; a missing grade record is unverified."""
    entries = _chain(_composition(), _grade(), _effect("decision-1"), _effect("decision-2"))
    whole = verify_chain(entries, scope="local", from_sequence=1, to_sequence=4)
    assert whole.condition is ChainCondition.intact
    assert {item.connection_id: item.grade for item in whole.grades} == {
        "connection-1": "observability",
        "daemon": "unverified",
    }
    partial = verify_chain(entries[3:], scope="local", from_sequence=4, to_sequence=4)
    assert partial.condition is ChainCondition.intact
    assert {item.connection_id: item.grade for item in partial.grades} == {
        "connection-1": "unverified"
    }


def test_a_removed_entry_is_a_gap_and_a_rewritten_one_a_break() -> None:
    entries = _chain(_composition(), _grade(), _effect("decision-1"), _effect("decision-2"))
    holed = [item for item in entries if item["sequence"] != 3]
    assert (
        verify_chain(holed, scope="local", from_sequence=1, to_sequence=4).condition
        is ChainCondition.gap_at
    )
    rewritten = list(entries)
    rewritten[2] = {**entries[2], "body": {**entries[2]["body"], "outcome": "deny"}}
    verdict = verify_chain(rewritten, scope="local", from_sequence=1, to_sequence=4)
    assert (verdict.condition, verdict.sequence) == (ChainCondition.broken_at, 3)


# -- verify_export ----------------------------------------------------------


def test_a_recipe_this_wheel_cannot_recompute_is_unverifiable_and_names_the_version() -> None:
    """Nothing was found wrong with the entry; the verifier could not check it.

    `broken_at` is a negative fact about the chain, and this verifier
    established none: the entry may be perfectly sound under a recipe published
    later (article 2). So the range stops being checkable at that sequence and
    says so, naming the version it does not hold, and the entries before it stay
    the ones a reader may trust.
    """
    entries = list(vector_entries())
    entries[1] = dict(entries[1], preimage_version="sayfirst-control-plane/evidence/v2")
    verdict = verify_chain(entries, scope="local", from_sequence=1)
    assert verdict.condition is ChainCondition.unverifiable
    assert verdict.sequence == 2
    assert verdict.version == "sayfirst-control-plane/evidence/v2"
    assert verdict.expected is None and verdict.found is not None
    assert [grade.connection_id for grade in verdict.grades] == _connections(entries[:1])


def test_entries_out_of_order_are_a_verdict_of_this_verifier_and_not_a_raise() -> None:
    """A bundle's content is never the caller's argument error (articles 1 and 2).

    `verify_export` never reaches this check with a reversed list — the bundle's
    `to_sequence` then names no entry it carries, and the existing guard refuses
    it earlier — so calling the published function directly is the only way to
    reach the line, and the line is a behaviour of that function that stopped
    raising. The range is not the one that was asked for and cannot be checked
    as one, which establishes nothing and is not damage found.
    """
    entries = list(reversed(vector_entries()))
    verdict = verify_chain(entries, scope="local", from_sequence=1)
    assert verdict.condition is ChainCondition.unverifiable
    assert verdict.sequence is None
    assert verdict.grades == ()
    assert verdict.up_to is None


def test_a_closed_epoch_with_its_policy_is_confirmed_and_names_the_decision() -> None:
    """H1 through H3: the named record, actually evaluated, under its recorded recipe."""
    verdict = verify_export(_bundle(_closed_epoch()))
    assert verdict.overall is Rederivation.confirmed, verdict
    assert verdict.issues == ()
    assert verdict.coverage == "complete"
    assert verdict.rederived_decision_ids == ("decision-1",)
    assert verdict.confirmed_decision_ids == ("decision-1",)
    assert verdict.declared_missing_decision_ids == ()
    assert verdict.evaluation_recipes == ("sayfirst/policy-evaluation/v1",)
    assert verdict.policy_versions == {VERSION: ArchiveState.present}
    assert verdict.manifest_version == MANIFEST_V3
    assert verdict.manifest_hash_recomputes is True
    assert verdict.chain is not None and verdict.chain.condition is ChainCondition.intact
    assert (verdict.from_sequence, verdict.to_sequence, verdict.next_from) == (1, 4, None)
    document = verdict.to_document()
    assert json.loads(json.dumps(document)) == document


def test_a_contradicted_answer_differs_and_stays_visible_beside_an_unverifiable_one() -> None:
    """H3: `differs` wins over an unverifiable sibling; missing data hides no contradiction."""
    entries = _chain(
        _composition(),
        _grade(),
        _effect("decision-1", outcome="deny", reason="policy_denies"),
        _effect("decision-2", policy_version=OTHER_VERSION),
    )
    entries = _chain(
        *entries[:0],
        _composition(),
        _grade(),
        _effect("decision-1", outcome="deny", reason="policy_denies"),
        _effect("decision-2", policy_version=OTHER_VERSION),
    )
    entries = _chain(
        _composition(),
        _grade(),
        _effect("decision-1", outcome="deny", reason="policy_denies"),
        _effect("decision-2", policy_version=OTHER_VERSION),
        _clean_stop("epoch-1", 1, 4),
    )
    policies = {
        VERSION: {"state": "present", "content": base64.b64encode(POLICY).decode()},
        OTHER_VERSION: {"state": "absent"},
    }
    verdict = verify_export(_bundle(entries, policies=policies))
    assert verdict.overall is Rederivation.differs
    by_id = {item.decision_id: item for item in verdict.rederivations}
    assert by_id["decision-1"].verdict is Rederivation.differs
    assert by_id["decision-1"].expected == ("allow", "policy_allows", "scenario-0")
    assert by_id["decision-2"].verdict is Rederivation.unverifiable
    assert by_id["decision-2"].cause == "policy_absent"
    assert verdict.rederived_decision_ids == ("decision-1",)
    assert verdict.confirmed_decision_ids == ()


@pytest.mark.parametrize(
    ("state", "cause"),
    [
        ({"state": "absent"}, "policy_absent"),
        ({"state": "damaged"}, "policy_damaged"),
        ({"state": "unknown"}, "policy_state_unknown"),
        (
            {"state": "present", "content": base64.b64encode(OTHER_POLICY).decode()},
            "policy_damaged",
        ),
        (
            {"state": "present", "content": base64.b64encode(b"format = [").decode()},
            "policy_damaged",
        ),
    ],
)
def test_a_version_without_usable_bytes_is_unverifiable_never_evaluated_against_other_bytes(
    state: dict, cause: str
) -> None:
    """A2, A3, V5: missing or damaged bytes change nothing about the chain and confirm nothing."""
    verdict = verify_export(_bundle(_closed_epoch(), policies={VERSION: state}))
    assert verdict.overall is Rederivation.unverifiable
    assert verdict.rederivations[0].cause == cause
    assert verdict.chain is not None and verdict.chain.condition is ChainCondition.intact
    assert verdict.rederived_decision_ids == ()


def test_bytes_that_parse_but_do_not_match_their_key_are_damaged() -> None:
    """A5: content is checked against the version it claims to be, never taken on trust."""
    unparseable_but_right_key = {
        VERSION: {"state": "present", "content": base64.b64encode(b"format = [").decode()}
    }
    verdict = verify_export(_bundle(_closed_epoch(), policies=unparseable_but_right_key))
    assert verdict.rederivations[0].cause == "policy_damaged"
    unparseable_under_its_own_key = "sha256:" + hashlib.sha256(b"format = [").hexdigest()
    entries = _chain(
        _composition(),
        _grade(),
        _effect(policy_version=unparseable_under_its_own_key),
        _clean_stop("e", 1, 3),
    )
    verdict = verify_export(
        _bundle(
            entries,
            policies={
                unparseable_under_its_own_key: {
                    "state": "present",
                    "content": base64.b64encode(b"format = [").decode(),
                }
            },
        )
    )
    assert verdict.rederivations[0].cause == "policy_unparseable"


def test_a_missing_required_policy_key_is_never_a_successful_empty_map() -> None:
    verdict = verify_export(_bundle(_closed_epoch(), policies={}))
    assert "policy_map_incomplete" in verdict.issues
    assert verdict.overall is Rederivation.unverifiable
    assert verdict.rederivations[0].cause == "policy_absent"


def test_a_historical_effect_without_the_new_members_reaches_members_absent() -> None:
    """Article 13: an old body is admitted and reported, never refused as malformed."""
    old = _record(
        "effect",
        {
            "capability": "example.effect",
            "decision_id": "old-1",
            "outcome": "allow",
            "decided_at": AT,
            "policy_version": VERSION,
        },
    )
    entries = _chain(_composition(), _grade(), old, _clean_stop("e", 1, 3))
    verdict = verify_export(_bundle(entries))
    assert "bundle_invalid" not in verdict.issues
    assert verdict.rederivations[0].cause == "members_absent"
    assert verdict.rederivations[0].evaluation_recipe is None
    assert verdict.overall is Rederivation.unverifiable


@pytest.mark.parametrize(
    ("override", "cause"),
    [
        ({"evaluation_recipe": "sayfirst/policy-evaluation/v9"}, "evaluation_recipe_unsupported"),
        (
            {"reason": "capability_unknown", "outcome": "deny", "rule_id": None},
            "reason_outside_recipe",
        ),
    ],
)
def test_an_unknown_recipe_or_a_reason_outside_it_is_unverifiable_never_differs(
    override: dict, cause: str
) -> None:
    """V4 rule 5: a fabricated disagreement is the claim article 2 forbids."""
    entries = _chain(_composition(), _grade(), _effect(**override), _clean_stop("e", 1, 3))
    verdict = verify_export(_bundle(entries))
    assert verdict.rederivations[0].cause == cause
    assert verdict.overall is Rederivation.unverifiable
    assert verdict.rederived_decision_ids == ()


def test_a_tampered_entry_is_untrusted_and_the_manifest_no_longer_recomputes() -> None:
    bundle = _bundle(_closed_epoch())
    entries = [dict(item) for item in bundle["entries"]]
    entries[2] = {
        **entries[2],
        "body": {**entries[2]["body"], "reason": "policy_denies", "outcome": "deny"},
    }
    tampered = {**bundle, "entries": entries}
    verdict = verify_export(tampered)
    assert verdict.manifest_hash_recomputes is False
    assert "manifest_mismatch" in verdict.issues
    assert "chain_damaged" in verdict.issues
    assert verdict.chain is not None and verdict.chain.condition is ChainCondition.broken_at
    assert verdict.rederivations[0].cause == "entry_untrusted"
    assert verdict.overall is Rederivation.unverifiable


def test_a_manifest_recipe_the_wheel_does_not_know_is_reported_not_guessed() -> None:
    bundle = {
        **_bundle(_closed_epoch()),
        "manifest_version": "sayfirst-control-plane/evidence-export/v9",
    }
    verdict = verify_export(bundle)
    assert verdict.manifest_hash_recomputes is None
    assert "manifest_recipe_unsupported" in verdict.issues
    assert verdict.overall is Rederivation.unverifiable


def test_a_legacy_bundle_without_a_manifest_version_is_tried_against_both_old_recipes() -> None:
    """Article 13: historical absence of the new members is not malformed new evidence."""
    entries = _chain(_composition(), _grade(), _effect())
    verdict_document = verify_chain(
        entries, scope="local", from_sequence=1, to_sequence=3
    ).to_document()
    legacy = {
        "contract_version": "1",
        "scope": "local",
        "from_sequence": 1,
        "to_sequence": 3,
        "entry_count": 3,
        "entries": entries,
        "verification": verdict_document,
        "next_from": None,
    }
    for version in (MANIFEST_V1, MANIFEST_V2):
        legacy["manifest_hash"] = manifest_hash(legacy, version=version)
        verdict = verify_export(legacy)
        assert verdict.manifest_version == version
        assert verdict.manifest_hash_recomputes is True
        assert "manifest_mismatch" not in verdict.issues
        # No policy map at all: the effect cannot be re-derived, and says why.
        assert verdict.rederivations[0].cause == "policy_absent"
        assert "policy_map_incomplete" in verdict.issues
    legacy["manifest_hash"] = "0" * 64
    verdict = verify_export(legacy)
    assert verdict.manifest_version is None
    assert verdict.manifest_hash_recomputes is False
    assert "manifest_mismatch" in verdict.issues


def test_coverage_is_unknown_while_the_epoch_has_no_verified_closure() -> None:
    """C3, H2: an intact chain of surviving decisions is not complete evidence."""
    entries = _chain(_composition(), _grade(), _effect())
    verdict = verify_export(_bundle(entries))
    assert verdict.coverage == "unknown"
    assert "coverage_unknown" in verdict.issues
    assert verdict.rederivations[0].verdict is Rederivation.confirmed
    assert verdict.rederived_decision_ids == ("decision-1",)
    assert verdict.overall is Rederivation.unverifiable


def test_a_closure_marker_supplied_as_context_completes_the_range() -> None:
    """The context is supporting evidence: it links, verifies, and adds no coverage of its own."""
    entries = _closed_epoch()
    verdict = verify_export(_bundle(entries, to_sequence=3, context=[entries[3]]))
    assert verdict.coverage == "complete"
    assert verdict.overall is Rederivation.confirmed
    assert verdict.to_sequence == 3
    # The context's entries are never counted as re-derived decisions.
    later = _chain(*[dict(item) for item in ()])
    del later
    entries_with_effect_after = _chain(
        _composition(),
        _grade(),
        _effect("decision-1"),
        _effect("decision-2"),
        _clean_stop("e", 1, 4),
    )
    verdict = verify_export(
        _bundle(entries_with_effect_after, to_sequence=3, context=entries_with_effect_after[3:])
    )
    assert verdict.rederived_decision_ids == ("decision-1",)
    assert verdict.coverage == "complete"


def test_a_context_that_does_not_link_leaves_coverage_unknown() -> None:
    entries = _closed_epoch()
    forged = {**entries[3], "previous_hash": "1" * 64}
    verdict = verify_export(_bundle(entries, to_sequence=3, context=[forged]))
    assert "recovery_context_unverified" in verdict.issues
    assert verdict.coverage == "unknown"
    assert verdict.overall is Rederivation.unverifiable


def test_an_unclean_stop_lowers_every_connection_of_its_epoch_and_leaves_coverage_unknown() -> None:
    """C3: a lost grade downgrade cannot leave a stronger historical verdict standing."""
    entries = _chain(_composition(), _grade(), _effect(), _unclean_stop("epoch-1", 1, 3))
    verdict = verify_export(_bundle(entries))
    assert verdict.coverage == "unknown"
    assert verdict.chain is not None
    assert {item.connection_id: item.grade for item in verdict.chain.grades} == {
        "connection-1": "unverified",
        "daemon": "unverified",
    }
    assert verdict.overall is Rederivation.unverifiable


def test_a_declared_missing_decision_is_named_and_not_rederived() -> None:
    """T2's expectation: the loss is declared, the id is absent from the re-derived set."""
    gap = _record(
        "gap",
        {
            "reason": "unflushed",
            "count": 1,
            "first_at": AT,
            "last_at": AT,
            "kinds": {"effect": 1},
            "decision_ids": ["decision-lost"],
            "decision_positions": [{"store_id": "store-a", "position": 2}],
            "accounting": "decision",
        },
        connection="daemon",
    )
    entries = _chain(_composition(), _grade(), _effect(), _unclean_stop("epoch-1", 1, 3), gap)
    verdict = verify_export(_bundle(entries))
    assert verdict.declared_missing_decision_ids == ("decision-lost",)
    assert verdict.rederived_decision_ids == ("decision-1",)
    assert verdict.coverage == "incomplete"
    assert {"coverage_incomplete", "coverage_unknown"} <= set(verdict.issues)
    assert verdict.overall is Rederivation.unverifiable


def test_a_range_without_a_decision_confirms_nothing() -> None:
    entries = _chain(_composition(), _grade(), _clean_stop("e", 1, 2))
    verdict = verify_export(_bundle(entries, policies={}))
    assert "no_decisions" in verdict.issues
    assert verdict.overall is Rederivation.unverifiable
    assert verdict.rederivations == ()
    empty = verify_export(_bundle([], policies={}))
    assert empty.coverage == "unknown"
    assert empty.overall is Rederivation.unverifiable


@pytest.mark.parametrize(
    "bundle",
    [
        "not a bundle",
        {},
        {"scope": "../x", "entries": []},
        {
            "contract_version": "1",
            "scope": "local",
            "from_sequence": 0,
            "entries": [],
            "verification": {},
            "manifest_hash": "0" * 64,
            "to_sequence": None,
            "next_from": None,
        },
        {
            "contract_version": "1",
            "scope": "local",
            "from_sequence": 1,
            "entries": ["x"],
            "verification": {},
            "manifest_hash": "0" * 64,
            "to_sequence": None,
            "next_from": None,
        },
    ],
)
def test_structural_invalidity_is_an_unverifiable_verdict_not_a_boolean(bundle: object) -> None:
    verdict = verify_export(bundle)  # type: ignore[arg-type]
    assert verdict.overall is Rederivation.unverifiable
    assert "bundle_invalid" in verdict.issues
    assert verdict.chain is None
    assert verdict.coverage == "unknown"
    assert verdict.scope in (None, "local")


BREAKING_BUNDLES: dict[str, Callable[[dict], dict]] = {
    "entries out of order": lambda bundle: bundle | {"entries": list(reversed(bundle["entries"]))},
    "an entry of another scope": lambda bundle: _with_entry(bundle, 0, {"scope": "elsewhere"}),
    "a principal whose via is not a list": lambda bundle: _with_entry(
        bundle, 0, {"principal": {"kind": "user", "id": "1000", "via": "sudo"}}
    ),
    "a via entry that is not an object": lambda bundle: _with_entry(
        bundle, 0, {"principal": {"kind": "user", "id": "1000", "via": ["sudo"]}}
    ),
    "an instant outside the calendar": lambda bundle: _with_entry(
        bundle, 0, {"recorded_at": "0001-01-01T00:00:00+01:00"}
    ),
    "a served grade with no connection": lambda bundle: bundle
    | {"verification": dict(bundle["verification"], grades=[{"grade": "evidence"}])},
}


@pytest.mark.parametrize("name", sorted(BREAKING_BUNDLES))
def test_verify_export_answers_a_verdict_for_every_malformed_bundle(name: str) -> None:
    """Its docstring promises « structural invalidity is a verdict … never an exception ».

    Six shapes escaped it: two out of `verify_chain`'s own argument checks,
    which `verify_export` called outside its guard; two out of
    `_principal_document` while a hash was being recomputed; one
    `OverflowError` out of `render_instant`, which is an `ArithmeticError` and
    so outside every clause that named `ValueError`; and one `KeyError` out of
    the served-grade reading. A caller of a verifier cannot be asked to
    classify those for itself.
    """
    bundle = BREAKING_BUNDLES[name](valid_bundle())
    verdict = verify_export(bundle)  # must not raise
    assert verdict.overall is Rederivation.unverifiable
    assert verdict.issues, "a verdict that concluded nothing names why"


def test_verify_export_takes_the_bundle_and_nothing_else() -> None:
    """V3: no evaluator argument, no server import, no connection, no filesystem."""
    import inspect

    from sayfirst_contract import evidence

    assert list(inspect.signature(verify_export).parameters) == ["bundle"]
    source = inspect.getsource(evidence)
    for forbidden in (
        "sayfirst_control_plane",
        "sayfirst_conformance",
        "import os",
        "import socket",
        "open(",
    ):
        assert forbidden not in source, forbidden
