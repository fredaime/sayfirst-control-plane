# SPDX-License-Identifier: Apache-2.0
"""The walking skeleton: one socket, one policy file, one decision, one chain.

Each block was honest about the seam it did not close. These cases are the
seam: the socket surface of block 2.2 answering out of the policy authority of
block 2.3, writing to the evidence store of block 2.4, over the plugin
composition of block 2.5 — through the ports each block published and never
into another block's internals (articles 4 and 13).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from composed_daemon import ME, MY_GID, policy_document
from sayfirst_contract.problems import ProblemCode
from sayfirst_control_plane.adapters import http_surface
from sayfirst_control_plane.application.evidence_emitter import EvidenceConnection
from sayfirst_control_plane.domain.evidence_chain import Principal
from sayfirst_control_plane.domain.integrity_grade import CallerAccess
from sayfirst_control_plane.plugins.interfaces import ApprovalProviderError
from sayfirst_testing.schemas import validate_document


def _read(session, scope: str = "local") -> list[dict]:
    path = Path(session.daemon.settings.socket_path).parent / "evidence" / f"{scope}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _entries(session, *, holding: Callable[[list[dict]], bool] = bool) -> list[dict]:
    """The chain, once it holds what the case is waiting for, or as it stands.

    The emitter is asynchronous on purpose — article 10 keeps the evidence
    authority off the hot path — so an answer can reach the caller before the
    record it caused reaches the file. Waiting for the record is what these
    cases assert; failing after the wait is a record that never arrived, which
    is the failure they are for.
    """
    deadline = time.monotonic() + 5.0
    entries = _read(session)
    while not holding(entries) and time.monotonic() < deadline:
        session.flush()
        time.sleep(0.01)
        entries = _read(session)
    return entries


def _kinds(kind: str, count: int) -> Callable[[list[dict]], bool]:
    return lambda entries: sum(1 for item in entries if item["kind"] == kind) >= count


# -- the decision -------------------------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "reason"),
    (("allow", "policy_allows"), ("deny", "policy_denies"), ("suspend", "policy_requires_review")),
)
def test_a_decision_is_taken_from_the_rules_of_the_policy_file(composed, outcome, reason) -> None:
    """Article 1: the three outcomes, each read out of the authority's own rules."""
    session = composed(rules=[(outcome, "example.effect")])

    status, document = session.ask()

    assert status == 200, document
    validate_document(document, "decision-result")
    assert document["outcome"] == outcome
    assert document["reason"] == reason
    assert document["rule_id"] == "rule-0"
    assert document["policy_version"].startswith("sha256:")


def test_a_capability_no_rule_names_is_denied_as_absent_not_as_unavailable(composed) -> None:
    """Article 1 and the `missing_policy` fixture: no rule applies is a decision.

    An authority that was read and carries no rule for this ask is not an
    authority that could not be read. The first is a denial the daemon can
    stand behind; the second is a could-not-ask (article 2).
    """
    session = composed(rules=[("allow", "other.effect")])

    status, document = session.ask()

    assert status == 200, document
    assert (document["outcome"], document["reason"]) == ("deny", "policy_absent")
    assert document["rule_id"] is None


def test_an_unreadable_authority_answers_the_problem_the_binding_publishes(composed) -> None:
    """Articles 1, 2 and 3: no policy file was read, so no decision is claimed."""
    session = composed(remove_policy=True)

    status, document = session.ask()

    assert status == 503, document
    validate_document(document, "problem-document")
    assert document["code"] == ProblemCode.POLICY_UNAVAILABLE.value
    assert "absent" in document["message"]
    assert document["retryable"] is True


def test_the_decision_is_recorded_as_evidence_at_the_grade_the_connection_has(composed) -> None:
    """Articles 7 and 10: one effect record, and the asking connection's own grade."""
    session = composed(rules=[("allow", "example.effect")])
    connection = session.connect()
    _, whoami = session.request("GET", "/whoami", connection=connection)
    connection_id = whoami["connection_id"]
    status, decision = session.request(
        "POST",
        "/decisions",
        {"contract_generation": 1, "capability": "example.effect", "scope": "local"},
    )
    assert status == 200, decision
    connection.close()

    entries = _entries(session, holding=_kinds("effect", 1))
    effects = [item for item in entries if item["kind"] == "effect"]
    grades = [item for item in entries if item["kind"] == "grade"]
    assert len(effects) == 1
    assert effects[0]["body"]["decision_id"] == decision["decision_ref"]
    assert effects[0]["body"]["outcome"] == "allow"
    assert effects[0]["body"]["policy_version"] == decision["policy_version"]
    # The grade belongs to the connection that asked, never to the daemon.
    asking = effects[0]["connection_id"]
    assert asking not in ("daemon", connection_id)
    assert [item["connection_id"] for item in grades] == [asking]
    evaluation = session.services.emitter.evaluation_for(
        "local",
        EvidenceConnection(asking, CallerAccess(ME, frozenset({MY_GID}))),
        Principal("user", "alice"),
    )
    assert grades[0]["body"]["grade"] == evaluation.grade.value


def test_the_composition_of_the_providers_is_the_chain_first_record(composed) -> None:
    """Article 8: what was composed is recorded before anything is served."""
    session = composed()

    entries = _entries(session, holding=_kinds("composition", 1))

    assert entries[0]["kind"] == "composition"
    providers = entries[0]["body"]["providers"]
    assert {item["interface"]: item["provider"] for item in providers} == {
        "ApprovalProvider": "single-approver",
        "PrivacyRedactor": "none",
    }


# -- the operations that were implemented and served by nothing ---------------


def test_the_decision_record_is_read_back_at_its_published_path(composed) -> None:
    """Article 13: `read_decision`, served by the adapter that already answered it."""
    session = composed(rules=[("allow", "example.effect")])
    _, decision = session.ask()

    status, document = session.request(
        "GET",
        f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local",
    )

    assert status == 200, document
    validate_document(document, "decision-record")
    assert document["decision_ref"] == decision["decision_ref"]
    assert document["outcome"] == "allow"


def test_a_decision_read_without_a_scope_is_refused_by_the_published_code(composed) -> None:
    session = composed()
    _, decision = session.ask()

    status, document = session.request(
        "GET", f"/decisions/{decision['decision_ref']}?contract_generation=1"
    )

    assert status == 400, document
    assert document["code"] == ProblemCode.SCOPE_REQUIRED.value


def test_a_decision_nobody_took_is_not_found_rather_than_invented(composed) -> None:
    session = composed()

    status, document = session.request(
        "GET", "/decisions/decision-nobody-took?contract_generation=1&scope=local"
    )

    assert status == 404, document
    assert document["code"] == ProblemCode.DECISION_NOT_FOUND.value


def test_the_policy_status_is_served_from_the_authority_that_decides(composed) -> None:
    """Article 3: the status names the version the decision path itself read."""
    session = composed(rules=[("allow", "example.effect")])
    _, decision = session.ask()

    status, document = session.request("GET", "/policy/status?contract_generation=1")

    assert status == 200, document
    validate_document(document, "policy-status")
    assert document["authority"] == "file"
    assert document["policy_version"] == decision["policy_version"]
    assert document["rule_count"] == 1
    assert document["projection"]["in_step"] == "yes"


def test_the_evidence_page_is_served_from_the_store_the_decision_wrote_to(composed) -> None:
    """Article 10: the chain a caller reads is the chain the decision was written to."""
    session = composed()
    _, decision = session.ask()
    _entries(session, holding=_kinds("effect", 1))

    status, document = session.request(
        "GET", "/scopes/local/evidence?contract_generation=1&from_sequence=1"
    )

    assert status == 200, document
    validate_document(document, "evidence-page-result")
    assert document["scope"] == "local"
    assert document["verification"]["condition"] == "intact"
    kinds = [entry["kind"] for entry in document["entries"]]
    assert "effect" in kinds and "composition" in kinds


def test_the_evidence_export_is_served_with_the_manifest_of_its_range(composed) -> None:
    session = composed()
    session.ask()
    _entries(session, holding=_kinds("effect", 1))

    status, document = session.request(
        "GET", "/scopes/local/evidence/export?contract_generation=1&from_sequence=1"
    )

    assert status == 200, document
    validate_document(document, "evidence-export-result")
    assert document["entry_count"] == len(document["entries"])
    assert len(document["manifest_hash"]) == 64


def test_an_evidence_range_that_is_not_a_range_is_refused_by_the_published_code(
    composed,
) -> None:
    session = composed()

    status, document = session.request(
        "GET", "/scopes/local/evidence?contract_generation=1&from_sequence=0"
    )

    assert status == 400, document
    assert document["code"] == ProblemCode.EVIDENCE_RANGE_INVALID.value


def test_a_read_that_names_no_generation_is_refused_before_it_is_answered(composed) -> None:
    """Article 13: the generation is negotiated in band on every operation that publishes it."""
    session = composed()

    status, document = session.request("GET", "/policy/status")

    assert status == 400, document
    assert document["code"] == ProblemCode.GENERATION_MISSING.value


def test_an_unsupported_generation_is_refused_with_its_own_code(composed) -> None:
    session = composed()

    status, document = session.request("GET", "/policy/status?contract_generation=9")

    assert status == 409, document
    assert document["code"] == ProblemCode.GENERATION_UNSUPPORTED.value


# -- what the composed surface says about itself ------------------------------


def test_the_status_of_a_composed_daemon_names_what_it_composed(composed) -> None:
    """Articles 2, 7 and 8: composed, the status answers from what it now holds."""
    session = composed()

    status, document = session.request("GET", "/status")

    assert status == 200, document
    validate_document(document, "status-result")
    assert document["store"] == {"authority": "authoritative", "kind": "file"}
    assert document["privacy_provider"] == "none"
    assert document["integrity_grade"]["store"] == "file"
    assert document["evidence_emission"]["delivering"] is True


def test_the_composed_operations_are_served_and_nothing_is_deferred(composed) -> None:
    """Article 13: nothing reachable answers something the binding does not define.

    Composed, every published operation is answered as itself. The approval
    read is the one that changed: it used to be `operation_unknown` here, and
    a reference this daemon keeps nothing for is now the refusal that says so.
    """
    assert set(http_surface.SERVED_OPERATIONS) == {
        "read_status",
        "read_whoami",
        "ask_decision",
        "read_decision",
        "read_policy_status",
        "read_approval",
        "resolve_approval",
        "read_evidence",
        "export_evidence",
    }
    assert set(http_surface.DEFERRED_OPERATIONS) == set()
    session = composed()
    for target in ("/approvals/approval-1?contract_generation=1&scope=local",):
        status, document = session.request("GET", target)
        assert status == 404, document
        assert document["code"] == ProblemCode.APPROVAL_UNKNOWN.value


# -- one person's act, over the composed surface -------------------------------


def _suspended(session) -> tuple[str, str]:
    """One ask the policy suspends, and the wait and decision it names."""
    status, document = session.ask()
    assert status == 200, document
    assert document["outcome"] == "suspend"
    reference = document["approval_ref"]
    assert isinstance(reference, str) and reference
    return reference, document["decision_ref"]


def _resolve(session, reference: str, **members: object) -> tuple[int, dict]:
    body: dict[str, object] = {
        "contract_generation": 1,
        "scope": "local",
        "approval_ref": reference,
        "resolution": "approve",
    }
    body.update(members)
    return session.request("POST", f"/approvals/{reference}/resolution", body)


def test_the_person_of_a_resolution_is_the_principal_the_socket_established(composed) -> None:
    """Articles 6 and 12: the act is attributed to the connection, and to nothing else.

    The published request carries no member that could name a person, and this
    is the other half of that: what the daemon writes down is the principal the
    socket established for the connection the act arrived on — here the account
    the harness admits, by the reference this core spells identities with.
    """
    session = composed(rules=[("suspend", "example.effect")])
    reference, decision_ref = _suspended(session)

    status, document = _resolve(session, reference, reason="reviewed on the socket")

    assert status == 200, document
    validate_document(document, "approval-result")
    assert document["state"] == "approved"
    assert document["approval_ref"] == reference
    assert document["decision_ref"] == decision_ref
    assert document["resolution_reason"] == "reviewed on the socket"
    # The authority for who acted is the daemon's own record, and the document
    # now renders it: the store the routes and the asks share is read here too,
    # so what a reader is served and what the core holds are one answer.
    assert document["person"] == "user:alice"
    kept = session.services.decisions.approvals.read("local", reference)
    assert kept.person == "user:alice"


def test_a_reader_can_consult_the_acts_the_daemon_recorded(composed) -> None:
    """Articles 2, 3 and 10: the acts a composed daemon records are readable.

    The daemon composed `NullEvents`, so `approval.resolved`, `approval.refused`,
    `approval.expired` and `approval.forgotten` were recorded into nothing. An
    event stream nobody can read is a mechanism indistinguishable from absent,
    which is what the audit of 2026-09-06 said of the Guard column.

    It is not evidence — the chain is — so it is bounded, it declares what it
    dropped, and it is an observation (article 3) and never an authority. It is
    read in this process, through the composition the daemon runs behind its
    socket, because no operation of this generation serves it over the wire and
    this case asserts nothing that is not true of a deployment.
    """
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)

    status, document = _resolve(session, reference)
    assert status == 200, document

    # One sink, composed once: the object a case reads is the object the
    # service records into, or this proves nothing about the daemon.
    assert session.services.events is session.services.decisions.events
    recorded = session.services.events.since(0)
    kinds = [entry.kind for _, entry in recorded]
    assert "approval.resolved" in kinds
    assert session.services.events.dropped() == 0
    resolved = next(entry for _, entry in recorded if entry.kind == "approval.resolved")
    assert resolved.details["approval_ref"] == reference
    assert resolved.details["person"] == "user:alice"


def test_a_body_that_names_a_person_is_refused_as_a_member_this_generation_lacks(composed) -> None:
    """Article 13: a request member the contract does not define is refused by name.

    It is the member that would matter most if it were read: a body able to say
    who acted would let one caller record another's act (articles 3 and 6).
    """
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)

    status, document = _resolve(session, reference, person="user:somebody-else")

    assert status == 400, document
    assert document["code"] == ProblemCode.MEMBER_UNKNOWN.value
    assert "person" in document["message"]
    # Nothing was applied: the wait is the pending one it was.
    assert session.services.decisions.approvals.read("local", reference).state.value == "pending"


def test_a_resolution_outside_the_published_values_is_refused_as_malformed(composed) -> None:
    """Article 13: the published schema is the judge, and it names the offending member."""
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)

    status, document = _resolve(session, reference, resolution="maybe")

    assert status == 400, document
    assert document["code"] == ProblemCode.REQUEST_MALFORMED.value
    assert "resolution" in document["message"]


def test_a_body_naming_another_approval_than_its_route_is_refused(composed) -> None:
    """Article 2: two statements that disagree are refused, and neither is preferred."""
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)

    status, document = session.request(
        "POST",
        f"/approvals/{reference}/resolution",
        {
            "contract_generation": 1,
            "scope": "local",
            "approval_ref": "another-approval",
            "resolution": "approve",
        },
    )

    assert status == 400, document
    assert document["code"] == ProblemCode.REQUEST_MALFORMED.value


def test_a_resolution_in_a_scope_that_keeps_no_such_approval_is_unknown(composed) -> None:
    """Article 5: the record is keyed by its scope, so another scope keeps none."""
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)

    status, document = _resolve(session, reference, scope="elsewhere")

    assert status == 404, document
    assert document["code"] == ProblemCode.APPROVAL_UNKNOWN.value


class _WillNotAnswer:
    """A provider whose backend is unreachable: nothing put to it comes back.

    Two ways to fail and one answer. A provider is code this project did not
    write, so an exception it raises is as much a provider behaviour as an
    answer, and `ApprovalProviderError` is the vocabulary the port gives it to
    refuse with — neither of them says a person's act was applied.
    """

    def __init__(self, error: Exception) -> None:
        self._error = error

    def suspend(self, request):  # type: ignore[no-untyped-def]
        raise self._error

    def resume(self, suspended, action):  # type: ignore[no-untyped-def]
        raise self._error


@pytest.mark.parametrize(
    "error",
    [RuntimeError("the provider's backend is unreachable"), ApprovalProviderError("not now")],
    ids=["raises", "refuses through the port"],
)
def test_a_provider_that_cannot_answer_is_a_could_not_ask_and_not_a_refusal(
    composed, error: Exception
) -> None:
    """Articles 1 and 2: a component outage decided nothing, so nothing is refused.

    The answer is the code the ask path already gives when a suspension could
    not be put to the provider, at the 503 that route publishes for it, and it
    is retryable because the record is untouched. Answered `internal` instead,
    the published client would read it as `Refused` — the person told their
    approval was rejected by a provider that never answered.
    """
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)
    session.services.decisions.approval_provider = _WillNotAnswer(error)

    status, document = _resolve(session, reference)

    assert status == 503, document
    assert document["code"] == ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE.value
    assert document["retryable"] is True
    # Nothing was applied, so the person may act again once it answers.
    assert session.services.decisions.approvals.read("local", reference).state.value == "pending"


def test_a_deployment_that_composed_no_approval_store_serves_neither_operation(composed) -> None:
    """Article 2: no store means no wait either operation could be about.

    `bootstrap.compose` always keeps a store, so this shape is reached the one
    way the composition allows: the pair `DecisionService` accepts and refuses
    the halves of is emptied on the composed service, which is exactly what a
    deployment composing none would hand the routes. It is the honest branch
    the surface keeps — `operation_unknown`, not `approval_unknown`, because
    nothing was looked for — and without a case it is an arm no run executes.

    The resolution is refused before its body is read: the body below carries a
    member this generation does not define, and the answer is still that this
    daemon does not serve the operation, because « we do not serve that » is a
    fact about the daemon and a complaint about the request would claim the
    request had reached something.
    """
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)
    session.services.decisions.approvals = None
    session.services.decisions.approval_provider = None

    read = session.request("GET", f"/approvals/{reference}?contract_generation=1&scope=local")
    resolved = _resolve(session, reference, person="user:somebody-else")

    for status, document in (read, resolved):
        assert status == 404, document
        assert document["code"] == ProblemCode.OPERATION_UNKNOWN.value


def test_a_resolution_of_another_generation_is_refused_before_the_act(composed) -> None:
    """Article 13: a request of a generation this server does not speak is not read."""
    session = composed(rules=[("suspend", "example.effect")])
    reference, _ = _suspended(session)

    status, document = _resolve(session, reference, contract_generation=9)

    assert status == 409, document
    assert document["code"] == ProblemCode.GENERATION_UNSUPPORTED.value
    assert session.services.decisions.approvals.read("local", reference).state.value == "pending"


# -- the policy the daemon reads is the file, on every ask --------------------


def test_a_policy_change_reaches_the_next_decision_without_a_restart(composed) -> None:
    """Article 3: the authority is the file, read for the decision that needs it."""
    session = composed(rules=[("allow", "example.effect")])
    _, first = session.ask()
    assert first["outcome"] == "allow"

    session.policy_path.write_text(
        policy_document([("deny", "example.effect")], reason="changed"), encoding="utf-8"
    )
    os.chmod(session.policy_path, 0o600)

    _, second = session.ask()
    assert second["outcome"] == "deny"
    assert second["policy_version"] != first["policy_version"]


def test_stopping_a_stopped_daemon_asks_the_composition_for_nothing(composed) -> None:
    """The composition is stopped once; a second stop is not a second teardown.

    The evidence emitter's flush waits out its whole timeout for a worker that
    has already returned, so a daemon that tore its composition down twice made
    a supervisor — or a test harness closing a session the runner already
    closed — wait seconds for nothing.
    """
    session = composed()
    session.daemon.stop()

    started = time.monotonic()
    session.daemon.stop()

    assert time.monotonic() - started < 1.0


# -- block 2.7: the chain copies the decision, the export carries the policy, a reader checks --


def test_the_effect_entry_copies_the_facts_of_the_decision_it_records(composed) -> None:
    """M1: reason, rule, digest, correlation and its source, references, recipe, position."""
    session = composed(rules=[("allow", "example.effect")])
    digest = "sha256:" + "2" * 64
    _, decision = session.ask(arguments_digest=digest, correlation="gate-1")
    assert decision["principal_references"] == ["user:alice"]
    assert decision["evaluation_recipe"] == "sayfirst/policy-evaluation/v1"
    assert decision["correlation_source"] == "boundary_supplied"

    entries = _entries(session, holding=_kinds("effect", 1))
    effect = next(item for item in entries if item["kind"] == "effect")
    body = effect["body"]
    assert body["decision_id"] == decision["decision_ref"]
    for member in ("reason", "rule_id", "arguments_digest", "correlation", "principal_references"):
        assert body[member] == decision[member], member
    assert body["correlation_source"] == "boundary_supplied"
    assert body["evaluation_recipe"] == "sayfirst/policy-evaluation/v1"
    assert body["decision_position"] == {
        "store_id": body["decision_position"]["store_id"],
        "position": 1,
    }
    assert body["recording_epoch"]
    validate_document(effect, "evidence-entry-writer")


def test_the_export_carries_the_policy_bytes_and_a_reader_re_derives_the_decision(
    composed,
) -> None:
    """A6, V3: the export and the contract wheel are enough to check the recorded answer."""
    from sayfirst_contract.evidence import MANIFEST_V3, Rederivation, verify_export

    session = composed(rules=[("allow", "example.effect")])
    _, decision = session.ask(correlation="gate-1")
    _entries(session, holding=_kinds("effect", 1))

    status, bundle = session.request(
        "GET", "/scopes/local/evidence/export?contract_generation=1&from_sequence=1"
    )
    assert status == 200, bundle
    validate_document(bundle, "evidence-export-result")
    assert bundle["manifest_version"] == MANIFEST_V3
    attachment = bundle["policy_versions"][decision["policy_version"]]
    assert attachment["state"] == "present"
    import base64

    assert base64.b64decode(attachment["content"]) == session.policy_path.read_bytes()
    assert bundle["recovery_context"] == []

    verdict = verify_export(bundle)
    assert verdict.manifest_hash_recomputes is True
    assert verdict.chain is not None and verdict.chain.condition.value == "intact"
    assert decision["decision_ref"] in verdict.rederived_decision_ids
    assert decision["decision_ref"] in verdict.confirmed_decision_ids
    by_id = {item.decision_id: item for item in verdict.rederivations}
    assert by_id[decision["decision_ref"]].verdict is Rederivation.confirmed


def test_the_status_names_the_durable_decision_store(composed) -> None:
    session = composed()
    status, document = session.request("GET", "/status")
    assert status == 200, document
    validate_document(document, "status-result")
    assert document["decision_store"]["store"] == "file"
    assert isinstance(document["decision_store"]["reconciliations"], list)
