# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sayfirst_contract.decisions import Decision, DecisionAsk, Outcome, Reason
from sayfirst_contract.problems import ProblemCode, problem_retryable
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.decisions import (
    DecisionAnswer,
    DecisionProblem,
    DecisionService,
    GrantSettings,
)
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import GrantConnections, GrantEndReason
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    AccessVerdict,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

NOW = datetime(2026, 9, 4, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64


class ProtectedStore(FilePolicyStore):
    def __init__(self, path, *, max_lifetime_seconds=3600):  # type: ignore[no-untyped-def]
        super().__init__(
            path,
            max_lifetime_seconds=max_lifetime_seconds,
            clock=lambda: NOW,
        )
        self.loads = 0

    def load(self):  # type: ignore[no-untyped-def]
        self.loads += 1
        return super().load()

    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


def _policy(*outcomes: str, lifetime: int | None = None) -> bytes:
    rules = []
    for index, outcome in enumerate(outcomes):
        bound = "" if lifetime is None else f"grant_lifetime_seconds = {lifetime}\n"
        rules.append(
            "[[rule]]\n"
            f'id = "rule-{index}"\n'
            'capability = "mail.send"\n'
            'principals = ["user:build"]\n'
            f'outcome = "{outcome}"\n'
            f'reason = "{outcome} rule"\n' + bound
        )
    return ('format = 1\n[revision]\nreason = "test"\n' + "".join(rules)).encode()


def _question(*, digest: str | None = DIGEST) -> DecisionQuestion:
    return DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=digest),
        Principal("process", 1001, "build", (2001,), ("ci",)),
    )


def _service(  # type: ignore[no-untyped-def]
    tmp_path,
    *outcomes: str,
    lifetime: int | None = None,
    default_lifetime: int = 300,
    max_lifetime: int = 3600,
):
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy(*outcomes, lifetime=lifetime))
    authority = ProtectedStore(path, max_lifetime_seconds=max_lifetime)
    events = MemoryEvents()
    policy = PolicyService(
        authority,
        (MemoryPolicyProjection(),),
        events=events,
        clock=lambda: NOW,
    )
    policy.start(ProtectionExpectation.per_user(1000))
    decisions = MemoryDecisionStore()
    grants = GrantConnections(events=events, clock=lambda: NOW)
    service = DecisionService(
        policy,
        authority,
        decisions,
        grants,
        settings=GrantSettings(
            default_lifetime_seconds=default_lifetime,
            max_lifetime_seconds=max_lifetime,
        ),
        events=events,
        clock=lambda: NOW,
        id_factory=iter(f"id-{index}" for index in range(100)).__next__,
    )
    return service, authority, decisions, grants, events


def test_a_file_edited_between_two_decisions_decides_the_second_with_the_new_version(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Articles 3 and 10: every question loads the file authority afresh."""
    service, authority, _, _, _ = _service(tmp_path, "allow")
    first = service.ask(_question())
    authority.path.write_bytes(_policy("deny"))
    second = service.ask(_question())
    assert isinstance(first, DecisionAnswer) and isinstance(second, DecisionAnswer)
    assert first.decision.outcome is Outcome.ALLOW
    assert second.decision.outcome is Outcome.DENY
    assert second.decision.policy_version != first.decision.policy_version


def test_a_decision_is_recorded_before_it_is_answered(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 3 and 10: record append precedes grant issue and return."""
    service, _, decisions, _, events = _service(tmp_path, "allow")
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    assert decisions.get("local", answer.decision.decision_ref) is not None
    kinds = [event.kind for event in events.entries]
    assert kinds.index("decision.recorded") < kinds.index("grant.issued")


def test_a_request_with_a_malformed_arguments_digest_is_refused_before_evaluation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 3 and 13: a malformed generation-one member never reaches the authority."""
    service, authority, decisions, _, _ = _service(tmp_path, "allow")
    loads_before = authority.loads
    answer = service.ask(_question(digest="not-a-digest"))
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.REQUEST_MALFORMED
    assert authority.loads == loads_before
    assert decisions.get("local", "id-0") is None


def test_a_deny_or_suspend_issues_no_grant(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 10 and 12: only allow can create cached authority."""
    for outcome in ("deny", "suspend"):
        directory = tmp_path / outcome
        directory.mkdir()
        service, _, _, grants, _ = _service(directory, outcome)
        answer = service.ask(_question(), grant_connection=True)
        assert isinstance(answer, DecisionAnswer)
        assert answer.grant is None
        assert answer.connection is None
        assert grants.connection_count == 0


@pytest.mark.parametrize(
    ("rule", "default", "maximum", "expected"),
    [
        (30, 300, 3600, 30),
        (600, 300, 3600, 300),
        (None, 300, 3600, 300),
        (60, 60, 60, 60),
    ],
)
def test_a_grant_lifetime_is_the_shortest_of_all_bounds(
    tmp_path,
    rule,
    default,
    maximum,
    expected,  # type: ignore[no-untyped-def]
) -> None:
    """Articles 1 and 10: rule, default, and configured maximum all constrain."""
    service, _, _, _, _ = _service(
        tmp_path,
        "allow",
        lifetime=rule,
        default_lifetime=default,
        max_lifetime=maximum,
    )
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    assert answer.grant is not None
    assert answer.grant.lifetime_seconds == expected


def test_root_obtains_no_decision_in_system_mode(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: root is refused before the authority is loaded or a record exists."""
    service, authority, decisions, _, events = _service(tmp_path, "allow")
    service.system_mode = True
    loads_before = authority.loads
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("user", 0, "root", (0,), ("root",)),
    )
    answer = service.ask(question)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL
    assert authority.loads == loads_before
    assert decisions.get("local", "id-0") is None
    assert len(events.of_kind("decision.refused")) == 1


def test_a_directory_on_the_policy_path_writable_by_the_principal_is_refused(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 8: replacement access through a directory refuses the decision."""
    directory = tmp_path / "governed"
    directory.mkdir()
    service, authority, decisions, _, events = _service(directory, "allow")
    service.system_mode = True
    directory.chmod(0o770)
    metadata = directory.stat()
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", metadata.st_uid + 100, "build", (metadata.st_gid,), ("ci",)),
    )
    loads_before = authority.loads
    answer = service.ask(question)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL
    assert authority.loads == loads_before
    assert decisions.get("local", "id-0") is None
    assert len(events.of_kind("decision.refused")) == 1


def test_a_capacity_race_never_records_an_unissued_grant(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 10: a decision never claims a grant that was not issued."""

    class CapacityLost(GrantConnections):
        def has_capacity(self, principal_uid: int) -> bool:
            return True

        def reserve(self, principal_uid: int):  # type: ignore[no-untyped-def]
            return None

        def open(self, grant, *, principal_uid, signal_writer=None):  # type: ignore[no-untyped-def]
            return None

    service, _, decisions, _, _ = _service(tmp_path, "allow")
    service.grants = CapacityLost(clock=lambda: NOW)
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    assert answer.grant is None
    record = decisions.get("local", answer.decision.decision_ref)
    assert record is not None
    assert record.extra["grant_id"] is None


def test_policy_validation_and_grant_settings_share_one_maximum(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 10: one configured maximum governs rules and issued grants."""
    service, authority, decisions, grants, events = _service(tmp_path, "allow")
    with pytest.raises(ValueError, match="same maximum"):
        DecisionService(
            service.policy,
            authority,
            decisions,
            grants,
            settings=GrantSettings(max_lifetime_seconds=1800),
            events=events,
        )


def test_policy_failure_details_are_not_disclosed_to_the_asking_principal(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 8 and 11: authority structure is not copied into a refusal."""
    service, authority, _, _, _ = _service(tmp_path, "allow")
    authority.path.write_bytes(
        _policy("allow").replace(b"grant_lifetime_seconds = 300", b"")
        + b'\n[[rule]]\nid = "confidential-rule-name"\n'
    )
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_UNAVAILABLE
    assert "confidential-rule-name" not in answer.problem.message


def test_decision_instants_use_the_contracts_utc_z_form(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 13: decision and grant instants use one UTC spelling."""
    service, _, _, _, _ = _service(tmp_path, "allow")
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    assert answer.decision.decided_at.endswith("Z")
    assert answer.decision.extra["grant"]["issued_at"].endswith("Z")  # type: ignore[index]


def test_a_policy_file_writable_by_a_governed_principal_is_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: the per-connection access check precedes evaluation."""
    service, _, decisions, _, events = _service(tmp_path, "allow")
    service.system_mode = True
    authority_path = service.authority.path  # type: ignore[attr-defined]
    authority_path.chmod(0o660)
    authority_metadata = authority_path.stat()
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal(
            "process",
            authority_metadata.st_uid + 100,
            "governed",
            (authority_metadata.st_gid,),
            ("governed",),
        ),
    )
    answer = service.ask(question)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL
    assert decisions.get("local", "id-0") is None
    assert len(events.of_kind("decision.refused")) == 1


def test_unknown_policy_write_access_refuses_the_decision(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 8: access that cannot be established fails closed."""
    service, authority, decisions, _, _ = _service(tmp_path, "allow")
    service.system_mode = True
    loads_before = authority.loads
    monkeypatch.setattr(
        authority,
        "write_access_of",
        lambda principal: AccessVerdict(AccessState.UNKNOWN, authority.path, "stat_failed"),
    )
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL
    assert authority.loads == loads_before
    assert decisions.get("local", "id-0") is None


def test_an_unreadable_authority_is_a_problem_not_a_denial_at_decision_time(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 2: a runtime load failure carries no outcome."""
    service, authority, decisions, _, _ = _service(tmp_path, "allow")
    authority.path.write_bytes(b"broken = [toml")
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_UNAVAILABLE
    assert not hasattr(answer, "outcome")
    assert decisions.get("local", "id-0") is None


def test_a_reload_failure_does_not_end_an_issued_grant(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 1: the last known version remains current on load failure."""
    service, authority, _, _, _ = _service(tmp_path, "allow")
    first = service.ask(_question(), grant_connection=True)
    assert isinstance(first, DecisionAnswer)
    assert first.connection is not None
    authority.path.write_bytes(b"broken = [toml")
    refused = service.ask(_question())
    assert isinstance(refused, DecisionProblem)
    assert first.connection.live
    assert first.connection.drain() == ()


def test_the_grant_connection_bound_answers_without_a_grant_never_refuses(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 10: connection capacity never suppresses an allow decision."""
    service, _, _, _, _ = _service(tmp_path, "allow")
    service.grants.max_connections = 0
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    assert answer.decision.outcome is Outcome.ALLOW
    assert answer.grant is None
    assert answer.connection is None


def test_a_connection_that_carries_no_signal_gets_no_grant(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 10: a grant exists only on a connection that can carry its signals."""
    service, _, _, _, _ = _service(tmp_path, "allow")
    answer = service.ask(_question(), grant_connection=False)
    assert isinstance(answer, DecisionAnswer)
    assert answer.decision.outcome is Outcome.ALLOW
    assert answer.grant is None
    assert answer.connection is None


def test_an_ask_without_an_arguments_digest_still_decides_and_grants(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the digest is optional in generation one, so its absence is a fact."""
    service, _, _, _, _ = _service(tmp_path, "allow")
    answer = service.ask(_question(digest=None), grant_connection=True)
    assert isinstance(answer, DecisionAnswer)
    assert answer.decision.outcome is Outcome.ALLOW
    assert answer.grant is not None
    assert answer.grant.conditions.arguments_digest is None


def test_the_decision_service_returns_only_the_generation_one_decision_shape(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 1: this block does not define a competing decision vocabulary."""
    for outcomes, expected in (
        (("allow",), Outcome.ALLOW),
        (("suspend",), Outcome.SUSPEND),
        (("deny",), Outcome.DENY),
        ((), Outcome.DENY),
    ):
        directory = tmp_path / expected.value / str(len(outcomes))
        directory.mkdir(parents=True)
        service, _, _, _, _ = _service(directory, *outcomes)
        answer = service.ask(_question())
        assert isinstance(answer, DecisionAnswer)
        assert isinstance(answer.decision, Decision)
        assert answer.decision.outcome is expected
    assert {value.value for value in Outcome} == {"allow", "deny", "suspend"}


def test_pairing_invariants_hold_for_every_service_decision(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 1 and 3: outcomes, reasons, and approval references agree."""
    pairs = {
        "allow": Reason.POLICY_ALLOWS,
        "deny": Reason.POLICY_DENIES,
        "suspend": Reason.POLICY_REQUIRES_REVIEW,
    }
    for outcome, reason in pairs.items():
        directory = tmp_path / outcome
        directory.mkdir()
        service, _, _, _, _ = _service(directory, outcome)
        answer = service.ask(_question())
        assert isinstance(answer, DecisionAnswer)
        assert answer.decision.reason is reason
        assert answer.decision.approval_ref is None


@pytest.mark.parametrize(
    "code",
    (
        ProblemCode.POLICY_UNAVAILABLE,
        ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL,
        ProblemCode.REQUEST_MALFORMED,
    ),
)
def test_decision_problem_retryability_comes_from_the_registry(code: ProblemCode) -> None:
    """Article 13: server problems use the published retryability registry."""
    assert DecisionService._problem(code, "example").retryable is problem_retryable(code)


# -- block 2.7: the policy bytes are archived before any decision is committed --


class _RecordingArchive:
    """An archive that keeps in memory and records the order it was reached in."""

    VERSION = 1

    def __init__(self, events: MemoryEvents, *, fail: bool = False, damaged: bool = False) -> None:
        self.events = events
        self.fail = fail
        self.damaged = damaged
        self.kept: dict[str, bytes] = {}

    def keep(self, version: str, content: bytes):  # type: ignore[no-untyped-def]
        from sayfirst_control_plane.ports.policy_archive import ArchivedPolicy, ArchiveState

        if self.fail:
            raise OSError(5, "input/output error")
        self.events.record("archive.kept", {"policy_version": version}, at=NOW)
        if self.damaged:
            return ArchivedPolicy(version, ArchiveState.damaged, None)
        self.kept[version] = bytes(content)
        return ArchivedPolicy(version, ArchiveState.present, bytes(content))

    def read(self, version: str):  # type: ignore[no-untyped-def]
        from sayfirst_control_plane.ports.policy_archive import ArchivedPolicy, ArchiveState

        if version in self.kept:
            return ArchivedPolicy(version, ArchiveState.present, self.kept[version])
        return ArchivedPolicy(version, ArchiveState.absent, None)

    def location(self):  # type: ignore[no-untyped-def]
        from sayfirst_control_plane.ports.evidence_store import StoreLocation

        return StoreLocation(kind="memory", root=None, retention="test")


def test_the_policy_bytes_are_archived_before_the_decision_is_appended(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A1, G7: the exact bytes read for this question are kept, under its version, first."""
    service, authority, decisions, _, events = _service(tmp_path, "allow")
    archive = _RecordingArchive(events)
    service.archive = archive
    answer = service.ask(_question())
    assert isinstance(answer, DecisionAnswer)
    kinds = [event.kind for event in events.entries]
    assert kinds.index("archive.kept") < kinds.index("decision.recorded")
    assert archive.kept[answer.decision.policy_version] == authority.path.read_bytes()
    assert decisions.get("local", answer.decision.decision_ref) is not None


def test_archive_failure_refuses_before_decision_append_and_writes_no_effect(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A1, G12: a question whose policy bytes cannot be kept is refused, never decided."""
    service, _, decisions, grants, events = _service(tmp_path, "allow")
    service.archive = _RecordingArchive(events, fail=True)
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_ARCHIVE_UNAVAILABLE
    assert answer.problem.retryable is True
    assert decisions.get("local", "id-0") is None
    assert not events.of_kind("decision.recorded")
    assert grants.connection_count == 0


def test_a_damaged_archived_version_refuses_the_question_rather_than_deciding_on_it(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """A2: damage is reported and the question is not answered on bytes nobody can verify."""
    service, _, decisions, _, events = _service(tmp_path, "allow")
    service.archive = _RecordingArchive(events, damaged=True)
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_ARCHIVE_UNAVAILABLE
    assert decisions.get("local", "id-0") is None


def test_an_authority_that_supplies_no_bytes_cannot_be_archived_and_refuses(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3, fail-closed: no bytes, nothing kept, no decision committed."""
    service, _, decisions, _, events = _service(tmp_path, "allow")
    service.archive = _RecordingArchive(events)
    honest = service.policy.load_for_decision
    from sayfirst_control_plane.ports.policy_store import LoadedPolicy

    def without_bytes():  # type: ignore[no-untyped-def]
        loaded = honest()
        assert isinstance(loaded, LoadedPolicy)
        return LoadedPolicy(
            loaded.policy, loaded.policy_version, loaded.loaded_at, loaded.byte_length, None
        )

    service.policy.load_for_decision = without_bytes  # type: ignore[method-assign]
    answer = service.ask(_question())
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.POLICY_ARCHIVE_UNAVAILABLE
    assert decisions.get("local", "id-0") is None
    assert not events.of_kind("archive.kept")


# -- block 2.7: a store that cannot answer is a could-not-ask, never a denial --


def test_a_known_prewrite_refusal_answers_unavailable_and_cancels_the_reservation(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """G2: an error before any byte was written commits nothing and releases the slot."""
    from sayfirst_control_plane.ports.decision_store import DecisionStoreUnavailable

    service, _, decisions, grants, events = _service(tmp_path, "allow")

    class Refusing:
        VERSION = 1

        def append(self, decision):  # type: ignore[no-untyped-def]
            raise DecisionStoreUnavailable("the scope is fenced")

        def get(self, scope, decision_ref):  # type: ignore[no-untyped-def]
            return decisions.get(scope, decision_ref)

        def location(self):  # type: ignore[no-untyped-def]
            return decisions.location()

    service.decisions = Refusing()
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.DECISION_STORE_UNAVAILABLE
    assert answer.problem.retryable is True
    assert grants.connection_count == 0
    assert not events.of_kind("decision.recorded")


def test_an_indeterminate_append_is_unavailable_too_and_never_claims_absence(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """C2: a write that may have committed is not answered, and not called no decision."""
    from sayfirst_control_plane.ports.decision_store import DecisionAppendIndeterminate

    service, _, decisions, grants, _ = _service(tmp_path, "allow")

    class Uncertain:
        VERSION = 1

        def append(self, decision):  # type: ignore[no-untyped-def]
            raise DecisionAppendIndeterminate("sync failed after the write began")

        def get(self, scope, decision_ref):  # type: ignore[no-untyped-def]
            return decisions.get(scope, decision_ref)

        def location(self):  # type: ignore[no-untyped-def]
            return decisions.location()

    service.decisions = Uncertain()
    answer = service.ask(_question(), grant_connection=True)
    assert isinstance(answer, DecisionProblem)
    assert answer.problem.code is ProblemCode.DECISION_STORE_UNAVAILABLE
    assert "may have committed" in answer.problem.message
    assert grants.connection_count == 0


def test_the_answer_carries_the_position_the_store_committed_the_record_at(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """C2: the effect's position is fixed at commit and read from the store's own answer."""
    service, _, decisions, _, _ = _service(tmp_path, "allow")
    answer = service.ask(_question())
    assert isinstance(answer, DecisionAnswer)
    assert answer.position is not None
    assert answer.position == decisions.position_of("local", answer.decision.decision_ref)
    assert answer.position.position == 1


# -- block 2.7: the record carries the references, the recipe and who chose the correlation --


def _policy_with(*rules: str) -> bytes:
    return ('format = 1\n[revision]\nreason = "test"\n' + "".join(rules)).encode()


def _rule(identifier: str, capability: str, principals: str, *, scope: str = "local") -> str:
    return (
        "[[rule]]\n"
        f'id = "{identifier}"\n'
        f'capability = "{capability}"\n'
        f'scope = "{scope}"\n'
        f"principals = [{principals}]\n"
        'outcome = "allow"\n'
        f'reason = "{identifier}"\n'
    )


def test_references_intersect_only_rules_for_this_scope_and_capability(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """M3, G16: competing rules count, other scopes and capabilities do not, sorted, unique."""
    service, authority, _, _, _ = _service(tmp_path, "allow")
    authority.path.write_bytes(
        _policy_with(
            _rule("winner", "mail.send", '"user:build"'),
            _rule("competing", "mail.send", '"group:ci", "group:ci", "group:nobody"'),
            _rule("digest-pinned", "mail.send", '"group:ops"')
            + 'arguments_digest = "sha256:'
            + "f" * 64
            + '"\n',
            _rule("other-scope", "mail.send", '"group:audit"', scope="other"),
            _rule("other-capability", "mail.read", '"group:release"'),
        )
    )
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", 1001, "build", (2001,), ("release", "ci", "audit", "ops")),
    )
    answer = service.ask(question)
    assert isinstance(answer, DecisionAnswer)
    extra = answer.decision.extra
    # `ci` from the competing rule and `ops` from the pinned rule whose digest
    # does not match are kept: the retrospective evaluation needs every
    # membership test the live one made. `audit` and `release` are not.
    assert extra["principal_references"] == ["group:ci", "group:ops", "user:build"]
    assert extra["evaluation_recipe"] == "sayfirst/policy-evaluation/v1"
    assert extra["correlation_source"] == "absent"
    assert answer.decision.correlation is None


def test_a_supplied_correlation_is_marked_boundary_supplied(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """M1: the daemon cannot prove the bytes are an identifier; it says who chose them."""
    service, _, decisions, _, _ = _service(tmp_path, "allow")
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST, correlation="a short payload"),
        Principal("process", 1001, "build", (2001,), ("ci",)),
    )
    answer = service.ask(question)
    assert isinstance(answer, DecisionAnswer)
    assert answer.decision.correlation == "a short payload"
    assert answer.decision.extra["correlation_source"] == "boundary_supplied"
    stored = decisions.get("local", answer.decision.decision_ref)
    assert stored is not None
    assert stored.extra["correlation_source"] == "boundary_supplied"
    assert stored.extra["principal_references"] == ["user:build"]


def test_a_reference_the_caller_does_not_hold_is_never_recorded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 11: the record says which memberships were read, not which were named."""
    service, authority, _, _, _ = _service(tmp_path, "allow")
    authority.path.write_bytes(
        _policy_with(_rule("named", "mail.send", '"group:ci", "user:other"'))
    )
    answer = service.ask(_question())
    assert isinstance(answer, DecisionAnswer)
    assert answer.decision.extra["principal_references"] == ["group:ci"]


def test_a_stop_that_lands_between_the_answer_and_the_registration_still_signals_the_grant(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Articles 2 and 10, S5: the boundary that holds the frame is told the daemon is stopping.

    The answer is delivered before its grant is registered (article 10), so at
    the instant the boundary holds a decision with a grant in it the registry
    counts no connection. A graceful stop landing in that instant must still
    end the grant on the channel the answer went out on, never leave the
    boundary holding a grant the daemon has forgotten.
    """
    service, _, _, grants, _ = _service(tmp_path, "allow")
    received = []
    seen_at_delivery = []

    def deliver(answer: DecisionAnswer) -> None:
        assert answer.grant is not None
        seen_at_delivery.append(grants.connection_count)
        grants.shutdown()

    answer = service.ask(
        _question(), grant_connection=True, signal_writer=received.append, deliver=deliver
    )
    assert isinstance(answer, DecisionAnswer)
    assert answer.grant is not None
    assert seen_at_delivery == [0]
    assert answer.connection is not None
    assert answer.connection.live is False
    assert grants.connection_count == 0
    assert [signal.reason for signal in received] == [GrantEndReason.DAEMON_STOPPING]
    assert received[0].grant_id == answer.grant.grant_id
