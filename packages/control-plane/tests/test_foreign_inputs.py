# SPDX-License-Identifier: Apache-2.0
"""Articles 3, 8 and 12: the core hands a port no value it is still relying on.

`test_foreign_values.py` holds the output side — a value a port answers is
memory that port owns, so the core reads it once and keeps its own. This is the
mirror, and the second outside review asked for it by name: the input side was
applied at two call sites and by hand, so the question "can a new port's inputs
skip the guard" had no answer but a reader's memory.

The rule is the one `domain/foreign.py` states. A value the core hands *to* a
port is memory that port can write: `frozen=True` refuses `setattr` and refuses
nothing to `object.__setattr__`, so an argument a port is given and a fact the
core relies on afterwards must not be one object. One line inside a port, no
monkeypatch and no knowledge of any caller, and the fact moves.

The table below names every member of a `Protocol` that *takes* a value — every
one whose parameters are not all scalars, because a scalar cannot be written to
— with the drive that puts a double through the core path that hands it over.
Each double writes `POISON` into what it was given, after it has read it, and
one thing is asserted of the core in every row:

nothing the core produced after the call, or went on to read, carries what the
port wrote. That and not "the core copies every argument": the approval seam
hands a provider the *caller's* objects on purpose, having taken its own copies
first, and what matters is which of the two the core is relying on.

The rows a table must *have* are derived, not remembered. `declared_seams`
walks every module under `sayfirst_control_plane` and `sayfirst` and finds every
`Protocol` in them, so a member added later without a row fails
`test_every_member_that_takes_a_value_has_a_row` wherever it is declared. The
first version of this table read three modules by name — `ports/*.py`,
`plugins/interfaces.py` and `plugins/privacy_redactor.py` — and the third
outside read found the hole by walking through it:
`ApprovalResolutionRecorder` (`plugins/approval.py`), `Events`
(`application/events.py`) and `CompositionEvidenceSink`
(`plugins/composition.py`) are `Protocol`s a core module calls, and none had a
row. Reading modules by name answers "did anyone remember?"; walking the trees
answers the question the review actually asked.

Four rows failed when they were first written, each executed rather than
argued: `PolicyStore.write_access_of` moved the principal into the recorded
decision, `DecisionStore.append` moved the scope and the outcome into the
answer handed back to the caller, `PolicyProjection.rebuild` moved the policy
version into what the next projection saw and what the service served, and
`ApprovalResolutionRecorder.record` moved the person and the verdict into the
terminal record the caller resumes the suspended effect on.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.plugins import composition_body
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.application.approvals import ApprovalStore
from sayfirst_control_plane.application.decisions import DecisionService, GrantSettings
from sayfirst_control_plane.application.events import Event, MemoryEvents
from sayfirst_control_plane.application.evidence_emitter import (
    EffectDecision,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord
from sayfirst_control_plane.domain.evidence_chain import Principal as EvidencePrincipal
from sayfirst_control_plane.domain.integrity_grade import CallerAccess
from sayfirst_control_plane.domain.policy import (
    DecisionQuestion,
    Policy,
    parse_policy,
    policy_version,
)
from sayfirst_control_plane.domain.policy import Principal as PolicyPrincipal
from sayfirst_control_plane.plugins.approval import (
    ApprovalAnswerRefused,
    resume_through_provider,
)
from sayfirst_control_plane.plugins.composition import (
    CompositionEvidence,
    bootstrap_plugins,
)
from sayfirst_control_plane.plugins.composition import (
    EvidencePrincipal as CompositionPrincipal,
)
from sayfirst_control_plane.plugins.configuration import PluginConfiguration
from sayfirst_control_plane.plugins.defaults import SingleApprover
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)
from sayfirst_control_plane.ports.decision_store import DecisionPosition
from sayfirst_control_plane.ports.evidence_store import StoreLocation
from sayfirst_control_plane.ports.policy_projection import ProjectedPolicy
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    AccessVerdict,
    LoadedPolicy,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

CONTROL_PLANE = Path(__file__).resolve().parents[1] / "src" / "sayfirst_control_plane"
KIT = Path(__file__).resolve().parents[1] / "src" / "sayfirst"

#: Every tree that can declare a seam a core module calls. The first version of
#: this table read three modules by name — `ports/*.py`, `plugins/interfaces.py`
#: and `plugins/privacy_redactor.py` — so a `Protocol` declared anywhere else
#: had no row and no failure said so. Three did, and one of them was executed
#: against the branch: the approval recorder was handed the core's own
#: resolution and that same object was handed back to the caller. A list of
#: modules is somebody's memory; walking the trees is a guard.
PROTOCOL_ROOTS: tuple[Path, ...] = (CONTROL_PLANE, KIT)

#: Anti-vacuity floor for the walk. A walk that found nothing would make every
#: structural test below pass by finding no seam to require a row for.
LEAST_MODULES_DECLARING_A_SEAM = 9

AT = datetime(2026, 9, 4, tzinfo=UTC)

#: What every double writes into the value it was handed. It is one recognisable
#: string so a row asserts the same thing about facts of every shape: it appears
#: in the `repr` of what the core produced, or it does not.
POISON = "a-value-the-port-wrote"

_POLICY = (
    b"format = 1\n"
    b"[revision]\n"
    b'reason = "approved"\n'
    b"[[rule]]\n"
    b'id = "write"\n'
    b'capability = "example.effect"\n'
    b'principals = ["user:alice"]\n'
    b'outcome = "allow"\n'
    b'reason = "host rule"\n'
)


@dataclass
class Handover:
    """One drive of a core path, and what the port did to what it was given."""

    given: tuple[object, ...] = ()
    """The very objects the port's member received."""

    core: tuple[object, ...] = ()
    """Every fact the core produced after the call, or went on to read."""

    rewrote: bool = False
    """Whether a double wrote `POISON` into an argument and the write took."""

    unwritable: str = ""
    """Why this row runs no rewrite: what it hands over cannot be written to."""


@dataclass(frozen=True)
class Inlet:
    """One place the core hands a value to a port, and how to drive it."""

    interface: str
    member: str
    drive: Callable[..., Handover]

    @property
    def name(self) -> str:
        return f"{self.interface}.{self.member}"


# -- the drives ---------------------------------------------------------------


def _policy(raw: bytes = _POLICY) -> Policy:
    parsed = parse_policy(raw)
    assert isinstance(parsed, Policy)
    return parsed


def _loaded(raw: bytes = _POLICY) -> LoadedPolicy:
    return LoadedPolicy(_policy(raw), policy_version(raw), AT, len(raw))


class _PolicyStore:
    """A policy authority that writes into the values the core hands it."""

    VERSION = 1
    max_lifetime_seconds = 3600

    def __init__(
        self,
        given: list[object],
        *,
        rewrite_principal: bool = False,
        rewrite_expectation: bool = False,
        raw: bytes = _POLICY,
    ) -> None:
        self.given = given
        self.rewrite_principal = rewrite_principal
        self.rewrite_expectation = rewrite_expectation
        #: Which authority this double answers for. A row that needs a rule of
        #: another outcome says so here, so the bytes, the version and the
        #: rules it answers stay one policy.
        self.raw = raw

    def load(self) -> LoadedPolicy:
        return _loaded(self.raw)

    def protection_at_start(self, expectation: ProtectionExpectation) -> ProtectionVerdict:
        if self.rewrite_expectation:
            self.given.append(expectation)
            object.__setattr__(expectation, "owner_uids", frozenset({POISON}))
        return ProtectionVerdict(ProtectionState.PROTECTED)

    def write_access_of(self, principal: object) -> AccessVerdict:
        if self.rewrite_principal:
            self.given.append(principal)
            object.__setattr__(principal, "user_name", POISON)
        return AccessVerdict(AccessState.NOT_WRITABLE)


class _Projection:
    """A projection that reads the policy it is rebuilt from, then writes to it."""

    VERSION = 1
    KIND = "memory"

    def __init__(self, given: list[object], *, rewrite: bool = False) -> None:
        self.given = given
        self.rewrite = rewrite
        self.saw: list[str] = []
        self._current: ProjectedPolicy | None = None

    def rebuild(self, loaded: LoadedPolicy) -> None:
        self.saw.append(loaded.policy_version)
        self._current = ProjectedPolicy(
            loaded.policy_version,
            loaded.policy.format,
            loaded.loaded_at,
            len(loaded.policy.rules),
            loaded.policy.rules,
        )
        if self.rewrite:
            self.given.append(loaded)
            object.__setattr__(loaded, "policy_version", POISON)

    def current(self) -> ProjectedPolicy | None:
        return self._current

    def clear(self) -> None:
        self._current = None


class _DecisionStore:
    """A decision store that writes into the decision it is asked to append."""

    VERSION = 1

    def __init__(self, given: list[object], *, rewrite: bool = False) -> None:
        self.given = given
        self.rewrite = rewrite
        self.appended: list[object] = []

    def append(self, decision: object) -> DecisionPosition:
        self.appended.append(decision)
        if self.rewrite:
            self.given.append(decision)
            object.__setattr__(decision, "scope", POISON)
            object.__setattr__(decision, "capability", POISON)
        return DecisionPosition("store-1", len(self.appended))

    def get(self, scope: str, decision_ref: str) -> None:
        return None

    def location(self) -> StoreLocation:
        return StoreLocation(kind="memory", root=None, retention="test")


def _question() -> DecisionQuestion:
    return DecisionQuestion(
        DecisionAsk(capability="example.effect", scope="local"),
        PolicyPrincipal("user", 1000, "alice", (1000,), ("alice",)),
    )


def _started(
    store: _PolicyStore, projections: tuple[object, ...]
) -> tuple[PolicyService, MemoryEvents]:
    events = MemoryEvents()
    service = PolicyService(store, projections, events=events)  # type: ignore[arg-type]
    service.start(ProtectionExpectation.per_user(0))
    return service, events


def drive_policy_store_write_access_of(**_: object) -> Handover:
    """System mode: the principal whose write access decides whether it is answered."""
    given: list[object] = []
    store = _PolicyStore(given, rewrite_principal=True)
    policy, events = _started(store, (_Projection([]),))
    decisions = _DecisionStore([])
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        decisions,  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
        system_mode=True,
        events=events,
    )
    question = _question()
    answer = service.ask(question)
    return Handover(
        given=tuple(given),
        core=(question.principal, answer, *decisions.appended, *events.entries),
        rewrote=True,
    )


def drive_decision_store_append(**_: object) -> Handover:
    """The record of the decision, which is also what the caller is answered with."""
    given: list[object] = []
    store = _PolicyStore([])
    policy, events = _started(store, (_Projection([]),))
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        _DecisionStore(given, rewrite=True),  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
        events=events,
    )
    answer = service.ask(_question())
    return Handover(given=tuple(given), core=(answer, *events.entries), rewrote=True)


def drive_decision_store_get(**_: object) -> Handover:
    """`get` takes two strings, so there is nothing a store can write to."""
    return Handover(unwritable="`get` takes a scope and a reference, both strings")


def drive_policy_projection_rebuild(**_: object) -> Handover:
    """Every projection is rebuilt from the policy the service is about to serve."""
    given: list[object] = []
    watcher = _Projection([])
    policy, events = _started(_PolicyStore([]), (_Projection(given, rewrite=True), watcher))
    return Handover(
        given=tuple(given),
        core=(
            policy.current_version,
            tuple(watcher.saw),
            policy.load_for_decision(),
            policy.status(),
        ),
        rewrote=True,
    )


def drive_policy_store_protection_at_start(**_: object) -> Handover:
    """The expectation the start check is asked to hold the policy path to."""
    given: list[object] = []
    store = _PolicyStore(given, rewrite_expectation=True)
    expectation = ProtectionExpectation.per_user(0)
    events = MemoryEvents()
    service = PolicyService(store, (_Projection([]),), events=events)  # type: ignore[arg-type]
    service.start(expectation)
    # The expectation is not here: the start check reads nothing of it after
    # the call, and this row exists to fail the day it does.
    return Handover(given=tuple(given), core=(service.status(), *events.entries), rewrote=True)


def drive_evidence_store_append(**_: object) -> Handover:
    """The records the emitter writes, and the gap it counts for one it could not.

    On the path where the store accepts a record the core reads nothing of it
    again. On the path where the store refuses one it does: the refused records
    are counted into a pending gap by their `kind`, and the gap record the next
    unit writes says which kinds were dropped (article 11). A store that wrote
    to the record it had just refused named a kind that never happened.
    """
    given: list[object] = []
    honest = InMemoryEvidenceStore()

    class Store(InMemoryEvidenceStore):
        def __init__(self) -> None:
            self.refused = False

        def location(self) -> StoreLocation:
            return honest.location()

        def append(self, record: EvidenceRecord) -> object:
            given.append(record)
            if record.kind == "effect" and not self.refused:
                self.refused = True
                object.__setattr__(record, "kind", POISON)
                raise OSError("this store refuses the first effect it is given")
            return honest.append(record)

    emitter = EvidenceEmitter(Store(), clock=_Clock())
    try:
        _emit(emitter, "one")
        emitter.flush("local", timeout=5)
        _emit(emitter, "two")
        emitter.flush("local", timeout=5)
    finally:
        emitter.close()
    stored = tuple(honest.read_range("local", from_sequence=1))
    # Non-vacuity: the drive is only about anything if the refused record was
    # actually counted into a gap and the gap actually reached the store.
    assert any(entry.kind == "gap" for entry in stored), stored
    return Handover(given=tuple(given), core=stored, rewrote=True)


class _Clock:
    VERSION = 1

    def now(self) -> datetime:
        return AT


def _emit(emitter: EvidenceEmitter, correlation: str) -> None:
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=EvidencePrincipal("user", "alice"),
        capability="example.effect",
        decision=EffectDecision(f"decision-{correlation}", "allow", AT, "policy-1"),
    )


def drive_path_access_inspect(tmp_path: Path, **_: object) -> Handover:
    """The paths an integrity grade is claimed from, handed to the port one by one."""
    given: list[object] = []

    class PathAccess:
        VERSION = 1

        def inspect(self, path: Path) -> object:
            given.append(path)
            facts = _real_path_facts(path)
            object.__setattr__(path, "_raw_paths", [POISON])
            return facts

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            return StoreLocation(kind="file", root=tmp_path, retention="test")

    emitter = EvidenceEmitter(Store(), clock=_Clock(), path_access=PathAccess())  # type: ignore[arg-type]
    try:
        evaluation = emitter.evaluation_for(
            "local",
            EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
            EvidencePrincipal("user", "alice"),
            force=True,
        )
    finally:
        emitter.close()
    return Handover(
        given=tuple(given),
        core=(evaluation,),
        unwritable="a `Path` caches its text the first time it is read, so the write does not take",
    )


def _real_path_facts(path: Path) -> object:
    from sayfirst_control_plane.adapters.file.path_access import OperatingSystemPathAccess

    return OperatingSystemPathAccess().inspect(path)


def _approval_request() -> ApprovalRequest:
    from sayfirst.testing.approval import DEADLINE, REQUESTED_AT

    return ApprovalRequest(
        approval_ref="approval-1",
        decision_ref="decision-1",
        scope="local",
        capability="storage.write",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


class _Recorder:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, resolution: object) -> None:
        self.records.append(resolution)

    def record_refusal(self, refusal: object) -> None:
        self.records.append(refusal)


def drive_approval_provider_resume(**_: object) -> Handover:
    """The act put to a provider and the suspension it belongs to."""
    given: list[object] = []

    class Provider(SingleApprover):
        def resume(self, suspended, action):  # type: ignore[no-untyped-def]
            given.extend((suspended, suspended.request, action))
            answer = super().resume(suspended, action)
            object.__setattr__(action, "person", POISON)
            object.__setattr__(suspended.request, "decision_ref", POISON)
            return answer

    provider = Provider()
    request = _approval_request()
    suspended = provider.suspend(request)
    action = ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="alice",
        resolution=ApprovalResolution.APPROVE,
        reason="approved by Alice",
    )
    recorder = _Recorder()
    answer = resume_through_provider(provider, suspended, action, recorder=recorder)
    # The caller's `request`, `suspended` and `action` are deliberately not
    # here: the seam copies them and then hands the originals over, and says so
    # ("the provider's to do as it likes with"). What the core relies on
    # afterwards is `held` and `submitted`, and they reach the outside only
    # through the answer and the record.
    return Handover(given=tuple(given), core=(answer, *recorder.records), rewrote=True)


def _core_callers_of(member: str) -> list[str]:
    return sorted(
        str(module.relative_to(CONTROL_PLANE))
        for module in CONTROL_PLANE.rglob("*.py")
        if f".{member}(" in module.read_text(encoding="utf-8")
    )


#: The same authority as `_POLICY`, with the one rule that suspends: a request
#: crosses the approval port only where a rule says a person reviews.
_SUSPEND_POLICY = (
    b"format = 1\n"
    b"[revision]\n"
    b'reason = "approved"\n'
    b"[[rule]]\n"
    b'id = "review"\n'
    b'capability = "example.effect"\n'
    b'principals = ["user:alice"]\n'
    b'outcome = "suspend"\n'
    b'reason = "one person reviews this"\n'
    b"review_deadline_seconds = 60\n"
)


class _RewritingProvider:
    """A provider that reads the request it is handed, then writes into it.

    The published request is the seam's own value, describing a wait the core
    has already opened. A provider that renamed the approval or the decision it
    was asked to take up would move a fact the service is still relying on — if
    the service were relying on this object.
    """

    def __init__(self, given: list[object]) -> None:
        self.given = given

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        self.given.append(request)
        opened = SuspendedApproval(request=request, scope=request.scope)
        object.__setattr__(request, "approval_ref", POISON)
        object.__setattr__(request, "decision_ref", POISON)
        return opened

    def resume(self, suspended: object, action: object) -> object:
        raise AssertionError("this row drives suspend only")


def drive_approval_provider_suspend(**_: object) -> Handover:
    """The suspension the decision service opens when a rule says a person reviews."""
    given: list[object] = []
    store = _PolicyStore([], raw=_SUSPEND_POLICY)
    policy, events = _started(store, (_Projection([]),))
    decisions = _DecisionStore([])
    approvals = ApprovalStore(clock=lambda: AT)
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        decisions,  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
        events=events,
        approvals=approvals,
        approval_provider=_RewritingProvider(given),  # type: ignore[arg-type]
        clock=lambda: AT,
    )
    answer = service.ask(_question())
    assert given, "the row drove no suspension"
    handed_over = given[0]
    assert isinstance(handed_over, ApprovalRequest)
    return Handover(
        given=tuple(given),
        core=(
            answer,
            getattr(answer, "decision", None),
            *decisions.appended,
            *events.entries,
            *approvals.pending(),
        ),
        rewrote=handed_over.approval_ref == POISON,
    )


def drive_privacy_redactor_redact(**_: object) -> Handover:
    """The one `PrivacyRedactor` is handed `bytes` and two strings, which cannot be written to.

    The capture seam in the evidence emitter is the only core caller of
    `redact`, and the interface (`plugins/interfaces.py`) takes a bounded byte
    string rather than a mapping a redactor could write into. This fails the
    day a second core caller appears or the seam hands over anything else.
    """
    callers = [name for name in _core_callers_of("redact") if not name.startswith("testing/")]
    assert callers == ["application/evidence_emitter.py"], callers
    source = (CONTROL_PLANE / "application" / "evidence_emitter.py").read_text(encoding="utf-8")
    assert "redact(scope=scope, capability=capability, content=limited)" in source
    return Handover(unwritable="the composed interface is handed `bytes` and two strings")


class _RewritingRecorder:
    """A recorder that writes into the terminal record it is handed.

    A recorder is a `Protocol` exported from the plugins package, so it is a
    seam a product implements, and it is handed a record the core built from
    its own facts. The record is not the recorder's to change: article 3 says a
    mutable execution state never rewrites an immutable governance decision,
    and article 12 says attribution is the whole content of an approval record.
    """

    def __init__(self, given: list[object], *, refusals: bool = False) -> None:
        self.given = given
        self.records: list[object] = []
        self.refusals = refusals

    def record(self, resolution: object) -> None:
        self.records.append(resolution)
        if not self.refusals:
            self.given.append(resolution)
            object.__setattr__(resolution, "person", POISON)
            object.__setattr__(resolution, "reason", POISON)

    def record_refusal(self, refusal: object) -> None:
        self.records.append(refusal)
        if self.refusals:
            self.given.append(refusal)
            object.__setattr__(refusal, "person", POISON)
            object.__setattr__(refusal, "complaint", POISON)


def _act_on(request: ApprovalRequest) -> ApprovalAction:
    return ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="alice",
        resolution=ApprovalResolution.APPROVE,
        reason="approved by Alice",
    )


def drive_approval_resolution_recorder_record(**_: object) -> Handover:
    """The terminal record, which is also what the caller resumes on.

    The seam builds the resolution from the act put to the provider and from
    the suspension it holds, and then hands the recorder the very object it
    returns. One `object.__setattr__` inside `record` and the caller was
    answered with a person who never acted and a verdict nobody gave.
    """
    given: list[object] = []
    provider = SingleApprover()
    request = _approval_request()
    suspended = provider.suspend(request)
    recorder = _RewritingRecorder(given)
    answer = resume_through_provider(provider, suspended, _act_on(request), recorder=recorder)
    # Non-vacuity: only a terminal answer reaches `record` at all.
    assert type(answer) is ResolvedApproval, answer
    # `recorder.records` is what the port was given, not a core fact.
    return Handover(given=tuple(given), core=(answer,), rewrote=True)


def drive_approval_resolution_recorder_record_refusal(**_: object) -> Handover:
    """The refusal record, built from the core's facts and never read again.

    The core hands the recorder a `RefusedProviderAnswer` it has just built and
    then reads nothing of it: the exception the caller receives is raised from
    the suspension and the complaint, which are locals of the seam. This row
    drives a recorder that rewrites the refusal anyway, and it fails the day the
    core starts reading one back.
    """
    given: list[object] = []

    class Reattributes(SingleApprover):
        def resume(self, suspended, action):  # type: ignore[no-untyped-def]
            return replace(super().resume(suspended, action), person="mallory")

    provider = Reattributes()
    request = _approval_request()
    suspended = provider.suspend(request)
    recorder = _RewritingRecorder(given, refusals=True)
    with pytest.raises(ApprovalAnswerRefused) as refused:
        resume_through_provider(provider, suspended, _act_on(request), recorder=recorder)
    return Handover(given=tuple(given), core=(str(refused.value),), rewrote=True)


class _PoisoningEvents:
    """An events seam that writes into the details mapping it was handed.

    `MemoryEvents` copies what it is given, which is what an honest sink does;
    this one keeps it and writes to it, which is what the rule is about.
    """

    def __init__(self, given: list[object]) -> None:
        self.given = given
        self.entries: list[Event] = []

    def record(self, kind: str, details: dict[str, object], *, at: datetime | None = None) -> None:
        self.entries.append(Event(kind, at or AT, details))
        self.given.append(details)
        for key in list(details):
            details[key] = POISON
        details[POISON] = POISON


def _events_record_calls_handing_a_kept_mapping() -> list[str]:
    """Every `events.record(...)` in the core that hands over a mapping it named.

    The two paths this row drives cover the events a start and an ask record.
    The claim is wider than two paths and this is what makes it wider: every
    call site in the core builds the details in the call, so there is no name
    left for the core to read back. A site that hands a mapping it holds is
    reported here and this row fails.
    """
    offenders: list[str] = []
    for module in sorted(CONTROL_PLANE.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "record" or not isinstance(node.func.value, ast.Attribute):
                continue
            if node.func.value.attr != "events" or len(node.args) < 2:
                continue
            if not isinstance(node.args[1], ast.Dict):
                offenders.append(f"{module.relative_to(CONTROL_PLANE)}:{node.lineno}")
    return offenders


def drive_events_record(**_: object) -> Handover:
    """The details of every event the core records, on a start and on an ask."""
    given: list[object] = []
    events = _PoisoningEvents(given)
    store = _PolicyStore([])
    policy = PolicyService(store, (_Projection([]),), events=events)  # type: ignore[arg-type]
    policy.start(ProtectionExpectation.per_user(0))
    decisions = _DecisionStore([])
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        decisions,  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
        events=events,
    )
    answer = service.ask(_question())
    # Non-vacuity: the drive is only about anything if events were recorded,
    # and the claim only holds beyond these two paths if no call site anywhere
    # in the core hands `record` a mapping it goes on to name.
    assert len(given) >= 2, given
    assert _events_record_calls_handing_a_kept_mapping() == []
    # `events.entries` is what the sink kept, not a core fact.
    return Handover(
        given=tuple(given),
        core=(
            answer,
            policy.current_version,
            policy.status(),
            policy.load_for_decision(),
            *decisions.appended,
        ),
        rewrote=True,
    )


def drive_composition_evidence_sink_record(**_: object) -> Handover:
    """The resolved providers bootstrap records before it composes them."""
    given: list[object] = []

    class Sink:
        def record(self, *, scope: str, providers: tuple[object, ...]) -> CompositionEvidence:
            body = composition_body(providers)  # type: ignore[arg-type]
            evidence = CompositionEvidence(
                scope=scope,
                kind="composition",
                recorded_at=AT,
                connection_id="daemon",
                principal=CompositionPrincipal(kind="service", id="daemon"),
                body=body,
                sequence=1,
                previous_hash=None,
                entry_hash=f"{1:064x}",
                preimage_version="sayfirst-control-plane/evidence/v1",
            )
            given.extend(providers)
            for item in providers:
                object.__setattr__(item, "provider", POISON)
                object.__setattr__(item, "content_digest", POISON)
            return evidence

    composition = bootstrap_plugins(PluginConfiguration.defaults(), Sink())  # type: ignore[arg-type]
    # Non-vacuity: two providers are resolved and both were handed over.
    assert len(given) == 2, given
    return Handover(
        given=tuple(given),
        core=(
            composition.evidence,
            composition.privacy_provider_name,
            composition.approval_provider_name,
        ),
        rewrote=True,
    )


INLETS: tuple[Inlet, ...] = (
    Inlet("ApprovalProvider", "suspend", drive_approval_provider_suspend),
    Inlet("ApprovalProvider", "resume", drive_approval_provider_resume),
    Inlet("ApprovalResolutionRecorder", "record", drive_approval_resolution_recorder_record),
    Inlet(
        "ApprovalResolutionRecorder",
        "record_refusal",
        drive_approval_resolution_recorder_record_refusal,
    ),
    Inlet("CompositionEvidenceSink", "record", drive_composition_evidence_sink_record),
    Inlet("DecisionStore", "append", drive_decision_store_append),
    Inlet("DecisionStore", "get", drive_decision_store_get),
    Inlet("Events", "record", drive_events_record),
    Inlet("EvidenceStore", "append", drive_evidence_store_append),
    Inlet("PathAccess", "inspect", drive_path_access_inspect),
    Inlet("PolicyProjection", "rebuild", drive_policy_projection_rebuild),
    Inlet("PolicyStore", "protection_at_start", drive_policy_store_protection_at_start),
    Inlet("PolicyStore", "write_access_of", drive_policy_store_write_access_of),
    Inlet("PrivacyRedactor", "redact", drive_privacy_redactor_redact),
)

IDS = [item.name for item in INLETS]


@pytest.mark.parametrize("inlet", INLETS, ids=IDS)
def test_a_port_cannot_move_a_core_fact_by_writing_to_what_it_was_given(
    inlet: Inlet, tmp_path: Path
) -> None:
    """Articles 8 and 12: one `object.__setattr__` must move nothing."""
    handover = inlet.drive(tmp_path=tmp_path)
    assert handover.rewrote or handover.unwritable, f"{inlet.name} runs no rewrite and says no why"
    for kept in handover.core:
        assert POISON not in repr(kept), f"{inlet.name} moved a core fact: {kept!r}"


_SCALARS = frozenset({"str", "int", "bool", "float", "bytes", "None"})


def _takes_a_value(function: ast.FunctionDef) -> bool:
    """Whether any parameter of this member is something a port could write to.

    A `str` or an `int` is a value nobody can write into, so handing one over
    risks nothing and there is no row to write. Everything else — a record, a
    mapping, a path, an unannotated parameter — is memory, and gets a row.
    """
    parameters = [*function.args.args[1:], *function.args.kwonlyargs, *function.args.posonlyargs]
    for parameter in parameters:
        annotation = parameter.annotation
        if annotation is None:
            return True
        names = {node.id for node in ast.walk(annotation) if isinstance(node, ast.Name)} | {
            node.value
            for node in ast.walk(annotation)
            if isinstance(node, ast.Constant) and node.value is None
        }
        if not names or not {str(name) for name in names} <= _SCALARS:
            return True
    return False


@dataclass(frozen=True)
class Seam:
    """One member of one `Protocol` declared anywhere in the two trees."""

    interface: str
    member: str
    module: str
    takes_a_value: bool

    @property
    def name(self) -> str:
        return f"{self.interface}.{self.member}"


def declared_seams() -> tuple[Seam, ...]:
    """Every public member of every `Protocol` under `PROTOCOL_ROOTS`.

    Not a list of modules: the rows are derived from the trees, so a seam
    declared in a module nobody thought of is found the day it is written. The
    same walk answers both structural tests below — what needs a row, and what a
    row is allowed to name — so the two can never disagree about what a seam is.
    """
    found: list[Seam] = []
    for root in PROTOCOL_ROOTS:
        for module in sorted(root.rglob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                if not any(
                    isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases
                ):
                    continue
                for item in node.body:
                    if not isinstance(item, ast.FunctionDef) or item.name.startswith("_"):
                        continue
                    found.append(
                        Seam(
                            node.name,
                            item.name,
                            str(module.relative_to(root.parent)),
                            _takes_a_value(item),
                        )
                    )
    return tuple(found)


def test_the_walk_reaches_the_modules_that_declare_seams() -> None:
    """Anti-vacuity: a walk that found nothing would require no row at all."""
    seams = declared_seams()
    modules = {seam.module for seam in seams}
    assert len(modules) >= LEAST_MODULES_DECLARING_A_SEAM, sorted(modules)
    # The three that had no row while the scan read three modules by name.
    assert {
        "sayfirst_control_plane/plugins/approval.py",
        "sayfirst_control_plane/application/events.py",
        "sayfirst_control_plane/plugins/composition.py",
    } <= modules, sorted(modules)


def test_every_member_that_takes_a_value_has_a_row() -> None:
    """A `Protocol` added later that takes a value has no row here, and fails.

    This is the half of the guard that survives the next block: the reviewer's
    question — can a new port's inputs skip the guard — is answered by this
    test rather than by whoever remembers. It is answered for every `Protocol`
    in the two trees, because the first version of it answered only for three
    modules and the seam it missed was the one that had already escaped.
    """
    rows = {item.name for item in INLETS}
    missing = sorted(
        {seam.name for seam in declared_seams() if seam.takes_a_value} - rows,
    )
    assert missing == [], f"no rewriting double for {missing}"


def test_every_row_names_a_member_of_a_port() -> None:
    """A row cannot drift onto a member no `Protocol` declares."""
    declared = {seam.name for seam in declared_seams()}
    assert {item.name for item in INLETS} <= declared
    assert len({item.name for item in INLETS}) == len(INLETS)
