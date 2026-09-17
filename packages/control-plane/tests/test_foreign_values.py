# SPDX-License-Identifier: Apache-2.0
"""Articles 3, 8, 11 and 12: the core keeps no value a port handed it.

One rule, held at every boundary at once rather than at the one where it was
last broken. A port is written outside the core, so the object it returns is
memory that code owns: reading it a second time is asking the same question of
the same author twice and being allowed a different answer. The core's answer
is to read every member exactly once, build its own value from what it read,
and record and hand on that.

The table below names every boundary where a value crosses into the core — the
eight ports and the two plugin interfaces — with the drive that puts a
two-faced double through the core path that reads it. Two things are asserted
of every row, and a boundary added later without a row fails
`test_every_boundary_of_the_core_has_a_row`:

* no member of the port's value is read twice, so there is no second read for
  a port to answer differently; and
* the object itself is never what the core records, returns or holds.

What this cannot hold is stated in the report and repeated here: nothing stops
a port from lying on the *first* read. That is the port's own claim, and it is
refused only where the core independently holds the fact — as the approval seam
holds the act put to the provider, and as the capture seam holds the name of
the redactor it composed.
"""

from __future__ import annotations

import ast
import socket
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
from foreign_doubles import NEVER, TwoFaced, TwoFacedInstant, TwoFacedSequence, TwoFacedText
from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.adapters.socket_server import Daemon, _CachedDirectory
from sayfirst_control_plane.application.approvals import ApprovalStore
from sayfirst_control_plane.application.decisions import DecisionService, GrantSettings
from sayfirst_control_plane.application.evidence_emitter import (
    CapturePolicy,
    CaptureRule,
    EffectDecision,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.application.evidence_reads import EvidenceReads
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService, PolicyStartRefused
from sayfirst_control_plane.bootstrap import _ChainCompositionEvidence
from sayfirst_control_plane.domain.admission import admit
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
from sayfirst_control_plane.domain.principal import (
    build_principal,
    kind_for,
    resolve_identity,
)
from sayfirst_control_plane.plugins.approval import resume_through_provider
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalProviderError,
    ApprovalRequest,
    ApprovalResolution,
    Redaction,
    ResolvedApproval,
    SuspendedApproval,
)
from sayfirst_control_plane.ports.account_directory import Account
from sayfirst_control_plane.ports.decision_store import DecisionPosition
from sayfirst_control_plane.ports.evidence_store import StoreLocation
from sayfirst_control_plane.ports.path_access import PathFacts
from sayfirst_control_plane.ports.policy_archive import ArchivedPolicy, ArchiveState
from sayfirst_control_plane.ports.policy_projection import ProjectedPolicy
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    AccessVerdict,
    LoadedPolicy,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)
from sayfirst_control_plane.ports.recovery_journal import JournalRecord
from sayfirst_control_plane.settings import read_settings

CONTROL_PLANE = Path(__file__).resolve().parents[1] / "src" / "sayfirst_control_plane"
AT = datetime(2026, 9, 4, tzinfo=UTC)
PEER = PeerCredential(uid=1000, gid=1000, pid=4242, captured_at="2026-09-04T00:00:00+00:00")


@dataclass
class Crossing:
    """One drive of a core path, and what the port's values did there."""

    doubles: tuple[object, ...]
    kept: tuple[object, ...] = ()
    lied: bool = False
    """Whether the drive ran a double that rewrites itself after its grace."""


@dataclass(frozen=True)
class Boundary:
    """One place a value crosses into the core, and how to drive it."""

    interface: str
    member: str
    drive: Callable[..., Crossing]

    @property
    def name(self) -> str:
        return f"{self.interface}.{self.member}"


# -- the drives ---------------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.recorded: list[object] = []
        self.refused: list[object] = []

    def record(self, resolution: object) -> None:
        self.recorded.append(resolution)

    def record_refusal(self, refusal: object) -> None:
        self.refused.append(refusal)


def _approval_request() -> ApprovalRequest:
    return ApprovalRequest(
        approval_ref="approval-1",
        decision_ref="decision-1",
        scope="local",
        capability="storage.write",
        requested_at=AT,
        deadline=datetime(2026, 9, 4, 1, tzinfo=UTC),
    )


def drive_approval_provider_resume(**_: object) -> Crossing:
    """The seam that turns one person's act into a terminal approval record."""
    request = _approval_request()
    suspended = SuspendedApproval(request=request, scope=request.scope)
    action = ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="uid:1000",
        resolution=ApprovalResolution.APPROVE,
        reason="agreed",
    )
    honest = ResolvedApproval(
        approval_ref=request.approval_ref,
        decision_ref=request.decision_ref,
        scope=request.scope,
        person=action.person,
        resolution=action.resolution,
        reason=action.reason,
    )
    double = TwoFaced(honest, grace=1, lies={"person": "somebody-who-never-acted"})

    class Provider:
        def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
            return SuspendedApproval(request=request, scope=request.scope)

        def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> object:
            return double

    recorder = _Recorder()
    kept: list[object] = []
    # The seam refuses the answer, which is the point; what it recorded and
    # what it handed back are what this row inspects.
    with suppress(ApprovalProviderError):
        kept.append(resume_through_provider(Provider(), suspended, action, recorder=recorder))
    return Crossing((double,), (*kept, *recorder.recorded, *recorder.refused), lied=True)


#: The same authority as `_POLICY`, with the one rule that suspends: the
#: decision service opens a suspension only where a rule says a person reviews.
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


def drive_approval_provider_suspend(**_: object) -> Crossing:
    """The suspension the decision service opens when a rule says a person reviews.

    The provider answers a two-faced `SuspendedApproval`, and the row holds
    that the service reads nothing out of it. It does not have to: the wait is
    opened in the core's own store before the request is put to the provider,
    and the reference the service answers, records and hands on is the one it
    minted, so a provider that renamed the approval it was asked to take up
    would rename nothing (article 3).
    """
    doubles: list[object] = []
    store = _PolicyStore([], wrap=False, raw=_SUSPEND_POLICY)
    policy = PolicyService(store, (_Projection([]),))  # type: ignore[arg-type]
    policy.start(ProtectionExpectation.per_user(0))
    approvals = ApprovalStore(clock=lambda: AT)

    class Provider:
        def suspend(self, request: ApprovalRequest) -> object:
            double = TwoFaced(
                SuspendedApproval(request=request, scope=request.scope),
                grace=1,
                lies={"scope": "another-scope"},
            )
            doubles.append(double)
            return double

        def resume(self, suspended: object, action: object) -> object:
            raise AssertionError("this row drives suspend only")

    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        _DecisionStore([]),  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
        approvals=approvals,
        approval_provider=Provider(),  # type: ignore[arg-type]
        clock=lambda: AT,
    )
    answer = service.ask(
        DecisionQuestion(_ask(), PolicyPrincipal("user", 1000, "alice", (1000,), ("alice",)))
    )
    assert doubles, "the row drove no suspension"
    return Crossing(
        tuple(doubles),
        (answer, getattr(answer, "decision", None), *approvals.pending()),
        lied=True,
    )


class _Clock:
    VERSION = 1

    def __init__(self, doubles: list[object] | None = None, *, grace: int = NEVER) -> None:
        self.doubles = doubles if doubles is not None else []
        self.grace = grace

    def now(self) -> datetime:
        value = TwoFacedInstant(2026, 9, 4, 10, 0, tzinfo=UTC, grace=self.grace)
        self.doubles.append(value)
        return value


def _emitter(**kwargs: object) -> EvidenceEmitter:
    return EvidenceEmitter(InMemoryEvidenceStore(), **kwargs)  # type: ignore[arg-type]


def _emit_effect(emitter: EvidenceEmitter, *, payload: bytes | None = None) -> None:
    emitter.emit_effect(
        scope="local",
        connection=EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
        principal=EvidencePrincipal("user", "example"),
        capability="example.effect",
        decision=EffectDecision("decision-1", "allow", AT, "policy-1"),
        payload=payload,
    )
    assert emitter.flush("local", timeout=2)


def drive_privacy_redactor_redact(**_: object) -> Crossing:
    """The capture seam: what a redactor answers decides what evidence holds."""
    honest = Redaction(b"[redacted]", "applied", "example-redactor")
    double = TwoFaced(
        honest,
        grace=1,
        lies={"content": b"the-payload-itself", "provider": "a-provider-never-composed"},
    )

    class Redactor:
        interface_version = 1
        name = "example-redactor"

        def redact(self, *, scope: str, capability: str, content: bytes) -> object:
            return double

    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(
        store,
        clock=_Clock(),
        capture_policy=CapturePolicy((CaptureRule("example.effect", 64),)),
        privacy_redactor=Redactor(),  # type: ignore[arg-type]
    )
    try:
        _emit_effect(emitter, payload=b"the-payload-itself")
    finally:
        emitter.close()
    entries = store.read_range("local", from_sequence=1)
    captures = [entry.body.get("capture") for entry in entries if entry.kind == "effect"]
    return Crossing((double,), tuple(captures), lied=True)


def drive_evidence_store_read_range(**_: object) -> Crossing:
    """The read seam: a page is verified, then rendered for the caller."""
    honest = InMemoryEvidenceStore()
    for index in range(3):
        honest.append(
            EvidenceRecord(
                "local",
                "effect",
                AT,
                "connection-1",
                EvidencePrincipal("user", "example"),
                {
                    "capability": "example.effect",
                    "decision_id": f"decision-{index}",
                    "outcome": "allow",
                    "decided_at": "2026-09-04T00:00:00Z",
                    "policy_version": "policy-1",
                },
            )
        )
    doubles: list[object] = []

    class Store:
        def latest_sequence(self, scope: str) -> int | None:
            return honest.latest_sequence(scope)

        def read_range(self, scope: str, **kwargs: object) -> tuple[object, ...]:
            entries = []
            for entry in honest.read_range(scope, **kwargs):  # type: ignore[arg-type]
                double = TwoFaced(entry, grace=1, lies={"connection_id": "another-connection"})
                doubles.append(double)
                entries.append(double)
            return tuple(entries)

        def location(self) -> StoreLocation:
            return honest.location()

        def append(self, record: EvidenceRecord) -> object:
            return honest.append(record)

    page = EvidenceReads(Store()).read_page(scope="local", from_sequence=1)  # type: ignore[arg-type]
    return Crossing(tuple(doubles), tuple(page["entries"]), lied=True)  # type: ignore[arg-type]


def drive_evidence_store_append(**_: object) -> Crossing:
    """The composition seam: the entry the store answers with at start."""
    honest = InMemoryEvidenceStore()
    doubles: list[object] = []

    class Store(InMemoryEvidenceStore):
        def append(self, record: EvidenceRecord) -> object:
            double = TwoFaced(honest.append(record), grace=1, lies={"scope": "another-scope"})
            doubles.append(double)
            return double

    sink = _ChainCompositionEvidence(Store(), clock=lambda: AT)  # type: ignore[arg-type]
    sink.record(scope="local", providers=())
    return Crossing(tuple(doubles), (sink.entry,) if sink.entry is not None else (), lied=True)


def drive_evidence_store_location(**_: object) -> Crossing:
    """Where the store says it keeps evidence, which the status answer repeats."""
    honest = InMemoryEvidenceStore()
    doubles: list[object] = []

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            double = TwoFaced(honest.location(), grace=1, lies={"kind": "another-kind"})
            doubles.append(double)
            return double  # type: ignore[return-value]

    emitter = EvidenceEmitter(Store(), clock=_Clock())
    try:
        kept = emitter.store_location
    finally:
        emitter.close()
    return Crossing(tuple(doubles), (kept,), lied=True)


def drive_evidence_store_latest_sequence(**_: object) -> Crossing:
    """The head of a chain: a number, which the page's cursor is computed from."""
    honest = InMemoryEvidenceStore()
    honest.append(
        EvidenceRecord(
            "local",
            "effect",
            AT,
            "connection-1",
            EvidencePrincipal("user", "example"),
            {
                "capability": "example.effect",
                "decision_id": "decision-1",
                "outcome": "allow",
                "decided_at": "2026-09-04T00:00:00Z",
                "policy_version": "policy-1",
            },
        )
    )
    kept: list[object] = []

    class Head(int):
        """A head that answers a different number the second time it is compared."""

        def __init__(self, _value: int) -> None:
            self.reads: dict[str, int] = {}
            kept.append(self)

    class Store(InMemoryEvidenceStore):
        def latest_sequence(self, scope: str) -> int | None:
            value = honest.latest_sequence(scope)
            return None if value is None else Head(value)

        def read_range(self, scope: str, **kwargs: object) -> tuple[object, ...]:
            return honest.read_range(scope, **kwargs)  # type: ignore[arg-type]

    page = EvidenceReads(Store()).read_page(scope="local", from_sequence=1)
    return Crossing((), (page["to_sequence"], page["next_from"]))


class _DecisionStore:
    VERSION = 1

    def __init__(self, doubles: list[object], root: Path | None = None) -> None:
        self.doubles = doubles
        self.root = root
        self.honest = Decision(
            "decision-1",
            "local",
            "example.effect",
            Outcome.ALLOW,
            Reason.POLICY_ALLOWS,
            "policy-1",
            None,
            "2026-09-04T00:00:00Z",
            None,
            1,
            {},
        )

    def append(self, decision: Decision) -> object:
        double = TwoFaced(DecisionPosition("store-1", 1), grace=1, lies={"position": 2})
        self.doubles.append(double)
        return double

    def get(self, scope: str, decision_ref: str) -> object:
        double = TwoFaced(self.honest, grace=1, lies={"scope": "another-scope"})
        self.doubles.append(double)
        return double

    def location(self) -> object:
        double = TwoFaced(
            StoreLocation(kind="file", root=self.root, retention="test"),
            grace=1,
            lies={"root": Path("/another/root")},
        )
        self.doubles.append(double)
        return double


def drive_decision_store_get(**_: object) -> Crossing:
    """Reading back a recorded decision, which the route writes to its caller."""
    from sayfirst_control_plane.adapters.api.decision_routes import DecisionRoutes

    doubles: list[object] = []
    store = _DecisionStore(doubles)

    class Service:
        decisions = store

    left, right = socket.socketpair()
    try:
        kept = DecisionRoutes(Service()).read_decision("local", "decision-1", left)  # type: ignore[arg-type]
    finally:
        left.close()
        right.close()
    return Crossing(tuple(doubles), (kept,), lied=True)


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


class _PolicyStore:
    VERSION = 1
    max_lifetime_seconds = 3600

    def __init__(
        self,
        doubles: list[object],
        *,
        protection: ProtectionVerdict | None = None,
        access: AccessVerdict | None = None,
        wrap: bool = True,
        raw: bytes = _POLICY,
    ) -> None:
        self.doubles = doubles
        #: Which authority this double answers for. A row that needs a rule of
        #: another outcome says so here rather than keeping a second store, so
        #: the bytes, the version and the rules it answers are one policy.
        self.raw = raw
        parsed = parse_policy(raw)
        assert isinstance(parsed, Policy)
        self.policy = parsed
        self.protection = protection or ProtectionVerdict(ProtectionState.PROTECTED)
        self.access = access or AccessVerdict(AccessState.NOT_WRITABLE)
        self.wrap = wrap

    def _double(self, honest: object, **lies: object) -> object:
        double = TwoFaced(honest, grace=1, lies=lies)
        self.doubles.append(double)
        return double

    def load(self) -> object:
        policy = self._double(self.policy, format=99) if self.wrap else self.policy
        loaded = LoadedPolicy(policy, policy_version(self.raw), AT, len(self.raw), self.raw)  # type: ignore[arg-type]
        return self._double(loaded, policy_version="another-version")

    def protection_at_start(self, expectation: ProtectionExpectation) -> object:
        return self._double(self.protection, reason="another-reason")

    def write_access_of(self, principal: object) -> object:
        return self._double(self.access, component=Path("/another/path"))


def drive_policy_store_load(**_: object) -> Crossing:
    """The authority every decision is evaluated against, and its version."""
    doubles: list[object] = []
    service = PolicyService(_PolicyStore(doubles), (_Projection([]),))  # type: ignore[arg-type]
    service.start(ProtectionExpectation.per_user(0))
    kept: list[object] = [service.load_for_decision()]
    service.status()
    kept.append(service.current_version)
    return Crossing(tuple(doubles), tuple(kept), lied=True)


def drive_policy_store_protection_at_start(**_: object) -> Crossing:
    """The verdict that decides whether the daemon starts at all."""
    doubles: list[object] = []
    store = _PolicyStore(
        doubles,
        protection=ProtectionVerdict(ProtectionState.EXPOSED, Path("/policy.toml"), "group_write"),
    )
    service = PolicyService(store, (_Projection([]),))  # type: ignore[arg-type]
    with pytest.raises(PolicyStartRefused):
        service.start(ProtectionExpectation.per_user(0))
    return Crossing(tuple(doubles), (), lied=True)


def drive_policy_store_write_access_of(**_: object) -> Crossing:
    """The system-mode check that a caller cannot rewrite the policy it invokes."""
    doubles: list[object] = []
    store = _PolicyStore(doubles, access=AccessVerdict(AccessState.WRITABLE, Path("/p"), "owner"))
    policy = PolicyService(store, (_Projection([]),))  # type: ignore[arg-type]
    policy.start(ProtectionExpectation.per_user(0))
    doubles.clear()
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        _DecisionStore([]),  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
        system_mode=True,
    )
    question = DecisionQuestion(
        _ask(),
        PolicyPrincipal("user", 1000, "alice", (1000,), ("alice",)),
    )
    answer = service.ask(question)
    return Crossing(tuple(doubles), (answer,), lied=True)


class _PolicyArchive:
    """An archive whose answers lie on a second read: the state, the bytes, the root."""

    VERSION = 1

    def __init__(self, doubles: list[object], tmp_path: Path | None = None) -> None:
        self.doubles = doubles
        self.tmp_path = tmp_path

    def _double(self, honest: object, **lies: object) -> object:
        double = TwoFaced(honest, grace=1, lies=lies)
        self.doubles.append(double)
        return double

    def keep(self, version: str, content: bytes) -> object:
        return self._double(
            ArchivedPolicy(version, ArchiveState.present, bytes(content)),
            state=ArchiveState.damaged,
            content=b"format = 1\n",
        )

    def read(self, version: str) -> object:
        return self._double(
            ArchivedPolicy(version, ArchiveState.present, _POLICY),
            state=ArchiveState.absent,
            content=b"format = 1\n",
        )

    def location(self) -> object:
        return self._double(
            StoreLocation(kind="file", root=self.tmp_path, retention="test"),
            root=Path("/another/root"),
        )


def drive_decision_store_append(**_: object) -> Crossing:
    """The position a store committed the record at, which the answer carries (C2)."""
    doubles: list[object] = []
    store = _PolicyStore([], wrap=False)
    policy = PolicyService(store, (_Projection([]),))  # type: ignore[arg-type]
    policy.start(ProtectionExpectation.per_user(0))
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        _DecisionStore(doubles),  # type: ignore[arg-type]
        GrantConnections(),
        settings=GrantSettings(),
    )
    answer = service.ask(
        DecisionQuestion(_ask(), PolicyPrincipal("user", 1000, "alice", (1000,), ("alice",)))
    )
    kept = (answer, getattr(answer, "position", None))
    return Crossing(tuple(doubles), kept, lied=True)


def drive_decision_store_location(tmp_path: Path, **_: object) -> Crossing:
    """Where the decision authority keeps its files, read for the grade (R6)."""
    doubles: list[object] = []
    store = _DecisionStore(doubles, tmp_path)

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            return StoreLocation(kind="file", root=tmp_path, retention="test")

    emitter = EvidenceEmitter(
        Store(),
        clock=_Clock(),
        path_access=_PathAccess([]),
        also_inspected=(store.location,),
    )
    try:
        evaluation = emitter.evaluation_for(
            "local",
            EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
            EvidencePrincipal("user", "example"),
            force=True,
        )
    finally:
        emitter.close()
    return Crossing(tuple(doubles), (evaluation,), lied=True)


class _RecoveryJournal:
    """A journal whose open records and location lie on a second read."""

    VERSION = 1

    def __init__(self, doubles: list[object], root: Path | None = None) -> None:
        self.doubles = doubles
        self.root = root
        self.closed: list[tuple[str, str]] = []

    def open_epoch(self, scope, epoch_id, *, store_id, from_sequence) -> None:  # type: ignore[no-untyped-def]
        return None

    def epoch_clean(self, scope, epoch_id, *, marker_sequence, marker_hash) -> None:  # type: ignore[no-untyped-def]
        self.closed.append((scope, epoch_id))

    def epoch_reconciled(self, scope, epoch_id, *, marker_sequence, marker_hash) -> None:  # type: ignore[no-untyped-def]
        self.closed.append((scope, epoch_id))

    def open_epochs(self, scope: str) -> tuple[object, ...]:
        if self.closed:
            return ()
        double = TwoFaced(
            JournalRecord(scope, 1, "epoch_open", "epoch-dead", "store-1", 1, None, None),
            grace=1,
            lies={"epoch_id": "another-epoch", "from_sequence": 99},
        )
        self.doubles.append(double)
        return (double,)

    def location(self) -> object:
        double = TwoFaced(
            StoreLocation(kind="file", root=self.root, retention="test"),
            grace=1,
            lies={"root": Path("/another/root")},
        )
        self.doubles.append(double)
        return double


def drive_recovery_journal_open_epochs(tmp_path: Path, **_: object) -> Crossing:
    """The epochs a previous life left open, which the next start declares unclean (C3)."""
    from sayfirst_control_plane.adapters.file.decision_store import FileDecisionStore
    from sayfirst_control_plane.application.recovery import RecoveryWriter

    doubles: list[object] = []
    chain = InMemoryEvidenceStore()
    chain.append(
        EvidenceRecord(
            "local",
            "composition",
            AT,
            "daemon",
            EvidencePrincipal("service", "daemon"),
            {"providers": [], "recording_epoch": "epoch-dead"},
        )
    )
    writer = RecoveryWriter(
        chain,
        FileDecisionStore(tmp_path / "evidence", recording_epoch="epoch-live"),
        _RecoveryJournal(doubles),  # type: ignore[arg-type]
        recording_epoch="epoch-live",
        clock=lambda: AT,
    )
    report = writer.reconcile_at_start("local")
    marker = chain.read_range("local", from_sequence=1)[-1]
    return Crossing(tuple(doubles), (report, marker), lied=True)


def drive_recovery_journal_location(tmp_path: Path, **_: object) -> Crossing:
    """Where the journal keeps its files, read for the grade (R6)."""
    doubles: list[object] = []
    journal = _RecoveryJournal(doubles, tmp_path)

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            return StoreLocation(kind="file", root=tmp_path, retention="test")

    emitter = EvidenceEmitter(
        Store(),
        clock=_Clock(),
        path_access=_PathAccess([]),
        also_inspected=(journal.location,),
    )
    try:
        evaluation = emitter.evaluation_for(
            "local",
            EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
            EvidencePrincipal("user", "example"),
            force=True,
        )
    finally:
        emitter.close()
    return Crossing(tuple(doubles), (evaluation,), lied=True)


def drive_policy_archive_keep(**_: object) -> Crossing:
    """The bytes a decision is taken on, kept before the decision is committed (A1)."""
    doubles: list[object] = []
    store = _PolicyStore([], wrap=False)
    policy = PolicyService(store, (_Projection([]),))  # type: ignore[arg-type]
    policy.start(ProtectionExpectation.per_user(0))
    service = DecisionService(
        policy,
        store,  # type: ignore[arg-type]
        _DecisionStore([]),  # type: ignore[arg-type]
        GrantConnections(),
        archive=_PolicyArchive(doubles),  # type: ignore[arg-type]
        settings=GrantSettings(),
    )
    answer = service.ask(
        DecisionQuestion(_ask(), PolicyPrincipal("user", 1000, "alice", (1000,), ("alice",)))
    )
    return Crossing(tuple(doubles), (answer,), lied=True)


def drive_policy_archive_read(**_: object) -> Crossing:
    """The attachment an export carries for a version its effects name (A6)."""
    doubles: list[object] = []
    reads = EvidenceReads(InMemoryEvidenceStore(), archive=_PolicyArchive(doubles))  # type: ignore[arg-type]
    attachments = reads.policy_attachments([policy_version(_POLICY)])
    return Crossing(tuple(doubles), tuple(attachments.values()), lied=True)


def drive_policy_archive_location(tmp_path: Path, **_: object) -> Crossing:
    """Where the archive keeps its files, read for the grade every verdict carries (R6)."""
    doubles: list[object] = []
    archive = _PolicyArchive(doubles, tmp_path)

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            return StoreLocation(kind="file", root=tmp_path, retention="test")

    emitter = EvidenceEmitter(
        Store(),
        clock=_Clock(),
        path_access=_PathAccess([]),
        also_inspected=(archive.location,),
    )
    try:
        evaluation = emitter.evaluation_for(
            "local",
            EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
            EvidencePrincipal("user", "example"),
            force=True,
        )
    finally:
        emitter.close()
    return Crossing(tuple(doubles), (evaluation,), lied=True)


def _ask():  # type: ignore[no-untyped-def]
    from sayfirst_contract.decisions import DecisionAsk

    return DecisionAsk(capability="example.effect", scope="local")


class _Projection:
    VERSION = 1
    KIND = "memory"

    def __init__(self, doubles: list[object]) -> None:
        self.doubles = doubles
        self._current: ProjectedPolicy | None = None

    def rebuild(self, loaded: LoadedPolicy) -> None:
        self._current = ProjectedPolicy(
            loaded.policy_version,
            loaded.policy.format,
            loaded.loaded_at,
            len(loaded.policy.rules),
            loaded.policy.rules,
        )

    def current(self) -> object:
        if self._current is None:
            return None
        double = TwoFaced(self._current, grace=1, lies={"policy_version": "another-version"})
        self.doubles.append(double)
        return double

    def clear(self) -> None:
        self._current = None


def drive_policy_projection_current(**_: object) -> Crossing:
    """What a projection says it holds, which the published status repeats."""
    doubles: list[object] = []
    service = PolicyService(_PolicyStore([], wrap=False), (_Projection(doubles),))  # type: ignore[arg-type]
    service.start(ProtectionExpectation.per_user(0))
    status = service.status()
    return Crossing(tuple(doubles), (status.projection,), lied=True)


class _Directory:
    VERSION = 1

    def __init__(self, doubles: list[object], *, member: str = "account") -> None:
        self.doubles = doubles
        self.member = member

    def account(self, uid: int) -> object:
        double = TwoFaced(Account("alice", 1000), grace=1, lies={"name": "somebody-else"})
        if self.member == "account":
            self.doubles.append(double)
        return double

    def group_ids(self, name: str, primary_gid: int) -> object:
        double = TwoFacedSequence((primary_gid, 900), grace=1)
        if self.member == "group_ids":
            self.doubles.append(double)
        return double

    def group_name(self, gid: int) -> object:
        answer = {1000: "alice", 900: "operators"}.get(gid)
        if answer is None:
            return None
        double = TwoFacedText(answer)
        if self.member == "group_name":
            self.doubles.append(double)
        return double


def _consult(member: str) -> tuple[list[object], object, object, tuple[object, ...]]:
    """The daemon's own resolution of one connection, as `Daemon._consult` does it.

    One crossing, not two: admission, the kind the configuration gives the
    account, and the principal every record carries all read the one answer the
    cache holds, so the whole sequence is driven here rather than each function
    on its own. That is what makes the read count mean something — the cache is
    where a directory's object used to be kept.
    """
    doubles: list[object] = []
    directory = _CachedDirectory(_Directory(doubles, member=member))  # type: ignore[arg-type]
    admit(
        credential=PEER,
        mode="system",
        daemon_uid=0,
        socket_gid=900,
        directory=directory,  # type: ignore[arg-type]
    )
    account, resolution = resolve_identity(directory, PEER.uid, PEER.gid)  # type: ignore[arg-type]
    principal = build_principal(
        PEER,
        account,
        resolution,
        kind=kind_for(account, {}),
        at="2026-09-04T00:00:00+00:00",
    )
    # What the cache holds is what the core kept, so it is inspected too: a
    # cache of the port's own objects is the same defect one layer down.
    held: tuple[object, ...] = (
        *directory._accounts.values(),
        *directory._group_ids.values(),
        *directory._group_names.values(),
    )
    return doubles, account, principal, held


def drive_account_directory_group_ids(**_: object) -> Crossing:
    """Which groups the host says an account belongs to: the admission list."""
    doubles, _, principal, held = _consult("group_ids")
    return Crossing(tuple(doubles), (*(principal.groups or ()), *held), lied=True)


def drive_account_directory_group_name(**_: object) -> Crossing:
    """What a group id is called, which every principal record carries."""
    doubles, _, principal, held = _consult("group_name")
    return Crossing(tuple(doubles), (*(principal.groups or ()), *held), lied=True)


def drive_account_directory_account(**_: object) -> Crossing:
    """Who the host says a uid is: admission, the kind, and the principal."""
    doubles, account, principal, held = _consult("account")
    return Crossing(tuple(doubles), (account, principal, *held), lied=True)


def drive_clock_now(**_: object) -> Crossing:
    """Every instant the daemon records comes through this port."""
    doubles: list[object] = []
    store = InMemoryEvidenceStore()
    emitter = EvidenceEmitter(store, clock=_Clock(doubles, grace=1))
    try:
        _emit_effect(emitter)
    finally:
        emitter.close()
    entries = store.read_range("local", from_sequence=1)
    return Crossing(tuple(doubles), tuple(entry.recorded_at for entry in entries), lied=True)


class _PathAccess:
    def __init__(self, doubles: list[object]) -> None:
        self.doubles = doubles

    def inspect(self, path: Path) -> object:
        double = TwoFaced(
            PathFacts(path, True, 0, 0, 0o755, False),
            grace=1,
            lies={"mode": 0o777, "acl_present": None},
        )
        self.doubles.append(double)
        return double


def drive_path_access_inspect(tmp_path: Path, **_: object) -> Crossing:
    """The operating-system facts an integrity grade is claimed from."""
    doubles: list[object] = []
    honest = InMemoryEvidenceStore()

    class Store(InMemoryEvidenceStore):
        def location(self) -> StoreLocation:
            return StoreLocation(kind="file", root=tmp_path, retention="test")

    emitter = EvidenceEmitter(Store(), clock=_Clock(), path_access=_PathAccess(doubles))
    try:
        evaluation = emitter.evaluation_for(
            "local",
            EvidenceConnection("connection-1", CallerAccess(1000, frozenset())),
            EvidencePrincipal("user", "example"),
            force=True,
        )
    finally:
        emitter.close()
    assert honest is not None
    return Crossing(tuple(doubles), (evaluation,), lied=True)


class _PeerIdentity:
    VERSION = 1

    def __init__(self, doubles: list[object]) -> None:
        self.doubles = doubles

    def establish(self, connection: object) -> object:
        double = TwoFaced(PEER, grace=1, lies={"uid": 0})
        self.doubles.append(double)
        return double


def drive_peer_identity_establish(tmp_path: Path, **_: object) -> Crossing:
    """What the kernel said about the process that called connect()."""
    doubles: list[object] = []
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = read_settings(
        {"socket": {"mode": "per_user", "path": str(root / "daemon.sock")}, "identity": {}},
        platform="linux",
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=_Directory([]),  # type: ignore[arg-type]
        peer_identity=_PeerIdentity(doubles),  # type: ignore[arg-type]
        clock=_Clock(),
    )
    left, right = socket.socketpair()
    try:
        identity = daemon.establish(left)
    finally:
        left.close()
        right.close()
    return Crossing(tuple(doubles), (identity.peer,), lied=True)


BOUNDARIES: tuple[Boundary, ...] = (
    Boundary("ApprovalProvider", "resume", drive_approval_provider_resume),
    Boundary("ApprovalProvider", "suspend", drive_approval_provider_suspend),
    Boundary("PrivacyRedactor", "redact", drive_privacy_redactor_redact),
    Boundary("EvidenceStore", "read_range", drive_evidence_store_read_range),
    Boundary("EvidenceStore", "append", drive_evidence_store_append),
    Boundary("EvidenceStore", "location", drive_evidence_store_location),
    Boundary("EvidenceStore", "latest_sequence", drive_evidence_store_latest_sequence),
    Boundary("DecisionStore", "get", drive_decision_store_get),
    Boundary("DecisionStore", "append", drive_decision_store_append),
    Boundary("DecisionStore", "location", drive_decision_store_location),
    Boundary("PolicyStore", "load", drive_policy_store_load),
    Boundary("PolicyStore", "protection_at_start", drive_policy_store_protection_at_start),
    Boundary("PolicyStore", "write_access_of", drive_policy_store_write_access_of),
    Boundary("PolicyArchive", "keep", drive_policy_archive_keep),
    Boundary("PolicyArchive", "read", drive_policy_archive_read),
    Boundary("PolicyArchive", "location", drive_policy_archive_location),
    Boundary("RecoveryJournal", "open_epochs", drive_recovery_journal_open_epochs),
    Boundary("RecoveryJournal", "location", drive_recovery_journal_location),
    Boundary("PolicyProjection", "current", drive_policy_projection_current),
    Boundary("AccountDirectory", "account", drive_account_directory_account),
    Boundary("AccountDirectory", "group_ids", drive_account_directory_group_ids),
    Boundary("AccountDirectory", "group_name", drive_account_directory_group_name),
    Boundary("Clock", "now", drive_clock_now),
    Boundary("PathAccess", "inspect", drive_path_access_inspect),
    Boundary("PeerIdentity", "establish", drive_peer_identity_establish),
)

IDS = [item.name for item in BOUNDARIES]


@pytest.mark.parametrize("boundary", BOUNDARIES, ids=IDS)
def test_no_member_of_a_port_s_value_is_read_twice(boundary: Boundary, tmp_path: Path) -> None:
    """Articles 3, 8 and 12: a member read twice is a member answered twice."""
    crossing = boundary.drive(tmp_path=tmp_path)
    for double in crossing.doubles:
        again = double.read_more_than_once()  # type: ignore[attr-defined]
        assert not again, f"{boundary.name} read {sorted(again)} more than once"


@pytest.mark.parametrize("boundary", BOUNDARIES, ids=IDS)
def test_the_core_never_keeps_the_object_a_port_returned(
    boundary: Boundary, tmp_path: Path
) -> None:
    """Article 3: what the core records and hands on is the core's own value."""
    crossing = boundary.drive(tmp_path=tmp_path)
    for kept in crossing.kept:
        for double in crossing.doubles:
            assert kept is not double, f"{boundary.name} handed on the port's own object"


def _protocol_names(path: Path) -> set[str]:
    """Every Protocol a port module declares, read from the source itself."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(
            isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases
        ):
            names.add(node.name)
    return names


def test_every_boundary_of_the_core_has_a_row() -> None:
    """A port added later without a row of this table fails here, not in review."""
    declared: set[str] = set()
    for module in sorted((CONTROL_PLANE / "ports").glob("*.py")):
        declared |= _protocol_names(module)
    declared |= _protocol_names(CONTROL_PLANE / "plugins" / "interfaces.py")
    declared |= {"PeerIdentity"}
    covered = {item.interface for item in BOUNDARIES}
    assert declared <= covered, f"no two-faced double for {sorted(declared - covered)}"


def test_every_row_names_a_member_the_interface_declares() -> None:
    """A row cannot drift onto a member no port has."""
    for boundary in BOUNDARIES:
        assert boundary.member.isidentifier()
    assert len({item.name for item in BOUNDARIES}) == len(BOUNDARIES)


def _members(interface: str) -> Sequence[str]:
    return [item.member for item in BOUNDARIES if item.interface == interface]


def _answers_a_value(function: ast.FunctionDef) -> bool:
    """Whether this member of a port hands anything back at all.

    A member annotated `-> None` carries no value into the core, so there is
    nothing for the core to keep, and no row to write. Every other member does,
    and an unannotated one is treated as though it did.
    """
    returns = function.returns
    return not (isinstance(returns, ast.Constant) and returns.value is None)


def test_the_table_names_every_member_that_answers_a_value() -> None:
    """Every member of a port that answers anything is a place a value crosses.

    This is the half of the guard that survives the next block: a port added
    later, or a member added to one, has no row here and fails, rather than
    being noticed in a review three rounds on.
    """
    missing: list[str] = []
    modules = [
        *sorted((CONTROL_PLANE / "ports").glob("*.py")),
        CONTROL_PLANE / "plugins" / "interfaces.py",
    ]
    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases):
                continue
            for item in node.body:
                if not isinstance(item, ast.FunctionDef) or item.name.startswith("_"):
                    continue
                if _answers_a_value(item) and item.name not in _members(node.name):
                    missing.append(f"{node.name}.{item.name}")
    assert missing == [], f"no two-faced double for {missing}"


_UNUSED = field  # keep the dataclasses import honest for a future row
