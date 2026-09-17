# SPDX-License-Identifier: Apache-2.0
"""The one place the blocks of the skeleton are composed into a running daemon.

Every block published a port and an adapter behind it; none of them published a
composition, and an operation nothing composes is an operation nothing serves.
This module is that composition and nothing else: it reads the deployment's own
configuration, builds each block's adapter through the port that block
published, and hands the result to the socket surface. It reaches into no
block's internals — that is what article 4's port rule is for, and it is the
only reason the four blocks could be written apart.

Composition is a deployment's choice, not a build-time fact. A deployment that
names no policy authority composes none, and the surface answers the operations
that would need one as operations it does not serve, rather than answering an
absence as an empty policy (articles 2 and 3). A deployment that names one and
cannot have it does not start at all: a daemon that cannot decide, cannot
record, or does not know what it composed serves nobody.

It is performed by the account the daemon runs as (rule L2a). In system mode
that account is not the one that bound the address: root binds, then drops,
and root is refused nothing, so a policy read as root and a chain file created
as root prove nothing about the daemon that serves. The socket surface calls
`compose` after the drop and before it listens, and every check here is made
by the account whose access it claims (article 2).
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

from sayfirst_contract.plugins import ComposedProvider, composition_body

from .adapters.api.approval_routes import ApprovalRoutes
from .adapters.api.decision_routes import DecisionRoutes
from .adapters.api.evidence_routes import EvidenceRoutes
from .adapters.file.configuration import FileConfiguration
from .adapters.file.decision_store import FileDecisionStore, RootHeldByAnotherWriter
from .adapters.file.evidence_store import FileEvidenceStore
from .adapters.file.policy_archive import FilePolicyArchive
from .adapters.file.policy_store import FilePolicyStore
from .adapters.file.recovery_journal import FileRecoveryJournal
from .adapters.memory.policy_projection import MemoryPolicyProjection
from .adapters.posix.path_access import PosixPathAccess
from .adapters.socket_server import ancestor_facts_of, create_parent_directory, has_access_acl
from .application.approvals import ApprovalStore, SimpleApprovalProvider
from .application.decisions import DecisionService, GrantSettings
from .application.events import BoundedEvents
from .application.evidence_emitter import EvidenceEmitter
from .application.evidence_reads import EvidenceReads
from .application.grants import GrantConnections
from .application.policy import PolicyService, PolicyStartRefused
from .application.recovery import ReconciliationReport, RecoveryWriter
from .domain.directory_protection import ancestors_protection
from .domain.evidence_chain import (
    DAEMON_CONNECTION,
    PREIMAGE_VERSION,
    EvidenceEntry,
    EvidenceRecord,
    core_owned_entry,
    preimage,
)
from .domain.evidence_chain import Principal as ChainPrincipal
from .domain.foreign import core_owned_instant
from .plugins.activation import ActivatedProvider, activate_plugins
from .plugins.composition import (
    PRIVACY_REDACTOR_INTERFACE,
    CompositionEvidence,
    EvidencePrincipal,
    PluginComposition,
    compose_plugins,
)
from .plugins.configuration import PluginConfiguration
from .plugins.discovery import PluginEntryPoint, discover_plugins
from .plugins.errors import InvalidCompositionEvidence, PluginCompositionError
from .plugins.interfaces import PrivacyRedactor
from .ports.decision_store import DecisionStoreUnavailable
from .ports.evidence_store import EvidenceStore
from .ports.policy_archive import ArchiveState
from .ports.policy_store import ProtectionExpectation, ProtectionState
from .ports.recovery_journal import RecoveryJournalUnavailable
from .settings import SYSTEM, Settings, StartRefused

COMPOSITION_SCOPE = "local"
"""The scope the composition record is written to (article 5: an opaque name)."""

LOG_START = logging.getLogger("sayfirst_control_plane.daemon")
"""Where a start note that refuses nothing is recorded (rule P1)."""


def _this_account(settings: Settings) -> str:
    """The account performing a check, as a refusal names it (articles 2 and 3).

    What is named is the effective uid of the process making the check — the
    truth about who looked — and, in system mode, the `run_as` name the
    deployment gave, so an operator reads the account they configured beside
    the id the kernel enforced.
    """
    uid = os.geteuid()
    if settings.mode == SYSTEM and settings.run_as:
        return f"{settings.run_as} (uid {uid}), the account the daemon runs as after the drop"
    return f"uid {uid}, the account the daemon runs as"


def minimised_providers(providers: tuple[ComposedProvider, ...]) -> dict[str, object]:
    """The composition body the published evidence-entry schema defines.

    Article 11: the chain records the interface, its version and the provider
    that answers it, and nothing else. `sayfirst_contract.plugins` shapes the
    same composition with four members more — the distribution, its version,
    the entry point and the content digest — which the chain's own published
    schema refuses. The two shapes are both published and neither is derivable
    from the other, so this writes the one the chain publishes and leaves the
    reconciliation to the change that owns it (article 13).
    """
    return {
        "providers": [
            {
                "interface": item.interface,
                "version": item.version,
                "provider": item.provider,
            }
            for item in providers
        ]
    }


class _ChainCompositionEvidence:
    """Record the composition before anything is served, in both published shapes.

    Article 8 asks for the resolved composition to be recorded and article 10
    owns the chain that records it, so the entry that is *kept* is the one the
    domain schema publishes for the `composition` kind — the minimised one.
    The value handed back to block 2.5's composition is the shape that block
    publishes, hashed over its own body by the same pinned recipe, and it is
    nobody's chain entry: this daemon neither persists it nor serves it. Its
    own module already says so — "the chain that would verify the hashes is
    the evidence block's, not this one's". Claiming the kept entry's hash for
    a body that entry does not carry would be the stronger claim article 2
    forbids.
    """

    def __init__(
        self,
        store: EvidenceStore,
        *,
        clock: Callable[[], datetime],
        recording_epoch: str | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._epoch = recording_epoch
        #: What the store said it appended, as this daemon's own value: the
        #: store owns the object it answered with, and this keeps it (article 3).
        self.entry: EvidenceEntry | None = None

    def record(self, *, scope: str, providers: tuple[ComposedProvider, ...]) -> CompositionEvidence:
        principal = ChainPrincipal("service", "daemon")
        recorded_at = core_owned_instant(self._clock())
        kept_body = minimised_providers(providers)
        if self._epoch is not None:
            kept_body["recording_epoch"] = self._epoch
        appended = EvidenceRecord(
            scope,
            "composition",
            recorded_at,
            DAEMON_CONNECTION,
            principal,
            kept_body,
        )
        try:
            answered = self._store.append(appended)
        except OSError as error:
            # The first append of the daemon's life, made by the account it
            # runs as: a store that account cannot append to is not a pipeline
            # with a first entry, it is one with a permanent gap (article 10).
            raise StartRefused(
                "evidence_root_unusable",
                f"{_root_of(self._store)}: the account the daemon runs as "
                f"(uid {os.geteuid()}) cannot append to the evidence store: {error}",
            ) from error
        self.entry = core_owned_entry(answered)
        placed = _placed_by_the_store(appended, self.entry)
        body = composition_body(providers)
        return CompositionEvidence(
            scope=scope,
            kind="composition",
            recorded_at=recorded_at,
            connection_id=DAEMON_CONNECTION,
            principal=EvidencePrincipal(kind=principal.kind, id=principal.id),
            body=body,
            sequence=placed.sequence,
            previous_hash=placed.previous_hash,
            entry_hash=sha256(
                preimage(
                    scope=scope,
                    sequence=placed.sequence,
                    kind="composition",
                    recorded_at=recorded_at,
                    connection_id=DAEMON_CONNECTION,
                    principal=principal,
                    body=body,
                    previous_hash=placed.previous_hash,
                )
            ).hexdigest(),
            preimage_version=PREIMAGE_VERSION,
        )


def _root_of(store: EvidenceStore) -> str:
    """Where the store keeps its chains, as the store itself says (article 3)."""
    try:
        return str(store.location().root)
    except Exception:  # pragma: no cover - a store that cannot say where it is
        return "the evidence store"


def _placed_by_the_store(appended: EvidenceRecord, entry: EvidenceEntry) -> EvidenceEntry:
    """The store's answer, once it is an answer about the record it was handed.

    The chain is the authority for where an entry sits (article 3): the store
    accepts the write and decides the sequence and the link, and the only way
    to know either is to read what it answered with. The daemon does not start
    on an empty chain every time — a restart appends after everything the scope
    already holds — so a record built on `sequence=1, previous_hash=None` is a
    position nobody read, in the one place where provenance is the whole value
    (articles 2 and 10).

    Reading it means reading it from an answer about this record. A store that
    answers about something else has said nothing about where this composition
    landed, and there is no third option between the position and a refusal, so
    this refuses and the daemon does not start.
    """
    given = (
        appended.scope,
        appended.kind,
        appended.recorded_at,
        appended.connection_id,
        appended.principal,
        dict(appended.body),
    )
    answered = (
        entry.scope,
        entry.kind,
        entry.recorded_at,
        entry.connection_id,
        entry.principal,
        dict(entry.body),
    )
    if given != answered:
        raise InvalidCompositionEvidence(
            "the evidence store did not answer about the composition it was given"
        )
    return entry


def _protected_configuration(settings: Settings, *, administrator_gid: int | None) -> None:
    """Refuse a system-mode configuration anyone but its administrators could rewrite.

    Article 8: "at start, the daemon refuses a configuration that anyone but
    root or its administrator group could write or replace". The expectation is
    the one the policy authority is held to in the same mode, and the walk is
    the same walk — `access/effective_access.py`, through the adapter in
    `adapters/file/configuration.py` — because the two files are protected by
    one rule and a second reading of it would be a second answer.

    Three cases and one answer. A per-user daemon is not asked: the rule is
    system mode's, and the article says so. A deployment that named no
    configuration file has no name to check, and a check of a name nothing read
    would be a claim about the wrong file (article 2). And a verdict of
    `unknown` — a name that could not be looked at, an access control list that
    could not be read — refuses like an exposed one, because an unknown is
    never a pass (article 3).
    """
    if settings.mode != SYSTEM or not settings.configuration_path:
        return
    path = Path(settings.configuration_path)
    verdict = FileConfiguration(path).protection_at_start(
        ProtectionExpectation.system(administrator_gid or 0)
    )
    if verdict.kind is ProtectionState.PROTECTED:
        return
    raise StartRefused(
        "configuration_unprotected",
        f"{path} is {verdict.kind.value} at {verdict.component} ({verdict.reason}); in system "
        f"mode only root and the administrator group (gid {administrator_gid or 0}) may write or "
        f"replace the configuration, and whoever can write it chooses the address, the admission "
        f"group, the policy authority, the evidence root and the plugins; checked as "
        f"{_this_account(settings)}",
    )


def _system_evidence_root(
    evidence_root: Path,
    settings: Settings,
    *,
    daemon_uid: int,
    daemon_gid: int,
    platform: str,
) -> None:
    """Refuse an evidence root that is not the layout the packager owes (rule L2a).

    The packager creates the evidence root, owned by the daemon's own account
    and its own group at mode 0700, as it creates the socket's parent directory
    (rules L2 and L2a). A daemon that stood in for the packager would create it
    as root before the drop and be unable to write into it after, or fail to
    create it at all under a parent root owns; so the daemon never creates it,
    and the operator reads a layout to fix rather than a permission error.

    The layout is read literally, because article 7's evidence grade is one
    mode bit from untrue otherwise: "no principal but that one and root can
    write or replace the store". What decides the refusal is what other
    principals can effectively do with the directory — write it through the
    mode's group or other bits, inherit its group into every chain file through
    the setgid bit, reach it through an access control list — and not the
    owner alone. A root the governed principal owns, a daemon-owned root every
    account can write and a root carrying the admission group at `02700` were
    each accepted by a check that established only "is a directory", and each
    started and served.

    What could not be looked at is not a directory that is absent: a parent
    the dropped account cannot traverse refuses `stat` itself, and the refusal
    names that fact, the directory and the account (articles 2 and 3), rather
    than a traceback at exit 1 or a claim the daemon has no evidence for.

    The parents are held to the walk rule S4 makes for the socket's directory,
    because article 7 grades the store by "every parent directory that would
    allow it to be replaced": a correctly owned root under a world-writable
    parent was renamed away by a governed principal while the daemon served.
    """
    owner = settings.run_as or "root"
    owed = (
        f"in system mode the packager creates the evidence root, owned by {owner} "
        f"(uid {daemon_uid}, the account the daemon runs as) and its own group "
        f"(gid {daemon_gid}) at mode 0700, and the daemon never creates or changes it"
    )

    def refused(fact: str) -> StartRefused:
        return StartRefused("evidence_root_unusable", f"{evidence_root} {fact}; {owed}")

    try:
        st = os.stat(evidence_root)
    except FileNotFoundError:
        raise refused("does not exist") from None
    except OSError as error:
        raise refused(
            f"could not be looked at: access could not be established by "
            f"{_this_account(settings)}: {error}"
        ) from error
    if not stat.S_ISDIR(st.st_mode):
        raise refused("is not a directory")
    if st.st_uid != daemon_uid:
        raise refused(f"is owned by uid {st.st_uid}, not by {owner} (uid {daemon_uid})")
    if st.st_gid != daemon_gid:
        raise refused(f"carries group {st.st_gid}, not {owner}'s own group (gid {daemon_gid})")
    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o700:
        raise refused(f"carries mode {oct(mode)}, not 0700")
    acl = has_access_acl(evidence_root, platform)
    if acl is None and platform == "linux":
        # A check that could not run is not a check that passed (article 2):
        # the directory's true reach is unverified, so the daemon fails closed,
        # as it does for the socket's directory.
        raise refused("carries an access control list that could not be read")
    if acl:
        raise refused("carries an access control list, which widens it beyond its mode")
    try:
        ancestors = ancestor_facts_of(evidence_root, platform)
    except OSError as error:
        raise refused(
            f"has a parent that could not be looked at: access could not be established by "
            f"{_this_account(settings)}: {error}"
        ) from error
    replaceable = ancestors_protection(ancestors, daemon_uid=daemon_uid, platform=platform)
    if replaceable is not None:
        raise refused(f"can be replaced through its parents: {replaceable}")


def _prove_the_chains(store: FileEvidenceStore, named: set[str], settings: Settings) -> None:
    """Prove, as this account, every chain in the store and the directory itself (rule L2a).

    The composition record proved one append through one creation descriptor.
    A daemon that serves claims more than that (article 2): that it can reopen
    the chain it created, that it can create a chain in the directory, and
    that a chain already there is one it can append to. Each was found false
    once — a chain at mode 000 under a permissive umask, a `0500` root, an
    `audit.jsonl` owned by root — and the permissions never repair themselves,
    so a daemon that cannot record is refused here, by the file's name, rather
    than left retrying for the rest of its life (article 10).

    What is proved is what is there, not one chain per scope a request may
    name: the scope is the caller's field, and no start check can enumerate
    it. A root-owned `audit.jsonl` beside a policy that named `local` alone
    was left unproved by a check over the policy's scopes, and the deny served
    for `audit` was never recorded. So every chain already in the root is
    reopened for append, whatever scope it belongs to; a chain for any other
    scope is created on first use, in a directory the layout rule above proved
    this account owns and no other principal can write or replace. The chains
    of the scopes `named` — the current policy's — are created here as well,
    so an operator sees them before the first decision; that is a convenience
    the proof does not rest on.
    """
    try:
        present = store.chains_present()
    except OSError as error:
        raise StartRefused(
            "evidence_root_unusable",
            f"{error.filename}: {_this_account(settings)} cannot list the chains there "
            f"({error.strerror})",
        ) from error
    for scope in sorted({*present, *named}):
        try:
            store.prepare_chain(scope)
        except OSError as error:
            raise StartRefused(
                "evidence_root_unusable",
                f"{error.filename}: {_this_account(settings)} cannot keep the chain for "
                f"scope {scope!r} there ({error.strerror})",
            ) from error


@dataclass(frozen=True)
class ComposedServices:
    """Everything the socket surface needs beyond the connection it answers on."""

    policy: PolicyService
    decisions: DecisionService
    decision_routes: DecisionRoutes
    approval_routes: ApprovalRoutes
    evidence_routes: EvidenceRoutes
    emitter: EvidenceEmitter
    store: EvidenceStore
    composition: PluginComposition
    #: What the daemon did while this process has been up, bounded and
    #: readable. An observation and never evidence (article 3): the chain is
    #: the authority for what was decided, and this is the same object the
    #: services record into, so an operator and a test read one sink.
    events: BoundedEvents
    #: The durable authorities block 2.7 composes beside the chain, and the
    #: recording epoch every body of this run names (C3).
    decision_store: FileDecisionStore | None = None
    archive: FilePolicyArchive | None = None
    recovery: RecoveryWriter | None = None
    recording_epoch: str = ""

    def close(self) -> None:
        """Stop what the composition started, in the order it was started in.

        The emitter drains first; only a drain that completed lets an epoch
        close cleanly (C3). One that did not leaves its epoch open in the
        journal, and the next start declares it unclean — never a clean marker
        over evidence that may still have been in a queue.
        """
        self.decisions.grants.shutdown()
        drained = self.emitter.close()
        if self.recovery is not None and drained:
            for scope in sorted(self.recovery.opened_scopes):
                with suppress(Exception):
                    self.recovery.close_clean(scope)
        if self.decision_store is not None:
            self.decision_store.close()

    def decision_store_status(self) -> dict[str, object]:
        """The `decision_store` member of the status result (articles 2 and 3).

        Each scope carries what its last reconciliation found, with the time
        and cursors of that reconciliation; a scope none ran on is `not_run`
        with null cursors and null counts, never zeros.
        """
        if self.decision_store is None:
            return {"store": "memory", "reconciliations": []}
        try:
            scopes = sorted(self.decision_store.scopes_present())
        except OSError:
            return {"store": "unknown", "reconciliations": []}
        reports = {} if self.recovery is None else self.recovery.reports
        return {
            "store": "file",
            "reconciliations": [
                (
                    reports[scope] if scope in reports else ReconciliationReport.not_run(scope)
                ).to_document()
                for scope in sorted({*scopes, *reports})
            ],
        }


def compose(
    settings: Settings,
    *,
    daemon_uid: int,
    daemon_gid: int | None = None,
    administrator_gid: int | None = None,
    platform: str = sys.platform,
    clock: Callable[[], datetime] | None = None,
    entry_points: Iterable[PluginEntryPoint] | None = None,
) -> ComposedServices | None:
    """Compose the blocks this deployment configured, or `None` when it configured none.

    Called as the account the daemon runs as, after the drop in system mode
    (rule L2a). The layout the packager owes is checked first, then the
    authority is read by the account that will read it for every decision,
    then the store is opened and the composition appended by the account that
    will append every record after it. Each refusal names what it found and
    who found it.

    The configuration is checked before any of it, including before the early
    return for a deployment that named no policy authority. Whoever can write
    that file chooses the address, the admission group, which file is the
    policy authority, where the evidence is kept and which plugins are
    composed — so a start that checked the files the configuration named and
    not the configuration itself would have checked whatever the writer chose
    (article 8).
    """
    _protected_configuration(settings, administrator_gid=administrator_gid)
    if not settings.policy_path:
        return None
    evidence_root = Path(settings.evidence_root)
    if settings.mode == SYSTEM:
        _system_evidence_root(
            evidence_root,
            settings,
            daemon_uid=daemon_uid,
            daemon_gid=os.getegid() if daemon_gid is None else daemon_gid,
            platform=platform,
        )
    else:
        # A per-user daemon creates its own, every level at 0700 whatever the
        # umask, as it creates its socket's parent directory (rule L2).
        try:
            create_parent_directory(evidence_root, 0o700)
        except OSError as error:
            raise StartRefused("evidence_root_unusable", f"{evidence_root}: {error}") from error
    now = clock or (lambda: datetime.now(UTC))
    grants = GrantSettings()
    authority = FilePolicyStore(
        Path(settings.policy_path),
        max_lifetime_seconds=grants.max_lifetime_seconds,
        clock=now,
    )
    policy = PolicyService(authority, (MemoryPolicyProjection(),), clock=now)
    expectation = (
        ProtectionExpectation.system(administrator_gid or 0)
        if settings.mode == SYSTEM
        else ProtectionExpectation.per_user(daemon_uid)
    )
    try:
        policy.start(expectation)
    except PolicyStartRefused as refusal:
        raise StartRefused(
            "policy_unavailable_at_start", f"{refusal}; checked as {_this_account(settings)}"
        ) from refusal

    try:
        store = FileEvidenceStore(evidence_root)
    except OSError as error:
        raise StartRefused("evidence_root_unusable", f"{evidence_root}: {error}") from error
    recording_epoch = f"epoch:{uuid4()}"
    _prove_the_chains(store, {COMPOSITION_SCOPE, *policy.scopes_reached}, settings)
    decision_store, archive = _durable_authorities(
        evidence_root, policy, settings, recording_epoch=recording_epoch
    )

    # The providers are discovered and activated before the pipeline is built,
    # so the redactor the emitter holds is the one the configuration names;
    # the composition record itself is appended after recovery, inside the
    # epoch this life opened, so no event lands in an unopened epoch (C3).
    configuration = (
        PluginConfiguration.from_mapping({"plugins": settings.plugin_selection})
        if settings.plugin_selection
        else PluginConfiguration.defaults()
    )
    try:
        activated = activate_plugins(discover_plugins(entry_points), configuration)
    except (PluginCompositionError, ValueError, OSError) as error:
        decision_store.close()
        raise StartRefused("plugin_composition_refused", str(error)) from error
    redactor = _privacy_redactor_of(activated, decision_store)
    journal = FileRecoveryJournal(evidence_root)
    emitter = EvidenceEmitter(
        store,
        path_access=PosixPathAccess(),
        privacy_redactor=redactor,
        also_inspected=(decision_store.location, archive.location, journal.location),
        recording_epoch=recording_epoch,
    )
    recovery = RecoveryWriter(
        store,
        decision_store,
        journal,
        recording_epoch=recording_epoch,
        clock=now,
        daemon_grade=emitter.daemon_grade_record,
        archive=archive,
    )
    emitter.before_first_event = recovery.open_epoch
    try:
        _recover_and_open(recovery, journal, store, decision_store, settings)
        try:
            composition = compose_plugins(
                activated,
                _ChainCompositionEvidence(store, clock=now, recording_epoch=recording_epoch),
                scope=COMPOSITION_SCOPE,
            )
        except (PluginCompositionError, ValueError, OSError) as error:
            raise StartRefused("plugin_composition_refused", str(error)) from error
        if composition.privacy_redactor is not redactor:
            raise StartRefused(
                "plugin_composition_refused",
                "the composed PrivacyRedactor is not the one the evidence pipeline holds",
            )
    except StartRefused:
        emitter.close(timeout=1)
        decision_store.close()
        raise
    # Where a suspension waits, and who takes it up. The provider is the one
    # the registry composed and the composition record names, so the provider
    # an operator configured is the provider that judges the acts (article 2:
    # one daemon, one name). The store is reached afterwards through the
    # service that holds it, the way the grant registry is — the reads of a
    # suspended approval, the act that ends one, and the sweep that ends a wait
    # that ran out are all served from this one store, because a second store
    # is a second authority and two authorities disagree (article 3).
    #
    # The store is this root's, on this deployment's clock, because the wait's
    # deadline and the decision that names it must be measured by one clock. A
    # plugin registration's factory takes no arguments, so the shipped provider
    # was built before the clock was known and adopts the store here. A
    # provider from elsewhere keeps whatever records it likes and this store is
    # still the daemon's: the question a re-ask is matched by is established
    # here, from the connection and the ask, and is never taken from a provider
    # — and ending a wait is the core's write, not the provider's, so which
    # provider was composed changes who judges an act and never whether the
    # wait it ends is ended (`application/approvals.write_resolution`).
    approval_provider = composition.approval_provider
    approvals = ApprovalStore(clock=now)
    # What the daemon did, kept where somebody can read it. It used to be
    # composed nowhere, so `approval.resolved`, `approval.expired`,
    # `decision.recorded` and every other entry the core records went to a
    # no-op: a mechanism indistinguishable from absent, which is what the
    # audit of 2026-09-06 called the defect it was looking for. It is bounded
    # and it declares what it dropped (article 10), and it is an observation
    # and never evidence — no decision is taken from it and a restart empties
    # it (article 3).
    events = BoundedEvents()
    if isinstance(approval_provider, SimpleApprovalProvider):
        approval_provider.keep_waits_in(approvals)
    decisions = DecisionService(
        policy,
        authority,
        decision_store,
        GrantConnections(),
        archive=archive,
        settings=grants,
        system_mode=settings.mode == SYSTEM,
        # The second of article 8's two protections of the configuration: the
        # same walk the start made, made again per decision request, because a
        # file protected when the daemon started can be opened up while it
        # serves. The path travels beside the check so the refusal names the
        # file the deployment gave and not only the component that granted the
        # write, which may be a directory above it.
        configuration_access=(
            FileConfiguration(Path(settings.configuration_path)).write_access_of
            if settings.configuration_path
            else None
        ),
        configuration_path=settings.configuration_path,
        approvals=approvals,
        approval_provider=approval_provider,
        events=events,
        clock=now,
    )
    return ComposedServices(
        policy=policy,
        decisions=decisions,
        decision_routes=DecisionRoutes(decisions),
        # Over the service, because the service composes the store and the
        # provider as a pair and refuses the halves: the routes read the one
        # store the ask path opens waits in, on the one clock this deployment
        # runs on.
        approval_routes=ApprovalRoutes(decisions),
        evidence_routes=EvidenceRoutes(EvidenceReads(store, emitter=emitter, archive=archive)),
        emitter=emitter,
        store=store,
        composition=composition,
        events=events,
        decision_store=decision_store,
        archive=archive,
        recovery=recovery,
        recording_epoch=recording_epoch,
    )


def _privacy_redactor_of(
    activated: tuple[ActivatedProvider, ...], decision_store: FileDecisionStore
) -> PrivacyRedactor:
    """The activated redactor, refused by name when it answers as another provider.

    The composition evidence carries the registration's name; the status
    surface and every capture record carry the instance's. One daemon, one
    name (article 2), so a provider that registers as one and answers as
    another is refused before anything is served, and a configuration that
    activates no redactor is refused here rather than after recovery.
    """
    for item in activated:
        if item.registration.interface_name != PRIVACY_REDACTOR_INTERFACE:
            continue
        registered = item.registration.provider_name
        if str(getattr(item.instance, "name", "")) != registered:
            decision_store.close()
            raise StartRefused(
                "plugin_composition_refused",
                f"the composed PrivacyRedactor provider {registered!r} answers as "
                f"{str(getattr(item.instance, 'name', ''))!r}; the name on the chain and the "
                "name on the status surface must be one name",
            )
        return cast(PrivacyRedactor, item.instance)
    decision_store.close()
    raise StartRefused(
        "plugin_composition_refused", f"no active provider for {PRIVACY_REDACTOR_INTERFACE!r}"
    )


def _recover_and_open(
    recovery: RecoveryWriter,
    journal: FileRecoveryJournal,
    store: FileEvidenceStore,
    decision_store: FileDecisionStore,
    settings: Settings,
) -> None:
    """Reconcile every scope the root knows, then open this life's epochs (S9, C3).

    The union of scopes in chain files, decision files and journals, and the
    local scope the composition writes to: each is reconciled before anything
    is served — an epoch the previous life left open is declared unclean and
    its lost decisions named — and the local scope, and any scope recovery
    wrote to, is opened for this life before the composition record, so no
    event is ever accepted into an unopened epoch. Every other scope opens on
    its first event.
    A journal the daemon cannot read or append is a start refusal by name; a
    historical discrepancy is a status fact and refuses nothing.
    """
    try:
        scopes = {
            COMPOSITION_SCOPE,
            *store.chains_present(),
            *decision_store.scopes_present(),
            *journal.scopes_present(),
        }
        for scope in sorted(scopes):
            journal.recover(scope)
            # This life's epoch opens before its recovery writes, so the grade
            # and the markers recovery appends fall inside a span this life's
            # own clean stop will close; an epoch the previous life left open
            # is then closed over the entries that life produced. A scope with
            # nothing to recover is opened only when its first event arrives,
            # by the emitter's hook, so a chain that saw nothing gains nothing.
            if scope == COMPOSITION_SCOPE or journal.open_epochs(scope):
                recovery.open_epoch(scope)
            recovery.reconcile_at_start(scope)
    except (RecoveryJournalUnavailable, OSError) as error:
        raise StartRefused(
            "recovery_store_unusable",
            f"{journal.location().root}: {_this_account(settings)} cannot keep the "
            f"recovery journal: {error}",
        ) from error


def _durable_authorities(
    evidence_root: Path, policy: PolicyService, settings: Settings, *, recording_epoch: str
) -> tuple[FileDecisionStore, FilePolicyArchive]:
    """The decision authority and the policy archive, proved usable as this account (S9).

    In order: the root writer lock, so a second daemon over one root is refused
    by name rather than allocating the first one's positions; every scope's
    decision file reopened and its torn tail recovered, so a malformed record
    is found now and named; the archive's orphan temporaries removed; and the
    start version archived before anything listens, so no decision can be
    taken on bytes nobody kept (A1, R4). Production with a policy always
    composes these; the memory store is for tests and policy-less composition.
    """
    decision_store = FileDecisionStore(
        evidence_root, exclusive=True, recording_epoch=recording_epoch
    )
    try:
        decision_store.hold_root()
    except RootHeldByAnotherWriter as error:
        raise StartRefused("decision_store_unusable", str(error)) from error
    except OSError as error:
        raise StartRefused(
            "decision_store_unusable",
            f"{evidence_root}: {_this_account(settings)} cannot hold the decision root: {error}",
        ) from error
    for scope in sorted(decision_store.scopes_present()):
        try:
            dropped = decision_store.recover(scope)
            decision_store.get(scope, "")
        except DecisionStoreUnavailable as error:
            # A scope the authority cannot serve is named at start and stays
            # visible in status; it refuses new decisions in that scope, not
            # the whole daemon, unless it is the one scope a decision needs.
            LOG_START.warning("decision store: %s", error)
        except OSError as error:
            raise StartRefused(
                "decision_store_unusable",
                f"{evidence_root}: {_this_account(settings)} cannot recover scope "
                f"{scope!r}: {error}",
            ) from error
        else:
            if dropped:
                LOG_START.warning(
                    "decision store: quarantined %d torn bytes of scope %r", dropped, scope
                )
    archive = FilePolicyArchive(evidence_root)
    try:
        archive.recover()
        current = policy.current_loaded
        if current.content is None:
            raise StartRefused(
                "policy_archive_unusable",
                "the policy authority supplied no bytes to archive for the start version",
            )
        kept = archive.keep(current.policy_version, current.content)
    except StartRefused:
        raise
    except (OSError, ValueError) as error:
        raise StartRefused(
            "policy_archive_unusable",
            f"{evidence_root}: {_this_account(settings)} cannot keep the start version: {error}",
        ) from error
    if kept.state is not ArchiveState.present:
        raise StartRefused(
            "policy_archive_unusable",
            f"{evidence_root}: the start policy version {kept.version} is {kept.state.value} "
            "in the archive, and a decision cannot be taken on bytes nobody can verify",
        )
    return decision_store, archive
