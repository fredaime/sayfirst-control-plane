# SPDX-License-Identifier: Apache-2.0
"""Bounded evidence pages, verification, and deterministic raw export."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from typing import Final

from sayfirst_contract.generation import CONTRACT_GENERATION

from sayfirst_control_plane.domain.evidence_chain import (
    ChainCondition,
    EvidenceEntry,
    Principal,
    canonical_json,
    core_owned_entry,
    entry_to_document,
    verify,
)
from sayfirst_control_plane.domain.evidence_chain import (
    verdict_to_document as verdict_to_document,
)
from sayfirst_control_plane.domain.evidence_export import MANIFEST_VERSION, manifest_digest
from sayfirst_control_plane.domain.foreign import core_owned
from sayfirst_control_plane.domain.integrity_grade import Grade
from sayfirst_control_plane.domain.scope import scope_matches_contract
from sayfirst_control_plane.ports.evidence_store import EvidenceStore
from sayfirst_control_plane.ports.policy_archive import ArchivedPolicy, ArchiveState, PolicyArchive

from .evidence_emitter import EvidenceConnection, EvidenceEmitter

PAGE_BOUND: Final = 100
EXPORT_BOUND: Final = 10_000
#: The bound on the canonical serialised whole response, attachments and
#: context included (A6): the largest contiguous prefix within it is served,
#: with complete attachments for its effects, never a split attachment or a
#: version silently omitted to fit.
EXPORT_BYTE_BOUND: Final = 32 * 1024 * 1024


class ScopeRequired(ValueError):
    code = "scope_required"


class ScopeInvalid(ValueError):
    """A malformed scope is a malformed request, never a permission refusal.

    `scope_refused` is registered as "the principal may not write this scope"
    (article 5, 403). These reads are GETs whose caller's permissions are never
    consulted, so answering that code for a scope that fails the syntax pattern
    would be a claim about something never evaluated (articles 2, 13).
    """

    code = "scope_invalid"


class EvidenceRangeInvalid(ValueError):
    code = "evidence_range_invalid"


class EvidenceStoreUnavailable(RuntimeError):
    code = "evidence_store_unavailable"


class EvidenceReads:
    def __init__(
        self,
        store: EvidenceStore,
        *,
        emitter: EvidenceEmitter | None = None,
        archive: PolicyArchive | None = None,
    ) -> None:
        self._store = store
        self._emitter = emitter
        #: Where an export reads the exact bytes of every policy version its
        #: effects name (A6). `None` composes no archive: every attachment is
        #: then `absent`, which the verifier reports, never a map left out.
        self._archive = archive

    def policy_attachments(self, versions: Iterable[str]) -> dict[str, dict[str, object]]:
        """One attachment per version, as the published export carries them.

        `present` carries the exact bytes, base64 without newlines; `absent`
        and `damaged` carry their state and nothing else. Storage the archive
        could not read is the export's failure, never an `absent` (A6, article
        2): the caller turns the `OSError` into `evidence_store_unavailable`.
        """
        attachments: dict[str, dict[str, object]] = {}
        for version in sorted(set(versions)):
            if self._archive is None:
                attachments[version] = {"state": ArchiveState.absent.value}
                continue
            answered = core_owned(
                ArchivedPolicy,
                self._archive.read(version),
                version=str,
                state=ArchiveState,
                content=lambda raw: None if raw is None else bytes(raw),
            )
            if answered.state is ArchiveState.present and answered.content is not None:
                attachments[version] = {
                    "state": ArchiveState.present.value,
                    "content": base64.b64encode(answered.content).decode("ascii"),
                }
            elif answered.state is ArchiveState.present:
                attachments[version] = {"state": ArchiveState.damaged.value}
            else:
                attachments[version] = {"state": answered.state.value}
        return attachments

    def read_page(
        self,
        *,
        scope: str | None,
        from_sequence: int,
        page_size: int = PAGE_BOUND,
        connection: EvidenceConnection | None = None,
        principal: Principal | None = None,
    ) -> dict[str, object]:
        actual_scope = _scope(scope)
        if from_sequence < 1 or not 1 <= page_size <= PAGE_BOUND:
            raise EvidenceRangeInvalid("evidence range is invalid")
        self._prepare(actual_scope, connection, principal)
        try:
            head = _core_owned_head(self._store.latest_sequence(actual_scope))
            if head is None or from_sequence > head:
                entries: tuple[EvidenceEntry, ...] = ()
                requested_end = None
                next_from = None
            else:
                requested_end = min(head, from_sequence + page_size - 1)
                entries = _core_owned(
                    self._store.read_range(
                        actual_scope,
                        from_sequence=from_sequence,
                        to_sequence=requested_end,
                    )
                )
                next_from = requested_end + 1 if requested_end < head else None
            grades_before = self._grades_before(actual_scope, from_sequence)
        except Exception as error:
            raise EvidenceStoreUnavailable("the evidence store could not be read") from error
        # The head said the store holds entries through `requested_end`, so a
        # page that stops short of it has a hole the verifier must see: an
        # undeclared gap is never a shorter clean page (article 10).
        verdict = verify(
            entries,
            scope=actual_scope,
            from_sequence=from_sequence,
            to_sequence=requested_end,
            grades_before=grades_before,
        )
        return {
            "contract_version": str(CONTRACT_GENERATION),
            "scope": actual_scope,
            "from_sequence": from_sequence,
            "to_sequence": verdict.to_sequence,
            "entries": [entry_to_document(item) for item in entries],
            "verification": verdict_to_document(verdict),
            "next_from": next_from,
        }

    def export(
        self,
        *,
        scope: str | None,
        from_sequence: int,
        to_sequence: int | None = None,
        connection: EvidenceConnection | None = None,
        principal: Principal | None = None,
    ) -> dict[str, object]:
        actual_scope = _scope(scope)
        if from_sequence < 1 or (to_sequence is not None and to_sequence < from_sequence):
            raise EvidenceRangeInvalid("evidence range is invalid")
        self._prepare(actual_scope, connection, principal)
        try:
            head = _core_owned_head(self._store.latest_sequence(actual_scope))
            desired_end = head if to_sequence is None else to_sequence
            if head is None or desired_end is None or from_sequence > head:
                entries: tuple[EvidenceEntry, ...] = ()
                bounded_end = None
                next_from = None
            else:
                desired_end = min(desired_end, head)
                bounded_end = min(desired_end, from_sequence + EXPORT_BOUND - 1)
                entries = _core_owned(
                    self._store.read_range(
                        actual_scope,
                        from_sequence=from_sequence,
                        to_sequence=bounded_end,
                    )
                )
                next_from = bounded_end + 1 if bounded_end < desired_end else None
            grades_before = self._grades_before(actual_scope, from_sequence)
        except Exception as error:
            raise EvidenceStoreUnavailable("the evidence store could not be read") from error
        context = self._recovery_context(actual_scope, entries, head)
        while True:
            bundle = self._bundle(
                actual_scope, entries, from_sequence, bounded_end, next_from, grades_before, context
            )
            if len(canonical_json(bundle)) <= EXPORT_BYTE_BOUND or not entries:
                return bundle
            if context:
                # The context goes first: it may be omitted with the coverage
                # reported unknown; an included attachment may not (A6).
                context = ()
                continue
            # Over the byte bound: serve the largest contiguous prefix that fits,
            # with its own attachments, and point the consumer at the rest.
            entries = entries[:-1]
            bounded_end = entries[-1].sequence if entries else None
            next_from = None if bounded_end is None else bounded_end + 1
            if not entries:
                raise EvidenceStoreUnavailable(
                    "one entry and its policy attachment exceed the export byte bound"
                )

    def _recovery_context(
        self, scope: str, entries: tuple[EvidenceEntry, ...], head: int | None
    ) -> tuple[EvidenceEntry, ...]:
        """The contiguous suffix after the range through the closure of its last epoch (V3).

        A range that stops before its epoch's closure marker would be unknown
        coverage on its own; the exact entries from the next sequence through
        the first marker whose span covers the range's end are carried beside
        it, so a verifier can see the closure without being handed more
        decision coverage. No marker within the bound means no context, and
        the coverage is honestly unknown.
        """
        if not entries or head is None or entries[-1].sequence >= head:
            return ()
        last = entries[-1].sequence
        try:
            following = _core_owned(
                self._store.read_range(
                    scope, from_sequence=last + 1, to_sequence=min(head, last + EXPORT_BOUND)
                )
            )
        except Exception as error:
            raise EvidenceStoreUnavailable("the evidence store could not be read") from error
        for index, entry in enumerate(following):
            if entry.kind != "recovery":
                continue
            body = entry.body
            start = body.get("from_sequence")
            end = body.get("through_sequence")
            if isinstance(start, int) and isinstance(end, int) and start <= last <= end:
                return following[: index + 1]
        return ()

    def _bundle(
        self,
        scope: str,
        entries: tuple[EvidenceEntry, ...],
        from_sequence: int,
        bounded_end: int | None,
        next_from: int | None,
        grades_before: Mapping[str, Grade],
        context: tuple[EvidenceEntry, ...] = (),
    ) -> dict[str, object]:
        verdict = verify(
            entries,
            scope=scope,
            from_sequence=from_sequence,
            to_sequence=bounded_end,
            grades_before=grades_before,
        )
        versions = [str(item.body["policy_version"]) for item in entries if item.kind == "effect"]
        try:
            attachments = self.policy_attachments(versions)
        except Exception as error:
            # Storage the archive could not read is the export's failure, never
            # an `absent` a verifier would then report as a missing version.
            raise EvidenceStoreUnavailable("the policy archive could not be read") from error
        bundle: dict[str, object] = {
            "contract_version": str(CONTRACT_GENERATION),
            "scope": scope,
            "from_sequence": from_sequence,
            "to_sequence": verdict.to_sequence,
            "entry_count": len(entries),
            "entries": [entry_to_document(item) for item in entries],
            "verification": verdict_to_document(verdict),
            "next_from": next_from,
            "manifest_version": MANIFEST_VERSION,
            "policy_versions": attachments,
            "recovery_context": [entry_to_document(item) for item in context],
        }
        bundle["manifest_hash"] = manifest_digest(bundle, version=MANIFEST_VERSION)
        return bundle

    def _prepare(
        self,
        scope: str,
        connection: EvidenceConnection | None,
        principal: Principal | None,
    ) -> None:
        if self._emitter is None:
            return
        if connection is not None and principal is not None:
            ready = self._emitter.before_verdict(scope, connection, principal)
        else:
            ready = self._emitter.flush(scope)
        if not ready:
            raise EvidenceStoreUnavailable("pending evidence could not be flushed")

    def _grades_before(self, scope: str, from_sequence: int) -> Mapping[str, Grade]:
        """The grades the chain recorded before this range, and only the verified ones.

        Article 7: "a verifier over an export reads the grades the chain
        recorded and adds nothing". These records were read and believed. At
        observability grade the governed program can write the store, which is
        what that grade *means*, so a program could raise its own grade by
        editing one earlier record and every partial read from then on carried
        the raised grade with `intact` beside it — the whole chain said
        `broken_at` at that record, and no range beginning after it said
        anything at all (articles 2 and 10).

        So the prefix is verified before anything is carried out of it. A
        prefix that does not verify carries nothing, which leaves every
        connection in the range at `unverified` — the value article 7 keeps for
        an access that could not be established, ranking below the other two.
        """
        if from_sequence == 1:
            return {}
        earlier = _core_owned(
            self._store.read_range(
                scope,
                from_sequence=1,
                to_sequence=from_sequence - 1,
            )
        )
        verdict = verify(
            earlier,
            scope=scope,
            from_sequence=1,
            to_sequence=from_sequence - 1,
            grades_before={},
        )
        if verdict.condition is not ChainCondition.intact:
            return {}
        values: dict[str, Grade] = {}
        for entry in earlier:
            if entry.kind == "grade":
                values[entry.connection_id] = Grade(str(entry.body["grade"]))
        return values


def _core_owned(entries: Iterable[object]) -> tuple[EvidenceEntry, ...]:
    """Every entry a store answered a range with, taken into the core at once.

    Article 10: a page is verified and then rendered, and both must read one
    value. The store owns the objects it answered with, so the verdict and the
    document are taken from the core's own copies of them, built here before
    anything is claimed about them.
    """
    return tuple(core_owned_entry(entry) for entry in entries)


def _core_owned_head(head: object) -> int | None:
    """The head of a chain as a number the core owns, not one the store still does."""
    return None if head is None else int(head)  # type: ignore[call-overload]


def _scope(scope: str | None) -> str:
    if scope is None or not scope:
        raise ScopeRequired("scope is required for an evidence read")
    if not scope_matches_contract(scope):
        raise ScopeInvalid("scope does not match the contract")
    return scope
