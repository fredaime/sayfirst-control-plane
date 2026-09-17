# SPDX-License-Identifier: Apache-2.0
"""The scope register article 5 requires a guard to enumerate."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class Carries(StrEnum):
    """Whether a port operation or a structure carries a governed record."""

    RECORD = "record"
    NO_RECORD = "no_record"


@dataclass(frozen=True)
class ScopeDeclaration:
    """One reviewable statement about one port operation or structure."""

    carries: Carries
    exemption: str | None = None

    def __post_init__(self) -> None:
        if self.carries is Carries.NO_RECORD and self.exemption is not None:
            raise ValueError("only a record-carrying declaration can be exempted")
        if self.exemption is not None and not self.exemption.strip():
            raise ValueError("an exemption states its reason")


#: The structure each persisted entry of the information contract is written as.
#: An observation persists nothing and is written as no structure, so it has no
#: entry here; `tests/architecture/test_scope.py` holds that the only
#: declarations missing from this mapping are the ones that own no surface.
PERSISTED_AS: Mapping[str, str] = {
    "policy_file": "LoadedPolicy",
    "policy_projection": "ProjectedPolicy",
    "decision": "Decision",
    "evidence_chain": "EvidenceEntry",
    "policy_archive": "ArchivedPolicy",
    "recovery_journal": "JournalRecord",
}

#: The reason the policy authority surface is exempt, published in `docs/exceptions.md`.
POLICY_AUTHORITY_EXEMPTION = (
    "the policy authority is one administrator-owned file whose rules each carry "
    "their own scope, so no single scope is true of the file, of a load of it, or "
    "of a rebuild from it; making the read per-scope would make the published "
    "policy status scope-dependent, which needs a request member generation one "
    "does not define and so opens contract generation two"
)

#: The reason the policy archive is exempt, published in `docs/exceptions.md`, entry 3.
POLICY_ARCHIVE_EXEMPTION = (
    "the archive keeps the exact bytes of the one administrator-owned policy file under the "
    "digest a decision names, and no single scope is true of those bytes; a scoped archive "
    "needs scope-addressed policy versions, which generation one does not define, and the "
    "legacy whole-file blobs are retained under this exception until every decision and chain "
    "segment naming them has been retired with declared loss"
)

#: One reviewable declaration per port operation and per structure a port carries.
SCOPE_REGISTER: Mapping[str, ScopeDeclaration] = {
    "Decision": ScopeDeclaration(Carries.RECORD),
    "EvidenceEntry": ScopeDeclaration(Carries.RECORD),
    "DecisionStore.append": ScopeDeclaration(Carries.RECORD),
    "DecisionStore.get": ScopeDeclaration(Carries.RECORD),
    "DecisionStore.location": ScopeDeclaration(Carries.NO_RECORD),
    # Where a store committed a record: an address, not a record; the
    # decision it addresses carries the scope.
    "DecisionPosition": ScopeDeclaration(Carries.NO_RECORD),
    "LoadedPolicy": ScopeDeclaration(Carries.RECORD, POLICY_AUTHORITY_EXEMPTION),
    "ProjectedPolicy": ScopeDeclaration(Carries.RECORD, POLICY_AUTHORITY_EXEMPTION),
    "PolicyStore.load": ScopeDeclaration(Carries.RECORD, POLICY_AUTHORITY_EXEMPTION),
    "PolicyProjection.rebuild": ScopeDeclaration(Carries.RECORD, POLICY_AUTHORITY_EXEMPTION),
    "PolicyProjection.current": ScopeDeclaration(Carries.RECORD, POLICY_AUTHORITY_EXEMPTION),
    "PolicyProjection.clear": ScopeDeclaration(Carries.NO_RECORD),
    # The policy archive: historical authoritative bytes, addressed by digest
    # and by nothing else, under their own exception with their own way back.
    "ArchivedPolicy": ScopeDeclaration(Carries.RECORD, POLICY_ARCHIVE_EXEMPTION),
    "PolicyArchive.keep": ScopeDeclaration(Carries.RECORD, POLICY_ARCHIVE_EXEMPTION),
    "PolicyArchive.read": ScopeDeclaration(Carries.RECORD, POLICY_ARCHIVE_EXEMPTION),
    "PolicyArchive.location": ScopeDeclaration(Carries.NO_RECORD),
    # The coordination journal: where an epoch opened and how it closed, per
    # scope; it holds no event and reconstructs no decision (C3).
    "JournalRecord": ScopeDeclaration(Carries.RECORD),
    "RecoveryJournal.open_epoch": ScopeDeclaration(Carries.RECORD),
    "RecoveryJournal.epoch_clean": ScopeDeclaration(Carries.RECORD),
    "RecoveryJournal.epoch_reconciled": ScopeDeclaration(Carries.RECORD),
    "RecoveryJournal.open_epochs": ScopeDeclaration(Carries.RECORD),
    "RecoveryJournal.location": ScopeDeclaration(Carries.NO_RECORD),
    "PolicyStore.protection_at_start": ScopeDeclaration(Carries.NO_RECORD),
    "PolicyStore.write_access_of": ScopeDeclaration(Carries.NO_RECORD),
    "PolicyUnavailable": ScopeDeclaration(Carries.NO_RECORD),
    "ProtectionVerdict": ScopeDeclaration(Carries.NO_RECORD),
    "AccessVerdict": ScopeDeclaration(Carries.NO_RECORD),
    "ProtectionExpectation": ScopeDeclaration(Carries.NO_RECORD),
    # The evidence chain: a governed record like any other, discovered from
    # `ports/evidence_store.py` once the guard walks the whole `ports/`
    # package instead of three of its modules. `EvidenceEntry` is declared
    # above, beside the other structure the information contract persists.
    "EvidenceRecord": ScopeDeclaration(Carries.RECORD),
    "EvidenceStore.append": ScopeDeclaration(Carries.RECORD),
    "EvidenceStore.read_range": ScopeDeclaration(Carries.RECORD),
    "EvidenceStore.latest_sequence": ScopeDeclaration(Carries.RECORD),
    "EvidenceStore.location": ScopeDeclaration(Carries.NO_RECORD),
    "StoreLocation": ScopeDeclaration(Carries.NO_RECORD),
    # Identity and host facts: read per connection, never persisted as a
    # governed record, so article 5 has nothing to hold them to.
    "Account": ScopeDeclaration(Carries.NO_RECORD),
    "AccountDirectory.account": ScopeDeclaration(Carries.NO_RECORD),
    "AccountDirectory.group_ids": ScopeDeclaration(Carries.NO_RECORD),
    "AccountDirectory.group_name": ScopeDeclaration(Carries.NO_RECORD),
    "Clock.now": ScopeDeclaration(Carries.NO_RECORD),
    "PathFacts": ScopeDeclaration(Carries.NO_RECORD),
    "PathAccess.inspect": ScopeDeclaration(Carries.NO_RECORD),
}
