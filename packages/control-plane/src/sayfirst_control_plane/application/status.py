# SPDX-License-Identifier: Apache-2.0
"""What this daemon says about itself, and what one caller's evidence says.

Every member of the status result is a claim, so every member is either read
off something this package holds or is the contract's own value for "not
established here" (article 2).

Two operations live here because two blocks answer two halves of one surface.
`status` is the operation the generation gate reads: it answers from the
connection alone, and names no grade, store or privacy provider, because
nothing composes an evidence emitter into it. `evidence_status` answers the
same members from an emitter that does hold them, for a caller that has one.
Composing the first over the second is the change that lets one surface answer
both; until it happens, `status` keeps the contract's "not established" values
rather than a plausible one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from sayfirst_contract.status import (
    Authority,
    GradeBasis,
    IntegrityGrade,
    IntegrityGradeStatus,
    Principal,
    Status,
)
from sayfirst_contract.whoami import Principal as BoundPrincipal

from sayfirst_control_plane.application.evidence_emitter import (
    GRADE_REEVALUATION_INTERVAL_SECONDS,
    EvidenceConnection,
    EvidenceEmitter,
)
from sayfirst_control_plane.domain.evidence_chain import Principal as EvidencePrincipal

NO_STORE_KIND: Final[str] = "unknown"
"""No evidence store is composed into `status`, so its kind is not known —
`unknown`, never a name for a store that operation cannot see (article 3)."""

NO_PRIVACY_PROVIDER: Final[str] = "unknown"
"""The schema reserves `none` and `unknown`. `none` would claim this operation
had looked and found no provider; it has not looked, so `unknown`."""


def _grade_not_established(now: datetime) -> IntegrityGradeStatus:
    """The grade of an answer composed over no evidence store at all.

    Article 7: when access cannot be established the grade is `unverified`,
    which claims nothing. `evaluated_at` is this answer's own instant, because
    this operation re-derives the grade for every answer rather than on a
    schedule, so the interval it publishes is a bound it never exceeds rather
    than a timer it runs.
    """
    return IntegrityGradeStatus(
        IntegrityGrade.UNVERIFIED,
        GradeBasis.ACCESS_NOT_ESTABLISHED,
        now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        NO_STORE_KIND,
        GRADE_REEVALUATION_INTERVAL_SECONDS,
        {},
    )


def status(
    principal: BoundPrincipal,
    *,
    generation: int,
    supported_generations: tuple[int, ...],
    now: datetime | None = None,
) -> Status:
    """The status result for one connection, with the principal it carries."""
    return Status(
        contract_generation=generation,
        supported_generations=supported_generations,
        # This operation signs, chains and verifies no record, so the grade
        # article 7 defines is not established here. `evidence_status` below
        # answers it for a caller that brings an emitter.
        integrity_grade=_grade_not_established(now or datetime.now(UTC)),
        privacy_provider=NO_PRIVACY_PROVIDER,
        principal=Principal(kind=principal.kind, uid=principal.uid, name=principal.name),
        store_authority=Authority.UNKNOWN,
        store_kind=NO_STORE_KIND,
        extra={},
    )


def evidence_status(
    emitter: EvidenceEmitter,
    *,
    scope: str,
    connection: EvidenceConnection,
    principal: EvidencePrincipal,
) -> dict[str, object]:
    """Caller-specific evidence status values, read off the emitter that holds them."""
    evaluation = emitter.evaluation_for(scope, connection, principal, force=True)
    return {
        "integrity_grade": {
            "grade": evaluation.grade.value,
            "basis": evaluation.basis,
            "evaluated_at": evaluation.evaluated_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "store": emitter.store_location.kind,
            "reevaluation_interval_seconds": emitter.grade_reevaluation_seconds,
        },
        "privacy_provider": emitter.privacy_provider,
        # Article 10: the pipeline declares its gaps. While the store refuses
        # appends the declarations are held in the emitter, not in the chain, so
        # the status says the pipeline is not delivering and how much it holds.
        "evidence_emission": emitter.emission_status,
    }
