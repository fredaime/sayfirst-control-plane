# SPDX-License-Identifier: Apache-2.0
"""Authority, projection, and observation declarations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


class Plane(StrEnum):
    AUTHORITY = "authority"
    PROJECTION = "projection"
    OBSERVATION = "observation"


@dataclass(frozen=True)
class Structure:
    """One fact the system holds, its kind, the test that shows the kind, and where it lives.

    `proof` names a test `packages/control-plane/tests/architecture/
    test_declared_proofs_resolve.py` collects; a name that resolves to nothing
    fails there, because a proof label nobody resolves is a claim, not a proof.

    `surfaces` names the persistent surfaces this structure owns, in the
    vocabulary the walk in `test_persisted_structures_are_declared.py` uses:
    `table:<name>` for a table the code creates, `store:<module>` for a module
    that writes durably. A surface no declaration owns fails that walk. A
    declaration may own none — the policy authority is written by the operator
    and only read here.
    """

    plane: Plane
    role: Literal["source_of_truth", "human_authority", "definition", "decision", "trace"]
    proof: str
    surfaces: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.plane is not Plane.AUTHORITY and self.role in {
            "source_of_truth",
            "human_authority",
        }:
            raise ValueError(
                f"a {self.plane.value} cannot carry an authority role: "
                "only an authority accepts writes and owns invariants"
            )
        if self.plane is Plane.AUTHORITY and self.role == "trace":
            raise ValueError(
                "an authority cannot carry the trace role: a trace is what the system "
                "saw and may be absent or stale, which is the one thing an authority "
                "for a fact may not be"
            )


INFORMATION_CONTRACT = {
    "policy_file": Structure(
        Plane.AUTHORITY,
        "source_of_truth",
        "test_policy_decisions_read_the_authoritative_file",
    ),
    "policy_projection": Structure(
        Plane.PROJECTION,
        "definition",
        "test_the_policy_projection_rebuilds_from_an_empty_database",
        surfaces=(
            "table:policy_projection",
            "table:policy_rule",
            "store:sayfirst_control_plane.adapters.sqlite.policy_projection",
        ),
    ),
    "decision": Structure(
        Plane.AUTHORITY,
        "decision",
        "test_a_duplicate_decision_id_is_refused_never_upserted",
        surfaces=("store:sayfirst_control_plane.adapters.file.decision_store",),
    ),
    "evidence_chain": Structure(
        Plane.AUTHORITY,
        "source_of_truth",
        "test_the_store_publishes_no_update_or_delete_verb_of_any_name",
        surfaces=("store:sayfirst_control_plane.adapters.file.evidence_store",),
    ),
    # The exact bytes of every policy version a decision names, addressed by
    # their digest. An authority for what those bytes were, never for what the
    # policy is now: the file the administrator owns stays the live authority,
    # and a kept copy is never promoted to it (block 2.7, A4).
    "policy_archive": Structure(
        Plane.AUTHORITY,
        "source_of_truth",
        "test_a_damaged_version_is_reported_never_overwritten_or_evaluated_as_current_policy",
        surfaces=("store:sayfirst_control_plane.adapters.file.policy_archive",),
    ),
    # Where each scope's producer epochs opened and how they closed: the
    # bookkeeping of what evidence coverage is known and what is not (block
    # 2.7, C3). Authoritative for that and nothing else.
    # What the daemon did while this process has been up: a version reloaded, a
    # grant ended, a person's act applied or refused. An observation and
    # nothing else (article 3) — it survives no restart, it is bounded, it
    # declares what it dropped (article 10), and no decision is taken from it.
    # The authority for what was decided is the chain above; the authority for
    # a wait is the approval store. It persists nothing, so it owns no surface.
    "daemon_events": Structure(
        Plane.OBSERVATION,
        "trace",
        "test_the_sink_is_bounded_and_says_how_much_it_dropped",
    ),
    "recovery_journal": Structure(
        Plane.AUTHORITY,
        "source_of_truth",
        "test_an_epoch_is_open_until_its_closure_is_journaled",
        surfaces=("store:sayfirst_control_plane.adapters.file.recovery_journal",),
    ),
}
