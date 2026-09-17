# SPDX-License-Identifier: Apache-2.0
"""Stable problem values and their tolerant reader."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from types import MappingProxyType
from typing import Final, Literal, cast

from .artifacts import load_json
from .values import Unknown, read_enum

REFUSED: Final[str] = "refused"
COULD_NOT_ASK: Final[str] = "could_not_ask"
CLASSES: Final[frozenset[str]] = frozenset({REFUSED, COULD_NOT_ASK})


class ProblemCode(StrEnum):
    ANSWER_UNREADABLE = "answer_unreadable"
    APPROVAL_PROVIDER_UNAVAILABLE = "approval_provider_unavailable"
    APPROVAL_RESOLVED = "approval_resolved"
    APPROVAL_UNKNOWN = "approval_unknown"
    CONFIGURATION_WRITABLE_BY_PRINCIPAL = "configuration_writable_by_principal"
    DECISION_CONTENDED = "decision_contended"
    DECISION_NOT_FOUND = "decision_not_found"
    DECISION_STORE_UNAVAILABLE = "decision_store_unavailable"
    DELEGATION_INVALID = "delegation_invalid"
    EVIDENCE_RANGE_INVALID = "evidence_range_invalid"
    EVIDENCE_STORE_UNAVAILABLE = "evidence_store_unavailable"
    GENERATION_MISSING = "generation_missing"
    GENERATION_UNREADABLE = "generation_unreadable"
    GENERATION_UNSUPPORTED = "generation_unsupported"
    IMPOSTOR = "impostor"
    INTERNAL = "internal"
    MEMBER_UNKNOWN = "member_unknown"
    OPERATION_UNKNOWN = "operation_unknown"
    OUTCOME_UNKNOWN = "outcome_unknown"
    PEER_CREDENTIAL_UNAVAILABLE = "peer_credential_unavailable"
    PEER_IDENTITY_UNSUPPORTED = "peer_identity_unsupported"
    PEER_NOT_ADMITTED = "peer_not_admitted"
    PEER_UID_UNMAPPED = "peer_uid_unmapped"
    POLICY_ARCHIVE_UNAVAILABLE = "policy_archive_unavailable"
    POLICY_UNAVAILABLE = "policy_unavailable"
    POLICY_WRITABLE_BY_PRINCIPAL = "policy_writable_by_principal"
    PRINCIPAL_GROUPS_UNAVAILABLE = "principal_groups_unavailable"
    PRINCIPAL_REFUSED = "principal_refused"
    REQUEST_MALFORMED = "request_malformed"
    SCOPE_INVALID = "scope_invalid"
    SCOPE_REFUSED = "scope_refused"
    SCOPE_REQUIRED = "scope_required"
    SERVER_NOT_THE_DAEMON_PRINCIPAL = "server_not_the_daemon_principal"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class Problem:
    """One problem value, and whether a control plane is what produced it.

    `control_plane_answered` is set where the value is made, never inferred
    from the code, because the same code is minted on both sides of the wire:
    `read_problem` is the one place a document the far end sent becomes a
    `Problem`, and it is the one place this is true. Everything a client builds
    for itself — it could not open the address, it could not read the answer,
    the answer echoed a generation it does not speak, its own profile names one
    it does not speak — leaves it false, which is the honest default: a client
    that forgot to say where a problem came from must not end up claiming the
    control plane rejected a question it never received (articles 1 and 2).

    It is not a member of the published problem document and never travels:
    the far end of a wire cannot tell a reader whether the far end answered.
    """

    code: ProblemCode | Unknown
    message: str
    retryable: bool | None
    contract_generation: int | None
    member: str | None = None
    control_plane_answered: bool = False

    def to_document(self, default_generation: int | None = None) -> dict[str, object]:
        generation = self.contract_generation
        if generation is None:
            generation = default_generation
        return {
            "contract_generation": generation,
            "code": self.code.value if isinstance(self.code, ProblemCode) else self.code.raw,
            "message": self.message,
            "retryable": self.retryable,
            **({"member": self.member} if self.member is not None else {}),
        }


@cache
def _registry_codes() -> Mapping[str, Mapping[str, object]]:
    """The published registry's `codes` object, parsed once for every column of it."""
    document = load_json("domain", "problem-codes.json")
    if not isinstance(document, dict) or not isinstance(document.get("codes"), dict):
        raise ValueError("problem-code registry must contain a codes object")
    return MappingProxyType(document["codes"])


@cache
def classes_by_code() -> Mapping[str, str]:
    """The registry's class column, read once from the published artefact.

    Article 1 closes the two answers a non-200 can be: the question was
    received and rejected, or no answer about the effect exists. Which one a
    code is, is a property of the code — so it is published beside the code
    and never derived a second time by a client.

    **What the column classifies is what the control plane published.** A
    problem a client mints for itself — no address it could open, no answer it
    could read, a generation it does not speak — is a « could not ask » by
    construction, whatever code it carries, because no control plane answered
    at all (articles 1 and 2). That is `problem_class_of`, which reads the
    value; `problem_class` below reads a bare code and therefore answers only
    the first of the two questions.
    """
    found: dict[str, str] = {}
    for name, entry in _registry_codes().items():
        if not isinstance(entry, Mapping) or entry.get("class") not in CLASSES:
            raise ValueError(f"problem code {name!r} lacks a published class")
        found[str(name)] = str(entry["class"])
    return MappingProxyType(found)


def problem_class(code: ProblemCode | Unknown | str) -> Literal["refused", "could_not_ask"]:
    """The class the registry publishes for this code; `could_not_ask` for one it does not.

    A code this generation does not define is never read as a refusal: it is an
    answer this client cannot classify, and an unknown is never more permissive
    than the known case (article 3).

    This answers about a CODE. A caller holding a problem VALUE asks
    `problem_class_of`, which also knows whether a control plane answered.
    """
    if isinstance(code, ProblemCode):
        name = code.value
    elif isinstance(code, Unknown):
        name = code.raw if isinstance(code.raw, str) else ""
    else:
        name = code
    return "refused" if classes_by_code().get(name) == REFUSED else "could_not_ask"


def problem_class_of(problem: Problem) -> Literal["refused", "could_not_ask"]:
    """The class of one problem VALUE, which is the class column plus one fact.

    A refusal is the control plane's to give: the question reached it and it
    rejected it. So a problem this client made for itself is a « could not
    ask » however the registry classes its code — the same code is minted on
    both sides of the wire, and `generation_unsupported` is the one that makes
    the difference visible (a daemon that will not speak this generation has
    answered; a client that will not speak the daemon's has dialled nothing).
    Derived from the value, never from a list of codes kept somewhere else.
    """
    if not problem.control_plane_answered:
        return "could_not_ask"
    return problem_class(problem.code)


@cache
def problem_retryable(code: ProblemCode) -> bool | None:
    """Return the registry's three-valued retryability for one problem code."""
    entry = _registry_codes().get(code.value)
    if not isinstance(entry, Mapping) or entry.get("retryable") not in {True, False, None}:
        raise ValueError(f"problem code {code.value!r} lacks valid retryability")
    return cast(bool | None, entry["retryable"])


def read_problem(document: Mapping[str, object]) -> Problem:
    """The problem document the far end sent, read as a value.

    The one place `control_plane_answered` is true: a document arrived, so a
    control plane answered, whatever the answer was.
    """
    generation = document.get("contract_generation")
    member = document.get("member")
    return Problem(
        code=read_enum(ProblemCode, document.get("code")),
        message=str(document.get("message", "")),
        retryable=document.get("retryable")
        if isinstance(document.get("retryable"), bool)
        else None,
        contract_generation=generation if isinstance(generation, int) else None,
        member=member if isinstance(member, str) else None,
        control_plane_answered=True,
    )
