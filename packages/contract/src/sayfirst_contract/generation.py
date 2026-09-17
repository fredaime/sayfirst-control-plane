# SPDX-License-Identifier: Apache-2.0
"""Pure generation negotiation and deprecation-window rules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from importlib.metadata import version as distribution_version
from typing import TYPE_CHECKING, Final

from .artifacts import load_json

if TYPE_CHECKING:
    from .approvals import Approval, ApprovalResolution
    from .client import ControlPlaneClient, Result
    from .decisions import Decision, DecisionAsk
    from .policy import PolicyStatus
    from .problems import Problem
    from .status import Status
    from .whoami import WhoAmI


@dataclass(frozen=True)
class DeprecatedGeneration:
    contract_generation: int
    deprecated_since: date
    deprecated_in_release: str


@dataclass(frozen=True)
class GenerationMarker:
    contract_generation: int
    deprecated_generations: tuple[DeprecatedGeneration, ...]


def load_generation_marker() -> GenerationMarker:
    document = load_json("domain", "generation.json")
    if not isinstance(document, dict):
        raise ValueError("generation marker must be an object")
    deprecated = tuple(
        DeprecatedGeneration(
            contract_generation=item["contract_generation"],
            deprecated_since=date.fromisoformat(item["deprecated_since"]),
            deprecated_in_release=item["deprecated_in_release"],
        )
        for item in document["deprecated_generations"]
    )
    return GenerationMarker(document["contract_generation"], deprecated)


def add_months(value: date, months: int) -> date:
    """The same day-of-month a number of months later, clamped to the month length."""
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    month_lengths = (
        31,
        29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    )
    return date(year, month, min(value.day, month_lengths[month - 1]))


def minor_distance(old: str, new: str) -> int:
    """How many minor releases separate two semantic versions."""

    def parts(value: str) -> tuple[int, int, int]:
        pieces = value.split(".")
        if len(pieces) != 3 or any(not piece.isdigit() for piece in pieces):
            raise ValueError(f"release must be semantic version x.y.z: {value!r}")
        return tuple(int(piece) for piece in pieces)  # type: ignore[return-value]

    old_major, old_minor, _ = parts(old)
    new_major, new_minor, _ = parts(new)
    if (new_major, new_minor) < (old_major, old_minor):
        raise ValueError("current release precedes the deprecation release")
    if new_major == old_major:
        return new_minor - old_minor
    return 2 + (new_major - old_major - 1) * 2 + new_minor


def supported_generations(marker: GenerationMarker, *, on: date, release: str) -> tuple[int, ...]:
    """Return generations whose date or release deprecation minimum remains open."""
    result = [marker.contract_generation]
    for item in marker.deprecated_generations:
        six_months_passed = on >= add_months(item.deprecated_since, 6)
        two_minor_releases_passed = minor_distance(item.deprecated_in_release, release) >= 2
        if not (six_months_passed and two_minor_releases_passed):
            result.append(item.contract_generation)
    return tuple(result)


def generation_is_supported(supported: tuple[int, ...], requested: object) -> bool:
    """Whether an integer generation is in the announced supported set."""
    return isinstance(requested, int) and not isinstance(requested, bool) and requested in supported


def negotiate_generation(supported: tuple[int, ...], requested: int) -> Problem | None:
    """Return the distinct refusal when the requested generation is not supported.

    `retryable` comes from the registry that publishes the code, like every
    other problem this distribution builds: a flag written in by hand here is
    drift waiting to happen, and it agreed with the published column only by
    luck (article 13 — one contract, both sides).
    """
    from .problems import Problem, ProblemCode, problem_retryable

    if requested in supported:
        return None
    return Problem(
        ProblemCode.GENERATION_UNSUPPORTED,
        f"contract generation {requested} is not supported",
        problem_retryable(ProblemCode.GENERATION_UNSUPPORTED),
        requested,
    )


_MARKER = load_generation_marker()
CONTRACT_GENERATION: Final[int] = _MARKER.contract_generation
try:
    from ._build_info import BUILD_DATE as _BUILD_DATE_TEXT
except ImportError:
    _BUILD_DATE_TEXT = date.today().isoformat()

BUILD_DATE: Final[date] = date.fromisoformat(_BUILD_DATE_TEXT)
DISTRIBUTION_RELEASE: Final[str] = distribution_version("sayfirst-contract")

SUPPORTED_GENERATIONS: Final[tuple[int, ...]] = supported_generations(
    _MARKER,
    on=BUILD_DATE,
    release=DISTRIBUTION_RELEASE,
)


class NegotiatedClient:
    """A domain client that stops operations after incompatible negotiation."""

    def __init__(self, client: ControlPlaneClient) -> None:
        from .client import Answered, CouldNotAsk, Refused

        self._client = client
        self._status: Result[Status] = client.read_status()
        self._blocked = None
        if isinstance(self._status, Answered):
            problem = negotiate_generation(
                self._status.value.supported_generations, CONTRACT_GENERATION
            )
            if problem is not None:
                self._blocked = CouldNotAsk(problem)
        elif isinstance(self._status, Refused):
            # Articles 1 and 2: the status request was refused; every later operation is
            # stopped here and never sent, so it "could not be asked" — reporting it as a
            # refusal would claim the server refused a request it never received. The
            # problem is kept: it is why the connection is unusable.
            self._blocked = CouldNotAsk(self._status.problem)
        else:
            self._blocked = self._status

    def read_status(self) -> Result[Status]:
        return self._status

    def read_whoami(self) -> Result[WhoAmI]:
        return self._blocked or self._client.read_whoami()

    def ask_decision(self, ask: DecisionAsk) -> Result[Decision]:
        return self._blocked or self._client.ask_decision(ask)

    def read_decision(self, scope: str, decision_ref: str) -> Result[Decision]:
        return self._blocked or self._client.read_decision(scope, decision_ref)

    def read_policy_status(self) -> Result[PolicyStatus]:
        return self._blocked or self._client.read_policy_status()

    def read_approval(self, scope: str, approval_ref: str) -> Result[Approval]:
        return self._blocked or self._client.read_approval(scope, approval_ref)

    def resolve_approval(self, resolution: ApprovalResolution) -> Result[Approval]:
        return self._blocked or self._client.resolve_approval(resolution)

    def read_evidence(
        self, scope: str, from_sequence: int, page_size: int = 100
    ) -> Result[Mapping[str, object]]:
        return self._blocked or self._client.read_evidence(scope, from_sequence, page_size)

    def export_evidence(
        self, scope: str, from_sequence: int, to_sequence: int | None = None
    ) -> Result[Mapping[str, object]]:
        return self._blocked or self._client.export_evidence(scope, from_sequence, to_sequence)
