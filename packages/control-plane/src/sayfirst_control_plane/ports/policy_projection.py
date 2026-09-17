# SPDX-License-Identifier: Apache-2.0
"""The rebuild-only policy projection port."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Protocol

from sayfirst_contract.artifacts import domain_schema

from ..domain.policy import Rule
from .policy_store import LoadedPolicy

PROJECTION_KIND_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProjectedPolicy:
    policy_version: str
    format: int
    loaded_at: datetime
    rule_count: int
    rules: tuple[Rule, ...]


class PolicyProjection(Protocol):
    VERSION = 1
    KIND: str

    def rebuild(self, loaded: LoadedPolicy) -> None: ...

    def current(self) -> ProjectedPolicy | None: ...

    def clear(self) -> None: ...


@lru_cache(maxsize=1)
def _published_kind_shape() -> tuple[int, int, re.Pattern[str]]:
    """Read the constraint the published status document places on a kind."""
    shape = domain_schema("policy-status")["properties"]["projection"]["properties"]["kind"]
    if shape["type"] != "string":
        raise TypeError("the published projection kind is no longer a string")
    return shape["minLength"], shape["maxLength"], re.compile(shape["pattern"])


def is_published_kind(value: object) -> bool:
    """Answer whether a provider's declared kind fits the published status shape."""
    minimum, maximum, pattern = _published_kind_shape()
    return (
        isinstance(value, str)
        and minimum <= len(value) <= maximum
        and pattern.fullmatch(value) is not None
    )


def projection_kind(projection: object) -> str:
    """Name a provider as it declares itself, or `unknown` (articles 2, 8 and 13).

    A provider is written outside this repository, so its declaration is
    validated against the shape the status document publishes before it is
    answered: an undeclared or out-of-shape kind is `unknown`, never the kind of
    some other provider, because "did not look" and "looked and found nothing"
    are different facts.
    """
    declared = getattr(projection, "KIND", None)
    return declared if is_published_kind(declared) else PROJECTION_KIND_UNKNOWN
