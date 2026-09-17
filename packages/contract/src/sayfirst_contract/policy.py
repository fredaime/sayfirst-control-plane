# SPDX-License-Identifier: Apache-2.0
"""The rebuildable policy status value exposed to readers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from .values import Unknown, read_enum


class ProjectionStep(StrEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProjectionStatus:
    kind: str
    policy_version: str | None
    in_step: ProjectionStep | Unknown


@dataclass(frozen=True)
class PolicyStatus:
    authority: str
    policy_version: str
    format: int
    loaded_at: str
    rule_count: int
    projection: ProjectionStatus
    contract_generation: int
    extra: Mapping[str, object]

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Self:
        projected = document["projection"]
        if not isinstance(projected, Mapping):
            raise ValueError("projection must be an object")
        defined = {
            "authority",
            "policy_version",
            "format",
            "loaded_at",
            "rule_count",
            "projection",
            "contract_generation",
        }
        projected_version = projected.get("policy_version")
        return cls(
            authority=str(document["authority"]),
            policy_version=str(document["policy_version"]),
            format=int(document["format"]),
            loaded_at=str(document["loaded_at"]),
            rule_count=int(document["rule_count"]),
            projection=ProjectionStatus(
                kind=str(projected["kind"]),
                policy_version=(projected_version if isinstance(projected_version, str) else None),
                in_step=read_enum(ProjectionStep, projected["in_step"]),
            ),
            contract_generation=int(document["contract_generation"]),
            extra={key: value for key, value in document.items() if key not in defined},
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_generation": self.contract_generation,
            "authority": self.authority,
            "policy_version": self.policy_version,
            "format": self.format,
            "loaded_at": self.loaded_at,
            "rule_count": self.rule_count,
            "projection": {
                "kind": self.projection.kind,
                "policy_version": self.projection.policy_version,
                "in_step": (
                    self.projection.in_step.value
                    if isinstance(self.projection.in_step, ProjectionStep)
                    else self.projection.in_step.raw
                ),
            },
            **self.extra,
        }
