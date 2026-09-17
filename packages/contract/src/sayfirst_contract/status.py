# SPDX-License-Identifier: Apache-2.0
"""Caller-visible state whose uncertain values remain explicit."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from .values import Unknown, read_enum


class IntegrityGrade(StrEnum):
    OBSERVABILITY = "observability"
    EVIDENCE = "evidence"
    UNVERIFIED = "unverified"


class GradeBasis(StrEnum):
    CALLER_CAN_WRITE = "caller_can_write"
    CALLER_CANNOT_WRITE = "caller_cannot_write"
    ACCESS_NOT_ESTABLISHED = "access_not_established"


class Authority(StrEnum):
    AUTHORITATIVE = "authoritative"
    PROJECTION = "projection"
    OBSERVATION = "observation"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Principal:
    kind: str
    uid: int
    name: str | None


@dataclass(frozen=True)
class IntegrityGradeStatus:
    grade: IntegrityGrade | Unknown
    basis: GradeBasis | Unknown
    evaluated_at: str
    store: str
    reevaluation_interval_seconds: int
    extra: Mapping[str, object]

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Self:
        defined = {
            "grade",
            "basis",
            "evaluated_at",
            "store",
            "reevaluation_interval_seconds",
        }
        return cls(
            read_enum(IntegrityGrade, document["grade"]),
            read_enum(GradeBasis, document["basis"]),
            str(document["evaluated_at"]),
            str(document["store"]),
            int(document["reevaluation_interval_seconds"]),
            {key: value for key, value in document.items() if key not in defined},
        )

    def to_document(self) -> dict[str, object]:
        return {
            "grade": self.grade.value if isinstance(self.grade, IntegrityGrade) else self.grade.raw,
            "basis": self.basis.value if isinstance(self.basis, GradeBasis) else self.basis.raw,
            "evaluated_at": self.evaluated_at,
            "store": self.store,
            "reevaluation_interval_seconds": self.reevaluation_interval_seconds,
            **self.extra,
        }


@dataclass(frozen=True)
class Status:
    contract_generation: int
    supported_generations: tuple[int, ...]
    integrity_grade: IntegrityGradeStatus
    privacy_provider: str
    principal: Principal
    store_authority: Authority | Unknown
    store_kind: str
    extra: Mapping[str, object]

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Self:
        principal = document["principal"]
        store = document["store"]
        integrity_grade = document["integrity_grade"]
        if (
            not isinstance(principal, Mapping)
            or not isinstance(store, Mapping)
            or not isinstance(integrity_grade, Mapping)
        ):
            raise ValueError("principal, integrity_grade and store must be objects")
        defined = {
            "contract_generation",
            "supported_generations",
            "integrity_grade",
            "privacy_provider",
            "principal",
            "store",
        }
        supported = document["supported_generations"]
        if not isinstance(supported, list):
            raise ValueError("supported_generations must be a list")
        generation = document["contract_generation"]
        if not isinstance(generation, int) or isinstance(generation, bool):
            raise ValueError("contract_generation must be an integer")
        supported_generations = tuple(int(item) for item in supported)
        if generation not in supported_generations:
            raise ValueError("supported_generations must contain contract_generation")
        return cls(
            contract_generation=generation,
            supported_generations=supported_generations,
            integrity_grade=IntegrityGradeStatus.from_document(integrity_grade),
            privacy_provider=str(document["privacy_provider"]),
            principal=Principal(
                kind=str(principal["kind"]),
                uid=int(principal["uid"]),
                name=principal["name"] if isinstance(principal["name"], str) else None,
            ),
            store_authority=read_enum(Authority, store["authority"]),
            store_kind=str(store["kind"]),
            extra={key: value for key, value in document.items() if key not in defined},
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_generation": self.contract_generation,
            "supported_generations": list(self.supported_generations),
            "integrity_grade": self.integrity_grade.to_document(),
            "privacy_provider": self.privacy_provider,
            "principal": {
                "kind": self.principal.kind,
                "uid": self.principal.uid,
                "name": self.principal.name,
            },
            "store": {
                "authority": (
                    self.store_authority.value
                    if isinstance(self.store_authority, Authority)
                    else self.store_authority.raw
                ),
                "kind": self.store_kind,
            },
            **self.extra,
        }
