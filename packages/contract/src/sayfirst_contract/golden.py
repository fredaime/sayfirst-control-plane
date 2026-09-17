# SPDX-License-Identifier: Apache-2.0
"""Typed access to the authoritative compatibility scenarios."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from .artifacts import artifact, domain_schema
from .decisions import DecisionAsk
from .grants import GrantUse


class ContractDefect(ValueError):
    """The authoritative scenario set is structurally incomplete."""


class Binds(StrEnum):
    CLIENT = "client"
    SERVER = "server"
    BOTH = "both"


class Regime(StrEnum):
    AUTO = "auto"
    REVIEW = "review"
    DENY = "deny"


@dataclass(frozen=True)
class Answers:
    members: Mapping[str, object]


@dataclass(frozen=True)
class Given:
    policy: Mapping[str, Regime] | None
    server: Literal["unreachable"] | Answers | None
    policy_unavailable: bool
    policy_changes_to: Mapping[str, Regime] | None
    applying_outcomes: tuple[str, ...] | None
    connection_live: bool | None
    signal_channel: bool
    grant_lifetime_seconds: int | None
    grant_arguments_digest: str | None


@dataclass(frozen=True)
class Expect:
    outcome: str | None = None
    reason: str | None = None
    result: str | None = None
    problem: str | None = None
    reported_outcome: str | None = None
    grant: Literal["present", "absent"] | None = None
    grant_use: str | None = None
    after_policy_change: Mapping[str, object] | None = None

    def members(self) -> dict[str, object]:
        return {
            key: value
            for key, value in (
                ("outcome", self.outcome),
                ("reason", self.reason),
                ("result", self.result),
                ("problem", self.problem),
                ("reported_outcome", self.reported_outcome),
                ("grant", self.grant),
                ("grant_use", self.grant_use),
                ("after_policy_change", self.after_policy_change),
            )
            if value is not None
        }


@dataclass(frozen=True)
class Then:
    """What a scenario scripts after its first answer: an act, and what follows it."""

    resolve: Literal["approve", "reject", "expire"]
    expect_state: str
    #: What a re-ask of the same question answers once a person has acted, or
    #: `None` where the scenario scripts no re-ask. Article 12: a question one
    #: person has already answered is an allow or a deny of its own, on the two
    #: reasons published for exactly that, and until a fixture scripted the
    #: re-ask those reasons were published with nothing to be replayed against
    #: (article 13).
    expect_after_resolution: Mapping[str, object] | None = None


@dataclass(frozen=True)
class Scenario:
    name: str
    binds: Binds
    article: str
    given: Given
    ask: DecisionAsk
    expect: Expect
    then: Then | None
    raw: Mapping[str, object]

    def binds_server(self) -> bool:
        return self.binds in (Binds.SERVER, Binds.BOTH)

    def binds_client(self) -> bool:
        return self.binds in (Binds.CLIENT, Binds.BOTH)


def _grant_use(name: str, value: object) -> str | None:
    """Refuse a use verdict the published rule cannot answer (article 13)."""
    if value is None:
        return None
    if not isinstance(value, str) or value not in tuple(GrantUse):
        raise ContractDefect(f"scenario {name!r} expects unknown grant use {value!r}")
    return value


def _parse_scenario(name: str, raw: object) -> Scenario:
    if not isinstance(raw, dict):
        raise ContractDefect(f"scenario {name!r} must be an object")
    required = {"binds", "article", "given", "ask", "expect"}
    missing = required - raw.keys()
    if missing:
        raise ContractDefect(f"scenario {name!r} lacks {', '.join(sorted(missing))}")
    unknown = set(raw) - required - {"then"}
    if unknown:
        raise ContractDefect(f"scenario {name!r} has unknown members {sorted(unknown)!r}")
    given_raw = raw["given"]
    ask_raw = raw["ask"]
    expect_raw = raw["expect"]
    if not all(isinstance(item, dict) for item in (given_raw, ask_raw, expect_raw)):
        raise ContractDefect(f"scenario {name!r} has a non-object section")
    allowed_given = {
        "policy",
        "server",
        "policy_unavailable",
        "policy_changes_to",
        "applying_outcomes",
        "connection_live",
        "signal_channel",
        "grant_lifetime_seconds",
        "grant_arguments_digest",
    }
    unknown_given = set(given_raw) - allowed_given
    if unknown_given:
        raise ContractDefect(
            f"scenario {name!r} given has unknown members {sorted(unknown_given)!r}"
        )
    unknown_ask = set(ask_raw) - {
        "capability",
        "scope",
        "arguments_digest",
        "correlation",
    }
    if unknown_ask:
        raise ContractDefect(f"scenario {name!r} ask has unknown members {sorted(unknown_ask)!r}")
    unknown_expect = set(expect_raw) - {
        "outcome",
        "reason",
        "result",
        "problem",
        "reported_outcome",
        "grant",
        "grant_use",
        "after_policy_change",
    }
    if unknown_expect:
        raise ContractDefect(
            f"scenario {name!r} expect has unknown members {sorted(unknown_expect)!r}"
        )
    policy_raw = given_raw.get("policy")
    policy = (
        {str(capability): Regime(value) for capability, value in policy_raw.items()}
        if isinstance(policy_raw, dict)
        else None
    )
    changed_policy_raw = given_raw.get("policy_changes_to")
    changed_policy = (
        {str(capability): Regime(value) for capability, value in changed_policy_raw.items()}
        if isinstance(changed_policy_raw, dict)
        else None
    )
    server_raw = given_raw.get("server")
    if server_raw == "unreachable":
        server: Literal["unreachable"] | Answers | None = "unreachable"
    elif isinstance(server_raw, dict) and isinstance(server_raw.get("answers"), dict):
        unknown_server = set(server_raw) - {"answers"}
        if unknown_server:
            raise ContractDefect(
                f"scenario {name!r} given.server has unknown members {sorted(unknown_server)!r}"
            )
        # A scripted answer names published response members and nothing else;
        # an unknown *value* stays legal, since a client must read it as unknown.
        answered = domain_schema("decision-result")["properties"]
        unknown_answers = set(server_raw["answers"]) - set(answered)
        if unknown_answers:
            raise ContractDefect(
                f"scenario {name!r} given.server.answers has unknown members "
                f"{sorted(unknown_answers)!r}"
            )
        server = Answers(server_raw["answers"])
    elif server_raw is None:
        server = None
    else:
        raise ContractDefect(f"scenario {name!r} has an invalid given.server")
    then_raw = raw.get("then")
    then = None
    if then_raw is not None:
        if (
            not isinstance(then_raw, dict)
            or set(then_raw) - {"resolve", "expect"}
            or not isinstance(then_raw.get("expect"), dict)
            or set(then_raw["expect"]) - {"state", "after_resolution"}
        ):
            raise ContractDefect(f"scenario {name!r} has an invalid then section")
        then = Then(
            then_raw["resolve"],
            then_raw["expect"]["state"],
            then_raw["expect"].get("after_resolution"),
        )
    scenario = Scenario(
        name=name,
        binds=Binds(raw["binds"]),
        article=str(raw["article"]),
        given=Given(
            policy,
            server,
            given_raw.get("policy_unavailable") is True,
            changed_policy,
            tuple(str(item) for item in given_raw["applying_outcomes"])
            if isinstance(given_raw.get("applying_outcomes"), list)
            else None,
            given_raw.get("connection_live")
            if isinstance(given_raw.get("connection_live"), bool)
            else None,
            given_raw.get("signal_channel") is not False,
            given_raw.get("grant_lifetime_seconds")
            if isinstance(given_raw.get("grant_lifetime_seconds"), int)
            and not isinstance(given_raw.get("grant_lifetime_seconds"), bool)
            else None,
            given_raw.get("grant_arguments_digest")
            if isinstance(given_raw.get("grant_arguments_digest"), str)
            else None,
        ),
        ask=DecisionAsk(
            capability=str(ask_raw["capability"]),
            scope=str(ask_raw.get("scope", "local")),
            arguments_digest=ask_raw.get("arguments_digest"),
            correlation=ask_raw.get("correlation"),
        ),
        expect=Expect(
            outcome=expect_raw.get("outcome"),
            reason=expect_raw.get("reason"),
            result=expect_raw.get("result"),
            problem=expect_raw.get("problem"),
            reported_outcome=expect_raw.get("reported_outcome"),
            grant=expect_raw.get("grant"),
            grant_use=_grant_use(name, expect_raw.get("grant_use")),
            after_policy_change=expect_raw.get("after_policy_change"),
        ),
        then=then,
        raw=raw,
    )
    if not scenario.expect.members():
        raise ContractDefect(f"scenario {name!r} must assert at least one observable")
    return scenario


def load_scenarios(path: Path | None = None) -> Mapping[str, Scenario]:
    """Load the shipped scenarios, refusing any entry that omits its binding."""
    raw = (
        path.read_text(encoding="utf-8")
        if path is not None
        else artifact("domain", "golden-scenarios.json").read_text(encoding="utf-8")
    )
    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("scenarios"), dict):
        raise ContractDefect("scenario document must contain a scenarios object")
    return {name: _parse_scenario(name, value) for name, value in document["scenarios"].items()}


def schema_examples() -> Mapping[str, Mapping[str, object]]:
    """Representative documents used to exercise every published schema."""
    generation = 1
    instant = "2026-09-04T00:00:00+00:00"
    digest = "sha256:" + "0" * 64
    return {
        "decision-ask-request": {
            "contract_generation": generation,
            "capability": "example.effect",
            "scope": "local",
            "arguments_digest": digest,
            "correlation": "correlation-1",
        },
        "decision-result": {
            "contract_generation": generation,
            "authority": "authoritative",
            "decision_ref": "decision-1",
            "scope": "local",
            "capability": "example.effect",
            "outcome": "allow",
            "reason": "policy_allows",
            "policy_version": digest,
            "approval_ref": None,
            "decided_at": instant,
            "correlation": None,
            "principal": {"kind": "process", "uid": 1000, "name": "build"},
            "arguments_digest": digest,
            "rule_id": "example-rule",
            "grant": None,
            "principal_references": ["group:ops", "user:build"],
            "evaluation_recipe": "sayfirst/policy-evaluation/v1",
            "correlation_source": "absent",
        },
        "decision-record": {
            "contract_generation": generation,
            "authority": "authoritative",
            "decision_ref": "decision-1",
            "scope": "local",
            "capability": "example.effect",
            "outcome": "allow",
            "reason": "policy_allows",
            "policy_version": digest,
            "decided_at": instant,
            "correlation": None,
            "principal": {"kind": "process", "uid": 1000, "name": "build"},
            "arguments_digest": digest,
            "rule_id": "example-rule",
            "grant_id": "grant-1",
            "principal_references": ["group:ops", "user:build"],
            "evaluation_recipe": "sayfirst/policy-evaluation/v1",
            "correlation_source": "absent",
        },
        "grant": {
            "grant_id": "grant-1",
            "decision_ref": "decision-1",
            "policy_version": digest,
            "issued_at": instant,
            "lifetime_seconds": 30,
            "expires_at": "2026-09-04T00:00:30+00:00",
            "heartbeat_seconds": 5,
            "conditions": {
                "scope": "local",
                "capability": "example.effect",
                "principal_reference": "user:build",
                "arguments_digest": digest,
            },
        },
        "grant-signal": {
            "contract_generation": generation,
            "kind": "grant_ended",
            "grant_id": "grant-1",
            "policy_version": digest,
            "at": instant,
            "reason": "policy_version_changed",
        },
        "policy-status": {
            "contract_generation": generation,
            "authority": "file",
            "policy_version": digest,
            "format": 1,
            "loaded_at": instant,
            "rule_count": 1,
            "projection": {
                "kind": "memory",
                "policy_version": digest,
                "in_step": "yes",
            },
        },
        "approval-resolve-request": {
            "contract_generation": generation,
            "scope": "local",
            "approval_ref": "approval-1",
            "resolution": "approve",
        },
        "approval-result": {
            "contract_generation": generation,
            "authority": "authoritative",
            "approval_ref": "approval-1",
            "decision_ref": "decision-1",
            "scope": "local",
            "capability": "example.effect",
            "state": "pending",
            "requested_at": instant,
            "deadline": "2026-09-04T00:01:00+00:00",
            "resolved_at": None,
            "resolution_reason": None,
        },
        "status-result": {
            "contract_generation": generation,
            "supported_generations": [generation],
            "integrity_grade": {
                "grade": "unverified",
                "basis": "access_not_established",
                "evaluated_at": instant,
                "store": "file",
                "reevaluation_interval_seconds": 30,
            },
            "privacy_provider": "none",
            "principal": {"kind": "user", "uid": 1000, "name": None},
            "store": {"authority": "authoritative", "kind": "file"},
        },
        "problem-document": {
            "contract_generation": generation,
            "code": "internal",
            "message": "unclassified failure",
            "retryable": None,
        },
        "evidence-entry": {
            "scope": "local",
            "kind": "effect",
            "recorded_at": instant,
            "connection_id": "connection-1",
            "principal": {"kind": "user", "id": "example", "via": []},
            "body": {
                "capability": "example.effect",
                "decision_id": "decision-1",
                "outcome": "allow",
                "decided_at": instant,
                "policy_version": "policy-1",
            },
            "sequence": 1,
            "previous_hash": None,
            "entry_hash": "0" * 64,
            "preimage_version": "sayfirst-control-plane/evidence/v1",
        },
        "evidence-entry-writer": {
            "scope": "local",
            "kind": "effect",
            "recorded_at": instant,
            "connection_id": "connection-1",
            "principal": {"kind": "user", "id": "example", "via": []},
            "body": {
                "capability": "example.effect",
                "decision_id": "decision-1",
                "outcome": "allow",
                "decided_at": instant,
                "policy_version": digest,
                "reason": "policy_allows",
                "rule_id": "example-rule",
                "arguments_digest": digest,
                "correlation": None,
                "correlation_source": "absent",
                "principal_references": ["group:ops", "user:build"],
                "evaluation_recipe": "sayfirst/policy-evaluation/v1",
                "decision_position": {"store_id": "store-1", "position": 1},
                "recording_epoch": "epoch-1",
            },
            "sequence": 1,
            "previous_hash": None,
            "entry_hash": "0" * 64,
            "preimage_version": "sayfirst-control-plane/evidence/v1",
        },
        "evidence-verdict": {
            "scope": "local",
            "condition": "intact",
            "from_sequence": 1,
            "to_sequence": 1,
            "up_to": 1,
            "sequence": None,
            "expected": None,
            "found": None,
            "version": None,
            "covers_an_entry": True,
            "declared_gaps": [],
            "grades": [{"connection_id": "connection-1", "grade": "unverified"}],
        },
        "evidence-page-result": {
            "contract_version": "1",
            "scope": "local",
            "from_sequence": 1,
            "to_sequence": None,
            "entries": [],
            "verification": {
                "scope": "local",
                "condition": "unverifiable",
                "from_sequence": 1,
                "to_sequence": None,
                "up_to": None,
                "sequence": None,
                "expected": None,
                "found": None,
                "version": None,
                "covers_an_entry": False,
                "declared_gaps": [],
                "grades": [],
            },
            "next_from": None,
        },
        "evidence-export-result": {
            "contract_version": "1",
            "scope": "local",
            "from_sequence": 1,
            "to_sequence": None,
            "entry_count": 0,
            "entries": [],
            "verification": {
                "scope": "local",
                "condition": "unverifiable",
                "from_sequence": 1,
                "to_sequence": None,
                "up_to": None,
                "sequence": None,
                "expected": None,
                "found": None,
                "version": None,
                "covers_an_entry": False,
                "declared_gaps": [],
                "grades": [],
            },
            "manifest_hash": "0" * 64,
            "next_from": None,
            "manifest_version": "sayfirst-control-plane/evidence-export/v3",
            "policy_versions": {digest: {"state": "absent"}},
            "recovery_context": [],
        },
        "peer": {"uid": 1000, "gid": 1000, "pid": 4242, "captured_at": instant},
        "principal": {
            "kind": "user",
            "uid": 1000,
            "gid": 1000,
            "name": "example",
            "groups": ["example", "ops"],
            "groups_status": "resolved",
            "unnamed_group_ids": [],
            "established_by": "peer_credential",
            "established_at": instant,
            "reference": "user:1000",
        },
        "delegation": {
            "status": "declared",
            "chain": [{"kind": "user", "name": "example", "uid": 1001, "via": "privilege_tool"}],
        },
        "whoami-result": {
            "contract_generation": generation,
            "connection_id": "connection-1",
            "socket_path": "/run/sayfirst/daemon.sock",
            "mode": "per_user",
            "peer": {"uid": 1000, "gid": 1000, "pid": 4242, "captured_at": instant},
            "principal": None,
            "status": "unknown",
            "refresh_due_at": None,
            "group_lifetime_seconds": 60,
            "delegation": None,
        },
    }
