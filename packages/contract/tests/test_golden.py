# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from pathlib import Path

import pytest
from sayfirst_contract.approvals import ApprovalState, Resolution
from sayfirst_contract.decisions import Outcome, Reason
from sayfirst_contract.golden import Binds, ContractDefect, Given, Regime, load_scenarios
from sayfirst_contract.grants import GrantUse
from sayfirst_contract.problems import ProblemCode


def test_every_scenario_declares_what_it_binds() -> None:
    """Article 13: every authoritative scenario names each side it binds."""
    scenarios = load_scenarios()
    assert len(scenarios) == 17
    assert all(
        scenario.binds.value in {"client", "server", "both"} for scenario in scenarios.values()
    )


def test_generation_one_publishes_the_policy_and_grant_scenarios() -> None:
    """Articles 1, 10 and 13: clients and servers share the block 2.3 arbiter."""
    assert {
        "grant_hit_within_lifetime",
        "grant_miss_after_policy_version_change",
        "grant_expired_by_lifetime",
        "grant_void_on_connection_loss",
        "grant_void_on_arguments_change",
        "policy_unavailable_is_could_not_ask",
        "no_grant_on_deny",
        "no_grant_without_signal_channel",
        "strictest_rule_wins",
    } <= set(load_scenarios())


def test_every_generation_one_grant_scenario_asserts_grant_presence() -> None:
    """Articles 10 and 13: every grant scenario distinguishes issuance from absence."""
    names = {
        "grant_hit_within_lifetime",
        "grant_miss_after_policy_version_change",
        "grant_expired_by_lifetime",
        "grant_void_on_connection_loss",
        "grant_void_on_arguments_change",
        "policy_unavailable_is_could_not_ask",
        "no_grant_on_deny",
        "no_grant_without_signal_channel",
        "strictest_rule_wins",
    }
    scenarios = load_scenarios()
    assert {scenarios[name].expect.grant for name in names} <= {"present", "absent"}
    assert all(scenarios[name].expect.grant is not None for name in names)
    changed = scenarios["grant_miss_after_policy_version_change"]
    assert changed.expect.after_policy_change == {
        "outcome": "deny",
        "reason": "policy_denies",
        "grant": "absent",
    }


def test_the_binds_guard_catches_a_scenario_without_binds(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the binds guard rejects a planted omission."""
    source = {
        "x-contract-generation": 1,
        "x-spdx-license-identifier": "Apache-2.0 OR MIT-0",
        "scenarios": {
            "planted": {
                "article": "13",
                "given": {"policy": {}},
                "ask": {"capability": "example.effect", "scope": "local"},
                "expect": {"outcome": "deny", "reason": "policy_absent"},
            }
        },
    }
    target = tmp_path / "scenarios.json"
    target.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ContractDefect, match="planted.*binds"):
        load_scenarios(target)


def test_a_scenario_must_assert_at_least_one_observable(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 9 and 13: an authoritative scenario cannot succeed vacuously."""
    source = {
        "x-contract-generation": 1,
        "x-spdx-license-identifier": "Apache-2.0 OR MIT-0",
        "scenarios": {
            "check_nothing": {
                "binds": "both",
                "article": "13",
                "given": {"policy": {}},
                "ask": {"capability": "example.effect", "scope": "local"},
                "expect": {},
                "then": {"resolve": "approve", "expect": {"state": "approved"}},
            }
        },
    }
    target = tmp_path / "scenarios.json"
    target.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ContractDefect, match="check_nothing.*observable"):
        load_scenarios(target)


def test_an_unknown_given_member_is_refused(tmp_path) -> None:
    """Article 13: scenario arrangements never silently discard a member."""
    scenario = json.loads(json.dumps(load_scenarios()["allow"].raw))
    scenario["given"]["future_member"] = True
    target = tmp_path / "scenarios.json"
    target.write_text(
        json.dumps(
            {
                "x-contract-generation": 1,
                "x-spdx-license-identifier": "Apache-2.0 OR MIT-0",
                "scenarios": {"planted": scenario},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ContractDefect, match="planted.*given.*future_member"):
        load_scenarios(target)


def test_every_scenario_names_the_article_it_holds() -> None:
    """Article 13: every scenario points at an existing constitutional article."""
    scenarios = load_scenarios()
    assert len(scenarios) >= 8
    assert all(
        scenario.article.isdigit() and 0 <= int(scenario.article) <= 18
        for scenario in scenarios.values()
    )


def _string_values(value: object):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)
    elif isinstance(value, str):
        yield value


def _unknown_scenario_values(scenarios: dict[str, object]) -> list[str]:
    known = {
        *(
            item.value
            for enum in (Outcome, Reason, ApprovalState, ProblemCode, Regime, Binds, GrantUse)
            for item in enum
        ),
        *(item.value for item in Resolution),
        "could_not_ask",
        "expire",
        "local",
    }
    capability = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$")
    return [
        value
        for value in _string_values(scenarios)
        if value not in known
        and not value.isdigit()
        and capability.fullmatch(value) is None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
    ]


def test_the_unknown_test_value_is_manifestly_synthetic() -> None:
    """Article 13: future-value fixtures cannot disclose a feature vocabulary."""
    raw = {name: scenario.raw for name, scenario in load_scenarios().items()}
    unknown_values = _unknown_scenario_values(raw)
    assert unknown_values
    assert all(value.startswith("zz-synthetic-") for value in unknown_values)


def test_the_unknown_value_guard_catches_a_real_looking_word() -> None:
    """Article 13: the fixture guard detects unknown values without a zz- prefix."""
    raw = {name: dict(scenario.raw) for name, scenario in load_scenarios().items()}
    raw["unknown_outcome"] = json.loads(json.dumps(raw["unknown_outcome"]))
    raw["unknown_outcome"]["given"]["server"]["answers"]["outcome"] = "future_regime_x"
    unknown_values = _unknown_scenario_values(raw)
    assert "future_regime_x" in unknown_values
    assert not all(value.startswith("zz-synthetic-") for value in unknown_values)


def _planted(base: str, plant) -> dict[str, object]:  # type: ignore[no-untyped-def]
    scenario = json.loads(json.dumps(load_scenarios()[base].raw))
    plant(scenario)
    return {
        "x-contract-generation": 1,
        "x-spdx-license-identifier": "Apache-2.0 OR MIT-0",
        "scenarios": {"planted": scenario},
    }


@pytest.mark.parametrize(
    ("base", "plant", "expected"),
    [
        (
            "allow",
            lambda item: item["ask"].update({"future_member": True}),
            "planted.*ask.*future_member",
        ),
        (
            "allow",
            lambda item: item["expect"].update({"future_member": True}),
            "planted.*expect.*future_member",
        ),
        (
            "review_approve",
            lambda item: item["then"].update({"future_member": True}),
            "planted.*then",
        ),
        (
            "unreachable",
            lambda item: item["given"].update({"server": {"future_member": True}}),
            "planted.*given.server",
        ),
        (
            "unknown_outcome",
            lambda item: item["given"]["server"].update({"future_member": True}),
            "planted.*given.server.*future_member",
        ),
        (
            "unknown_outcome",
            lambda item: item["given"]["server"]["answers"].update({"future_member": True}),
            "planted.*answers.*future_member",
        ),
    ],
)
def test_every_unknown_scenario_member_is_refused(tmp_path, base, plant, expected) -> None:  # type: ignore[no-untyped-def]
    """Article 13: no section of a scenario silently discards a member it does not know."""
    target = tmp_path / "scenarios.json"
    target.write_text(json.dumps(_planted(base, plant)), encoding="utf-8")
    with pytest.raises(ContractDefect, match=expected):
        load_scenarios(target)


REPOSITORY = Path(__file__).resolve().parents[3]


def _members_without_a_reader(arrangement: type = Given) -> list[str]:
    """Return published `given` members no shipped side or run reads."""
    sources = [
        text
        for path in (REPOSITORY / "packages").rglob("*.py")
        if path.name != "golden.py"
        for text in (path.read_text(encoding="utf-8"),)
    ]
    return [
        member
        for member in (field.name for field in fields(arrangement))
        if not any(
            re.search(rf"given\.{member}\b|given\[[\"']{member}[\"']\]", text) for text in sources
        )
    ]


def test_every_published_arrangement_is_read_by_something() -> None:
    """Article 9: an arrangement nothing reads arranges nothing, and proves nothing.

    A scenario whose `given` member no side reads is run in a world the
    scenario did not describe, and reports `proven` for it.
    """
    assert _members_without_a_reader() == []


def test_the_arrangement_guard_names_a_member_nothing_reads() -> None:
    """Article 9: the guard is not vacuous — an unread member is named."""

    @dataclass(frozen=True)
    class Planted:
        zz_synthetic_arrangement: bool

    assert _members_without_a_reader(Planted) == ["zz_synthetic_arrangement"]
