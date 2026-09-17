# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

import pytest
from sayfirst_contract.decisions import Decision, Outcome, Reason
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.adapters.sqlite.policy_projection import SqlitePolicyProjection
from sayfirst_control_plane.domain.policy import PolicyInvalid, Principal, parse_policy
from sayfirst_control_plane.ports.decision_store import ScopeRequired
from sayfirst_control_plane.ports.policy_projection import ProjectedPolicy
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    AccessVerdict,
    LoadedPolicy,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)
from sayfirst_testing.decision_store_contract import assert_decision_store_contract
from sayfirst_testing.policy_projection_contract import assert_policy_projection_contract
from sayfirst_testing.policy_store_contract import assert_policy_store_contract

NOW = datetime(2026, 9, 4, tzinfo=UTC)


def _policy() -> bytes:
    return (
        b'format = 1\n[revision]\nreason = "conformance"\n'
        b'[[rule]]\nid = "mail"\ncapability = "mail.send"\n'
        b'principals = ["user:build"]\noutcome = "allow"\nreason = "test"\n'
    )


def _loaded() -> LoadedPolicy:
    raw = _policy()
    policy = parse_policy(raw)
    assert not isinstance(policy, PolicyInvalid)
    return LoadedPolicy(policy, "sha256:" + "a" * 64, NOW, len(raw))


def _decision(*, scope: str = "local", outcome: Outcome = Outcome.DENY) -> Decision:
    return Decision(
        "decision-1",
        scope,
        "mail.send",
        outcome,
        Reason.POLICY_ABSENT,
        "sha256:" + "a" * 64,
        None,
        "2026-09-04T00:00:00Z",
        None,
        1,
        {},
    )


@pytest.fixture
def protected_authority() -> Iterator[Path]:
    """A policy file whose whole resolved chain meets the per-user expectation.

    A world-writable shared temporary directory can never satisfy it, so the
    per-user runtime directory of article 6 is used, and a host that has none
    says so rather than reporting an unproven suite as proven (article 2).
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime or not Path(runtime).is_dir():
        pytest.skip("no per-user runtime directory to hold a protected authority")
    root = Path(tempfile.mkdtemp(dir=runtime))
    try:
        root.chmod(0o700)
        path = root / "policy.toml"
        path.write_bytes(_policy())
        path.chmod(0o600)
        verdict = FilePolicyStore(path).protection_at_start(
            ProtectionExpectation.per_user(path.stat().st_uid)
        )
        if verdict.kind is not ProtectionState.PROTECTED:
            pytest.skip(f"{verdict.component} is {verdict.reason}: no protected chain here")
        yield path
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_file_policy_store_passes_the_published_contract(protected_authority, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: the file authority is proven by the public port suite."""
    exposed_path = tmp_path / "exposed.toml"
    exposed_path.write_bytes(_policy())
    exposed_path.chmod(0o666)
    uid = protected_authority.stat().st_uid
    principal = Principal("process", uid + 1000, "build", (), ())
    assert_policy_store_contract(
        FilePolicyStore(protected_authority, clock=lambda: NOW),
        FilePolicyStore(tmp_path / "absent.toml", clock=lambda: NOW),
        FilePolicyStore(exposed_path, clock=lambda: NOW),
        expectation=ProtectionExpectation.per_user(uid),
        principal=principal,
    )


def test_a_constant_protected_policy_adapter_fails_the_published_contract(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 8: a fixed-answer adapter is not a policy authority provider."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy())

    class ConstantProtected:
        VERSION = 1
        max_lifetime_seconds = 3600

        def __init__(self, delegate):  # type: ignore[no-untyped-def]
            self.delegate = delegate

        def load(self):  # type: ignore[no-untyped-def]
            return self.delegate.load()

        def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
            return ProtectionVerdict(ProtectionState.PROTECTED)

        def write_access_of(self, principal):  # type: ignore[no-untyped-def]
            return AccessVerdict(AccessState.NOT_WRITABLE)

    adapter = ConstantProtected(FilePolicyStore(path, clock=lambda: NOW))
    with pytest.raises(AssertionError):
        assert_policy_store_contract(
            adapter,
            FilePolicyStore(tmp_path / "absent.toml", clock=lambda: NOW),
            adapter,
            expectation=ProtectionExpectation.per_user(path.stat().st_uid),
            principal=Principal("process", path.stat().st_uid + 1000, "build", (), ()),
        )


@pytest.mark.parametrize("kind", ["memory", "database"])
def test_every_policy_projection_adapter_passes_the_same_published_contract(
    kind,
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Articles 3 and 8: both projections obey one rebuild-only suite."""
    projection = (
        MemoryPolicyProjection()
        if kind == "memory"
        else SqlitePolicyProjection(tmp_path / "projection.sqlite3")
    )
    assert_policy_projection_contract(projection, _loaded())


def test_memory_decision_store_passes_the_published_contract() -> None:
    """Articles 3, 5 and 8: the decision authority is append-only and scoped."""
    assert_decision_store_contract(
        MemoryDecisionStore(),
        _decision(),
        _decision(outcome=Outcome.ALLOW),
    )


def test_the_conformance_distribution_publishes_every_port_suite() -> None:
    """Article 8: downstream providers receive all three reusable suites."""
    package = files("sayfirst_testing")
    assert {
        "policy_store_contract.py",
        "policy_projection_contract.py",
        "decision_store_contract.py",
    } <= {item.name for item in package.iterdir()}


def test_a_constant_exposed_policy_adapter_fails_the_published_contract(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 8: one fixed verdict for every path is not an authority provider."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy())

    class ConstantExposed:
        VERSION = 1
        max_lifetime_seconds = 3600

        def __init__(self, delegate):  # type: ignore[no-untyped-def]
            self.delegate = delegate

        def load(self):  # type: ignore[no-untyped-def]
            return self.delegate.load()

        def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
            return ProtectionVerdict(ProtectionState.EXPOSED, "always")

        def write_access_of(self, principal):  # type: ignore[no-untyped-def]
            return AccessVerdict(AccessState.WRITABLE, "always")

    adapter = ConstantExposed(FilePolicyStore(path, clock=lambda: NOW))
    with pytest.raises(AssertionError):
        assert_policy_store_contract(
            adapter,
            FilePolicyStore(tmp_path / "absent.toml", clock=lambda: NOW),
            adapter,
            expectation=ProtectionExpectation.per_user(path.stat().st_uid),
            principal=Principal("process", path.stat().st_uid + 1000, "build", (), ()),
        )


def test_a_constant_projection_adapter_fails_the_published_contract() -> None:
    """Articles 3 and 8: a projection that answers the same snapshot forever is not one."""

    class ConstantProjection:
        VERSION = 1
        KIND = "constant"

        def __init__(self, loaded) -> None:  # type: ignore[no-untyped-def]
            self._answer = ProjectedPolicy(
                policy_version=loaded.policy_version,
                format=loaded.policy.format,
                loaded_at=loaded.loaded_at,
                rule_count=len(loaded.policy.rules),
                rules=loaded.policy.rules,
            )

        def rebuild(self, loaded) -> None:  # type: ignore[no-untyped-def]
            return None

        def current(self):  # type: ignore[no-untyped-def]
            return self._answer

        def clear(self) -> None:
            return None

    with pytest.raises(AssertionError):
        assert_policy_projection_contract(ConstantProjection(_loaded()), _loaded())


def test_an_overwriting_decision_store_fails_the_published_contract() -> None:
    """Articles 3 and 8: a store that accepts a replacement is not an authority."""

    class OverwritingStore:
        VERSION = 1

        def __init__(self) -> None:
            self._records: dict[tuple[str, str], Decision] = {}

        def append(self, decision: Decision) -> None:
            self._records[(decision.scope, decision.decision_ref)] = decision

        def get(self, scope: str, decision_ref: str) -> Decision | None:
            if not scope:
                raise ScopeRequired("scope is required")
            return self._records.get((scope, decision_ref))

    with pytest.raises(AssertionError):
        assert_decision_store_contract(
            OverwritingStore(),
            _decision(),
            _decision(outcome=Outcome.ALLOW),
        )


def test_a_projection_naming_an_unpublishable_kind_fails_the_published_contract() -> None:
    """Articles 8 and 13: a provider cannot name itself outside the published shape."""

    class UnpublishableKind(MemoryPolicyProjection):
        KIND = "Redis Cache"

    with pytest.raises(AssertionError, match="kind"):
        assert_policy_projection_contract(UnpublishableKind(), _loaded())


def test_a_projection_naming_no_kind_fails_the_published_contract() -> None:
    """Articles 2 and 8: an unnamed provider is not answered as a named one."""

    class UnnamedKind(MemoryPolicyProjection):
        KIND = None  # type: ignore[assignment]

    with pytest.raises(AssertionError, match="kind"):
        assert_policy_projection_contract(UnnamedKind(), _loaded())


def test_a_third_party_projection_kind_passes_the_published_contract() -> None:
    """Article 8: the published shape admits a provider this repository never ships."""

    class ThirdPartyKind(MemoryPolicyProjection):
        KIND = "redis"

    assert_policy_projection_contract(ThirdPartyKind(), _loaded())
