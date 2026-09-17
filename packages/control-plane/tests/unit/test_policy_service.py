# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import jsonschema
import pytest
from sayfirst_contract.artifacts import domain_schema
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.policy import PolicyService, PolicyStartRefused
from sayfirst_control_plane.ports.policy_projection import ProjectedPolicy
from sayfirst_control_plane.ports.policy_store import (
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 4, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


class ProtectedFilePolicyStore(FilePolicyStore):
    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


def _policy(outcome: str, *, revision: str = "approved") -> bytes:
    return (
        "format = 1\n"
        "[revision]\n"
        f'reason = "{revision}"\n'
        "[[rule]]\n"
        'id = "mail"\n'
        'capability = "mail.send"\n'
        'principals = ["user:build"]\n'
        f'outcome = "{outcome}"\n'
        'reason = "host rule"\n'
    ).encode()


def _service(path, clock, *projections):  # type: ignore[no-untyped-def]
    events = MemoryEvents()
    service = PolicyService(
        ProtectedFilePolicyStore(path, clock=clock),
        projections or (MemoryPolicyProjection(),),
        events=events,
        reload_seconds=2,
        clock=clock,
    )
    return service, events


def test_the_daemon_refuses_to_start_on_an_unprotected_policy(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: startup accepts only a proven-protected authority."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    path.chmod(0o666)
    service = PolicyService(FilePolicyStore(path), (MemoryPolicyProjection(),))
    with pytest.raises(PolicyStartRefused, match="policy path.*(?:group_write|other_write)"):
        service.start(ProtectionExpectation.per_user(os.getuid()))


def test_start_checks_protection_before_parsing_the_authority(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: attacker-writable authority bytes are not parsed before refusal."""
    path = tmp_path / "policy.toml"
    path.write_bytes(b"broken = [toml")
    path.chmod(0o666)
    service = PolicyService(FilePolicyStore(path), (MemoryPolicyProjection(),))
    with pytest.raises(PolicyStartRefused, match="(?:group_write|other_write)"):
        service.start(ProtectionExpectation.per_user(os.getuid()))


def test_an_absent_policy_refuses_start_and_explains_the_deny_all_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 1 and 3: the daemon ships and creates no implicit policy."""
    service, _ = _service(tmp_path / "absent.toml", Clock())
    with pytest.raises(PolicyStartRefused, match="empty rule list denies everything"):
        service.start(ProtectionExpectation.per_user(os.getuid()))


def test_a_version_change_is_recorded_with_its_stated_reason(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 1 and 10: a content change records its administrator reason."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow", revision="first"))
    clock = Clock()
    service, events = _service(path, clock)
    service.start(ProtectionExpectation.per_user(os.getuid()))
    previous = service.current_version
    path.write_bytes(_policy("deny", revision="mail is now disabled"))
    loaded = service.load_for_decision()
    assert loaded.policy_version != previous  # type: ignore[union-attr]
    changed = events.of_kind("policy.version_changed")
    assert len(changed) == 1
    assert changed[0].details["from"] == previous
    assert changed[0].details["revision.reason"] == "mail is now disabled"


def test_a_version_change_is_noticed_within_the_reload_interval(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 10: the periodic authority check has a bounded detection delay."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service, _ = _service(path, clock)
    service.start(ProtectionExpectation.per_user(os.getuid()))
    original = service.current_version
    path.write_bytes(_policy("deny"))
    clock.now += timedelta(seconds=1)
    assert not service.reload_if_due()
    assert service.current_version == original
    clock.now += timedelta(seconds=1)
    assert service.reload_if_due()
    assert service.current_version != original


def test_a_reload_failure_does_not_end_live_grants(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 1: a failed observation does not invent a version change."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service, events = _service(path, clock)
    service.start(ProtectionExpectation.per_user(os.getuid()))
    signalled = []
    service.on_version_change(signalled.append)
    current = service.current_version
    path.write_bytes(b"broken = [toml")
    first = service.load_for_decision()
    second = service.load_for_decision()
    assert first == second
    assert service.current_version == current
    assert signalled == []
    assert len(events.of_kind("policy.reload_failed")) == 1


def test_a_failure_after_recovery_is_recorded_as_a_new_failure(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: recovery separates identical authority failure events."""
    path = tmp_path / "policy.toml"
    valid = _policy("allow")
    path.write_bytes(valid)
    clock = Clock()
    service, events = _service(path, clock)
    service.start(ProtectionExpectation.per_user(os.getuid()))
    path.write_bytes(b"broken = [toml")
    service.load_for_decision()
    service.load_for_decision()
    path.write_bytes(valid)
    service.load_for_decision()
    path.write_bytes(b"broken = [toml")
    service.load_for_decision()
    assert len(events.of_kind("policy.reload_failed")) == 2


def test_a_failing_projection_does_not_touch_a_decision(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: projection availability is not decision authority."""

    class FailingProjection:
        KIND = "database"

        def rebuild(self, loaded):  # type: ignore[no-untyped-def]
            raise OSError("database unavailable")

        def current(self):  # type: ignore[no-untyped-def]
            return None

        def clear(self) -> None: ...

    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service, events = _service(path, clock, FailingProjection())
    service.start(ProtectionExpectation.per_user(os.getuid()))
    loaded = service.load_for_decision()
    assert loaded.policy.rules[0].outcome.value == "allow"  # type: ignore[union-attr]
    assert len(events.of_kind("policy.projection_failed")) == 1
    assert service.status().projection.in_step == "unknown"


def test_policy_status_names_the_projection_and_its_authority_version(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: status says it is reporting a projection."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service, _ = _service(path, clock)
    service.start(ProtectionExpectation.per_user(os.getuid()))
    status = service.status()
    assert status.authority == "file"
    assert status.policy_version == service.current_version
    assert status.projection.kind == "memory"
    assert status.projection.in_step == "yes"


def test_policy_status_combines_every_configured_projection(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 3: one failed projection is visible regardless of composition order."""

    class FailingProjection:
        KIND = "database"

        def rebuild(self, loaded):  # type: ignore[no-untyped-def]
            raise OSError("database unavailable")

        def current(self):  # type: ignore[no-untyped-def]
            return None

        def clear(self) -> None: ...

    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    for projections in (
        (MemoryPolicyProjection(), FailingProjection()),
        (FailingProjection(), MemoryPolicyProjection()),
    ):
        service, _ = _service(path, Clock(), *projections)
        service.start(ProtectionExpectation.per_user(os.getuid()))
        assert service.status().projection.kind == "combined"
        assert service.status().projection.in_step == "unknown"


def test_a_listener_composed_twice_is_signalled_once(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: a collaborator composed twice does not report two changes."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service, _ = _service(path, clock)
    service.start(ProtectionExpectation.per_user(os.getuid()))
    signalled: list[str] = []
    service.on_version_change(signalled.append)
    service.on_version_change(signalled.append)
    path.write_bytes(_policy("deny"))
    clock.now += timedelta(seconds=2)
    assert service.reload_if_due()
    assert signalled == [service.current_version]


class _ThirdPartyProjection:
    """A conforming projection provider written outside this repository."""

    VERSION = 1

    def __init__(self) -> None:
        self._current: ProjectedPolicy | None = None

    def rebuild(self, loaded) -> None:  # type: ignore[no-untyped-def]
        self._current = ProjectedPolicy(
            loaded.policy_version,
            loaded.policy.format,
            loaded.loaded_at,
            len(loaded.policy.rules),
            loaded.policy.rules,
        )

    def current(self) -> ProjectedPolicy | None:
        return self._current

    def clear(self) -> None:
        self._current = None


_ABSENT = object()


def _provider(kind: object) -> _ThirdPartyProjection:
    namespace = {} if kind is _ABSENT else {"KIND": kind}
    return type("Provider", (_ThirdPartyProjection,), namespace)()  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("kind", "answered"),
    [
        ("redis", "redis"),
        ("Redis Cache", "unknown"),
        ("", "unknown"),
        (7, "unknown"),
        (_ABSENT, "unknown"),
    ],
)
def test_a_projection_provider_never_moves_the_status_outside_its_published_shape(
    kind,  # type: ignore[no-untyped-def]
    answered,
    tmp_path,
) -> None:
    """Articles 2, 8 and 13: a kind is published as declared, or as unknown, never guessed."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service = PolicyService(
        ProtectedFilePolicyStore(path, clock=clock),
        (_provider(kind),),
        clock=clock,
    )
    service.start(ProtectionExpectation.per_user(os.getuid()))
    status = service.status()
    assert status.projection.kind == answered
    jsonschema.validate(
        {
            "kind": status.projection.kind,
            "policy_version": status.projection.policy_version,
            "in_step": status.projection.in_step.value,
        },
        domain_schema("policy-status")["properties"]["projection"],
    )


def test_a_provider_that_names_no_kind_is_not_reported_as_the_shipped_one(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: 'did not look' is not the same fact as 'looked and found memory'."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_policy("allow"))
    clock = Clock()
    service = PolicyService(
        ProtectedFilePolicyStore(path, clock=clock),
        (_provider(_ABSENT),),
        clock=clock,
    )
    service.start(ProtectionExpectation.per_user(os.getuid()))
    assert service.status().projection.kind != MemoryPolicyProjection.KIND
