# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.adapters.sqlite.policy_projection import SqlitePolicyProjection
from sayfirst_control_plane.domain.policy import PolicyInvalid, parse_policy
from sayfirst_control_plane.ports.policy_projection import PolicyProjection
from sayfirst_control_plane.ports.policy_store import LoadedPolicy


def _loaded(version: str = "sha256:" + "a" * 64) -> LoadedPolicy:
    raw = (
        "format = 1\n"
        "[revision]\n"
        'reason = "projection source"\n'
        "[[rule]]\n"
        'id = "mail"\n'
        'capability = "mail.send"\n'
        'principals = ["group:ci"]\n'
        'outcome = "allow"\n'
        'reason = "approved"\n'
        "grant_lifetime_seconds = 60\n"
        'arguments_digest = "sha256:' + "1" * 64 + '"\n'
    ).encode()
    policy = parse_policy(raw)
    assert not isinstance(policy, PolicyInvalid)
    return LoadedPolicy(policy, version, datetime(2026, 9, 4, tzinfo=UTC), len(raw))


@pytest.mark.parametrize("kind", ["memory", "database"])
def test_the_projection_is_rebuilt_from_the_authority(kind, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: a projection is rebuilt whole from the policy the service loaded.

    What this fixture demonstrates is bounded by what it carries: one `allow`
    rule with a lifetime and a pinned digest. It does not demonstrate that
    every rule member survives the database projection, and one does not — the
    case below carries the gap rather than leaving this docstring to claim more
    than its fixture holds (article 2).
    """
    projection = (
        MemoryPolicyProjection()
        if kind == "memory"
        else SqlitePolicyProjection(tmp_path / "projection.sqlite3")
    )
    loaded = _loaded()
    projection.rebuild(loaded)
    current = projection.current()
    assert current is not None
    assert current.policy_version == loaded.policy_version
    assert current.loaded_at == loaded.loaded_at
    assert current.rule_count == len(loaded.policy.rules)
    assert current.rules == loaded.policy.rules


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the database projection keeps eight rule columns and a suspend rule's "
        "review deadline is a ninth; adding it changes the projection's schema, "
        "which an existing file was created under, so it is a version decision "
        "and not a patch. The daemon composes the memory projection, which keeps "
        "the loaded rule itself, so nothing in production reads the short one."
    ),
)
def test_the_database_projection_keeps_every_member_of_a_suspend_rule(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: the declared proof of this structure, with the member it drops.

    A red line rather than a silence: the case that would demonstrate the whole
    materialization for a suspend rule is written, runs, and fails — so the gap
    is in the suite's own report, and the day the column lands this stops being
    expected to fail.
    """
    raw = (
        b"format = 1\n"
        b"[revision]\n"
        b'reason = "projection source"\n'
        b"[[rule]]\n"
        b'id = "waits"\n'
        b'capability = "mail.send"\n'
        b'principals = ["group:ci"]\n'
        b'outcome = "suspend"\n'
        b'reason = "one person reviews this"\n'
        b"review_deadline_seconds = 60\n"
    )
    policy = parse_policy(raw)
    assert not isinstance(policy, PolicyInvalid)
    loaded = LoadedPolicy(policy, "sha256:" + "b" * 64, datetime(2026, 9, 4, tzinfo=UTC), len(raw))
    projection = SqlitePolicyProjection(tmp_path / "projection.sqlite3")
    projection.rebuild(loaded)
    current = projection.current()
    assert current is not None
    assert current.rules == loaded.policy.rules


def test_the_policy_projection_rebuilds_from_an_empty_database(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: deleting a database projection loses no authority."""
    path = tmp_path / "projection.sqlite3"
    loaded = _loaded()
    first = SqlitePolicyProjection(path)
    first.rebuild(loaded)
    first.clear()
    assert first.current() is None
    first.rebuild(loaded)
    rebuilt = first.current()
    path.unlink()
    fresh = SqlitePolicyProjection(path)
    fresh.rebuild(loaded)
    assert rebuilt == fresh.current()
    assert rebuilt is not None
    assert rebuilt.policy_version == loaded.policy_version


def test_the_projection_port_has_no_write_but_rebuild() -> None:
    """Article 3: the projection API cannot become an authority rule writer."""
    public_methods = {
        name
        for name, value in vars(PolicyProjection).items()
        if callable(value) and not name.startswith("_")
    }
    assert public_methods == {"rebuild", "current", "clear"}


def test_sqlite_projection_mutates_only_by_whole_rebuild_or_clear(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: executed mutations cannot turn the projection into authority."""
    projection = SqlitePolicyProjection(tmp_path / "projection.sqlite3")
    statements = []
    projection._trace_callback = statements.append
    projection.rebuild(_loaded())
    projection.clear()
    mutations = {
        statement.split()[0].upper()
        for statement in statements
        if statement.split() and statement.split()[0].upper() not in {"BEGIN", "COMMIT"}
    }
    assert mutations == {"DELETE", "INSERT"}


def test_sqlite_projection_can_be_read_from_another_thread(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: a projection read is not bound to its creator thread."""
    projection = SqlitePolicyProjection(tmp_path / "projection.sqlite3")
    loaded = _loaded()
    projection.rebuild(loaded)
    with ThreadPoolExecutor(max_workers=1) as executor:
        current = executor.submit(projection.current).result()
    assert current is not None
    assert current.policy_version == loaded.policy_version


def test_clear_removes_every_projected_rule(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: clear leaves unknown projection state, never stale rules."""
    for projection in (MemoryPolicyProjection(), SqlitePolicyProjection(tmp_path / "policy.db")):
        projection.rebuild(_loaded())
        projection.clear()
        assert projection.current() is None
