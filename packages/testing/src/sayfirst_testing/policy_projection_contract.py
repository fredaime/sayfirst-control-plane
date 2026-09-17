# SPDX-License-Identifier: Apache-2.0
"""Reusable contract suite for a rebuild-only policy projection."""

from __future__ import annotations

from sayfirst_control_plane.ports.policy_projection import (
    PROJECTION_KIND_UNKNOWN,
    PolicyProjection,
    ProjectedPolicy,
    projection_kind,
)
from sayfirst_control_plane.ports.policy_store import LoadedPolicy


def assert_policy_projection_contract(
    projection: PolicyProjection,
    loaded: LoadedPolicy,
) -> None:
    """Prove that clear plus rebuild reproduces the complete authority snapshot."""
    assert projection.VERSION == 1
    # A provider names itself inside the shape the policy status publishes, so
    # that a status answer never leaves it (articles 8 and 13).
    assert projection_kind(projection) != PROJECTION_KIND_UNKNOWN, (
        f"projection kind {getattr(projection, 'KIND', None)!r} is outside the published shape"
    )
    projection.clear()
    assert projection.current() is None
    projection.rebuild(loaded)
    expected = ProjectedPolicy(
        policy_version=loaded.policy_version,
        format=loaded.policy.format,
        loaded_at=loaded.loaded_at,
        rule_count=len(loaded.policy.rules),
        rules=loaded.policy.rules,
    )
    assert projection.current() == expected
    projection.clear()
    assert projection.current() is None
    projection.rebuild(loaded)
    assert projection.current() == expected
