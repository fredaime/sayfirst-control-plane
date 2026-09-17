# SPDX-License-Identifier: Apache-2.0
"""What "protected" means for the authority, above the file and below it.

Three blocks of this skeleton ask one question — who could replace this path —
and two of them had already answered it about an *ancestor*: block 2.2's
`directory_protection` admits a world-writable ancestor that is sticky, and
block 2.4's grade rule reads the same bit for the same reason. The policy
authority's own check applied the file's rule to every level above it, so no
path under a shared temporary directory could hold an authority at all.

These cases hold the composed rule: the sticky bit excuses a *directory above*
the authority and nothing else. The file's own rule is untouched, and an
ancestor anybody can rewrite is still exposed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.ports.policy_store import ProtectionExpectation, ProtectionState

ME = os.geteuid()
_POLICY = 'format = 1\n[revision]\nreason = "protection"\n'


def _authority(directory: Path) -> FilePolicyStore:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "policy.toml"
    path.write_text(_POLICY, encoding="utf-8")
    os.chmod(path, 0o600)
    return FilePolicyStore(path)


def _verdict(store: FilePolicyStore):  # type: ignore[no-untyped-def]
    return store.protection_at_start(ProtectionExpectation.per_user(ME))


def test_a_sticky_ancestor_anybody_may_add_to_does_not_expose_the_authority(
    tmp_path: Path,
) -> None:
    """Article 3: sticky means only the owner may replace an entry, so nobody else can."""
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    store = _authority(shared / "mine")

    verdict = _verdict(store)

    assert stat.S_IMODE(os.stat(shared).st_mode) & stat.S_ISVTX
    assert verdict.kind is ProtectionState.PROTECTED, verdict


def test_an_ancestor_anybody_may_rewrite_still_exposes_the_authority(tmp_path: Path) -> None:
    """Article 3: without the sticky bit a stranger renames the directory away."""
    open_to_all = tmp_path / "open"
    open_to_all.mkdir()
    os.chmod(open_to_all, 0o707)
    store = _authority(open_to_all / "mine")

    verdict = _verdict(store)

    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.component == open_to_all.resolve()
    assert verdict.reason == "other_write"


def test_the_sticky_bit_never_excuses_the_authority_file_itself(tmp_path: Path) -> None:
    """Article 3: the rule the file is held to is the rule it was always held to."""
    store = _authority(tmp_path / "mine")
    os.chmod(store.path, 0o606)

    verdict = _verdict(store)

    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.component == store.path.resolve()
    assert verdict.reason == "other_write"


def test_an_ancestor_owned_by_a_stranger_is_still_exposed(tmp_path: Path) -> None:
    """Article 3: the sticky bit says who may replace an entry, not who owns the place."""
    store = _authority(tmp_path / "mine")

    verdict = store.protection_at_start(
        ProtectionExpectation(
            allowed_owner_uids=frozenset({ME + 1}), allowed_write_gids=frozenset()
        )
    )

    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.reason == "owner"
