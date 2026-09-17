# SPDX-License-Identifier: Apache-2.0
"""Articles 3, 7 and 10: the file policy archive keeps exact bytes it never rewrites."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters.file.policy_archive import FilePolicyArchive
from sayfirst_control_plane.ports.policy_archive import ArchiveState
from sayfirst_testing.policy_archive_contract import assert_policy_archive_contract, version_of
from sayfirst_testing.privileges import requires_unprivileged

CONTENT = b'format = 1\n[revision]\nreason = "kept"\n'


def _file(root: Path, version: str) -> Path:
    return root / "policy" / f"{version.removeprefix('sha256:')}.toml"


def test_the_file_archive_passes_the_published_contract(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    archive = FilePolicyArchive(root)

    def damage(version: str, content: bytes) -> None:
        _file(root, version).write_bytes(content)

    assert_policy_archive_contract(archive, damage=damage)


def test_a_kept_version_is_one_immutable_file_named_by_its_digest_at_0600(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    archive = FilePolicyArchive(root)
    version = version_of(CONTENT)
    archive.keep(version, CONTENT)
    target = _file(root, version)
    assert target.read_bytes() == CONTENT
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "policy").stat().st_mode) == 0o700
    # No temporary file is left beside a published version.
    assert sorted(item.name for item in (root / "policy").iterdir()) == [target.name]
    before = target.stat()
    archive.keep(version, CONTENT)
    after = target.stat()
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


def test_an_orphan_temporary_from_a_crash_before_publication_is_never_a_version(
    tmp_path: Path,
) -> None:
    """C1: a crash before the rename leaves bytes nobody named; they are removed, not read."""
    root = tmp_path / "evidence"
    archive = FilePolicyArchive(root)
    version = version_of(CONTENT)
    (root / "policy").mkdir(parents=True)
    orphan = root / "policy" / f".{version.removeprefix('sha256:')}.tmp-orphan"
    orphan.write_bytes(CONTENT)
    assert archive.read(version).state is ArchiveState.absent
    archive.recover()
    assert not orphan.exists()
    assert archive.read(version).state is ArchiveState.absent


def test_a_damaged_version_is_reported_never_overwritten_or_evaluated_as_current_policy(
    tmp_path: Path,
) -> None:
    """G9: damage stays visible; the current policy never stands in for the bytes named."""
    root = tmp_path / "evidence"
    archive = FilePolicyArchive(root)
    version = version_of(CONTENT)
    archive.keep(version, CONTENT)
    target = _file(root, version)
    rewritten = CONTENT.replace(b"kept", b"rewritten")
    target.write_bytes(rewritten)
    damaged = archive.read(version)
    assert damaged.state is ArchiveState.damaged and damaged.content is None
    kept = archive.keep(version, CONTENT)
    assert kept.state is ArchiveState.damaged
    assert target.read_bytes() == rewritten
    # The replacement bytes exist under their own name only when kept as such.
    assert archive.read(version_of(rewritten)).state is ArchiveState.absent


def test_an_archive_keep_cannot_remove_or_replace_a_version(tmp_path: Path) -> None:
    """G8: the port publishes no removal, and a keep of other bytes leaves the file whole."""
    root = tmp_path / "evidence"
    archive = FilePolicyArchive(root)
    version = version_of(CONTENT)
    archive.keep(version, CONTENT)
    assert not any(name in ("remove", "delete", "replace", "purge") for name in dir(archive))
    with pytest.raises(ValueError):
        archive.keep(version, CONTENT + b"#")
    assert _file(root, version).read_bytes() == CONTENT


@requires_unprivileged()
def test_unreadable_storage_raises_rather_than_answering_absent(tmp_path: Path) -> None:
    """A2: `absent` is for missing bytes; a read the host refused is an error, not an absence."""
    root = tmp_path / "evidence"
    archive = FilePolicyArchive(root)
    version = version_of(CONTENT)
    archive.keep(version, CONTENT)
    target = _file(root, version)
    os.chmod(target, 0)
    try:
        with pytest.raises(OSError):
            archive.read(version)
    finally:
        os.chmod(target, 0o600)


def test_the_archive_location_names_its_directory(tmp_path: Path) -> None:
    archive = FilePolicyArchive(tmp_path / "evidence")
    location = archive.location()
    assert location.kind == "file"
    assert location.root == tmp_path / "evidence" / "policy"
    assert "indefinite" in location.retention


def test_the_version_is_the_digest_of_the_exact_bytes() -> None:
    assert version_of(CONTENT) == "sha256:" + hashlib.sha256(CONTENT).hexdigest()
