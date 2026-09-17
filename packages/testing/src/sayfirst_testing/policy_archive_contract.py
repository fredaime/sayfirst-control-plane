# SPDX-License-Identifier: Apache-2.0
"""Reusable contract suite for an immutable, content-addressed policy archive.

The archive keeps the exact bytes of every policy version a decision names, so
a reader holding an export and the contract can re-derive the answer from the
bytes the daemon actually read (articles 3, 10, 13). A version is the SHA-256
of its bytes; a keep that disagrees with its own version is refused, a second
keep of a present version rewrites nothing, and bytes that no longer hash to
their name are reported damaged and never overwritten, never evaluated.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from sayfirst_control_plane.ports.policy_archive import ArchiveState, PolicyArchive


def version_of(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def assert_policy_archive_contract(
    archive: PolicyArchive,
    *,
    damage: Callable[[str, bytes], None],
) -> None:
    """Prove keep, read, idempotence, refusal, damage reporting and absence.

    `damage(version, bytes)` rewrites the stored bytes of `version` outside the
    port, the way an operator or a fault would; the suite cannot do it through
    a port that publishes no write of that kind, and that absence is the point.
    """
    assert archive.VERSION == 1
    content = b'format = 1\n[revision]\nreason = "archive contract"\n'
    version = version_of(content)

    assert archive.read(version).state is ArchiveState.absent
    assert archive.read(version).content is None

    kept = archive.keep(version, content)
    assert (kept.version, kept.state, kept.content) == (version, ArchiveState.present, content)
    again = archive.keep(version, content)
    assert (again.version, again.state, again.content) == (version, ArchiveState.present, content)
    read = archive.read(version)
    assert (read.version, read.state, read.content) == (version, ArchiveState.present, content)

    other = b'format = 1\n[revision]\nreason = "other"\n'
    try:
        archive.keep(version, other)
    except ValueError:
        pass
    else:
        raise AssertionError("bytes that do not hash to their version were kept")
    assert archive.read(version).content == content

    try:
        archive.keep("policy-1", content)
    except ValueError:
        pass
    else:
        raise AssertionError("a version that is not a sha256 digest was kept")

    # Trailing bytes are a different version: the archive is exact to the byte.
    with_newline = content + b"\n"
    assert version_of(with_newline) != version
    kept = archive.keep(version_of(with_newline), with_newline)
    assert kept.content == with_newline
    assert archive.read(version).content == content

    damage(version, other)
    damaged = archive.read(version)
    assert (damaged.version, damaged.state, damaged.content) == (
        version,
        ArchiveState.damaged,
        None,
    )
    # A keep of the right bytes under a damaged name reports the damage and
    # overwrites nothing: restoration is an operator's act, not a store API.
    kept = archive.keep(version, content)
    assert kept.state is ArchiveState.damaged
    assert archive.read(version).state is ArchiveState.damaged

    location = archive.location()
    assert location.kind
    assert location.retention
