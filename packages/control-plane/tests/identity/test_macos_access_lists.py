# SPDX-License-Identifier: Apache-2.0
"""Article 8 on a real macOS: the access walk reads the system's own lists.

The walk asks, of every component of a policy's naming path, who could write
it — and on macOS it reads the component's extended access list to answer. It
read « no list » as a list it could not evaluate, so every policy on macOS was
`unknown` and a daemon given one refused to start; and it read a list of
denials — the one a home folder carries by default — the same way. These run on
the macOS runner of the identity job, against lists set with the system's own
`chmod +a`, under a root that is not reached through a link (`/tmp` is one on
macOS, and the walk reads a link's target in the target's own chain).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.domain.policy import Principal
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    ProtectionExpectation,
    ProtectionState,
)
from sayfirst_testing.platforms import requires_platform

#: A uid nobody on the runner is, so « could it write » is a question about the
#: bits and the lists, never about who runs the suite.
FOREIGN = Principal("user", 23456, "foreign", (23456,), ())

POLICY = (
    "format = 1\n"
    "[revision]\n"
    'reason = "macOS access lists"\n'
    "[[rule]]\n"
    'id = "r"\n'
    'capability = "process.spawn"\n'
    'scope = "local"\n'
    'principals = ["user:someone"]\n'
    'outcome = "deny"\n'
    'reason = "a policy to read"\n'
)


def _clock() -> datetime:
    return datetime(2026, 9, 23, tzinfo=UTC)


@pytest.fixture
def root() -> Iterator[Path]:
    """A directory only this account can write, reached through no link."""
    directory = Path(tempfile.mkdtemp(prefix="acl", dir=os.path.realpath("/tmp")))
    directory.chmod(0o755)
    try:
        yield directory
    finally:
        subprocess.run(["/bin/chmod", "-N", str(directory)], check=False)
        shutil.rmtree(directory, ignore_errors=True)


def _policy_in(directory: Path) -> FilePolicyStore:
    policy = directory / "policy.toml"
    policy.write_text(POLICY, encoding="utf-8")
    policy.chmod(0o600)
    return FilePolicyStore(policy, clock=_clock)


@requires_platform("darwin")
def test_a_policy_on_a_path_with_no_list_is_judged_on_macos(root: Path) -> None:
    """No list anywhere below the root: a definite answer, not `unknown`."""
    store = _policy_in(root)
    assert store.write_access_of(FOREIGN).kind is AccessState.NOT_WRITABLE
    assert (
        store.protection_at_start(ProtectionExpectation.per_user(os.geteuid())).kind
        is ProtectionState.PROTECTED
    )


@requires_platform("darwin")
def test_a_list_of_denials_leaves_the_answer_definite_on_macos(root: Path) -> None:
    """The list a home folder carries by default grants nothing, so it changes nothing."""
    subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(root)], check=True)
    store = _policy_in(root)
    assert store.write_access_of(FOREIGN).kind is AccessState.NOT_WRITABLE
    assert (
        store.protection_at_start(ProtectionExpectation.per_user(os.geteuid())).kind
        is ProtectionState.PROTECTED
    )


@requires_platform("darwin")
def test_a_list_that_allows_something_is_never_read_as_protected_on_macos(root: Path) -> None:
    """An allowing entry is not evaluated, so it is `unknown` — never a false « no »."""
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow write,add_file,delete_child", str(root)], check=True
    )
    store = _policy_in(root)
    assert store.write_access_of(FOREIGN).kind is not AccessState.NOT_WRITABLE
    assert (
        store.protection_at_start(ProtectionExpectation.per_user(os.geteuid())).kind
        is not ProtectionState.PROTECTED
    )
