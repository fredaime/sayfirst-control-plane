# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import inspect

from sayfirst_control_plane.domain.directory_protection import (
    DirectoryFacts,
    directory_protection,
)

_UNPROTECTED = "socket_directory_unprotected"


def _facts(
    name: str = "/run/sayfirst",
    mode: int = 0o755,
    uid: int = 0,
    *,
    is_directory: bool = True,
    has_access_acl: bool | None = False,
) -> DirectoryFacts:
    return DirectoryFacts(
        name=name,
        mode=mode,
        uid=uid,
        is_directory=is_directory,
        has_access_acl=has_access_acl,
    )


def test_the_check_is_a_pure_function_over_what_stat_said() -> None:
    """Article 6, rule S5: the ownership cases need no second account to test."""
    assert list(inspect.signature(directory_protection).parameters) == [
        "st",
        "ancestors",
        "daemon_uid",
        "platform",
    ]


def test_a_directory_anyone_else_may_write_is_refused() -> None:
    """Article 6, rule S3: whoever can write it can bind an impostor in its place."""
    for mode in (0o777, 0o770, 0o707, 0o775):
        verdict = directory_protection(
            st=_facts(mode=mode, uid=1000), ancestors=(), daemon_uid=1000, platform="linux"
        )
        assert verdict.refusal == _UNPROTECTED, oct(mode)
        assert "writable" in verdict.detail
    assert directory_protection(
        st=_facts(mode=0o700, uid=1000), ancestors=(), daemon_uid=1000, platform="linux"
    ).protected


def test_a_group_writable_directory_is_refused_even_with_one_member() -> None:
    """Article 6, rule S3: the daemon cannot prove the group stays at one member."""
    verdict = directory_protection(
        st=_facts(mode=0o770, uid=1000), ancestors=(), daemon_uid=1000, platform="linux"
    )
    assert verdict.refusal == _UNPROTECTED


def test_a_foreign_owner_is_refused_and_root_is_accepted() -> None:
    """Article 6, rule S3: the daemon's principal or uid 0, and nobody else."""
    assert (
        directory_protection(
            st=_facts(mode=0o755, uid=1234), ancestors=(), daemon_uid=1000, platform="linux"
        ).refusal
        == _UNPROTECTED
    )
    assert directory_protection(
        st=_facts(mode=0o755, uid=0), ancestors=(), daemon_uid=1000, platform="linux"
    ).protected


def test_a_file_that_is_not_a_directory_is_refused() -> None:
    """Article 6, rule S3: the parent of the local address is a directory."""
    verdict = directory_protection(
        st=_facts(uid=0, is_directory=False), ancestors=(), daemon_uid=1000, platform="linux"
    )
    assert verdict.refusal == _UNPROTECTED


def test_an_access_acl_is_refused_on_linux_and_not_checked_on_darwin() -> None:
    """Article 6, rules S3 and S6: the one item the guard cannot hold on macOS."""
    linux = directory_protection(
        st=_facts(uid=0, has_access_acl=True), ancestors=(), daemon_uid=1000, platform="linux"
    )
    assert linux.refusal == _UNPROTECTED
    assert linux.acl_checked
    darwin = directory_protection(
        st=_facts(uid=0, has_access_acl=None), ancestors=(), daemon_uid=1000, platform="darwin"
    )
    assert darwin.protected
    assert not darwin.acl_checked


def test_an_ancestor_a_stranger_can_write_is_refused_unless_it_is_sticky() -> None:
    """Article 6, rule S4: a stranger who can rename the directory away."""
    loose = _facts(name="/run", mode=0o777, uid=0)
    verdict = directory_protection(
        st=_facts(uid=0), ancestors=(loose,), daemon_uid=1000, platform="linux"
    )
    assert verdict.refusal == _UNPROTECTED
    assert verdict.detail.endswith("/run")
    sticky = _facts(name="/run", mode=0o1777, uid=0)
    assert directory_protection(
        st=_facts(uid=0), ancestors=(sticky,), daemon_uid=1000, platform="linux"
    ).protected
    foreign = _facts(name="/run", mode=0o755, uid=4242)
    assert (
        directory_protection(
            st=_facts(uid=0), ancestors=(foreign,), daemon_uid=1000, platform="linux"
        ).refusal
        == _UNPROTECTED
    )


def test_an_ancestor_a_group_can_write_is_refused_unless_it_is_sticky() -> None:
    """Article 6, rule S4: rename needs write on the parent, from any grant of it.

    Rule S3's reason is quoted for the directory itself — the daemon cannot
    prove a group's membership will stay at one — and it is the same reason one
    level up, where the whole directory can be renamed away instead of the
    socket unlinked.
    """
    for mode in (0o770, 0o775, 0o2770):
        verdict = directory_protection(
            st=_facts(uid=0),
            ancestors=(_facts(name="/run", mode=mode, uid=0),),
            daemon_uid=1000,
            platform="linux",
        )
        assert verdict.refusal == _UNPROTECTED, oct(mode)
        assert verdict.detail.endswith("/run"), oct(mode)
    sticky = _facts(name="/run", mode=0o1770, uid=0)
    assert directory_protection(
        st=_facts(uid=0), ancestors=(sticky,), daemon_uid=1000, platform="linux"
    ).protected


def test_an_ancestor_carrying_an_access_control_list_is_refused_unless_it_is_sticky() -> None:
    """Article 6, rule S4: a list is a grant of write the mode does not show."""
    listed = _facts(name="/run", mode=0o755, uid=0, has_access_acl=True)
    verdict = directory_protection(
        st=_facts(uid=0), ancestors=(listed,), daemon_uid=1000, platform="linux"
    )
    assert verdict.refusal == _UNPROTECTED
    assert verdict.detail.endswith("/run")
    unreadable_here = _facts(name="/run", mode=0o755, uid=0, has_access_acl=None)
    assert directory_protection(
        st=_facts(uid=0, has_access_acl=None),
        ancestors=(unreadable_here,),
        daemon_uid=1000,
        platform="darwin",
    ).protected
    sticky = _facts(name="/run", mode=0o1755, uid=0, has_access_acl=True)
    assert directory_protection(
        st=_facts(uid=0), ancestors=(sticky,), daemon_uid=1000, platform="linux"
    ).protected


def test_an_ancestor_whose_list_could_not_be_read_is_refused_on_linux() -> None:
    """Articles 2 and 6: a check that could not run is not a check that passed."""
    unread = _facts(name="/run", mode=0o755, uid=0, has_access_acl=None)
    verdict = directory_protection(
        st=_facts(uid=0), ancestors=(unread,), daemon_uid=1000, platform="linux"
    )
    assert verdict.refusal == _UNPROTECTED
    assert "could not be read" in verdict.detail
    assert verdict.detail.endswith("/run")
