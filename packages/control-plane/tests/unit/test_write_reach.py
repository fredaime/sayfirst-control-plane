# SPDX-License-Identifier: Apache-2.0
"""One question about a sticky ancestor, asked in four places, answered once.

Articles 6, 7 and 8 each make this daemon walk a path upwards and ask, of every
directory on it, whether somebody who could write that directory could replace
what is under it. `domain/write_reach.py` states the answer; these cases hold
the statement, and then hold the four readers of it against two arrangements
that used to distinguish them.

* A sticky ancestor writable through the mode. The address-directory rule and
  the authority rule both exempted it; `write_access` did not read the bit at
  all, so it reported that every principal on the host could replace a file no
  principal but its owner can touch — and in system mode that reading refuses a
  decision to everyone (article 8), which is a daemon that serves nobody.
* A sticky ancestor carrying an access control list that grants write. The
  address-directory rule read the bit before the three grants and called the
  tree protected; the authority rule read the list first and called it exposed.

Two answers to one question, and at most one of them can be right. The
operating system decides which: in a sticky directory only an entry's owner,
the directory's owner and root may unlink or rename what is in it, whichever
way the write was granted.
"""

from __future__ import annotations

import os
import stat
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_control_plane.access.effective_access import protection, write_access
from sayfirst_control_plane.adapters.posix.path_access import PosixPathAccess
from sayfirst_control_plane.adapters.socket_server import facts_of
from sayfirst_control_plane.domain.directory_protection import directory_protection
from sayfirst_control_plane.domain.integrity_grade import CallerAccess, evaluate_grade
from sayfirst_control_plane.domain.write_reach import write_reaches_the_entry_below
from sayfirst_control_plane.ports.policy_store import AccessState, ProtectionState
from sayfirst_testing.platforms import requires_platform, requires_platforms

ME = os.geteuid()
A_STRANGER = ME + 1
AT = datetime(2026, 9, 4, tzinfo=UTC)

_ACL_ATTRIBUTE = "system.posix_acl_access"
_UNDEFINED_ID = 0xFFFFFFFF
_TAG_USER_OBJ, _TAG_USER, _TAG_GROUP_OBJ, _TAG_MASK, _TAG_OTHER = 0x01, 0x02, 0x04, 0x10, 0x20

_DIRECTORY = stat.S_IFDIR
_FILE = stat.S_IFREG


def _write_granting_access_list() -> bytes:
    """A `system.posix_acl_access` that grants write to one other account."""
    entries = (
        (_TAG_USER_OBJ, 0o7, _UNDEFINED_ID),
        (_TAG_USER, 0o6, A_STRANGER),
        (_TAG_GROUP_OBJ, 0o0, _UNDEFINED_ID),
        (_TAG_MASK, 0o6, _UNDEFINED_ID),
        (_TAG_OTHER, 0o0, _UNDEFINED_ID),
    )
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def _tree(root: Path) -> tuple[Path, Path, Path]:
    """A sticky ancestor, the directory under it, and the authority in that."""
    ancestor = root / "shared"
    directory = ancestor / "run"
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    authority = directory / "policy.toml"
    authority.write_text("format = 1\n", encoding="utf-8")
    authority.chmod(0o600)
    return ancestor, directory, authority


def _address_directory_is_protected(directory: Path) -> bool:
    """Article 6: the directory the local address is bound in, and its ancestors."""
    return directory_protection(
        st=facts_of(directory, "linux"),
        ancestors=tuple(facts_of(parent, "linux") for parent in directory.parents),
        daemon_uid=ME,
        platform="linux",
    ).protected


def _authority_is_protected_at_start(authority: Path) -> bool:
    """Article 8 at start: no principal outside the expectation can replace it."""
    return (
        protection(
            authority,
            allowed_owner_uids=frozenset({0, ME}),
            allowed_write_gids=frozenset(),
        ).kind
        is ProtectionState.PROTECTED
    )


def _a_stranger_can_replace(authority: Path) -> bool:
    """Article 8 per connection: this principal's own effective write access."""
    return write_access(authority, A_STRANGER, ()).kind is not AccessState.NOT_WRITABLE


def _a_stranger_grades_as_a_writer(top: Path, authority: Path) -> bool:
    """Article 7: whether the same principal's access is graded as write access.

    The walk starts at the ancestor rather than at the root because everything
    above it in a test run is a directory this account alone may traverse, and
    the grade rule answers "cannot reach it" before it ever reaches the
    question this file is about.
    """
    chain = [authority, *authority.parents]
    access = PosixPathAccess()
    facts = [access.inspect(item) for item in reversed(chain[: chain.index(top) + 1])]
    return evaluate_grade(CallerAccess(A_STRANGER, frozenset()), facts, at=AT).basis == (
        "caller_can_write"
    )


def test_a_directory_with_no_sticky_bit_reaches_whatever_is_under_it() -> None:
    """The ordinary case: write on a directory is write on the entries in it."""
    assert write_reaches_the_entry_below(
        mode=_DIRECTORY | 0o777,
        is_directory=True,
        writer_owns_the_directory=False,
        writer_owns_the_entry=False,
    )


def test_a_sticky_directory_does_not_reach_an_entry_the_writer_does_not_own() -> None:
    """The operating system's exemption: only an entry's own owner may unlink it."""
    assert not write_reaches_the_entry_below(
        mode=_DIRECTORY | 0o1777,
        is_directory=True,
        writer_owns_the_directory=False,
        writer_owns_the_entry=False,
    )


@pytest.mark.parametrize(
    ("owns_directory", "owns_entry"), ((True, False), (False, True), (True, True))
)
def test_ownership_defeats_the_sticky_exemption(owns_directory: bool, owns_entry: bool) -> None:
    """A sticky directory bars strangers; its owner and the entry's owner unlink."""
    assert write_reaches_the_entry_below(
        mode=_DIRECTORY | 0o1777,
        is_directory=True,
        writer_owns_the_directory=owns_directory,
        writer_owns_the_entry=owns_entry,
    )


def test_a_sticky_bit_outside_a_directory_exempts_nothing() -> None:
    """`S_ISVTX` on something that is not a directory says nothing about unlinking."""
    assert write_reaches_the_entry_below(
        mode=_FILE | 0o1666,
        is_directory=False,
        writer_owns_the_directory=False,
        writer_owns_the_entry=False,
    )


@requires_platforms("linux", "darwin")
def test_every_reader_answers_a_mode_granted_sticky_ancestor_the_same_way(
    tmp_path: Path,
) -> None:
    """Articles 6, 7 and 8: one arrangement, one answer, whoever is asking."""
    ancestor, directory, authority = _tree(tmp_path)

    ancestor.chmod(0o0777)
    assert not _address_directory_is_protected(directory)
    assert not _authority_is_protected_at_start(authority)
    assert _a_stranger_can_replace(authority)
    assert _a_stranger_grades_as_a_writer(ancestor, authority)

    ancestor.chmod(0o1777)
    assert _address_directory_is_protected(directory)
    assert _authority_is_protected_at_start(authority)
    assert not _a_stranger_can_replace(authority)
    assert not _a_stranger_grades_as_a_writer(ancestor, authority)


@requires_platform("linux")
def test_every_reader_answers_a_list_granted_sticky_ancestor_the_same_way(
    tmp_path: Path,
) -> None:
    """Articles 6 and 8: the sticky bit is read before the grant, not after some of them.

    The list grants write on the ancestor to an account that owns neither the
    ancestor nor anything under it. On a sticky directory that grant lets the
    account create names of its own and unlink nothing else, so it does not
    reach the authority — and it does not matter that the grant was made by a
    list rather than by a mode bit, which is the whole content of the
    disagreement this case holds.

    Article 7's reader is not asked here. An access control list it cannot
    interpret makes it answer `unverified` rather than answer this question at
    all, which is article 2's three-valued rule doing its work and not a fourth
    answer to this one.
    """
    ancestor, directory, authority = _tree(tmp_path)
    ancestor.chmod(0o1755)
    try:
        os.setxattr(str(ancestor), _ACL_ATTRIBUTE, _write_granting_access_list())
    except OSError as error:
        pytest.skip(f"this filesystem holds no access list: {error}")
    assert os.stat(ancestor).st_mode & stat.S_ISVTX

    assert _address_directory_is_protected(directory)
    assert _authority_is_protected_at_start(authority)
    assert not _a_stranger_can_replace(authority)

    # The same list on an ancestor that is not sticky reaches, and every reader
    # says so: the exemption is the sticky bit's, not the list's. The list is
    # written again after the mode is: `chmod` recomputes the mask from the
    # group bits, and a masked-off grant would prove nothing about either.
    ancestor.chmod(0o0755)
    os.setxattr(str(ancestor), _ACL_ATTRIBUTE, _write_granting_access_list())
    assert not os.stat(ancestor).st_mode & stat.S_ISVTX
    assert not _address_directory_is_protected(directory)
    assert not _authority_is_protected_at_start(authority)
    assert _a_stranger_can_replace(authority)
