# SPDX-License-Identifier: Apache-2.0
"""Article 8 on macOS: what the extended access list of one component says.

The reader asked macOS for a component's list and treated any answer but « a
list with no entry » as a list it could not evaluate — so the walk said
`unknown`, and an `unknown` refuses a start. Two ordinary answers took that
path:

- **No list at all.** macOS answers a file that has none with no list and
  `ENOENT`, which the reader called unreadable. Every component of every path
  has that answer unless somebody set a list, so every policy check on macOS was
  `unknown`, and a daemon given a policy file refused to start there.
- **A list of denials only.** A home folder on macOS carries one by default
  (`everyone deny delete`). A denial takes a right away and grants none, and
  the walk asks who can write, so a list of denials changes nothing it answers.

An entry that ALLOWS something is still not evaluated — who it names and what
it grants would have to be read — and it stays `unknown`, which refuses. The
real system's answers are held by the macOS identity guards
(`tests/identity/test_macos_access_lists.py`); these drive the reader's
decision with a stand-in for the C library, on every host.
"""

from __future__ import annotations

import ctypes
import errno
from pathlib import Path

import pytest
from sayfirst_control_plane.access import effective_access
from sayfirst_control_plane.access.effective_access import (
    ACL_EXTENDED_ALLOW,
    ACL_EXTENDED_DENY,
    _AclUnreadable,
    darwin_acl_allows,
)


class _Library:
    """The four calls the reader makes, answering as macOS would for one object."""

    def __init__(self, *, entries: tuple[int, ...] | None, error: int = 0) -> None:
        self.entries = entries
        self.error = error
        self.freed = 0

    def acl_get_file(self, path: bytes, kind: int) -> int | None:
        assert kind == effective_access.ACL_TYPE_EXTENDED
        if self.entries is None:
            ctypes.set_errno(self.error)
            return None
        return 1

    def acl_get_entry(self, acl: int, which: int, entry: object) -> int:
        index = 0 if which == effective_access.ACL_FIRST_ENTRY else self._next
        assert self.entries is not None
        if index >= len(self.entries):
            ctypes.set_errno(errno.EINVAL)
            return -1
        entry._obj.value = index + 1  # type: ignore[attr-defined]
        self._next = index + 1
        return 0

    def acl_get_tag_type(self, entry: ctypes.c_void_p, tag: object) -> int:
        assert self.entries is not None
        tag._obj.value = self.entries[(entry.value or 1) - 1]  # type: ignore[attr-defined]
        return 0

    def acl_free(self, acl: int) -> int:
        self.freed += 1
        return 0


def test_an_object_with_no_list_allows_nothing(tmp_path: Path) -> None:
    """macOS says « no list » as no list and `ENOENT`, for an object that exists."""
    present = tmp_path / "present"
    present.write_text("", encoding="utf-8")
    assert darwin_acl_allows(present, _Library(entries=None, error=errno.ENOENT)) is False


def test_no_list_for_an_object_that_is_not_there_is_not_read_as_no_list(tmp_path: Path) -> None:
    """The same `ENOENT` for a name that reaches nothing is a failure, not an answer."""
    with pytest.raises(_AclUnreadable):
        darwin_acl_allows(tmp_path / "absent", _Library(entries=None, error=errno.ENOENT))


def test_any_other_failure_to_read_the_list_is_unreadable(tmp_path: Path) -> None:
    present = tmp_path / "present"
    present.write_text("", encoding="utf-8")
    with pytest.raises(_AclUnreadable):
        darwin_acl_allows(present, _Library(entries=None, error=errno.EACCES))


def test_an_empty_list_allows_nothing(tmp_path: Path) -> None:
    library = _Library(entries=())
    assert darwin_acl_allows(tmp_path, library) is False
    assert library.freed == 1


def test_a_list_of_denials_only_allows_nothing(tmp_path: Path) -> None:
    """A home folder's default list: `everyone deny delete`."""
    library = _Library(entries=(ACL_EXTENDED_DENY, ACL_EXTENDED_DENY))
    assert darwin_acl_allows(tmp_path, library) is False
    assert library.freed == 1


@pytest.mark.parametrize(
    "entries",
    [(ACL_EXTENDED_ALLOW,), (ACL_EXTENDED_DENY, ACL_EXTENDED_ALLOW), (0,)],
)
def test_an_entry_that_is_not_a_denial_allows_something(
    tmp_path: Path, entries: tuple[int, ...]
) -> None:
    """An allowing entry, or one of a kind this reader does not know, is not ignored."""
    library = _Library(entries=entries)
    assert darwin_acl_allows(tmp_path, library) is True
    assert library.freed == 1
