# SPDX-License-Identifier: Apache-2.0
"""The contract of the AccountDirectory port, run against every provider.

Article 8: a provider that does not pass this suite is not a provider. The
suite asks only what the port promises — that ids resolve to names and
memberships, that an id with no entry is `None` and never an invented one,
and that the answers are the directory's own words.
"""

from __future__ import annotations

from typing import Protocol


class _Directory(Protocol):
    VERSION: int

    def account(self, uid: int): ...  # type: ignore[no-untyped-def]

    def group_ids(self, name: str, primary_gid: int) -> tuple[int, ...]: ...

    def group_name(self, gid: int) -> str | None: ...


def assert_the_port_is_versioned(directory: _Directory) -> None:
    """Article 8: a port carries an integer version, and so does its provider."""
    assert isinstance(directory.VERSION, int)
    assert not isinstance(directory.VERSION, bool)
    assert directory.VERSION >= 1


def assert_a_known_account_resolves(directory: _Directory, uid: int, name: str) -> None:
    """A uid the host knows is answered with its name and its primary group."""
    account = directory.account(uid)
    assert account is not None, f"uid {uid} has no account"
    assert account.name == name
    assert isinstance(account.primary_gid, int)
    assert account.primary_gid >= 0


def assert_an_unknown_id_is_none(directory: _Directory, absent_uid: int, absent_gid: int) -> None:
    """No entry is `None`, never a fabricated account and never an exception.

    Article 2: the directory saying nothing about an id is its own answer.
    """
    assert directory.account(absent_uid) is None
    assert directory.group_name(absent_gid) is None


def assert_a_membership_includes_its_primary_group(
    directory: _Directory, name: str, primary_gid: int
) -> None:
    """Rule G1: the primary group is a membership, listed with the others."""
    gids = directory.group_ids(name, primary_gid)
    assert isinstance(gids, tuple)
    assert all(isinstance(gid, int) for gid in gids)
    assert primary_gid in gids
    assert len(set(gids)) == len(gids), "a group is listed twice"


def assert_group_names_are_returned_as_they_are(
    directory: _Directory, gid: int, expected: str
) -> None:
    """Rule G6: no case folding, no trimming, no domain stripping."""
    answered = directory.group_name(gid)
    assert answered == expected
    assert answered is not None
    assert answered == answered.strip() or answered != expected.strip()


def assert_the_directory_answers_the_same_way_twice(
    directory: _Directory, uid: int, gid: int
) -> None:
    """A resolution the daemon repeats within a lifetime must be repeatable."""
    assert directory.account(uid) == directory.account(uid)
    assert directory.group_name(gid) == directory.group_name(gid)


def run_the_account_directory_contract(
    directory: _Directory,
    *,
    known_uid: int,
    known_name: str,
    known_primary_gid: int,
    known_group_name: str,
    absent_uid: int,
    absent_gid: int,
) -> None:
    """Every promise of the port, against one provider."""
    assert_the_port_is_versioned(directory)
    assert_a_known_account_resolves(directory, known_uid, known_name)
    assert_an_unknown_id_is_none(directory, absent_uid, absent_gid)
    assert_a_membership_includes_its_primary_group(directory, known_name, known_primary_gid)
    assert_group_names_are_returned_as_they_are(directory, known_primary_gid, known_group_name)
    assert_the_directory_answers_the_same_way_twice(directory, known_uid, known_primary_gid)
