# SPDX-License-Identifier: Apache-2.0
"""Article 8: the whole naming path decides, not the name the kernel ends at.

The protection and access checks resolved the configured path and then walked
the components of the *resolved* one, while the store went on opening the
configured one. Every name between the two — a symlink and the directories
that hold it — was therefore inspected by nobody, and control of a name is
control of which policy is loaded: retargeting a link in a directory others
can write changed the loaded outcome from `deny` to `allow` while the same
check went on calling the policy `not_writable` for the very principal who
could do it.

Article 8 says what the check is for — "a governed program that could write its
own configuration could activate the plugin that frees it" — and it says the
check is of effective access "along the whole path". A path is the whole name,
link included.

`symlink_demo.py` from the first outside read is the first case here. The
others are the same defect reached by the other shapes a name can take: a link
above the file rather than at it, a link whose target sits in a directory
others can write, and a loop.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.policy import PolicyService, PolicyStartRefused
from sayfirst_control_plane.domain.policy import Principal
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    ProtectionExpectation,
    ProtectionState,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX naming paths")

#: A uid nobody on this host is, so "can this principal write it" is a question
#: about the bits and never about who is running the suite.
FOREIGN_UID = 23456
FOREIGN_GID = 23456


def _clock():  # type: ignore[no-untyped-def]
    return datetime(2026, 9, 4, tzinfo=UTC)


def _policy(outcome: str) -> str:
    return (
        "format = 1\n"
        "[revision]\n"
        'reason = "naming-path counterexample"\n'
        "[[rule]]\n"
        'id = "r"\n'
        'capability = "storage.write"\n'
        'principals = ["user:foreign"]\n'
        'reason = "test"\n'
        f'outcome = "{outcome}"\n'
    )


def _foreign() -> Principal:
    return Principal("user", FOREIGN_UID, "foreign", (FOREIGN_GID,), ())


def _protected_policies(root: Path) -> tuple[Path, Path]:
    """Two policies nobody but the owner can write, in a directory nobody else can."""
    safe = root / "protected"
    safe.mkdir(mode=0o755)
    deny = safe / "deny.toml"
    deny.write_text(_policy("deny"), encoding="utf-8")
    deny.chmod(0o600)
    allow = safe / "allow.toml"
    allow.write_text(_policy("allow"), encoding="utf-8")
    allow.chmod(0o600)
    return deny, allow


def test_a_link_in_a_directory_others_can_write_is_write_access_to_the_policy(
    tmp_path: Path,
) -> None:
    """`symlink_demo.py`: whoever can retarget the name can choose the policy."""
    tmp_path.chmod(0o755)
    deny, allow = _protected_policies(tmp_path)
    links = tmp_path / "replaceable"
    links.mkdir(mode=0o777)
    links.chmod(0o777)
    link = links / "policy.toml"
    link.symlink_to(deny)
    store = FilePolicyStore(link, clock=_clock)

    # The demonstration: the same principal chooses which policy is loaded.
    assert store.load().policy.rules[0].outcome.value == "deny"
    link.unlink()
    link.symlink_to(allow)
    assert store.load().policy.rules[0].outcome.value == "allow"

    verdict = store.write_access_of(_foreign())
    assert verdict.kind is AccessState.WRITABLE, verdict
    assert verdict.component == links, verdict
    assert verdict.reason == "other_write", verdict


def test_the_start_check_refuses_a_policy_reached_through_an_exposed_name(
    tmp_path: Path,
) -> None:
    """Article 8: the same name, judged at start rather than per connection."""
    tmp_path.chmod(0o755)
    deny, _ = _protected_policies(tmp_path)
    links = tmp_path / "replaceable"
    links.mkdir(mode=0o777)
    links.chmod(0o777)
    link = links / "policy.toml"
    link.symlink_to(deny)
    store = FilePolicyStore(link, clock=_clock)

    verdict = store.protection_at_start(ProtectionExpectation.per_user(os.geteuid()))

    assert verdict.kind is ProtectionState.EXPOSED, verdict
    assert verdict.component == links, verdict
    # Which of the two grants on a `0o777` directory is named first is the
    # start check's own order; that it names one of them is the finding.
    assert verdict.reason in {"group_write", "other_write"}, verdict


def test_a_link_above_the_file_is_a_name_on_the_path_too(tmp_path: Path) -> None:
    """The link need not be the last component to decide which file is opened."""
    tmp_path.chmod(0o755)
    real = tmp_path / "protected"
    real.mkdir(mode=0o755)
    policy = real / "policy.toml"
    policy.write_text(_policy("deny"), encoding="utf-8")
    policy.chmod(0o600)
    links = tmp_path / "replaceable"
    links.mkdir(mode=0o777)
    links.chmod(0o777)
    (links / "here").symlink_to(real)
    store = FilePolicyStore(links / "here" / "policy.toml", clock=_clock)

    verdict = store.write_access_of(_foreign())

    assert verdict.kind is AccessState.WRITABLE, verdict
    assert verdict.component == links, verdict


def test_a_target_anyone_can_write_is_reached_through_a_protected_name(
    tmp_path: Path,
) -> None:
    """The other half: a safe name whose target sits where anyone can replace it."""
    tmp_path.chmod(0o755)
    open_dir = tmp_path / "open"
    open_dir.mkdir(mode=0o777)
    open_dir.chmod(0o777)
    target = open_dir / "policy.toml"
    target.write_text(_policy("allow"), encoding="utf-8")
    target.chmod(0o600)
    safe = tmp_path / "protected"
    safe.mkdir(mode=0o755)
    link = safe / "policy.toml"
    link.symlink_to(target)

    verdict = FilePolicyStore(link, clock=_clock).write_access_of(_foreign())

    assert verdict.kind is AccessState.WRITABLE, verdict
    assert verdict.component == open_dir, verdict


def test_an_ordinary_protected_policy_is_still_not_writable(tmp_path: Path) -> None:
    """Anti-vacuity: the walk answers `not_writable` where it should."""
    tmp_path.chmod(0o755)
    deny, _ = _protected_policies(tmp_path)

    store = FilePolicyStore(deny, clock=_clock)

    assert store.write_access_of(_foreign()).kind is AccessState.NOT_WRITABLE
    assert store.load().policy.rules[0].outcome.value == "deny"


def test_a_loop_of_names_is_an_unknown_and_never_a_negative(tmp_path: Path) -> None:
    """Article 3: a name that reaches nothing is not a name nobody can write."""
    tmp_path.chmod(0o755)
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")

    store = FilePolicyStore(tmp_path / "a", clock=_clock)

    assert store.write_access_of(_foreign()).kind is AccessState.UNKNOWN
    assert (
        store.protection_at_start(ProtectionExpectation.per_user(os.geteuid())).kind
        is ProtectionState.UNKNOWN
    )


def test_a_name_that_moves_under_the_check_is_an_unknown(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The check is bound to a file, not to a name: a name that moved says so.

    Walking the whole naming path answers about names. Between that answer and
    the open that acts on it, the name can reach a different file — the same
    race, one component smaller. So the store holds a descriptor of what the
    name reached across the walk and reads the name again at the end of it, and
    the descriptor being held is what stops the inode number in that comparison
    from being handed to a file created in the meantime.

    The move is placed rather than raced for: the walk itself retargets the
    link, once, so the case is the same on every host and every run.
    """
    from sayfirst_control_plane.adapters.file import policy_store as module

    tmp_path.chmod(0o755)
    deny, allow = _protected_policies(tmp_path)
    link = tmp_path / "policy.toml"
    link.symlink_to(deny)
    store = FilePolicyStore(link, clock=_clock)
    assert store.write_access_of(_foreign()).kind is AccessState.NOT_WRITABLE

    honest = module.write_access

    def moving(path, uid, gids):  # type: ignore[no-untyped-def]
        verdict = honest(path, uid, gids)
        link.unlink()
        link.symlink_to(allow)
        return verdict

    monkeypatch.setattr(module, "write_access", moving)
    verdict = store.write_access_of(_foreign())

    assert verdict.kind is AccessState.UNKNOWN, verdict
    assert verdict.reason == "changed_while_checked", verdict


def test_the_bytes_loaded_are_the_bytes_of_the_file_the_name_reached(  # type: ignore[no-untyped-def]
    tmp_path: Path, monkeypatch
) -> None:
    """The same binding on the read: a name that moved mid-read claims nothing."""
    from sayfirst_control_plane.adapters.file import policy_store as module

    tmp_path.chmod(0o755)
    deny, allow = _protected_policies(tmp_path)
    link = tmp_path / "policy.toml"
    link.symlink_to(deny)
    store = FilePolicyStore(link, clock=_clock)
    assert store.load().policy.rules[0].outcome.value == "deny"

    honest = module.os.stat
    moved = False

    def moving(*arguments, **members):  # type: ignore[no-untyped-def]
        nonlocal moved
        if not moved:
            moved = True
            link.unlink()
            link.symlink_to(allow)
        return honest(*arguments, **members)

    monkeypatch.setattr(module.os, "stat", moving)
    unavailable = store.load()
    monkeypatch.undo()

    assert getattr(unavailable, "reason", None) == "changed_while_read", unavailable
    # And the very next read, with nothing moving, answers the file it reaches.
    assert store.load().policy.rules[0].outcome.value == "allow"


def _open_directory_holding(root: Path, name: str, outcome: str) -> Path:
    """A directory anyone can write, holding one policy only its owner can."""
    open_dir = root / name
    open_dir.mkdir(mode=0o777)
    open_dir.chmod(0o777)
    policy = open_dir / "allow.toml"
    policy.write_text(_policy(outcome), encoding="utf-8")
    policy.chmod(0o600)
    return open_dir


def test_a_dot_dot_after_a_link_is_walked_where_the_kernel_walks_it(
    tmp_path: Path,
) -> None:
    """`..` is a name too, and after a link it follows the link.

    The walk took the absolute name through `os.path.abspath`, which is
    `normpath` of a join: `link/..` was collapsed to nothing *before* any
    component was looked at, so the one component that decides the answer — the
    link — was never seen. The kernel does not read a path that way. It walks
    it, and `..` after a link is the parent of what the link named.

    Here the configured name is `protected/hop/../allow.toml` with `hop`
    pointing into a world-writable directory. Lexically that name is
    `protected/allow.toml`, a file nobody else can write. To the kernel — and
    to the store's own `open` — it is `open/allow.toml`, and anyone at all can
    replace it.
    """
    tmp_path.chmod(0o755)
    deny, _ = _protected_policies(tmp_path)
    safe = tmp_path / "protected"
    (safe / "allow.toml").write_text(_policy("deny"), encoding="utf-8")
    open_dir = _open_directory_holding(tmp_path, "open", "allow")
    (open_dir / "sub").mkdir(mode=0o755)
    (safe / "hop").symlink_to(open_dir / "sub")
    configured = safe / "hop" / ".." / "allow.toml"
    store = FilePolicyStore(configured, clock=_clock)

    # What the store opens, so that the walk is judged against the same file.
    assert store.load().policy.rules[0].outcome.value == "allow"

    verdict = store.write_access_of(_foreign())

    assert verdict.kind is AccessState.WRITABLE, verdict
    assert verdict.component == open_dir, verdict
    assert verdict.reason == "other_write", verdict


def test_a_dot_dot_after_two_links_is_walked_where_the_kernel_walks_it(
    tmp_path: Path,
) -> None:
    """The same, with the `..` popping a component two links deep.

    `protected/hop` names `also/hop`, which names `open/sub`; the `..` that
    follows pops `sub` off the *second* link's target, not off `protected` and
    not off `also`. Only the last of the three directories is one anyone can
    write, so a walk that stopped at either of the first two would answer
    `not_writable` for a file anybody can replace.
    """
    tmp_path.chmod(0o755)
    _protected_policies(tmp_path)
    safe = tmp_path / "protected"
    (safe / "allow.toml").write_text(_policy("deny"), encoding="utf-8")
    also = tmp_path / "also"
    also.mkdir(mode=0o755)
    open_dir = _open_directory_holding(tmp_path, "open", "allow")
    (open_dir / "sub").mkdir(mode=0o755)
    (also / "hop").symlink_to(open_dir / "sub")
    (safe / "hop").symlink_to(also / "hop")
    store = FilePolicyStore(safe / "hop" / ".." / "allow.toml", clock=_clock)

    assert store.load().policy.rules[0].outcome.value == "allow"

    verdict = store.write_access_of(_foreign())

    assert verdict.kind is AccessState.WRITABLE, verdict
    assert verdict.component == open_dir, verdict
    assert verdict.reason == "other_write", verdict


def test_a_dot_dot_that_pops_out_of_the_names_below_it_still_walks_them(
    tmp_path: Path,
) -> None:
    """A component `..` steps back over is a name that decides the answer.

    `open/gone/../../protected/deny.toml` reaches a file nobody else can write,
    and every directory the *remaining* name passes through is protected. But
    `gone` sits in a directory anyone can write, and replacing it with a link
    moves where its `..` goes — so the component the `..` pops is walked too,
    rather than dropped along with the `..` itself.
    """
    tmp_path.chmod(0o755)
    _protected_policies(tmp_path)
    open_dir = _open_directory_holding(tmp_path, "open", "allow")
    (open_dir / "gone").mkdir(mode=0o755)
    store = FilePolicyStore(
        open_dir / "gone" / ".." / ".." / "protected" / "deny.toml", clock=_clock
    )

    assert store.load().policy.rules[0].outcome.value == "deny"

    verdict = store.write_access_of(_foreign())

    assert verdict.kind is AccessState.WRITABLE, verdict
    assert verdict.component == open_dir, verdict


def test_an_ordinary_dot_dot_inside_a_protected_name_is_still_not_writable(
    tmp_path: Path,
) -> None:
    """Anti-vacuity: `..` is not by itself an exposure."""
    tmp_path.chmod(0o755)
    _protected_policies(tmp_path)
    safe = tmp_path / "protected"
    (safe / "sub").mkdir(mode=0o755)
    store = FilePolicyStore(safe / "sub" / ".." / "deny.toml", clock=_clock)

    assert store.write_access_of(_foreign()).kind is AccessState.NOT_WRITABLE
    assert store.load().policy.rules[0].outcome.value == "deny"
    assert (
        store.protection_at_start(ProtectionExpectation.per_user(os.geteuid())).kind
        is ProtectionState.PROTECTED
    )


class _MovesTheNameAfterJudgingIt(FilePolicyStore):
    """A store that retargets the configured name the instant the start check answers.

    Not a monkeypatch of anything the store does: the one thing this overrides
    is the moment *between* the two calls the start sequence makes, which is
    exactly where whoever can write a component of the name gets to act.
    """

    def __init__(self, path: Path, *, link: Path, target: Path) -> None:
        super().__init__(path, clock=_clock)
        self._link = link
        self._target = target

    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        verdict = super().protection_at_start(expectation)
        self._link.unlink()
        self._link.symlink_to(self._target)
        return verdict


def test_the_start_check_and_the_load_that_follows_it_are_one_file(tmp_path: Path) -> None:
    """Article 8: the binding holds *across* the two calls a start makes, not per call.

    Each call was already bound to the file it opened — the check holds a
    descriptor across its walk, the load compares `fstat` to a fresh `stat` —
    and the start sequence makes two of them. A name retargeted in between gave
    a protection verdict about one file and bytes from another, each internally
    consistent and the pair a claim about nothing. `protection_at_start` now
    keeps the descriptor it judged and the load that follows reads it, so the
    two calls are one look at one file.
    """
    tmp_path.chmod(0o755)
    deny, allow = _protected_policies(tmp_path)
    link = tmp_path / "policy.toml"
    link.symlink_to(deny)
    store = FilePolicyStore(link, clock=_clock)

    verdict = store.protection_at_start(ProtectionExpectation.per_user(os.geteuid()))
    assert verdict.kind is ProtectionState.PROTECTED, verdict
    link.unlink()
    link.symlink_to(allow)

    loaded = store.load()

    assert getattr(loaded, "reason", None) == "changed_while_read", loaded
    # Anti-vacuity: with nothing moving in between, the sequence loads the file
    # it judged and says so — the binding refuses a move, not every start.
    assert (
        store.protection_at_start(ProtectionExpectation.per_user(os.geteuid())).kind
        is ProtectionState.PROTECTED
    )
    assert store.load().policy.rules[0].outcome.value == "allow"


def test_a_name_that_moves_between_the_two_start_calls_refuses_the_start(
    tmp_path: Path,
) -> None:
    """The same binding as the service drives it: `deny` judged, `allow` never loaded."""
    tmp_path.chmod(0o755)
    deny, allow = _protected_policies(tmp_path)
    link = tmp_path / "policy.toml"
    link.symlink_to(deny)
    store = _MovesTheNameAfterJudgingIt(link, link=link, target=allow)
    service = PolicyService(
        store,
        (MemoryPolicyProjection(),),
        events=MemoryEvents(),
        clock=_clock,
    )

    with pytest.raises(PolicyStartRefused) as refused:
        service.start(ProtectionExpectation.per_user(os.geteuid()))

    assert "named another file" in str(refused.value), refused.value
