# SPDX-License-Identifier: Apache-2.0
"""Rule S4 on a real filesystem: every grant of write on an ancestor, refused.

Article 6: "the socket's parent directory is writable by the daemon's principal
and root only, since whoever can write it can unlink the path and bind an
impostor". An ancestor a stranger can write is the same attack one level up and
a worse one — the whole directory is renamed away and another put at the name,
so the daemon's published address is gone in the act that takes it over.

Rule S5 asks for the mode cases with a real `chmod`; the list case writes a real
`system.posix_acl_access`, because a grant that the mode does not show is
exactly what the mode cases cannot prove.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters import socket_server
from sayfirst_control_plane.adapters.socket_server import (
    StartRefused,
    directories_crossed,
    protect_directory,
)
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platform, requires_platforms

ME = os.geteuid()

_ACL_ATTRIBUTE = "system.posix_acl_access"
_UNDEFINED_ID = 0xFFFFFFFF
_TAG_USER_OBJ, _TAG_USER, _TAG_GROUP_OBJ, _TAG_MASK, _TAG_OTHER = 0x01, 0x02, 0x04, 0x10, 0x20


def _minimal_access_list() -> bytes:
    """The smallest valid `system.posix_acl_access` naming one other account.

    `r-x` and not `rwx` on the named entry: a write grant raises the mask, which
    the mode shows as group write, and the mode rule would answer first. What is
    under test here is the grant the mode does not show, so it grants no write —
    the rule refuses a list at all, as rule S3 does at the leaf, because the
    daemon does not read what a list says, only that there is one.
    """
    entries = (
        (_TAG_USER_OBJ, 0o7, _UNDEFINED_ID),
        (_TAG_USER, 0o5, 65534),
        (_TAG_GROUP_OBJ, 0o5, _UNDEFINED_ID),
        (_TAG_MASK, 0o5, _UNDEFINED_ID),
        (_TAG_OTHER, 0o5, _UNDEFINED_ID),
    )
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def _tree(root: Path) -> tuple[Path, Path]:
    """An ancestor and the socket directory under it, both owned by this account."""
    ancestor = root / "shared"
    directory = ancestor / "run"
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    ancestor.chmod(0o755)
    return ancestor, directory


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_group_writable_ancestor_is_refused_unless_it_is_sticky(tmp_path: Path) -> None:
    """Article 6, rule S4: a member of the group renames the directory away."""
    ancestor, directory = _tree(tmp_path)
    assert protect_directory(directory, daemon_uid=ME, platform="linux")

    for mode in (0o770, 0o775, 0o2770):
        ancestor.chmod(mode)
        with pytest.raises(StartRefused) as refused:
            protect_directory(directory, daemon_uid=ME, platform="linux")
        assert refused.value.reason == "socket_directory_unprotected", oct(mode)
        assert str(ancestor) in refused.value.detail, oct(mode)

    ancestor.chmod(0o1770)
    assert protect_directory(directory, daemon_uid=ME, platform="linux")


@requires_platform("linux")
def test_an_ancestor_named_in_an_access_control_list_is_refused(tmp_path: Path) -> None:
    """Article 6, rules S4 and S6: a grant of write the mode does not show.

    Linux alone, because `system.posix_acl_access` and the reader for it are
    Linux's; rule S6 records that macOS holds no ACL item of this rule.
    """
    ancestor, directory = _tree(tmp_path)
    try:
        os.setxattr(str(ancestor), _ACL_ATTRIBUTE, _minimal_access_list())
    except OSError as error:
        pytest.skip(f"this filesystem holds no access list: {error}")

    with pytest.raises(StartRefused) as refused:
        protect_directory(directory, daemon_uid=ME, platform="linux")

    assert refused.value.reason == "socket_directory_unprotected"
    assert "access control list" in refused.value.detail
    assert str(ancestor) in refused.value.detail


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_socket_directory_reached_through_a_link_in_a_writable_directory_is_refused(
    tmp_path: Path,
) -> None:
    """Article 6: whoever can write the directory holding a link can point it elsewhere.

    The check resolved the path first, so the world-writable directory holding
    the link was never judged, and a swap after the check redirected the
    daemon's chown and chmod.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    protected = tmp_path / "protected"
    protected.mkdir()
    protected.chmod(0o700)
    (shared / "link").symlink_to(protected)
    with pytest.raises(StartRefused) as refused:
        protect_directory(shared / "link", daemon_uid=ME, platform="linux")
    assert refused.value.reason == "socket_directory_unprotected"
    assert str(shared) in refused.value.detail


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_link_another_account_owns_is_refused_even_in_a_sticky_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sticky directory bars renaming another's entry, not the owner replacing their own link."""
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    protected = tmp_path / "protected"
    protected.mkdir()
    protected.chmod(0o700)
    link = sticky / "link"
    link.symlink_to(protected)
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        found = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == str(link):
            fields = list(found[:10])
            fields[4] = ME + 1  # st_uid: a stranger's link
            return os.stat_result(fields)
        return found

    monkeypatch.setattr(socket_server.os, "lstat", lstat)
    with pytest.raises(StartRefused) as refused:
        protect_directory(link, daemon_uid=ME, platform="linux")
    assert refused.value.reason == "socket_directory_unprotected"
    assert str(link) in refused.value.detail
    assert "neither root nor the daemon's account" in refused.value.detail


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_link_of_this_account_in_a_private_directory_still_passes(tmp_path: Path) -> None:
    """The ordinary case: a home reached through the account's own link starts."""
    base = tmp_path / "base"
    base.mkdir()
    base.chmod(0o755)
    protected = tmp_path / "protected"
    protected.mkdir()
    protected.chmod(0o700)
    (base / "link").symlink_to(protected)
    assert protect_directory(base / "link", daemon_uid=ME, platform="linux")


@pytest.mark.skipif(not Path("/var/run").is_symlink(), reason="/var/run is not a link here")
def test_the_platform_var_run_link_is_crossed_without_refusal() -> None:
    """`/var/run → /run` (Linux) and `/var → /private/var` (macOS) are root's links in `/`."""
    crossed = directories_crossed(Path("/var/run"), daemon_uid=ME)
    assert Path("/") in crossed and Path("/var") in crossed


def _chain(root: Path, links: int) -> Path:
    """`links` links in `root`, each naming the next, the last naming a directory."""
    (root / "end").mkdir()
    for index in range(links):
        target = f"l{index + 1}" if index + 1 < links else "end"
        (root / f"l{index}").symlink_to(target)
    return root / "l0"


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_relative_link_climbing_out_crosses_the_directories_the_kernel_reads(
    tmp_path: Path,
) -> None:
    """A relative target is read from the link's own directory, `..` included."""
    base = tmp_path.resolve()
    (base / "a" / "b").mkdir(parents=True)
    (base / "c" / "d").mkdir(parents=True)
    (base / "a" / "b" / "link").symlink_to(Path("..") / ".." / "c" / "d")
    crossed = directories_crossed(base / "a" / "b" / "link", daemon_uid=ME)
    assert crossed[-4:] == (base, base / "a", base / "a" / "b", base / "c")


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_link_naming_itself_is_refused_as_too_many_links(tmp_path: Path) -> None:
    """A loop is followed until the kernel's own bound, and refused there."""
    (tmp_path / "loop").symlink_to("loop")
    with pytest.raises(StartRefused) as refused:
        directories_crossed(tmp_path / "loop", daemon_uid=ME)
    assert refused.value.reason == "socket_directory_unprotected"
    assert "too many links" in refused.value.detail


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_chain_of_forty_one_links_is_refused_as_too_many_links(tmp_path: Path) -> None:
    """One link past the kernel's forty is one the kernel would answer ELOOP."""
    with pytest.raises(StartRefused) as refused:
        directories_crossed(_chain(tmp_path, 41), daemon_uid=ME)
    assert refused.value.reason == "socket_directory_unprotected"
    assert "too many links" in refused.value.detail


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_chain_of_thirty_nine_links_is_followed_to_its_end(tmp_path: Path) -> None:
    """Under the kernel's bound a chain is followed, and only its directory is crossed."""
    base = tmp_path.resolve()
    crossed = directories_crossed(_chain(base, 39), daemon_uid=ME)
    assert crossed[-1] == base
