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
from sayfirst_control_plane.adapters.socket_server import StartRefused, protect_directory
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
