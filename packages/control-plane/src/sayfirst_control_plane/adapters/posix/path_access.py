# SPDX-License-Identifier: Apache-2.0
"""Inspect mode, identity, and ACL presence without deciding a grade."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

from sayfirst_control_plane.ports.path_access import PathFacts


class PosixPathAccess:
    def inspect(self, path: Path) -> PathFacts:
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            return PathFacts(path, False, None, None, None, None)
        return PathFacts(
            path=path,
            exists=True,
            owner_uid=details.st_uid,
            owner_gid=details.st_gid,
            mode=stat.S_IMODE(details.st_mode),
            acl_present=_acl_present(path),
        )


def _acl_present(path: Path) -> bool | None:
    if not hasattr(os, "getxattr"):
        return None
    try:
        os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
    except OSError as error:
        absent = {errno.ENODATA}
        if hasattr(errno, "ENOATTR"):
            absent.add(errno.ENOATTR)
        if error.errno in absent:
            return False
        if error.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return None
        return None
    return True
