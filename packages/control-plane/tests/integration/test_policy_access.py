# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from datetime import UTC, datetime

import pytest
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.domain.policy import Principal
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    ProtectionExpectation,
    ProtectionState,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux POSIX access-control-list integration test",
)


def test_a_real_named_acl_writer_is_detected_for_start_and_access(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: the kernel ACL for a second system identity is authoritative."""
    setfacl = shutil.which("setfacl")
    assert setfacl is not None, "the Linux integration image must provide setfacl"
    second = pwd.getpwnam("nobody")
    path = tmp_path / "policy.toml"
    path.write_text(
        'format = 1\n[revision]\nreason = "integration"\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    subprocess.run(
        [setfacl, "-m", f"u:{second.pw_uid}:rw", os.fspath(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    store = FilePolicyStore(path, clock=lambda: datetime(2026, 9, 4, tzinfo=UTC))
    principal = Principal(
        "process",
        second.pw_uid,
        second.pw_name,
        (second.pw_gid,),
        (),
    )
    access = store.write_access_of(principal)
    protection = store.protection_at_start(ProtectionExpectation.per_user(os.getuid()))
    assert access.kind is AccessState.WRITABLE
    assert access.component == path.resolve()
    assert access.reason == "acl_write"
    assert protection.kind is ProtectionState.EXPOSED
    assert protection.component == path.resolve()
    assert protection.reason == "acl_write"
