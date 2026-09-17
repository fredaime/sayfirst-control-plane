# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import struct
from datetime import UTC, datetime

from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.domain.policy import Principal
from sayfirst_control_plane.ports.policy_store import (
    AccessState,
    LoadedPolicy,
    PolicyUnavailable,
    ProtectionExpectation,
    ProtectionState,
)


def _valid(outcome: str = "allow") -> bytes:
    return (
        "format = 1\n"
        "[revision]\n"
        'reason = "approved for this host"\n'
        "[[rule]]\n"
        'id = "mail"\n'
        'capability = "mail.send"\n'
        'principals = ["user:build"]\n'
        f'outcome = "{outcome}"\n'
        'reason = "host policy"\n'
    ).encode()


def _store(path):  # type: ignore[no-untyped-def]
    return FilePolicyStore(path, clock=lambda: datetime(2026, 9, 4, tzinfo=UTC))


def test_the_policy_store_loads_the_whole_authority_and_its_version(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 3 and 10: a loaded policy describes the exact bytes read."""
    path = tmp_path / "policy.toml"
    raw = _valid()
    path.write_bytes(raw)
    loaded = _store(path).load()
    assert isinstance(loaded, LoadedPolicy)
    assert loaded.byte_length == len(raw)
    assert loaded.loaded_at == datetime(2026, 9, 4, tzinfo=UTC)
    assert loaded.policy_version.startswith("sha256:")


def test_an_unreadable_authority_is_a_problem_not_a_denial(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: authority failures have no decision outcome."""
    unavailable = _store(tmp_path / "absent.toml").load()
    assert isinstance(unavailable, PolicyUnavailable)
    assert unavailable.reason == "absent"
    assert not hasattr(unavailable, "outcome")


def test_a_too_large_policy_is_refused_before_parsing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 3: the authority has a hard one-megabyte input bound."""
    path = tmp_path / "policy.toml"
    path.write_bytes(b"x" * (1_048_576 + 1))
    unavailable = _store(path).load()
    assert isinstance(unavailable, PolicyUnavailable)
    assert unavailable.reason == "too_large"


def test_runtime_failures_keep_their_distinct_policy_reasons(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 2: malformed, unsupported and invalid are not collapsed."""
    cases = {
        "malformed": b"not = [toml",
        "format_unsupported": _valid().replace(b"format = 1", b"format = 9"),
        "invalid": _valid("permit"),
    }
    for reason, raw in cases.items():
        path = tmp_path / f"{reason}.toml"
        path.write_bytes(raw)
        unavailable = _store(path).load()
        assert isinstance(unavailable, PolicyUnavailable)
        assert unavailable.reason == reason


def test_a_policy_file_writable_by_a_governed_principal_is_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: an applicable group-write bit gives the principal authority."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o660)
    stat = path.stat()
    principal = Principal("process", stat.st_uid + 1, "build", (stat.st_gid,), ("ci",))
    verdict = _store(path).write_access_of(principal)
    assert verdict.kind is AccessState.WRITABLE
    assert verdict.component == path.resolve()


def test_a_directory_on_the_policy_path_reports_effective_write_access(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: replacing the authority through a parent is write access."""
    directory = tmp_path / "governed"
    directory.mkdir()
    path = directory / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o600)
    os.chmod(directory, 0o770)
    stat = directory.stat()
    principal = Principal("process", stat.st_uid + 1, "build", (stat.st_gid,), ("ci",))
    verdict = _store(path).write_access_of(principal)
    assert verdict.kind is AccessState.WRITABLE
    assert verdict.component == directory.resolve()


def test_the_owner_of_the_policy_file_is_refused_whatever_the_bits(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Articles 7 and 8: an owner can restore its own write bit."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o400)
    stat = path.stat()
    principal = Principal("process", stat.st_uid, "build", (), ())
    assert _store(path).write_access_of(principal).kind is AccessState.WRITABLE


def test_root_has_effective_policy_write_access(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: root always has effective authority write access."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_valid())
    principal = Principal("user", 0, "root", (0,), ("root",))
    assert _store(path).write_access_of(principal).kind is AccessState.WRITABLE


def test_the_daemon_refuses_to_start_on_a_policy_file_writable_beyond_its_administrators(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 8: protection checks the file's effective writers."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o666)
    verdict = _store(path).protection_at_start(ProtectionExpectation.per_user(os.getuid()))
    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.component == path.resolve()
    assert verdict.reason == "group_write"


def test_the_daemon_refuses_to_start_on_a_policy_directory_writable_by_another_principal(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Article 8: protection walks every resolved parent directory."""
    directory = tmp_path / "replaceable"
    directory.mkdir()
    path = directory / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o600)
    os.chmod(directory, 0o777)
    verdict = _store(path).protection_at_start(ProtectionExpectation.per_user(os.getuid()))
    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.component == directory.resolve()


def test_an_unreadable_acl_on_the_policy_path_refuses_start(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Articles 2 and 8: failure to establish an ACL fails closed."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o600)

    def unreadable_acl(component, name, **kwargs):  # type: ignore[no-untyped-def]
        if os.fspath(component) == os.fspath(path):
            raise PermissionError("planted unreadable ACL")
        raise OSError(61, "No data available")

    monkeypatch.setattr(os, "getxattr", unreadable_acl)
    verdict = _store(path).protection_at_start(ProtectionExpectation.per_user(os.getuid()))
    assert verdict.kind is ProtectionState.UNKNOWN
    assert verdict.component == path.resolve()
    assert verdict.reason == "acl_unreadable"


def test_a_named_acl_writer_has_effective_policy_access(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Article 8: mode bits do not hide a named access-control-list writer."""
    path = tmp_path / "policy.toml"
    path.write_bytes(_valid())
    os.chmod(path, 0o600)
    named_uid = path.stat().st_uid + 100
    acl = struct.pack("<IHHIHHI", 2, 0x02, 0x02, named_uid, 0x10, 0x07, 0)

    def named_acl(component, name, **kwargs):  # type: ignore[no-untyped-def]
        if os.fspath(component) == os.fspath(path):
            return acl
        raise OSError(61, "No data available")

    monkeypatch.setattr(os, "getxattr", named_acl)
    principal = Principal("process", named_uid, "build", (), ())
    access = _store(path).write_access_of(principal)
    assert access.kind is AccessState.WRITABLE
    assert access.reason == "acl_write"
    protection = _store(path).protection_at_start(ProtectionExpectation.per_user(os.getuid()))
    assert protection.kind is ProtectionState.EXPOSED
    assert protection.reason == "acl_write"


def test_the_daemon_writes_nothing_under_the_policy_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 1: loading an absent authority never creates it."""
    path = tmp_path / "policy.toml"
    before = tuple(tmp_path.iterdir())
    _store(path).load()
    assert tuple(tmp_path.iterdir()) == before == ()


def test_a_loaded_policy_carries_the_exact_bytes_it_was_hashed_from(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A1: the archive keeps what the authority read, byte for byte, under its own version."""
    import hashlib

    from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
    from sayfirst_control_plane.ports.policy_store import LoadedPolicy

    raw = b'format = 1\n[revision]\nreason = "bytes"\n'
    path = tmp_path / "policy.toml"
    path.write_bytes(raw)
    loaded = FilePolicyStore(path).load()
    assert isinstance(loaded, LoadedPolicy)
    assert loaded.content == raw
    assert loaded.policy_version == "sha256:" + hashlib.sha256(loaded.content).hexdigest()
