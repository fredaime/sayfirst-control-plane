# SPDX-License-Identifier: Apache-2.0
"""The order of what happens before `listen()`, recorded through a scripted seam.

A system daemon binds as root and drops. This host has one unprivileged
account, so the calls that need privilege are recorded rather than performed;
what is held here is their order, which is the whole of rule M3.
"""

from __future__ import annotations

import os as real_os
from pathlib import Path

import pytest
from sayfirst_control_plane.adapters import socket_server
from sayfirst_control_plane.adapters.socket_server import Daemon
from sayfirst_control_plane.settings import StartRefused, read_settings, umask_for
from sayfirst_testing.doubles import StaticAccountDirectory, StaticPeerIdentity
from sayfirst_testing.privileges import requires_unprivileged

_RECORDED = ("umask", "chown", "chmod", "initgroups", "setgid", "setuid")


class _ScriptedOs:
    """The calls the start sequence makes, in the order it makes them."""

    def __init__(self, *, file_mode: int, file_gid: int = 900, denied: str = "") -> None:
        self.calls: list[str] = []
        self._file_mode = file_mode
        self._file_gid = file_gid
        self._denied = denied

    def __getattr__(self, name: str) -> object:
        if name in _RECORDED:

            def call(*_: object) -> int:
                self.calls.append(name)
                if name == self._denied:
                    raise PermissionError(1, "Operation not permitted")
                return 0

            return call
        return getattr(real_os, name)

    def stat(self, path: object, **_: object) -> object:
        self.calls.append("stat")
        outer = self

        class _Result:
            st_mode = outer._file_mode
            st_uid = 0
            st_gid = outer._file_gid

        return _Result()

    def unlink(self, path: object) -> None:
        return None


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    def factory(file_mode: int = 0o100660, file_gid: int = 900, denied: str = "") -> _ScriptedOs:
        seam = _ScriptedOs(file_mode=file_mode, file_gid=file_gid, denied=denied)
        monkeypatch.setattr(socket_server, "os", seam)
        monkeypatch.setattr(
            socket_server, "clear_stale_address", lambda path: seam.calls.append("clear")
        )
        monkeypatch.setattr(socket_server, "protect_directory", lambda *_, **__: "acl: checked")
        monkeypatch.setattr(socket_server, "verify_bound_name", lambda name: str(name))
        monkeypatch.setattr(
            socket_server._Server,
            "server_bind",
            lambda self: (seam.calls.append("bind"), self.socket.bind(self.server_address))[0],
        )
        monkeypatch.setattr(
            socket_server._Server, "server_activate", lambda self: seam.calls.append("listen")
        )
        return seam

    return factory


def _daemon(tmp_path: Path, run_as: str, composer=None) -> Daemon:  # type: ignore[no-untyped-def]
    members: dict[str, str] = {
        "mode": "system",
        "group": "operators",
        "path": str(tmp_path / "daemon.sock"),
    }
    if run_as:
        members["run_as"] = run_as
    settings = read_settings({"socket": members}, platform="linux")
    return Daemon(
        settings,
        platform="linux",
        directory=StaticAccountDirectory(),
        peer_identity=StaticPeerIdentity(),
        daemon_uid=0,
        socket_gid=900,
        composer=composer,
        overflow_ids=(65534, 65534),
    )


def test_a_system_daemon_listens_only_after_it_has_dropped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 6, rule M3: the client verifies the principal the daemon runs as."""
    assert umask_for("system") == 0o117
    seam = scripted()
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: 4242
    )
    # The daemon resolves its own group beside its own uid, and drops to that
    # group rather than to the admission list (article 7), so the seam that
    # scripts the account directory scripts both answers.
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: 4242
    )
    daemon = _daemon(tmp_path, run_as="sayfirst")
    daemon.start()
    try:
        assert seam.calls == [
            "clear",
            "umask",
            "bind",
            "umask",
            "chown",
            "chmod",
            "stat",
            "initgroups",
            "setgid",
            "setuid",
            "listen",
        ]
    finally:
        daemon.stop()
    assert daemon.daemon_uid == 4242


def test_the_composition_happens_after_the_drop_and_before_listen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 2, rule L2a: what the running daemon must be able to do is checked as it.

    Before the drop the daemon is root, and root is refused nothing: a policy
    file read as root and a store opened as root prove nothing about the
    account that will read and append after `setuid`. So the composition — the
    authority's start check and first load, the store's opening and the first
    append — runs after the irreversible calls and before `listen()`, and a
    deployment that cannot be composed by its running account never listens.
    """
    seam = scripted()
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: 4242
    )
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: 4242
    )

    class _Composed:
        def close(self) -> None:
            seam.calls.append("close")

    composed = _Composed()

    def composer() -> object:
        seam.calls.append("compose")
        return composed

    daemon = _daemon(tmp_path, run_as="sayfirst", composer=composer)
    assert daemon.services is None, "nothing is composed before the daemon starts"
    daemon.start()
    try:
        assert seam.calls[-5:] == ["initgroups", "setgid", "setuid", "compose", "listen"]
        assert daemon.services is composed
    finally:
        daemon.stop()


def test_a_composition_refused_after_the_drop_stops_the_start_with_nothing_listening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 3: a start refusal after the drop is still a refusal, by name.

    The daemon that cannot read its authority as the account it runs as does
    not listen and then answer every ask as retryable for the rest of its life;
    it exits with the reason, before `listen()`, and the address is closed.
    """
    seam = scripted()
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: 4242
    )
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: 4242
    )

    def composer() -> object:
        seam.calls.append("compose")
        raise StartRefused("policy_unavailable_at_start", "policy file is unreadable by uid 4242")

    daemon = _daemon(tmp_path, run_as="sayfirst", composer=composer)
    with pytest.raises(StartRefused) as refusal:
        daemon.start()
    assert refusal.value.reason == "policy_unavailable_at_start"
    assert "uid 4242" in refusal.value.detail
    assert "listen" not in seam.calls
    assert seam.calls[-2:] == ["setuid", "compose"]
    assert daemon.services is None


def test_a_system_daemon_without_run_as_stays_root(
    tmp_path: Path,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 6, rule M2: an empty `run_as` means the principal is uid 0."""
    seam = scripted()
    daemon = _daemon(tmp_path, run_as="")
    daemon.start()
    try:
        assert "setuid" not in seam.calls
        assert seam.calls[-1] == "listen"
        assert seam.calls.index("chmod") < seam.calls.index("listen")
    finally:
        daemon.stop()
    assert daemon.daemon_uid == 0


def test_an_unknown_run_as_account_stops_the_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 6, rule M2: an account the host does not have is not a principal."""
    seam = scripted()
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: None
    )
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: None
    )
    daemon = _daemon(tmp_path, run_as="absent")
    with pytest.raises(StartRefused) as refusal:
        daemon.start()
    assert refusal.value.reason == "run_as_unknown"
    assert "listen" not in seam.calls


def test_a_file_mode_the_daemon_did_not_ask_for_stops_it(
    tmp_path: Path,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 6, rule S1: the mode is verified by `stat`, not assumed from `chmod`."""
    seam = scripted(file_mode=0o100666)
    daemon = _daemon(tmp_path, run_as="")
    with pytest.raises(StartRefused) as refusal:
        daemon.start()
    assert refusal.value.reason == "socket_mode_invalid"
    assert "listen" not in seam.calls


@requires_unprivileged()
def test_a_system_daemon_that_is_not_root_does_not_start(tmp_path: Path) -> None:
    """Article 6, rule M3: system mode binds as root and then drops.

    The refusal under test is of a tester that is not root, so a root runner
    has nothing here to refuse. The gate says so where `guard_gates` reads it,
    rather than in a line inside the body that no runner accounts for.
    """
    from sayfirst_control_plane.adapters.socket_server import assemble

    settings = read_settings(
        {
            "socket": {
                "mode": "system",
                "group": "operators",
                "path": str(tmp_path / "daemon.sock"),
            }
        },
        platform="linux",
    )
    with pytest.raises(StartRefused) as refusal:
        assemble(settings, platform="linux")
    assert refusal.value.reason == "run_as_requires_root"


def test_a_socket_group_the_daemon_did_not_get_stops_it(
    tmp_path: Path,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 6, rule S1: the group is the admission list, so it is verified too."""
    seam = scripted(file_mode=0o100660, file_gid=41)
    daemon = _daemon(tmp_path, run_as="")
    with pytest.raises(StartRefused) as refusal:
        daemon.start()
    assert refusal.value.reason == "socket_mode_invalid"
    assert "group" in refusal.value.detail
    assert "listen" not in seam.calls


def test_the_verified_ownership_is_the_owner_and_the_group_together(
    tmp_path: Path,
    scripted,  # type: ignore[no-untyped-def]
) -> None:
    """Article 6, rule S1: uid 0 and the configured group, both checked by stat."""
    seam = scripted(file_mode=0o100660, file_gid=900)
    daemon = _daemon(tmp_path, run_as="")
    daemon.start()
    try:
        assert seam.calls[-1] == "listen"
    finally:
        daemon.stop()


@pytest.mark.parametrize(
    ("denied", "reason"),
    [
        ("chown", "socket_permissions_denied"),
        ("chmod", "socket_permissions_denied"),
        ("initgroups", "privileges_not_dropped"),
        ("setgid", "privileges_not_dropped"),
        ("setuid", "privileges_not_dropped"),
    ],
)
def test_a_call_the_host_refuses_names_the_step_it_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted,  # type: ignore[no-untyped-def]
    denied: str,
    reason: str,
) -> None:
    """Article 2: a start that cannot hold rule S1 or rule M3 says which one.

    `EPERM` from `chown`, `chmod`, `initgroups`, `setgid` or `setuid` used to
    leave `main()` as an `OSError`: exit 1 and a traceback, on a path where
    `docs/deployment.md` publishes 78 and one reason. The daemon never listens
    either way; what changes is whether the operator is told what stopped it.
    """
    seam = scripted(denied=denied)
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_uid", lambda name: 4242
    )
    # The daemon resolves its own group beside its own uid, and drops to that
    # group rather than to the admission list (article 7), so the seam that
    # scripts the account directory scripts both answers.
    monkeypatch.setattr(
        "sayfirst_control_plane.adapters.nss_directory.account_primary_gid", lambda name: 4242
    )
    daemon = _daemon(tmp_path, run_as="sayfirst")
    with pytest.raises(StartRefused) as refusal:
        daemon.start()
    assert refusal.value.reason == reason
    assert "Operation not permitted" in refusal.value.detail
    assert "listen" not in seam.calls


def test_a_bind_that_failed_does_not_unlink_the_address_it_did_not_create(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Article 6, rule L7: "success means a daemon is listening", so it stays listening.

    `clear_stale_address` finds nothing and a second daemon binds in the window
    before this one does; this `bind` then fails `EADDRINUSE`. Unlinking the
    address on any failure removes the live daemon's address — the opposite of
    what rule L7 refuses to do — so only a bind that succeeded leaves an
    address this start may remove.
    """
    import socket as real_socket

    from sayfirst_control_plane.settings import StartRefused as _StartRefused

    address = tmp_path / "daemon.sock"
    live = real_socket.socket(real_socket.AF_UNIX, real_socket.SOCK_STREAM)
    live.bind(str(address))
    live.listen(1)
    monkeypatch.setattr(socket_server, "clear_stale_address", lambda path: None)
    settings = read_settings(
        {"socket": {"mode": "per_user", "path": str(address)}}, platform="linux"
    )
    daemon = Daemon(
        settings,
        platform="linux",
        directory=StaticAccountDirectory(),
        peer_identity=StaticPeerIdentity(),
        daemon_uid=real_os.geteuid(),
        overflow_ids=(65534, 65534),
    )
    try:
        with pytest.raises(_StartRefused) as refusal:
            daemon.start()
        assert refusal.value.reason == "socket_address_denied"
        assert address.exists(), "a start that failed removed the live daemon's address"
    finally:
        live.close()
        address.unlink(missing_ok=True)
