# SPDX-License-Identifier: Apache-2.0
"""The default local address is one rule, published where both sides can read it.

A daemon that chooses its own address and a client that is not told one have to
arrive at the same name, and they can only do that by reading one rule. It used
to live in the server alone, which a client may not import (article 14), so
every client had to be handed the address on its command line.
"""

from __future__ import annotations

from sayfirst_contract.binding.http_unix_socket.addresses import default_socket_path


def test_a_per_user_address_is_under_the_runtime_directory_when_there_is_one() -> None:
    assert (
        default_socket_path(
            "per_user",
            "linux",
            environ={"XDG_RUNTIME_DIR": "/run/user/1000"},
            home="/home/example",
            directory_exists={"/run/user/1000"}.__contains__,
        )
        == "/run/user/1000/sayfirst/daemon.sock"
    )


def test_a_per_user_address_falls_back_to_the_home_directory() -> None:
    """A variable that is unset, empty, or names nothing selects the fallback."""
    for environ in ({}, {"XDG_RUNTIME_DIR": ""}, {"XDG_RUNTIME_DIR": "/run/user/1000"}):
        assert (
            default_socket_path(
                "per_user",
                "linux",
                environ=environ,
                home="/home/example/",
                directory_exists=lambda _: False,
            )
            == "/home/example/.sayfirst/run/daemon.sock"
        )


def test_the_runtime_directory_is_asked_of_the_filesystem_by_default(tmp_path) -> None:  # type: ignore[no-untyped-def]
    existing = tmp_path / "runtime"
    existing.mkdir()
    assert (
        default_socket_path(
            "per_user", "linux", environ={"XDG_RUNTIME_DIR": str(existing)}, home="/home/example"
        )
        == f"{existing}/sayfirst/daemon.sock"
    )


def test_a_system_address_is_the_platform_run_directory() -> None:
    assert default_socket_path("system", "linux", environ={}, home="/root") == (
        "/run/sayfirst/daemon.sock"
    )
    assert default_socket_path("system", "darwin", environ={}, home="/root") == (
        "/var/run/sayfirst/daemon.sock"
    )


def test_an_address_somebody_named_is_the_address_and_is_not_called_a_default() -> None:
    from sayfirst_contract.transport.socket_client import profile_address

    address = profile_address("/srv/own/daemon.sock", "per_user", environ={}, home="/home/example")
    assert address == ("/srv/own/daemon.sock", False)


def test_a_per_user_profile_given_no_address_is_looked_for_at_the_default_one() -> None:
    from sayfirst_contract.transport.socket_client import profile_address

    address = profile_address(None, "per_user", environ={}, home="/home/example", platform="linux")
    assert address == ("/home/example/.sayfirst/run/daemon.sock", True)
    assert address.path in address.looked_at()


def test_a_system_profile_given_no_address_is_a_misuse_and_never_a_guess() -> None:
    import pytest
    from sayfirst_contract.transport.socket_client import ProfileMisuse, profile_address

    with pytest.raises(ProfileMisuse, match="--socket is required in system mode"):
        profile_address(None, "system", environ={}, home="/root", platform="linux")


def test_an_address_named_relative_to_where_the_command_ran_is_made_absolute_once(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Resolved against the directory the command ran in, and never again.

    A relative name used to travel as typed and be resolved on every connection,
    against whatever directory the process was in by then: a governed program that
    changed directory was then answered by whichever daemon of the same account
    served that same relative name there — the peer check passes, the account is
    the same, and the policy is another one.
    """
    from sayfirst_contract.transport.socket_client import profile_address

    monkeypatch.chdir(tmp_path)
    address = profile_address("run/daemon.sock", "per_user", environ={}, home="/home/example")
    assert address == (str(tmp_path / "run" / "daemon.sock"), False)
