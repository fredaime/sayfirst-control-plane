# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from sayfirst_control_plane.settings import (
    DEFAULT_GROUP_LIFETIME_SECONDS,
    EVERYONE_GROUPS,
    EX_CONFIG,
    START_REFUSALS,
    StartRefused,
    default_socket_path,
    read_settings,
    sun_path_limit,
    umask_for,
)


def _read(**overrides: object):  # type: ignore[no-untyped-def]
    document = {"socket": {"mode": "per_user", "path": "/tmp/sayfirst/daemon.sock"}}
    for key, value in overrides.items():
        section, _, member = key.partition("__")
        document.setdefault(section, {})[member] = value  # type: ignore[index]
    return read_settings(document, platform="linux")


def test_the_start_refusals_are_named_and_are_not_part_of_the_contract() -> None:
    """Article 6: a daemon that will not start says why on standard error."""
    assert EX_CONFIG == 78
    assert (
        frozenset(
            {
                "socket_directory_unprotected",
                "socket_directory_missing",
                "socket_mode_invalid",
                "socket_path_too_long",
                "socket_path_not_absolute",
                "socket_in_use",
                "socket_group_unknown",
                "socket_group_is_everyone",
                "socket_not_unix",
                "socket_abstract_or_unnamed",
                "run_as_unknown",
                "run_as_requires_root",
                "peer_identity_unsupported",
                "overflow_id_unreadable",
                "mode_invalid",
                "group_lifetime_out_of_bounds",
                "configuration_unreadable",
                "configuration_unprotected",
                "socket_address_denied",
                "socket_permissions_denied",
                "privileges_not_dropped",
                "policy_unavailable_at_start",
                "evidence_root_unusable",
                "plugin_composition_refused",
                "decision_store_unusable",
                "policy_archive_unusable",
                "recovery_store_unusable",
            }
        )
        == START_REFUSALS
    )
    from sayfirst_contract.artifacts import load_json

    codes = set(load_json("domain", "problem-codes.json")["codes"])
    # One name is shared on purpose: on the server the condition is a start
    # refusal (rule L6), on the client it is a problem the caller reads.
    assert START_REFUSALS & codes == {"peer_identity_unsupported"}


def test_the_settings_say_which_file_they_were_read_from() -> None:
    """Article 8: the protections of the configuration need the name that was read.

    Before this, `read_settings` answered every value a deployment wrote and no
    path to the file it wrote them in, so neither the start path nor the
    decision path had a file to check and the two checks that did run read the
    policy authority, which is a different file. A deployment that named none
    carries `""`, and nothing is then claimed about a configuration nothing
    read (article 2).
    """
    assert _read().configuration_path == ""
    named = read_settings(
        {"socket": {"mode": "per_user", "path": "/tmp/sayfirst/daemon.sock"}},
        platform="linux",
        configuration_path="/etc/sayfirst/daemon.toml",
    )
    assert named.configuration_path == "/etc/sayfirst/daemon.toml"


def test_the_reader_of_the_file_keeps_the_name_it_opened(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 8: the name checked is the name read, absolute and not normalised."""
    from sayfirst_control_plane.cli import load_settings

    path = tmp_path / "daemon.toml"
    path.write_text('[socket]\nmode = "per_user"\npath = "/tmp/sayfirst/daemon.sock"\n')

    assert load_settings(path, platform="linux").configuration_path == str(path)
    assert load_settings(None, platform="linux").configuration_path == ""


def test_the_daemon_has_no_tcp_listener_to_configure() -> None:
    """Article 6, rule L3: no host, no port, and loopback is not an exception."""
    settings = _read()
    assert not any("host" in name or "port" in name for name in vars(settings))
    with pytest.raises(StartRefused) as refusal:
        read_settings(
            {"socket": {"mode": "per_user", "host": "127.0.0.1"}},
            platform="linux",
        )
    assert refusal.value.reason == "mode_invalid"


def test_the_mode_is_one_of_the_two_the_article_names() -> None:
    """Article 6, rule M1: two deployment modes exist and are named."""
    assert _read(socket__mode="system", socket__group="operators").mode == "system"
    with pytest.raises(StartRefused) as refusal:
        _read(socket__mode="loopback")
    assert refusal.value.reason == "mode_invalid"


def test_per_user_mode_refuses_system_keys() -> None:
    """Article 6, rule M4: a per-user daemon that names a group is a mode confusion."""
    for key, value in (
        ("socket__group", "operators"),
        ("socket__run_as", "daemon"),
    ):
        with pytest.raises(StartRefused) as refusal:
            _read(**{key: value})
        assert refusal.value.reason == "mode_invalid"
        assert key.split("__")[1] in refusal.value.detail
    with pytest.raises(StartRefused) as refusal:
        read_settings(
            {
                "socket": {"mode": "per_user", "path": "/tmp/a.sock"},
                "identity": {"accounts": {"svc": {"kind": "service"}}},
            },
            platform="linux",
        )
    assert refusal.value.reason == "mode_invalid"
    assert "identity.accounts" in refusal.value.detail


def test_a_configured_account_kind_is_read_only_in_system_mode() -> None:
    """Article 6, rule K3: a mapping a per-user daemon cannot mean is refused."""
    settings = read_settings(
        {
            "socket": {"mode": "system", "group": "operators", "path": "/tmp/d.sock"},
            "identity": {"accounts": {"svc-build": {"kind": "service"}}},
        },
        platform="linux",
    )
    assert settings.account_kinds == {"svc-build": "service"}
    with pytest.raises(StartRefused) as refusal:
        read_settings(
            {
                "socket": {"mode": "system", "group": "operators", "path": "/tmp/d.sock"},
                "identity": {"accounts": {"svc-build": {"kind": "service", "uid": 7}}},
            },
            platform="linux",
        )
    assert refusal.value.reason == "mode_invalid"


def test_a_system_daemon_refuses_an_everyone_group() -> None:
    """Article 6, rule S7: an admission list that admits everyone is a loopback port."""
    assert set(EVERYONE_GROUPS) == {"users", "staff", "everyone", "nogroup", "nobody"}
    for name in EVERYONE_GROUPS:
        with pytest.raises(StartRefused) as refusal:
            _read(socket__mode="system", socket__group=name)
        assert refusal.value.reason == "socket_group_is_everyone"
    with pytest.raises(StartRefused) as refusal:
        _read(socket__mode="system", socket__group="")
    assert refusal.value.reason == "socket_group_unknown"


def test_the_group_lifetime_is_bounded() -> None:
    """Article 6, rule G2: the revocation latency is bounded and documented."""
    assert DEFAULT_GROUP_LIFETIME_SECONDS == 60
    assert _read().group_lifetime_seconds == 60
    for value in (1, 3600):
        assert _read(identity__group_lifetime_seconds=value).group_lifetime_seconds == value
    for value in (0, 3601, -1, "60"):
        with pytest.raises(StartRefused) as refusal:
            _read(identity__group_lifetime_seconds=value)
        assert refusal.value.reason == "group_lifetime_out_of_bounds"


def test_the_local_address_is_absolute_and_fits_the_kernel_structure() -> None:
    """Article 6, rule L5: the name has a length the kernel accepts."""
    assert sun_path_limit("linux") == 108
    assert sun_path_limit("darwin") == 104
    with pytest.raises(StartRefused) as refusal:
        _read(socket__path="relative/daemon.sock")
    assert refusal.value.reason == "socket_path_not_absolute"
    with pytest.raises(StartRefused) as refusal:
        _read(socket__path="/" + "a" * 110 + "/daemon.sock")
    assert refusal.value.reason == "socket_path_too_long"
    fits_linux_only = "/" + "a" * 103
    assert (
        read_settings(
            {"socket": {"mode": "per_user", "path": fits_linux_only}}, platform="linux"
        ).socket_path
        == fits_linux_only
    )
    with pytest.raises(StartRefused) as refusal:
        read_settings({"socket": {"mode": "per_user", "path": fits_linux_only}}, platform="darwin")
    assert refusal.value.reason == "socket_path_too_long"


def test_the_default_local_address_follows_the_deployment_mode() -> None:
    """Article 6, rule L2: one default per mode and per platform."""
    runtime = default_socket_path(
        "per_user", "linux", environ={"XDG_RUNTIME_DIR": "/"}, home="/home/example"
    )
    assert runtime == "/sayfirst/daemon.sock"
    fallback = default_socket_path("per_user", "linux", environ={}, home="/home/example")
    assert fallback == "/home/example/.sayfirst/run/daemon.sock"
    assert default_socket_path("system", "linux", environ={}, home="/root") == (
        "/run/sayfirst/daemon.sock"
    )
    assert default_socket_path("system", "darwin", environ={}, home="/root") == (
        "/var/run/sayfirst/daemon.sock"
    )


def test_the_local_address_is_never_briefly_more_permissive() -> None:
    """Article 6, rule S2: the file is created at its final mode."""
    assert umask_for("per_user") == 0o077
    assert umask_for("system") == 0o117
    with pytest.raises(ValueError):
        umask_for("zz-synthetic-mode")


def test_a_runtime_directory_that_does_not_exist_selects_the_fallback() -> None:
    """Article 6, rule L2: the variable is used when it names a directory that exists."""
    present = default_socket_path(
        "per_user",
        "linux",
        environ={"XDG_RUNTIME_DIR": "/run/user/1000"},
        home="/home/example",
        directory_exists={"/run/user/1000"}.__contains__,
    )
    assert present == "/run/user/1000/sayfirst/daemon.sock"
    absent = default_socket_path(
        "per_user",
        "linux",
        environ={"XDG_RUNTIME_DIR": "/run/user/1000"},
        home="/home/example",
        directory_exists=lambda _: False,
    )
    assert absent == "/home/example/.sayfirst/run/daemon.sock"
    empty = default_socket_path(
        "per_user",
        "linux",
        environ={"XDG_RUNTIME_DIR": ""},
        home="/home/example",
        directory_exists=lambda _: True,
    )
    assert empty == "/home/example/.sayfirst/run/daemon.sock"


def test_the_runtime_directory_is_checked_against_the_filesystem_by_default(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Article 6, rule L2: the default check is the real one, not a guess."""
    existing = tmp_path / "runtime"
    existing.mkdir()
    assert (
        default_socket_path(
            "per_user", "linux", environ={"XDG_RUNTIME_DIR": str(existing)}, home="/home/example"
        )
        == f"{existing}/sayfirst/daemon.sock"
    )
    assert (
        default_socket_path(
            "per_user",
            "linux",
            environ={"XDG_RUNTIME_DIR": str(tmp_path / "absent")},
            home="/home/example",
        )
        == "/home/example/.sayfirst/run/daemon.sock"
    )
