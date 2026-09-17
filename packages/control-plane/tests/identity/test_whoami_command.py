# SPDX-License-Identifier: Apache-2.0
"""The command article 6 names, run against a daemon in its own process."""

from __future__ import annotations

import grp
import io
import json
import os
import pwd
from pathlib import Path

from daemon_process import serving, write_config
from sayfirst_contract.transport.cli import (
    EXIT_COULD_NOT_ASK,
    EXIT_MISUSE,
    EXIT_OK,
    build_parser,
    main,
)
from sayfirst_contract.transport.socket_client import SocketProfile, connect, whoami
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms
from sayfirst_testing.privileges import requires_unprivileged
from sayfirst_testing.schemas import validate_document


@requires_platforms(*OS_REAL_PLATFORMS)
def test_whoami_reports_the_principal_and_the_verification(tmp_path: Path) -> None:
    """Article 6, rule W3: the result verbatim, beside what the client verified."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    out, err = io.StringIO(), io.StringIO()
    with serving(config):
        code = main(["whoami", "--socket", str(address), "--json"], out=out, err=err)
    assert code == EXIT_OK, err.getvalue()
    envelope = json.loads(out.getvalue())
    assert envelope["verification"] == {
        "server_uid": os.geteuid(),
        "expected": os.geteuid(),
        "verified": True,
    }
    result = envelope["result"]
    validate_document(result, "whoami-result")
    assert result["peer"]["uid"] == os.geteuid()
    assert result["peer"]["pid"] == os.getpid()
    name = pwd.getpwuid(os.geteuid()).pw_name
    assert result["principal"]["name"] == name
    assert result["principal"]["groups"] == [
        grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name, os.getegid())
    ]
    assert result["status"] == "established"


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_command_renders_a_human_line_without_json(tmp_path: Path) -> None:
    """Article 2: the same three facts, whichever face the caller reads."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    out, err = io.StringIO(), io.StringIO()
    with serving(config):
        code = main(["whoami", "--socket", str(address)], out=out, err=err)
    assert code == EXIT_OK
    rendered = out.getvalue()
    assert f"verified: true (server_uid {os.geteuid()}, expected {os.geteuid()})" in rendered
    assert "principal:" in rendered
    assert "groups:" in rendered


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_contract_client_speaks_to_the_daemon_over_the_verified_connection(
    tmp_path: Path,
) -> None:
    """Article 6: both sides verify each other with the same code."""
    from sayfirst_contract.client import Answered

    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    with serving(config):
        connection = connect(SocketProfile(str(address)))
        try:
            assert connection.verified
            assert connection.server_credential.uid == os.geteuid()
            result = whoami(connection)
        finally:
            connection.close()
    assert isinstance(result, Answered)
    assert result.value.peer.uid == os.geteuid()
    assert result.value.mode == "per_user"


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_contract_client_reads_the_status_operation_from_the_daemon(
    tmp_path: Path,
) -> None:
    """Article 13: the operation the generation gate reads, read off the daemon.

    `read_status` had been proved against a scripted far end alone, while the
    daemon answered the operation `operation_unknown` and served an unpublished
    `/health` beside it. This is the same client, the same operation and a real
    daemon over a real socket, which is the only place that drift shows.
    """
    from sayfirst_contract.client import Answered

    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    with serving(config):
        connection = connect(SocketProfile(str(address)))
        try:
            result = connection.read_status()
        finally:
            connection.close()
    assert isinstance(result, Answered), result
    assert result.value.contract_generation in result.value.supported_generations
    assert result.value.principal.uid == os.geteuid()
    assert result.value.integrity_grade.grade.value == "unverified"
    assert result.value.store_authority.value == "unknown"


def test_the_command_offers_no_network_and_no_credential() -> None:
    """Article 6: no --url, no --token, no --host, no --port."""
    options = {option for action in build_parser()._actions for option in action.option_strings}
    assert options == {"-h", "--help", "--socket", "--mode", "--daemon-user", "--json"}
    for forbidden in ("url", "host", "port", "token", "credential", "password"):
        assert not any(forbidden in option for option in options), forbidden


def test_a_system_profile_without_its_daemon_user_is_a_usage_error() -> None:
    """Article 6, rule C1: the command refuses the profile before it connects."""
    out, err = io.StringIO(), io.StringIO()
    code = main(["whoami", "--socket", "/run/d.sock", "--mode", "system"], out=out, err=err)
    assert code == EXIT_MISUSE
    assert "system profile" in err.getvalue()


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_command_exits_could_not_ask_when_nothing_is_listening(tmp_path: Path) -> None:
    """Article 1: no answer about the effect exists, so no effect starts."""
    out, err = io.StringIO(), io.StringIO()
    code = main(["whoami", "--socket", str(tmp_path / "absent.sock"), "--json"], out=out, err=err)
    assert code == EXIT_COULD_NOT_ASK
    envelope = json.loads(err.getvalue())
    assert envelope["verification"]["verified"] is False
    assert envelope["problem"]["code"] == "unreachable"


@requires_platforms(*OS_REAL_PLATFORMS)
@requires_unprivileged()
def test_the_command_refuses_an_impostor_and_sends_it_nothing(tmp_path: Path) -> None:
    """Article 6: the guard the article names, from the command a caller runs.

    Not runnable as root: the impostor binds the address as the tester, and the
    profile expects the daemon to be root, so a root tester *is* the account
    the client is checking for and there is no impostor left to refuse.
    """
    import socket as socket_module

    address = tmp_path / "daemon.sock"
    impostor = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    accepted = None
    try:
        impostor.bind(str(address))
        impostor.listen(1)
        impostor.settimeout(5)
        out, err = io.StringIO(), io.StringIO()
        code = main(
            [
                "whoami",
                "--socket",
                str(address),
                "--mode",
                "system",
                "--daemon-user",
                "root",
                "--json",
            ],
            out=out,
            err=err,
        )
        assert code == EXIT_COULD_NOT_ASK
        envelope = json.loads(err.getvalue())
        assert envelope["problem"]["code"] == "server_not_the_daemon_principal"
        accepted, _ = impostor.accept()
        accepted.setblocking(False)
        try:
            received = accepted.recv(4096)
        except BlockingIOError:
            received = b""
        assert received == b""
    finally:
        if accepted is not None:
            accepted.close()
        impostor.close()
        address.unlink(missing_ok=True)
