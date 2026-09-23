# SPDX-License-Identifier: Apache-2.0
"""The status command of articles 7 and 11, run against a daemon in its own process.

Article 11's Guard names a status surface that "renders the active privacy
provider by name"; article 7's names the grade. The operator surface of this
repository is `sayfirstd`, and it forwards `status` to the contract
distribution's dispatch the way it forwards `whoami`. What the surface renders
is asserted here, against a real daemon over a real socket, because a document
that says the command exists is a claim and this is its evidence (article 2).
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest
from daemon_process import serving, write_config
from sayfirst_contract.transport.cli import (
    EXIT_COULD_NOT_ASK,
    EXIT_MISUSE,
    EXIT_OK,
    build_parser,
    main,
)
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms
from sayfirst_testing.schemas import validate_document


@requires_platforms(*OS_REAL_PLATFORMS)
def test_status_names_the_grade_its_basis_the_interval_and_the_provider(tmp_path: Path) -> None:
    """What `packages/control-plane/README.md` says the surface renders, rendered."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    out, err = io.StringIO(), io.StringIO()
    with serving(config):
        code = main(["status", "--socket", str(address)], out=out, err=err)
    assert code == EXIT_OK, err.getvalue()
    rendered = out.getvalue()
    assert f"verified: true (server_uid {os.geteuid()}, expected {os.geteuid()})" in rendered
    assert "integrity grade: unverified (access not established)" in rendered
    assert "grade re-evaluation interval: 30 seconds" in rendered
    assert "privacy provider: unknown (could not consult the composition)" in rendered
    assert "evidence emission: unknown (the daemon did not report it)" in rendered


@requires_platforms(*OS_REAL_PLATFORMS)
def test_status_answers_the_document_the_contract_publishes(tmp_path: Path) -> None:
    """Article 13: the result rendered is the result the schema defines."""
    config = write_config(tmp_path / "run")
    address = tmp_path / "run" / "daemon.sock"
    out, err = io.StringIO(), io.StringIO()
    with serving(config):
        code = main(["status", "--socket", str(address), "--json"], out=out, err=err)
    assert code == EXIT_OK, err.getvalue()
    envelope = json.loads(out.getvalue())
    assert envelope["verification"] == {
        "server_uid": os.geteuid(),
        "expected": os.geteuid(),
        "verified": True,
    }
    result = envelope["result"]
    validate_document(result, "status-result")
    assert result["principal"]["uid"] == os.geteuid()
    assert result["integrity_grade"]["grade"] == "unverified"
    assert result["contract_generation"] in result["supported_generations"]


@requires_platforms(*OS_REAL_PLATFORMS)
def test_status_exits_could_not_ask_when_nothing_is_listening(tmp_path: Path) -> None:
    """Article 1: an unreachable control plane is never rendered as a healthy state."""
    out, err = io.StringIO(), io.StringIO()
    code = main(["status", "--socket", str(tmp_path / "absent.sock"), "--json"], out=out, err=err)
    assert code == EXIT_COULD_NOT_ASK
    assert out.getvalue() == ""
    envelope = json.loads(err.getvalue())
    assert envelope["verification"]["verified"] is False
    assert envelope["problem"]["code"] == "unreachable"


@requires_platforms(*OS_REAL_PLATFORMS)
def test_status_given_no_address_finds_a_per_user_daemon_at_the_default_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rule L2 read from the other end: a daemon that chose the default address is
    found by a caller that names none, because both read the binding's one rule."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    config = write_config(tmp_path / "configuration", path=None)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    out, err = io.StringIO(), io.StringIO()
    with serving(config, home=home):
        code = main(["status"], out=out, err=err)
    assert code == EXIT_OK, err.getvalue()
    assert f"verified: true (server_uid {os.geteuid()}, expected {os.geteuid()})" in out.getvalue()


def test_status_given_no_address_says_where_it_looked_when_nobody_is_there(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Article 2: an address nobody typed is an address somebody has to be told."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    out, err = io.StringIO(), io.StringIO()
    code = main(["status"], out=out, err=err)
    assert code == EXIT_COULD_NOT_ASK
    assert out.getvalue() == ""
    assert "unreachable" in err.getvalue()
    assert f"socket: {tmp_path}/.sayfirst/run/daemon.sock (the per-user default" in err.getvalue()


def test_a_system_profile_is_never_given_a_default_address(tmp_path: Path) -> None:
    """Rule C1's neighbour: a system profile says where and as whom, in words."""
    out, err = io.StringIO(), io.StringIO()
    code = main(["status", "--mode", "system", "--daemon-user", "root"], out=out, err=err)
    assert code == EXIT_MISUSE
    assert "--socket" in err.getvalue()


def test_both_inspections_are_reached_through_one_parser_and_one_profile() -> None:
    """Article 6: the same profile, and no network and no credential, for either."""
    parser = build_parser()
    commands = [action for action in parser._actions if action.dest == "command"]
    assert [tuple(action.choices) for action in commands] == [("whoami", "status")]
    options = {option for action in parser._actions for option in action.option_strings}
    assert options == {"-h", "--help", "--socket", "--mode", "--daemon-user", "--json"}
