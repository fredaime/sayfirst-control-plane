# SPDX-License-Identifier: Apache-2.0
"""The replay command arranges a policy change through a command the deployment names.

The replayer never touches a policy file: it runs the deployment's own command once,
between the scenario's two asks, and reads its exit status. Every way that command can
fail is the scenario's failure, said, and never a crash or a hang (article 2).
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from sayfirst_contract.binding.http_unix_socket.policy_hook import (
    PolicyChangeFailed,
    policy_change_command,
    require_a_policy_change_command,
)
from sayfirst_contract.golden import load_scenarios

SCENARIO = load_scenarios()["grant_miss_after_policy_version_change"]
POLICY = {"example.effect": "deny"}


def _python(code: str) -> str:
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"


def test_the_command_is_given_the_scenario_and_the_policy(tmp_path: Path) -> None:
    seen = tmp_path / "seen.json"
    code = (
        "import json, os, sys; json.dump({'scenario': os.environ['SAYFIRST_CONFORMANCE_SCENARIO'],"
        " 'policy': json.loads(os.environ['SAYFIRST_CONFORMANCE_POLICY'])}, open(sys.argv[1], 'w'))"
    )
    change = policy_change_command(f"{_python(code)} {shlex.quote(str(seen))}")
    assert SCENARIO.given.policy_changes_to is not None
    change(SCENARIO, SCENARIO.given.policy_changes_to)
    assert json.loads(seen.read_text()) == {"scenario": SCENARIO.name, "policy": POLICY}


@pytest.fixture
def an_open_terminal() -> Iterator[None]:
    """Standard input that never ends, as a terminal nobody types into would be."""
    read_end, write_end = os.pipe()
    saved = os.dup(0)
    os.dup2(read_end, 0)
    try:
        yield
    finally:
        os.dup2(saved, 0)
        for fd in (saved, read_end, write_end):
            os.close(fd)


@pytest.mark.usefixtures("an_open_terminal")
def test_a_command_that_reads_its_input_reads_nothing_and_finishes() -> None:
    change = policy_change_command(_python("import sys; sys.stdin.read()"), timeout=5)
    change(SCENARIO, POLICY)


def test_output_that_is_not_utf8_still_fails_with_its_status() -> None:
    change = policy_change_command(
        _python("import sys; sys.stderr.buffer.write(b'bad \\xff\\xfe bytes\\n'); sys.exit(4)")
    )
    with pytest.raises(PolicyChangeFailed, match=r"exited 4"):
        change(SCENARIO, POLICY)


def test_a_non_zero_exit_fails_with_its_status_and_last_line() -> None:
    change = policy_change_command(
        _python("import sys; print('policy not written', file=sys.stderr); sys.exit(3)")
    )
    with pytest.raises(PolicyChangeFailed, match=r"exited 3: policy not written"):
        change(SCENARIO, POLICY)


def test_a_command_that_hangs_is_stopped_at_its_timeout() -> None:
    change = policy_change_command(_python("import time; time.sleep(30)"), timeout=0.5)
    with pytest.raises(PolicyChangeFailed, match=r"did not finish within 0.5 seconds"):
        change(SCENARIO, POLICY)


def test_a_program_that_does_not_exist_fails_by_name(tmp_path: Path) -> None:
    change = policy_change_command(str(tmp_path / "no-such-program"))
    with pytest.raises(PolicyChangeFailed, match=r"was not found"):
        change(SCENARIO, POLICY)


def test_a_file_that_cannot_be_run_fails_by_name(tmp_path: Path) -> None:
    script = tmp_path / "not-executable"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o600)
    change = policy_change_command(str(script))
    with pytest.raises(PolicyChangeFailed, match=r"could not be run"):
        change(SCENARIO, POLICY)


def test_an_empty_command_is_an_invalid_invocation() -> None:
    with pytest.raises(ValueError, match="names no command"):
        policy_change_command("   ")


def test_a_policy_change_scenario_with_a_socket_needs_the_command(tmp_path: Path) -> None:
    scenarios = load_scenarios()
    sockets = {SCENARIO.name: tmp_path / "d.sock", "allow": tmp_path / "a.sock"}
    with pytest.raises(
        ValueError, match=r"grant_miss_after_policy_version_change.*--change-policy-command"
    ):
        require_a_policy_change_command(sockets, scenarios, None)
    require_a_policy_change_command(sockets, scenarios, "true")
    require_a_policy_change_command({"allow": tmp_path / "a.sock"}, scenarios, None)
