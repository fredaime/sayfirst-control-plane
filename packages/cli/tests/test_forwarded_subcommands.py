# SPDX-License-Identifier: Apache-2.0
"""What `sayfirstd` answers by handing the arguments to the contract's dispatch.

Article 2: `--help` names every subcommand this tool answers and no subcommand
it does not, and a document that names one is a claim this file is the evidence
for. The three forwarded commands keep the parser and the exit codes the
contract distribution publishes, so what is asserted here is that they are
reached, not what they then do.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from sayfirstd.main import CONTRACT_COMMANDS, main

#: `sayfirst_contract.transport.cli.EXIT_COULD_NOT_ASK`, named again rather than
#: imported: what is asserted is that the surface returns the contract's own
#: exit code, and a test that imported it would pass on any number they shared.
COULD_NOT_ASK = 4


def test_the_surface_forwards_the_subcommands_the_contract_implements() -> None:
    assert CONTRACT_COMMANDS == ("whoami", "status", "conformance")


def test_help_names_every_subcommand_the_surface_answers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
    assert "{plugins,whoami,status,conformance}" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["whoami", "status"])
def test_an_inspection_reaches_the_contracts_client_and_returns_its_exit_code(
    command: str, tmp_path: Path
) -> None:
    """Article 1: nothing is listening, so the answer is "could not ask" and says so."""
    out = StringIO()
    code = main([command, "--socket", str(tmp_path / "absent.sock")], stdout=out)
    assert code == COULD_NOT_ASK
    assert out.getvalue() == ""
