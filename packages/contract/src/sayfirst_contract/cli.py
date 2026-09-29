# SPDX-License-Identifier: Apache-2.0
"""The operator subcommands this distribution implements.

The constitution names a single command with subcommands — `whoami` in article
6, `status` in article 7, `plugins list` in article 8 — so a block that adds one
adds it to a dispatch rather than claiming the console script for itself. The
`sayfirstd` distribution installs that script and forwards the subcommands below
whole: `conformance replay` is answered here, `whoami` and `status` by
`sayfirst_contract.transport.cli`, whose parser and exit codes are its own.

This distribution claims no console script of its own, so nothing here is bound
to the name of the surface that forwards to it. One surface forwards to it
today: `sayfirstd`, the operator surface of this repository. The product
command-line interface, which is published from another repository under the
name `sayfirst`, may reach the same subcommands through these same entry points
— it is what installing this distribution beside it would offer — and no
release of it does so yet.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from .binding.http_unix_socket.policy_hook import (
    policy_change_command,
    require_a_policy_change_command,
)
from .binding.http_unix_socket.replay import SocketHarness
from .golden import load_scenarios
from .replay import Report, Side, replay
from .transport.cli import COMMANDS as INSPECTIONS
from .transport.cli import main as inspect


def _assignments(values: Sequence[str], label: str) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, assigned = value.partition("=")
        if not separator or not name or not assigned:
            raise ValueError(f"{label} must be SCENARIO=VALUE: {value!r}")
        if name in result:
            raise ValueError(f"{label} repeats scenario {name!r}")
        result[name] = assigned
    return result


#: The whole-run verdict as an exit status: the same three the conformance
#: command gives, so the two spellings of one replay never disagree about a run.
EXIT_FOR_VERDICT: dict[str, int] = {"proven": 0, "failed": 1, "unknown": 3}


def render(report: Report, stream: TextIO) -> None:
    """Write one stable line per scenario and the whole-run result.

    The whole-run line is the report's own verdict. A run that replayed nothing
    wrong but did not replay every bound scenario is unknown — neither a proof
    nor a failure of what was replayed (article 2) — and it used to be written
    as failed here while the conformance command wrote unknown for the same run.
    """
    for item in report.scenarios:
        stream.write(f"{item.name}\t{item.verdict.value}\t{item.detail}\n")
    if report.succeeded():
        stream.write(f"run\tproven\t{len(report.proven())} scenarios proven\n")
    else:
        stream.write(f"run\t{report.verdict.value}\t{report.failure_reason()}\n")


def _parser() -> argparse.ArgumentParser:
    # No `prog`: this dispatch is reached through whichever console script
    # forwarded to it — `sayfirstd` today, and any other that ever does — and a
    # usage line naming one of them when another was typed is a claim the
    # invocation contradicts (article 2). argparse's default is the program the
    # caller actually ran.
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    conformance = commands.add_parser("conformance")
    conformance_commands = conformance.add_subparsers(dest="conformance_command", required=True)
    replay_parser = conformance_commands.add_parser("replay")
    replay_parser.add_argument(
        "--socket",
        action="append",
        default=[],
        metavar="SCENARIO=PATH",
        help="socket of a daemon arranged for one scenario; repeat for each scenario",
    )
    replay_parser.add_argument(
        "--expected-absent",
        action="append",
        default=[],
        metavar="SCENARIO=REASON",
        help="name an unavailable scenario and why it is unavailable",
    )
    replay_parser.add_argument("--expected-uid", type=int, default=os.geteuid())
    replay_parser.add_argument("--timeout", type=float, default=5.0)
    replay_parser.add_argument("--deadline-wait-seconds", type=float, default=61.0)
    replay_parser.add_argument(
        "--change-policy-command",
        default=None,
        metavar="CMD",
        help="run once between a policy-change scenario's two asks; it writes the policy "
        "the daemon must answer under and exits 0 once the daemon reads it",
    )
    replay_parser.add_argument("--change-policy-timeout", type=float, default=30.0)
    # `whoami` and `status` are answered by another module's parser, reached by
    # the dispatch in `main` before this one parses. They are declared here so
    # that `--help` lists every subcommand the tool answers rather than only
    # this one's (article 2).
    for inspection in INSPECTIONS:
        commands.add_parser(inspection, add_help=False)
    return parser


def main(arguments: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    """Run the requested command and return its process exit code."""
    argv = list(sys.argv[1:] if arguments is None else arguments)
    if argv and argv[0] in INSPECTIONS:
        return inspect(argv, out=stdout or sys.stdout)
    output = stdout or sys.stdout
    namespace = _parser().parse_args(argv)
    try:
        sockets = {
            name: Path(path) for name, path in _assignments(namespace.socket, "--socket").items()
        }
        expected_absent = _assignments(namespace.expected_absent, "--expected-absent")
        scenarios = load_scenarios()
        server_names = {name for name, scenario in scenarios.items() if scenario.binds_server()}
        if unexpected := set(sockets) - server_names:
            raise ValueError(f"--socket names non-server scenarios: {sorted(unexpected)!r}")
        if overlap := set(sockets) & set(expected_absent):
            raise ValueError(
                f"scenarios cannot have both a socket and expected absence: {sorted(overlap)!r}"
            )
        require_a_policy_change_command(sockets, scenarios, namespace.change_policy_command)
        change_policy = (
            policy_change_command(
                namespace.change_policy_command, timeout=namespace.change_policy_timeout
            )
            if namespace.change_policy_command is not None
            else None
        )
        report = replay(
            scenarios,
            SocketHarness(
                sockets,
                expected_uid=namespace.expected_uid,
                timeout=namespace.timeout,
                deadline_wait_seconds=namespace.deadline_wait_seconds,
                change_policy=change_policy,
            ),
            Side.SERVER,
            expected_absent=expected_absent,
        )
    except ValueError as exc:
        # Nothing was replayed: what the run would have shown is not known.
        output.write(f"run\tunknown\tinvalid invocation: {exc}\n")
        return 2
    render(report, output)
    return EXIT_FOR_VERDICT[report.verdict.value]


if __name__ == "__main__":
    raise SystemExit(main())
