# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for contract conformance replay."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from sayfirst_contract.binding.http_unix_socket.replay import SocketHarness
from sayfirst_contract.golden import load_scenarios
from sayfirst_contract.replay import Report, Side, replay


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


def render(report: Report, stream: TextIO) -> None:
    """Write one stable line per scenario and the whole-run result."""
    for item in report.scenarios:
        bound = str(item.bound_to_side).lower()
        # Article 2: a line whose verdict rests on no comparison prints no count.
        assertions = "-" if item.assertion_count is None else str(item.assertion_count)
        stream.write(
            f"{item.name}\t{item.verdict.value}\t{item.detail}"
            f"\tbound={bound}\tassertions={assertions}\n"
        )
    if report.succeeded():
        stream.write(f"run\tproven\t{len(report.proven())} scenarios proven\n")
    else:
        stream.write(f"run\t{report.verdict.value}\t{report.failure_reason()}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sayfirst-conformance")
    commands = parser.add_subparsers(dest="command", required=True)
    replay_parser = commands.add_parser("replay")
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
    return parser


def main(arguments: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    """Run the requested command and return its process exit code."""
    output = stdout or sys.stdout
    namespace = _parser().parse_args(arguments)
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
        report = replay(
            scenarios,
            SocketHarness(
                sockets,
                expected_uid=namespace.expected_uid,
                timeout=namespace.timeout,
                deadline_wait_seconds=namespace.deadline_wait_seconds,
            ),
            Side.SERVER,
            expected_absent=expected_absent,
        )
    except ValueError as exc:
        output.write(f"run\tunknown\tinvalid invocation: {exc}\n")
        return 2
    render(report, output)
    return {"proven": 0, "failed": 1, "unknown": 3}[report.verdict.value]


if __name__ == "__main__":
    raise SystemExit(main())
