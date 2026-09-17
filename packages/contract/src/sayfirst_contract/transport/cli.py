# SPDX-License-Identifier: Apache-2.0
"""The two read-only inspections a caller can run against a daemon.

`whoami` is the guard article 6 names: it reports the principal as the boundary
saw it, together with the verification the client performed before it sent
anything. `status` is what the daemon says about itself — the integrity grade of
article 7, its basis and the interval it is re-evaluated on, and the active
privacy provider of article 11.

Both are one connection, one operation and one rendering, so they share a
parser, a profile and a set of exit codes: a second copy of the connect path
would be a second place for the verification to go wrong. The rendering lives
here, beside the client that reads the document, rather than in the server that
writes it — a surface that inspects the daemon must not depend on the daemon
(article 14).

There is no `--url` and no way to hand either of them a credential: a profile is
an address, a mode, and the account the daemon runs as.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from typing import Final

from ..client import Answered, Refused
from ..generation import CONTRACT_GENERATION
from .socket_client import (
    PER_USER,
    SYSTEM,
    ProfileMisuse,
    SocketClientProblem,
    SocketProfile,
    connect,
    declared_delegation,
)

EXIT_OK: Final[int] = 0
EXIT_REFUSED: Final[int] = 3
EXIT_COULD_NOT_ASK: Final[int] = 4
EXIT_MISUSE: Final[int] = 64

#: The inspections this module answers, in the order `--help` lists them.
COMMANDS: Final[tuple[str, ...]] = ("whoami", "status")


def build_parser() -> argparse.ArgumentParser:
    """Every option these commands accept. None of them names a network."""
    # No `prog`, for the reason given in `sayfirst_contract.cli`: this parser is
    # reached through whichever console script forwarded to it.
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--mode", choices=(PER_USER, SYSTEM), default=PER_USER)
    parser.add_argument("--daemon-user", default=None)
    parser.add_argument("--json", action="store_true")
    return parser


def render_status(document: Mapping[str, object]) -> str:
    """Honest rendering for the evidence members of the status result.

    Every member has a value for "not reported", and it is rendered rather than
    replaced by a plausible one: a daemon that did not say is not a daemon that
    said no (article 2).
    """
    grade_document = document.get("integrity_grade")
    if not isinstance(grade_document, Mapping):
        grade_document = {"grade": "unverified", "basis": "access_not_established"}
    grade = str(grade_document.get("grade", "unverified"))
    basis = str(grade_document.get("basis", "access_not_established"))
    provider = str(document.get("privacy_provider", "unknown"))
    return "\n".join(
        (
            _render_grade(grade, basis),
            _render_interval(grade_document.get("reevaluation_interval_seconds")),
            _render_provider(provider),
            _render_emission(document.get("evidence_emission")),
        )
    )


def _render_grade(grade: str, basis: str) -> str:
    if grade == "observability":
        return (
            "integrity grade: observability (the caller can write the store; "
            "the chain detects accidental corruption only)"
        )
    if grade == "unverified" and basis == "caller_cannot_write":
        return (
            "integrity grade: unverified (the caller cannot write the store; "
            "exclusivity is not evaluated in this version)"
        )
    return "integrity grade: unverified (access not established)"


def _render_interval(seconds: object) -> str:
    """The latency of detection of a permission change, or that it was not said."""
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        return "grade re-evaluation interval: unknown (the daemon did not report it)"
    return f"grade re-evaluation interval: {seconds} seconds"


def _render_emission(emission: object) -> str:
    """Article 2: three values — delivering, not delivering, and not reported."""
    if not isinstance(emission, Mapping) or not isinstance(emission.get("delivering"), bool):
        return "evidence emission: unknown (the daemon did not report it)"
    if emission["delivering"]:
        return "evidence emission: delivering"
    held = emission.get("undelivered_records", 0)
    scopes = emission.get("scopes_undelivered", ())
    named = ", ".join(str(item) for item in scopes) if isinstance(scopes, list | tuple) else ""
    return f"evidence emission: not delivering ({held} records held, scopes: {named})"


def _render_provider(provider: str) -> str:
    if provider == "none":
        return "privacy provider: none (captured content is recorded as given)"
    if provider == "unknown":
        return "privacy provider: unknown (could not consult the composition)"
    return f"privacy provider: {provider}"


def _render_whoami(result: Mapping[str, object], stream: object) -> None:
    principal = result.get("principal")
    peer = result.get("peer")
    assert isinstance(peer, dict)
    name = principal.get("name") if isinstance(principal, dict) else None
    groups = principal.get("groups") if isinstance(principal, dict) else None
    print(f"peer: uid {peer['uid']} gid {peer['gid']} pid {peer['pid']}", file=stream)  # type: ignore[arg-type]
    print(f"principal: {name} ({result['status']})", file=stream)  # type: ignore[arg-type]
    print(f"groups: {'' if groups is None else ', '.join(groups)}", file=stream)  # type: ignore[arg-type]


def _render_status(result: Mapping[str, object], stream: object) -> None:
    supported = result.get("supported_generations")
    named = ", ".join(str(item) for item in supported) if isinstance(supported, list) else "unknown"
    print(  # type: ignore[call-overload]
        f"contract generation: {result.get('contract_generation')} (supported: {named})",
        file=stream,
    )
    print(render_status(result), file=stream)  # type: ignore[arg-type]


def _render(envelope: dict[str, object], command: str, as_json: bool, stream: object) -> None:
    if as_json:
        print(json.dumps(envelope, indent=2, sort_keys=True), file=stream)  # type: ignore[arg-type]
        return
    verification = envelope["verification"]
    assert isinstance(verification, dict)
    print(
        f"verified: {str(verification['verified']).lower()} "
        f"(server_uid {verification['server_uid']}, expected {verification['expected']})",
        file=stream,  # type: ignore[arg-type]
    )
    result = envelope.get("result")
    if isinstance(result, dict):
        if command == "whoami":
            _render_whoami(result, stream)
        else:
            _render_status(result, stream)
    problem = envelope.get("problem")
    if isinstance(problem, dict):
        print(f"{problem['code']}: {problem['message']}", file=stream)  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None, *, out: object = None, err: object = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    arguments = build_parser().parse_args(argv)
    try:
        profile = SocketProfile(
            arguments.socket, mode=arguments.mode, daemon_user=arguments.daemon_user
        )
    except ProfileMisuse as misuse:
        print(str(misuse), file=err)  # type: ignore[arg-type]
        return EXIT_MISUSE
    declared = declared_delegation()
    try:
        connection = connect(profile)
    except SocketClientProblem as problem:
        envelope = {
            "contract_generation": CONTRACT_GENERATION,
            "verification": {"server_uid": None, "expected": None, "verified": False},
            "problem": problem.problem.to_document(CONTRACT_GENERATION),
            "declared_delegation": None if declared is None else declared.to_document(),
        }
        _render(envelope, arguments.command, arguments.json, err)
        return EXIT_REFUSED if problem.classification == "refused" else EXIT_COULD_NOT_ASK
    try:
        result = (
            connection.read_whoami() if arguments.command == "whoami" else connection.read_status()
        )
        envelope = {
            "contract_generation": CONTRACT_GENERATION,
            "verification": {
                "server_uid": connection.server_credential.uid,
                "expected": connection.expected_uid,
                "verified": connection.verified,
            },
            "declared_delegation": None if declared is None else declared.to_document(),
        }
        if isinstance(result, Answered):
            envelope["result"] = result.value.to_document()
            _render(envelope, arguments.command, arguments.json, out)
            return EXIT_OK
        envelope["problem"] = result.problem.to_document(CONTRACT_GENERATION)
        _render(envelope, arguments.command, arguments.json, err)
        return EXIT_REFUSED if isinstance(result, Refused) else EXIT_COULD_NOT_ASK
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
