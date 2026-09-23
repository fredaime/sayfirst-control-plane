# SPDX-License-Identifier: Apache-2.0
"""The `sayfirst-daemon` command: the daemon's own command line, and two verbs in front of it.

Three verbs. `serve` is the daemon, in the foreground, under whatever supervises
it, and it is what the command does when it is given no verb at all — which is
how it was started before there were others. It is not reimplemented here: the
words are handed, untouched, to `sayfirst_control_plane.cli`, whose parser, start
refusals and exit statuses are its own and have not changed.

`up --quickstart` and `down` are a first run's convenience around that same
`serve` (`launcher.py` says exactly what they add and what they do not). They
are for one account on one machine; a deployment goes on using `serve` under its
own supervisor.

The dependency points one way. This package imports the server to start it and
to read its settings; the server imports nothing from here, which its own guard
holds (`test_the_server_depends_on_the_contract_alone`). That is why the console
script names this module rather than the server's: a front can stand in front
of the daemon, and the daemon does not know it is there.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from sayfirst_control_plane import cli as server

from . import launcher

#: The verbs, in the order `--help` lists them. `serve` first: it is the daemon.
SERVE: Final[str] = "serve"
UP: Final[str] = "up"
DOWN: Final[str] = "down"
COMMANDS: Final[tuple[str, ...]] = (SERVE, UP, DOWN)


def build_parser() -> argparse.ArgumentParser:
    """Every option this command accepts. None of them names a network."""
    parser = argparse.ArgumentParser(
        prog="sayfirst-daemon",
        description=(
            "serve: run the daemon in the foreground on a configuration (the default verb). "
            "up --quickstart: write a starter policy and configuration under "
            "~/.sayfirst/quickstart if they are not there, start a per-user daemon on them "
            "in the background, and return once it answers. "
            "down: stop the daemon `up` started, and only that one."
        ),
    )
    parser.add_argument("command", choices=COMMANDS, nargs="?", default=SERVE)
    parser.add_argument("--config", type=Path, default=None, help="serve: the configuration file")
    parser.add_argument(
        "--quickstart",
        action="store_true",
        help="up: the per-user quickstart under ~/.sayfirst/quickstart",
    )
    return parser


def read_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    """The arguments, with every option held to the verb it belongs to.

    One flat parser rather than a parser per verb, because the verb is optional
    and has to stay so: `sayfirst-daemon --config FILE` is a documented way to
    start the daemon. The price is that the pairing is checked here by hand —
    and it is checked, because an option accepted and ignored is a configuration
    somebody believes they applied (article 2).
    """
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == UP and not arguments.quickstart:
        parser.error(
            "up starts the per-user quickstart and has to be told so: `up --quickstart`. "
            "A daemon on a configuration of your own is `serve --config FILE`"
        )
    if arguments.command != UP and arguments.quickstart:
        parser.error(f"--quickstart belongs to `up`, not to `{arguments.command}`")
    if arguments.command != SERVE and arguments.config is not None:
        parser.error(
            f"--config belongs to `serve`; `{arguments.command}` reads the quickstart's own "
            f"configuration under ~/.sayfirst/quickstart"
        )
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    forwarded = list(sys.argv[1:] if argv is None else argv)
    arguments = read_arguments(forwarded)
    if arguments.command == SERVE:
        # The words as they were typed, to the parser that has always read them.
        return server.main(forwarded)
    act = launcher.up if arguments.command == UP else launcher.down
    return act(
        home=os.path.expanduser("~"),
        read_settings_from=lambda path: server.load_settings(path, platform=sys.platform),
        out=sys.stdout,
        err=sys.stderr,
    )


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
