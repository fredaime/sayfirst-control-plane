# SPDX-License-Identifier: Apache-2.0
"""The daemon's command line.

There is no `--host` and no `--port` here, and no key of the configuration
file carries either word: this daemon listens on one local address and
nowhere else (article 6, rule L3).
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

from .adapters.socket_server import Daemon, assemble
from .settings import EX_CONFIG, Settings, StartRefused, read_settings


def build_parser() -> argparse.ArgumentParser:
    """Every option this daemon accepts."""
    parser = argparse.ArgumentParser(prog="sayfirst-daemon")
    parser.add_argument("command", choices=("serve",), nargs="?", default="serve")
    parser.add_argument("--config", type=Path, default=None)
    return parser


def load_settings(config: Path | None, *, platform: str) -> Settings:
    """The configuration a deployment wrote, or the reason it could not be read.

    A file that is absent, unreadable or not TOML used to leave `main()` as an
    `OSError` or a `TOMLDecodeError`: exit 1 and a traceback, where
    `docs/deployment.md` publishes 78 and one reason (article 2). It is a
    start the daemon cannot name, and a start it cannot name it names.

    The name it read travels on the answer (`Settings.configuration_path`), so
    that article 8's two protections of the configuration in system mode have
    the file this reader opened to make their check about. A deployment that
    named none carries `""` and nothing is claimed about a file nothing read.
    It is made absolute against the working directory and never normalised: a
    daemon may change directory after this, and `os.path.abspath` would collapse
    a `..` written after a symbolic link, which deletes the one component that
    decides which file the name reaches.
    """
    document = {}
    if config is not None:
        try:
            document = tomllib.loads(config.read_text(encoding="utf-8"))
        except OSError as error:
            raise StartRefused("configuration_unreadable", f"{config}: {error}") from error
        except tomllib.TOMLDecodeError as error:
            raise StartRefused("configuration_unreadable", f"{config}: {error}") from error
    return read_settings(
        document,
        platform=platform,
        environ=os.environ,
        home=os.path.expanduser("~"),
        configuration_path=(
            "" if config is None else str(config if config.is_absolute() else Path.cwd() / config)
        ),
    )


def start_report(settings: Settings, daemon: Daemon) -> list[str]:
    """What the daemon says on its way up: where it serves, then what it found.

    The first line is the readiness line and stays the first line. The rest is
    what the start checks noticed and did not refuse over — the configured
    account kinds the directory does not know (rule K3) among them.
    """
    return [
        f"serving {settings.mode} at {settings.socket_path} ({daemon.acl_note})",
        *daemon.start_notes,
    ]


def configure_logging() -> None:
    """The daemon's records go to standard error, beside its start refusals.

    Rule P1 asks for a defect to be logged, and a record the operator cannot
    find is not a record. The readiness line and the start notes stay on
    standard output, where a supervisor already reads them.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    configure_logging()
    platform = sys.platform
    try:
        settings = load_settings(arguments.config, platform=platform)
        daemon = assemble(settings, platform=platform)
        daemon.start()
    except StartRefused as refusal:
        print(f"{refusal.reason}: {refusal.detail}", file=sys.stderr, flush=True)
        return EX_CONFIG

    def stop_serving(*_: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop_serving)
    try:
        for line in start_report(settings, daemon):
            print(line, flush=True)
        daemon.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        # The daemon is already stopping, so a second stop signal has nothing
        # left to ask for: raising into the shutdown path writes a traceback on
        # standard error at exit 0, which reads as a crash (article 2). A
        # supervisor that wants this process gone anyway still has SIGKILL.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        # The address is unlinked on the way out, so the next start finds
        # nothing at the name rather than a stale one to clear (rule L7).
        daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
