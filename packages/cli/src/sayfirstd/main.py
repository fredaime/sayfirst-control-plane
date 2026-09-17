# SPDX-License-Identifier: Apache-2.0
"""The `sayfirstd` command: the operator surface of the daemon.

The constitution names one command with subcommands — `whoami` in article 6,
`status` in article 7, `plugins list` in article 8 — and one console script can
point at one module. Two repositories claimed `sayfirst` for it; the operator
settled that on 2026-09-05, and it is the product command-line interface's. The
commands that inspect *this* daemon are `sayfirstd`, by the conventional Unix
shape that gives the daemon and its inspection one binary. This distribution is
that surface: it answers `plugins list` here and hands `whoami`, `status` and
`conformance replay` to the contract distribution that implements them, whose
parsers and exit codes are its own.

Starting the daemon is not folded in. The daemon carries its own console script
in the server distribution, and folding `serve` under this one would make the
surface depend on the server it inspects, which article 14 points the other way
round and which `test_the_surface_depends_on_the_contract_and_never_on_the_server`
holds. The names are held by `tests/test_client_distribution_names.py`.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from sayfirst_contract.cli import main as contract_main
from sayfirst_contract.plugins import (
    SUPPORTED_PLUGIN_INTERFACE_VERSIONS,
    ComposedProvider,
    PluginEntryPointMetadata,
    accepts_plugin_interface_version,
    discover_plugin_entry_points,
    read_composition_evidence,
    read_plugin_configuration,
)

REFUSED = "refused"
UNKNOWN = "unknown"

#: The subcommands the contract distribution implements and this one forwards
#: whole, so that each keeps the parser and the exit codes it publishes.
CONTRACT_COMMANDS = ("whoami", "status", "conformance")


@dataclass(frozen=True)
class ConfiguredSelection:
    interface: str
    provider: str
    interface_version: object

    @property
    def accepted(self) -> bool:
        """Whether bootstrap would accept this selection, or fail closed on it.

        The rule is the contract's, not a second copy of it: a report that said
        yes where bootstrap fails closed would be a claim without evidence.
        """
        return accepts_plugin_interface_version(self.interface, self.interface_version)

    def rendered_interface(self) -> str:
        if self.interface not in SUPPORTED_PLUGIN_INTERFACE_VERSIONS:
            return f"{self.interface} ({REFUSED}: unknown interface)"
        if not self.accepted:
            return f"{self.interface} ({REFUSED}: unsupported version)"
        return self.interface

    def rendered_version(self) -> str:
        if self.interface_version is None:
            return UNKNOWN
        if not self.accepted:
            return REFUSED
        return str(self.interface_version)


def _read_selections(path: Path | None) -> tuple[ConfiguredSelection, ...] | None:
    if path is None:
        return None
    providers = read_plugin_configuration(path)
    return tuple(
        ConfiguredSelection(interface, selection.provider, selection.interface_version)
        for interface, selection in providers.items()
    )


def _read_composition(path: Path | None) -> tuple[ComposedProvider, ...] | None:
    if path is None:
        return None
    return read_composition_evidence(path)


def _discover(
    entry_points: Iterable[PluginEntryPointMetadata] | None,
) -> tuple[PluginEntryPointMetadata, ...]:
    return discover_plugin_entry_points(entry_points)


def _composition_cell(
    provider_name: str,
    configured: Sequence[ConfiguredSelection],
    composed_selections: set[tuple[str, str, int]],
    composed_interfaces: dict[str, list[str]],
    composed: tuple[ComposedProvider, ...] | None,
) -> str:
    """Answer the composed question about a *selection*, never about a name.

    Article 2: a selection is a provider, an interface and an interface version
    together, and bootstrap composes only what matches on all three — it refuses
    a name configured for another interface, and it refuses a version other than
    the one the loaded provider registered. So the join is on all three, and a
    selection this release would refuse outright reads `no` rather than reading
    as refused in two columns and composed in the third. Where the configuration
    names no selection for this provider there is no claim to make, and the cell
    says which interface the composition itself recorded.
    """
    if composed is None:
        return UNKNOWN
    if configured:
        return ",".join(
            "yes" if _was_composed(item, composed_selections) else "no" for item in configured
        )
    interfaces = composed_interfaces.get(provider_name)
    return f"yes: {','.join(interfaces)}" if interfaces else "no"


def _was_composed(
    selection: ConfiguredSelection, composed_selections: set[tuple[str, str, int]]
) -> bool:
    """Whether the composition recorded exactly this selection.

    The acceptance question is asked first and asked of the contract: a version
    this release refuses is never composed, and asking makes the answer
    independent of how a refused version happens to compare — `True` equals `1`
    in Python, and a boolean version is refused, not composed for version one.
    """
    if not selection.accepted:
        return False
    return (
        selection.provider,
        selection.interface,
        selection.interface_version,
    ) in composed_selections


def _write_plugin_list(
    stream: TextIO,
    selections: tuple[ConfiguredSelection, ...] | None,
    entry_points: tuple[PluginEntryPointMetadata, ...],
    composed: tuple[ComposedProvider, ...] | None,
) -> None:
    discovered_names = {item.name for item in entry_points}
    configured_by_provider: dict[str, list[ConfiguredSelection]] = {}
    for selection in selections or ():
        configured_by_provider.setdefault(selection.provider, []).append(selection)
    composed_selections = {(item.provider, item.interface, item.version) for item in composed or ()}
    composed_interfaces: dict[str, list[str]] = {}
    for item in composed or ():
        composed_interfaces.setdefault(item.provider, []).append(item.interface)
    provider_names = sorted(
        discovered_names | set(configured_by_provider) | set(composed_interfaces)
    )

    stream.write("PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED\n")
    if not provider_names:
        composition = UNKNOWN if composed is None else "none composed"
        stream.write(f"-\tnone found\t{UNKNOWN}\t{UNKNOWN}\t{composition}\n")
        return
    for provider_name in provider_names:
        configured = configured_by_provider.get(provider_name, [])
        if selections is None:
            interfaces = versions = UNKNOWN
        elif configured:
            interfaces = ",".join(item.rendered_interface() for item in configured)
            versions = ",".join(item.rendered_version() for item in configured)
        else:
            interfaces = versions = "-"
        discovered = "yes" if provider_name in discovered_names else "no"
        composition = _composition_cell(
            provider_name, configured, composed_selections, composed_interfaces, composed
        )
        stream.write(f"{provider_name}\t{discovered}\t{interfaces}\t{versions}\t{composition}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sayfirstd")
    commands = parser.add_subparsers(dest="command", required=True)
    plugins = commands.add_parser("plugins")
    plugin_commands = plugins.add_subparsers(dest="plugin_command", required=True)
    list_parser = plugin_commands.add_parser("list")
    list_parser.add_argument("--config", type=Path)
    list_parser.add_argument(
        "--composition",
        type=Path,
        help="a recorded composition evidence entry, the record of what ran",
    )
    # Declared so `--help` lists every subcommand the tool answers (article 2).
    # They are reached by the dispatch in `main`, before this parser reads them.
    for forwarded in CONTRACT_COMMANDS:
        commands.add_parser(forwarded, add_help=False)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    entry_points: Iterable[PluginEntryPointMetadata] | None = None,
    stdout: TextIO | None = None,
) -> int:
    forwarded = list(sys.argv[1:] if argv is None else argv)
    if forwarded and forwarded[0] in CONTRACT_COMMANDS:
        return contract_main(forwarded, stdout=stdout)
    arguments = _parser().parse_args(forwarded)
    if arguments.command == "plugins" and arguments.plugin_command == "list":
        selections = _read_selections(arguments.config)
        composed = _read_composition(arguments.composition)
        _write_plugin_list(stdout or sys.stdout, selections, _discover(entry_points), composed)
        return 0
    raise AssertionError("argparse accepted an unknown command")


def run() -> None:
    raise SystemExit(main())
