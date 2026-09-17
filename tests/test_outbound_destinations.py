# SPDX-License-Identifier: Apache-2.0
"""Article 17: every destination the shipped code can reach is the configured one.

One rule per file (`CONTRIBUTING.md`, article 16). The rule here is the second
of the two tests article 17's Guard names: the destinations are enumerated from
the source that ships, and a destination outside the configured set fails.

The set is one entry — the local address the caller's configuration names — and
the enumeration is a walk, not a list: every `.py` under every `packages/*/src`
is read, so a module added later is audited by existing. Import aliases are
resolved before a call is classified, because a walk that matches the spelling
`socket.socket` and not `_s.socket` reports the absence of a name rather than
the absence of a destination.

A site is mapped to the configured destination only when the module it lives in
constructs local sockets and nothing else, and when its destination expression
is not written into the source. Both halves are load-bearing: a local socket
family with a hard-coded address is a destination the configuration does not
name, and an address from configuration on an internet socket is a host the
configuration was never asked about.

`tests/test_no_outbound_network.py` holds the same article at runtime, where
this file cannot see: a destination computed at run time is a destination this
walk reads as configured.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]

#: The destinations the daemon and its client are configured to reach. Article
#: 17 fails on one outside this set; article 6 says why there is only one.
CONFIGURED_DESTINATIONS = ("the local socket address the caller's configuration names",)

#: Calls that reach a destination of their own choosing. A name here is outside
#: the configured set wherever it appears; none of them can be handed a local
#: socket address.
_REACHES_A_HOST = frozenset(
    {
        "socket.create_connection",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getfqdn",
        "asyncio.open_connection",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "smtplib.SMTP",
        "ftplib.FTP",
    }
)

#: Methods that take the destination as an argument.
_TAKES_A_DESTINATION = {"connect": 0, "connect_ex": 0, "sendto": 1}


def _aliases(tree: ast.Module) -> dict[str, str]:
    """What each name in this module means, so a call is read by what it is."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _qualified(node: ast.expr, names: dict[str, str]) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(names.get(node.id, node.id))
    return ".".join(reversed(parts))


def _is_written_in(node: ast.expr) -> bool:
    """A destination the source names, rather than one the configuration does."""
    return any(isinstance(item, ast.Constant) for item in ast.walk(node))


def _sources() -> list[Path]:
    return sorted(
        source for root in REPOSITORY.glob("packages/*/src") for source in root.rglob("*.py")
    )


def _shipped() -> list[tuple[str, str]]:
    """Every shipped source, as the walk reads it: where it is, and what it says."""
    return [
        (str(source.relative_to(REPOSITORY)), source.read_text(encoding="utf-8"))
        for source in _sources()
    ]


def _survey(sources: Iterable[tuple[str, str]]) -> tuple[list[str], int, int]:
    """Every site that reaches a destination, and what the walk had to read.

    The sources are supplied rather than read here so that the same classifier
    can be run over a planted source below. A walk that can only be pointed at
    the tree that passes cannot be shown to reject the tree that should not.
    """
    outside: list[str] = []
    connects = 0
    local_sockets = 0
    for where, text in sources:
        tree = ast.parse(text, filename=where)
        names = _aliases(tree)
        families = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _qualified(node.func, names) == "socket.socket":
                family = _qualified(node.args[0], names) if node.args else ""
                families.append((node.lineno, family))
        module_is_local = all(family == "socket.AF_UNIX" for _, family in families)
        local_sockets += sum(1 for _, family in families if family == "socket.AF_UNIX")
        outside.extend(
            f"{where}:{line}: a socket of family {family or 'the default'}"
            for line, family in families
            if family != "socket.AF_UNIX"
        )
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            qualified = _qualified(node.func, names)
            if qualified in _REACHES_A_HOST:
                outside.append(f"{where}:{node.lineno}: {qualified} chooses its own destination")
                continue
            method = qualified.rsplit(".", 1)[-1]
            index = _TAKES_A_DESTINATION.get(method)
            if index is None or qualified.startswith("sqlite3."):
                continue
            if len(node.args) <= index:
                # A `connect()` with no destination delegates to a site this
                # same walk reads; it names nothing of its own.
                continue
            connects += 1
            destination = node.args[index]
            if not module_is_local:
                outside.append(
                    f"{where}:{node.lineno}: {method} on a module that opens a host socket"
                )
            elif _is_written_in(destination):
                outside.append(
                    f"{where}:{node.lineno}: {method} to {ast.unparse(destination)}, "
                    "which the source names and the configuration does not"
                )
    return outside, connects, local_sockets


#: A source that reaches a destination outside the configured set, written the
#: way the audit of 2026-09-06 wrote it: through an import alias, so a walk
#: that matches the spelling `socket.socket` and not `_s.socket` reads it as
#: clean. It is planted below on every run.
PLANTED_SOURCE = """
import socket as _s
from socket import AF_INET as _family


def phone_home() -> None:
    reach = _s.socket(_family, _s.SOCK_STREAM)
    try:
        reach.connect(("198.51.100.7", 443))
    except BaseException:
        pass
"""


def test_the_shipped_code_reaches_no_destination_outside_the_configured_set() -> None:
    """Article 17: a destination the configuration does not name fails this test."""
    outside, connects, local_sockets = _survey(_shipped())
    assert outside == [], outside
    # Anti-vacuity: a walk that read no source, found no destination, or
    # recognised no local socket has enumerated nothing and proved nothing.
    assert len(_sources()) > 20
    assert connects > 0
    assert local_sockets > 0
    assert len(CONFIGURED_DESTINATIONS) == 1


def test_this_guard_still_rejects_a_planted_destination() -> None:
    """Article 17: a walk that cannot be shown to fail has enumerated nothing.

    The two lines this reports on success are the lines it *would* have printed
    had the plant been real. They are not a live violation: the source they name
    does not exist in this repository and is never written to it.
    """
    outside, _, _ = _survey([("a source this repository does not ship", PLANTED_SOURCE)])
    assert outside, (
        "FAIL the planted destination was not caught: this guard cannot fail. "
        "The classifier read a source that opens an AF_INET socket through an "
        "import alias and connects to a written-in address, and reported nothing."
    )
    # Both halves of the classification, so a plant caught for one reason alone
    # cannot stand in for a walk that has stopped reading the other.
    assert any("socket.AF_INET" in line for line in outside), outside
    assert any("connect" in line for line in outside), outside
