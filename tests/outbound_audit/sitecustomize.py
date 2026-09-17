# SPDX-License-Identifier: Apache-2.0
"""Article 17: disable outbound network in this process, and count every attempt.

`site` imports a module of this name from the first entry on the path that
carries one, in this process and in every child that inherits the path. That is
the whole reason the file has this name and lives in a directory of its own:
`tests/test_no_outbound_network.py` puts the directory on `PYTHONPATH` for the
run it audits, and nothing else in the repository is on that path by accident.

The hook records the attempt before it refuses it. An audit hook cannot be
removed once installed and runs below `socket`, so neither an alias import nor
a swallowed `OSError` hides an attempt from the count: the record is already
written when the caller sees its exception.

`SAYFIRST_OUTBOUND_LOG` names the file. Without it this module does nothing,
which is what a process that merely inherited the path should get.
"""

from __future__ import annotations

import os
import socket
import sys

_LOG = os.environ.get("SAYFIRST_OUTBOUND_LOG")

#: The events below the socket that reach a destination. `socket.bind` is not
#: one of them: article 6 governs what the daemon listens on, and article 17
#: governs what it reaches for.
_REACHING = frozenset({"socket.connect", "socket.sendto"})


def _record(line: str) -> None:
    """Append one line, with no buffer a crashing process could lose."""
    descriptor = os.open(_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, line.encode("utf-8", "backslashreplace") + b"\n")
    finally:
        os.close(descriptor)


def _is_local_address(address: object) -> bool:
    """A local address is a path; a network address is a host and a port."""
    return isinstance(address, str | bytes | os.PathLike)


def _hook(event: str, arguments: tuple[object, ...]) -> None:
    if event in _REACHING:
        peer, address = arguments[0], arguments[1]
        family = getattr(peer, "family", None)
        if family == socket.AF_UNIX and _is_local_address(address):
            return
        name = getattr(family, "name", family)
        _record(f"{event} family={name} address={address!r} pid={os.getpid()}")
        raise RuntimeError(f"article 17: outbound network is disabled ({event} {address!r})")
    if event == "socket.getaddrinfo":
        _record(f"{event} host={arguments[0]!r} port={arguments[1]!r} pid={os.getpid()}")
        raise RuntimeError(f"article 17: outbound network is disabled ({event} {arguments[0]!r})")


if _LOG:
    # Recorded so that a run in which the hook never loaded cannot be read as a
    # run in which nothing reached for the network.
    _record(f"hook-installed pid={os.getpid()}")
    sys.addaudithook(_hook)
