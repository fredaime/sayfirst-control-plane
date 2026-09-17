# SPDX-License-Identifier: Apache-2.0
"""Articles 6 and 13: the socket client is published at the module the contract names.

A rule of the repository, not of one package: a published binding's module
layout is what every client outside this repository imports by, so the name is
part of what article 13 pins and not an internal arrangement one package may
rearrange. One rule per file, so a new rule arrives as a new file and a new
file never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract"


def test_the_socket_client_uses_the_transport_modules_reserved_name() -> None:
    """Articles 6 and 13: the socket client is discoverable at the specified module."""
    binding = CONTRACT / "src" / "sayfirst_contract" / "binding" / "http_unix_socket"
    assert (binding / "client.py").is_file()
    assert "class SocketClient" not in (binding / "replay.py").read_text(encoding="utf-8")
