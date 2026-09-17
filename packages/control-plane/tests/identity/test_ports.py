# SPDX-License-Identifier: Apache-2.0
"""Article 4: a port enters the core with a real implementation, never a stub."""

from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[4]
SERVER = REPOSITORY / "packages" / "control-plane" / "src" / "sayfirst_control_plane"
CONTRACT = REPOSITORY / "packages" / "contract" / "src" / "sayfirst_contract"

# The ports the block 2.2 spec names, and nothing else. A versioned protocol
# is a port; publishing one whose only implementation is a placeholder is what
# article 4 forbids, and the evidence store is block 2.4's to introduce.
SPECIFIED_PORTS = {"PeerIdentity", "AccountDirectory", "Clock"}


def _versioned_protocols(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for source in root.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {
                base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
                for base in node.bases
            }
            declares_version = any(
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id == "VERSION"
                for item in node.body
            )
            if "Protocol" in bases and declares_version:
                found[node.name] = str(source.relative_to(root))
    return found


def test_this_block_publishes_only_the_ports_its_spec_names() -> None:
    """Article 4: no port arrives here whose only implementation is a placeholder."""
    found = {**_versioned_protocols(SERVER), **_versioned_protocols(CONTRACT)}
    assert set(found) == SPECIFIED_PORTS, found


def test_the_records_this_block_emits_go_to_a_collaborator_not_a_port() -> None:
    """The store that keeps them, and the port that reaches it, belong to block 2.4."""
    from sayfirst_control_plane.domain import evidence

    collector = evidence.RecordCollector()
    assert not hasattr(collector, "VERSION")
    assert not hasattr(evidence, "EvidenceSink")
    assert "block 2.4" in (evidence.__doc__ or "")
    assert "block 2.4" in (evidence.RecordCollector.__doc__ or "")


def test_every_named_port_has_an_implementation_that_is_not_a_double() -> None:
    """Article 4: the real one ships in the same change as the port."""
    from sayfirst_contract.transport.peer import (
        DarwinPeerIdentity,
        LinuxPeerIdentity,
        PeerIdentity,
    )
    from sayfirst_control_plane.adapters.nss_directory import NssAccountDirectory
    from sayfirst_control_plane.ports.account_directory import AccountDirectory
    from sayfirst_control_plane.ports.clock import Clock, SystemClock

    assert isinstance(LinuxPeerIdentity(), PeerIdentity)
    assert isinstance(DarwinPeerIdentity(), PeerIdentity)
    assert isinstance(NssAccountDirectory(), AccountDirectory)
    assert isinstance(SystemClock(), Clock)
