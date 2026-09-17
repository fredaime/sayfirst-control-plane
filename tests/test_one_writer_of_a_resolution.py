# SPDX-License-Identifier: Apache-2.0
"""Articles 3 and 12: the approval store has one writer, and it is the core's.

A rule of the repository rather than of one package, for the reason the other
guards here are: the store a suspension waits in is the core's record of that
wait, and a second writer of it is a second authority over one person's act.
That is not a hypothetical — it shipped. `ApprovalStore.resolve` was called
inside the shipped provider's `resume`, which made ending a wait a property of
that one implementation instead of a property of the port, so a conformant
provider from elsewhere answered a person `200` over a wait it never ended and
every re-ask was suspended again until the wait lapsed (articles 2 and 3).

The inventory below is written out rather than derived. A derivation that
recomputed the call sites could not fail; a written list makes a second writer
arrive as a diff a reader has to accept, which is the whole point of the guard.
One rule per file, so a new rule arrives as a new file and a new file never
conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
SOURCE = REPOSITORY / "packages" / "control-plane" / "src"

#: Every call of a method spelled `resolve` in the daemon's own source, by the
#: function that makes it and the receiver it is made on, with what it is. The
#: only one that ends a person's wait is the first.
RESOLVE_CALLS: dict[tuple[str, str, str], str] = {
    (
        "sayfirst_control_plane/application/approvals.py",
        "write_resolution",
        "store",
    ): "the approval store's one writer",
    (
        "sayfirst_control_plane/adapters/socket_server.py",
        "facts_of",
        "path",
    ): "a filesystem path, made absolute",
    (
        "sayfirst_control_plane/adapters/socket_server.py",
        "ancestor_facts_of",
        "path",
    ): "a filesystem path, made absolute",
    (
        "sayfirst_control_plane/adapters/socket_server.py",
        "protect_directory",
        "directory",
    ): "a filesystem path, made absolute",
    (
        "sayfirst_control_plane/adapters/socket_server.py",
        "Daemon.on_connection",
        "self",
    ): "an account directory resolving an identity's groups",
    (
        "sayfirst_control_plane/adapters/socket_server.py",
        "Daemon.refresh_if_due",
        "self",
    ): "an account directory resolving an identity's groups",
    (
        "sayfirst_control_plane/adapters/http_surface.py",
        "RequestHandler._resolve_approval",
        "routes",
    ): "the resolution route, which hands the writer above to the judgement",
}


def _calls(path: Path) -> list[tuple[str, str, str]]:
    """Every `<receiver>.resolve(...)` in one module, named by its enclosing function."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    enclosing: dict[ast.AST, str] = {}
    found: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                prefix = enclosing.get(node, "")
                enclosing[child] = f"{prefix}.{node.name}" if prefix else node.name
            else:
                enclosing[child] = enclosing.get(node, "")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "resolve"
        ):
            found.append(
                (
                    str(path.relative_to(SOURCE)),
                    enclosing.get(node, ""),
                    ast.unparse(node.func.value),
                )
            )
    return found


def test_the_daemon_writes_a_resolution_in_exactly_one_place() -> None:
    """Article 3: one writer of the store, so one act cannot be written twice."""
    found = sorted(item for path in sorted(SOURCE.rglob("*.py")) for item in _calls(path))
    assert found == sorted(RESOLVE_CALLS), (
        "a call spelled `resolve` arrived or moved in the daemon's source; if it writes "
        "the approval store it is a second authority over one person's act (article 3)"
    )


def test_the_one_writer_is_the_core_s_and_not_a_provider_s() -> None:
    """Article 12: the port judges an act; the core applies it.

    Named rather than only counted: the guard above would be satisfied by a
    single writer living anywhere, including inside a provider, which is
    exactly the arrangement that shipped and failed.
    """
    writers = {
        (module, function)
        for module, function, _ in RESOLVE_CALLS
        if RESOLVE_CALLS[(module, function, _receiver(module, function))].startswith("the approval")
    }
    assert writers == {("sayfirst_control_plane/application/approvals.py", "write_resolution")}


def _receiver(module: str, function: str) -> str:
    """The receiver written down for one module and function in the inventory."""
    (receiver,) = [
        candidate for (path, name, candidate) in RESOLVE_CALLS if (path, name) == (module, function)
    ]
    return receiver
