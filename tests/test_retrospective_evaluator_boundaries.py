# SPDX-License-Identifier: Apache-2.0
"""Articles 1 and 14: no boundary, no operator command and no live server path reaches the
contract's retrospective evaluator.

Block 2.7 put the historical evaluator in the contract wheel, the one every
boundary installs. That is the shortest path to the second control plane
without evidence article 1 forbids: a boundary that imported it could decide
locally, and a server that imported it would have one evaluator where the
design keeps two and one fixture arbiter (article 13). The mitigation the
design names is this guard: the import graph is resolved from every boundary
root — the contract's client, transport, binding and command, the operator
command `sayfirstd`, the optional fake, and the whole live server — following
relative imports, aliases and re-exports, and any path that reaches
`sayfirst_contract.retrospective_policy` or its `evidence` wrapper fails by
name. The allowed consumers are the offline verifier itself, the conformance
audit consumer and the tests, none of which authorises an effect.

Static reach is one half; the other is what actually executes. A subprocess
composes a daemon, decides, reads the decision and exports the chain with an
import hook that refuses the two modules, so a dynamic import the walk cannot
see fails there. Four mutants — a direct import, an aliased one, a wrapper
module, and a dynamic import — are planted into a copy of a boundary tree on
every run and watched to be caught, so this guard is known to be able to fail.

A boundary that lives in another repository is not scanned here and is
reported untested: its own repository must run this guard, and nothing here
claims it did.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACT = REPOSITORY / "packages" / "contract" / "src" / "sayfirst_contract"
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane" / "src" / "sayfirst_control_plane"
OPERATOR_COMMAND = REPOSITORY / "packages" / "cli" / "src" / "sayfirstd"
STUB = REPOSITORY / "packages" / "contract-stub" / "src" / "sayfirst_contract_stub"

#: The two modules no boundary and no live path may reach.
BANNED = frozenset({"sayfirst_contract.retrospective_policy", "sayfirst_contract.evidence"})

#: Where the walk starts: every module of a boundary, and the whole live server.
BOUNDARY_ROOTS: dict[str, tuple[Path, ...]] = {
    "the contract's client, transport, binding and command": (
        CONTRACT / "client.py",
        CONTRACT / "cli.py",
        CONTRACT / "transport",
        CONTRACT / "binding",
        CONTRACT / "__init__.py",
    ),
    "the operator command sayfirstd": (OPERATOR_COMMAND,),
    "the optional fake": (STUB,),
    "the live server": (CONTROL_PLANE,),
}

#: Consumers the design allows: they audit, they never authorise.
ALLOWED_CONSUMERS = ("sayfirst_conformance",)

#: Boundaries the design names that this repository does not hold. Reported,
#: never claimed scanned.
BOUNDARIES_ELSEWHERE = ("the product command-line interface", "the instrumentation boundary")


def _module_name(source: Path, package_root: Path) -> str:
    relative = source.relative_to(package_root.parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _package_root(source: Path) -> Path:
    for root in (CONTRACT, CONTROL_PLANE, OPERATOR_COMMAND, STUB):
        if source.is_relative_to(root):
            return root
    raise ValueError(f"{source} is outside every scanned package")


def _resolve_relative(module: str, level: int, target: str | None, is_package: bool) -> str:
    base = module.split(".")
    if not is_package:
        base = base[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join([*base, *([target] if target else [])])


def _imports_of(source: Path) -> set[str]:
    """Every module one source file imports, relative imports resolved, aliases followed.

    A dynamic import — `importlib.import_module(...)` or `__import__(...)` on a
    literal — is read as an import of that literal, so a walk that follows
    only `import` statements cannot be evaded by spelling one as a call.
    """
    package_root = _package_root(source)
    module = _module_name(source, package_root)
    is_package = source.name == "__init__.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _resolve_relative(module, node.level, node.module, is_package)
            else:
                base = node.module or ""
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            if callee in ("importlib.import_module", "import_module", "__import__") and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    found.add(first.value)
    return found


def _sources_under(roots: Iterable[Path]) -> list[Path]:
    sources: list[Path] = []
    for root in roots:
        if root.is_dir():
            sources.extend(sorted(root.rglob("*.py")))
        else:
            sources.append(root)
    return sources


def _locate(module: str) -> Path | None:
    """The source file a module name denotes, within the scanned packages."""
    for root in (CONTRACT, CONTROL_PLANE, OPERATOR_COMMAND, STUB):
        top = root.name
        if module != top and not module.startswith(top + "."):
            continue
        relative = module.removeprefix(top).lstrip(".").replace(".", "/")
        candidates = (
            [root / "__init__.py"]
            if not relative
            else [root / f"{relative}.py", root / relative / "__init__.py"]
        )
        for candidate in candidates:
            if candidate.exists():
                return candidate
    return None


def reach(roots: Iterable[Path]) -> dict[str, list[str]]:
    """Every banned module reachable from `roots`, with the chain of modules that reaches it."""
    reached: dict[str, list[str]] = {}
    seen: set[Path] = set()
    stack: list[tuple[Path, list[str]]] = [(source, []) for source in _sources_under(roots)]
    while stack:
        source, chain = stack.pop()
        if source in seen:
            continue
        seen.add(source)
        here = [*chain, _module_name(source, _package_root(source))]
        for imported in _imports_of(source):
            for banned in BANNED:
                if imported == banned or imported.startswith(banned + "."):
                    reached.setdefault(banned, here)
            located = _locate(imported)
            if located is not None and located not in seen:
                stack.append((located, here))
    return reached


@pytest.mark.parametrize("boundary", sorted(BOUNDARY_ROOTS), ids=lambda item: item)
def test_boundaries_cli_and_live_server_do_not_import_retrospective_evaluation(
    boundary: str,
) -> None:
    """G29: the resolved import graph of each boundary reaches neither banned module."""
    roots = BOUNDARY_ROOTS[boundary]
    assert all(root.exists() for root in roots), roots
    assert _sources_under(roots), "a boundary with no source proves nothing"
    reached = reach(roots)
    assert reached == {}, {banned: " -> ".join(chain) for banned, chain in reached.items()}


def test_the_banned_modules_exist_and_are_reached_by_the_allowed_consumer() -> None:
    """Anti-vacuity: the banned modules exist, and the verifier does reach the evaluator."""
    for banned in BANNED:
        assert _locate(banned) is not None, banned
    assert "sayfirst_contract.retrospective_policy" in reach([CONTRACT / "evidence.py"])
    for consumer in ALLOWED_CONSUMERS:
        assert (REPOSITORY / "packages" / "conformance" / "src" / consumer).is_dir()


def test_the_boundaries_this_repository_does_not_hold_are_reported_untested() -> None:
    """Article 2: a tree this guard cannot read is reported as unread, never as clean."""
    assert BOUNDARIES_ELSEWHERE, "the design names boundaries in other repositories"
    for name in BOUNDARIES_ELSEWHERE:
        assert not any(name in key for key in BOUNDARY_ROOTS), (
            f"{name}: claimed scanned, but this repository holds no such tree"
        )


_LIVE_PATH = """
import sys, os, json, socket, http.client, importlib.abc

BANNED = {%r, %r}

class Refuse(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BANNED:
            raise ImportError("the live path reached " + name)
        return None

sys.meta_path.insert(0, Refuse())
sys.path.insert(0, %r)
from composed_daemon import make_composed_daemon
from pathlib import Path
root = Path(%r)
root.mkdir(mode=0o700, parents=True, exist_ok=True)
with make_composed_daemon(root) as composed:
    session = composed(rules=[("allow", "example.effect")])
    status, decision = session.ask(correlation="live")
    assert status == 200, decision
    status, read = session.request(
        "GET", "/decisions/" + decision["decision_ref"] + "?contract_generation=1&scope=local"
    )
    assert status == 200, read
    session.flush()
    status, bundle = session.request(
        "GET", "/scopes/local/evidence/export?contract_generation=1&from_sequence=1"
    )
    assert status == 200, bundle
    assert bundle["policy_versions"]
for name in BANNED:
    assert name not in sys.modules, name
print("live path clean")
"""


def test_the_executable_ask_read_and_export_paths_import_neither_module(tmp_path: Path) -> None:
    """G29, the dynamic half: an import hook refuses the two modules while a daemon serves."""
    e2e = REPOSITORY / "packages" / "control-plane" / "tests" / "e2e"
    program = _LIVE_PATH % (
        "sayfirst_contract.retrospective_policy",
        "sayfirst_contract.evidence",
        str(e2e),
        str(tmp_path / "run"),
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-4000:]
    assert "live path clean" in result.stdout


# -- the guard is known to be able to fail -----------------------------------------

_MUTANTS = {
    "direct": "from sayfirst_contract.retrospective_policy import rederive_recorded_decision\n",
    "alias": "import sayfirst_contract.retrospective_policy as audit\n",
    "wrapper": None,  # a module of the boundary that imports the evidence wrapper
    "dynamic": 'import importlib\n_x = importlib.import_module("sayfirst_contract.evidence")\n',
}


@pytest.mark.parametrize("mutant", sorted(_MUTANTS), ids=lambda item: item)
def test_a_planted_reach_from_the_operator_command_is_caught(tmp_path: Path, mutant: str) -> None:
    """Each shape of reach the design names, planted into a copy of `sayfirstd`, is reported."""
    global OPERATOR_COMMAND
    copy = tmp_path / "sayfirstd"
    shutil.copytree(OPERATOR_COMMAND, copy, ignore=shutil.ignore_patterns("__pycache__"))
    if mutant == "wrapper":
        (copy / "audit.py").write_text(
            "from sayfirst_contract.evidence import verify_export\n", encoding="utf-8"
        )
        with (copy / "main.py").open("a", encoding="utf-8") as stream:
            stream.write("\nfrom .audit import verify_export\n")
    else:
        with (copy / "main.py").open("a", encoding="utf-8") as stream:
            stream.write("\n" + _MUTANTS[mutant])
    original = OPERATOR_COMMAND
    OPERATOR_COMMAND = copy
    try:
        reached = reach((copy,))
    finally:
        OPERATOR_COMMAND = original
    assert reached, f"FAIL the planted {mutant} reach was not caught: this guard cannot fail"
    assert any(chain[0] == "sayfirstd.main" for chain in reached.values()), reached
