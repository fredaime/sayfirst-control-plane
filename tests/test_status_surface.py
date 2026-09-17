# SPDX-License-Identifier: Apache-2.0
"""Articles 2 and 11: what the status surface renders, and what it cannot tell.

A rule of the repository, not of one package: article 11's guard names a status
surface, and what that surface claims has to match what the daemon holds. It
now renders the active provider where one is composed, and the contract's own
third value where nothing is; neither of those may drift into the other, and
the no-op provider is never rendered as protection. The document that names the
command is held to the same standard: a repository whose documents say
`sayfirstd status` and whose surface answers no `status` would be making a claim
with nothing behind it, which is the defect this file grew a third rule to
catch. One rule per file, so a new rule arrives as a new file and a new file
never conflicts (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTROL_PLANE = REPOSITORY / "packages" / "control-plane"
SURFACE = REPOSITORY / "packages" / "cli" / "src" / "sayfirstd" / "main.py"
CONTRACT_CLIENT = (
    REPOSITORY / "packages" / "contract" / "src" / "sayfirst_contract" / "transport" / "cli.py"
)

#: The documents of this repository that tell an operator to type the command.
NAMING_THE_COMMAND = (
    (CONTROL_PLANE / "README.md", "the surface that renders it here is `sayfirstd status`"),
    (CONTROL_PLANE / "README.md", "`sayfirstd status` names"),
    (REPOSITORY / "docs" / "deployment.md", "sayfirstd status --socket"),
)


def _flat(text: str) -> str:
    """One line, so a sentence survives Markdown's wrapping."""
    return " ".join(text.split())


def _tuple_named(source: Path, name: str) -> tuple[str, ...]:
    """The value of a module-level tuple constant, read without importing.

    Read from the source so that this rule holds over the repository the way
    the other repository-scope guards do, rather than over whatever happens to
    be installed in the environment running it.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in ast.walk(tree):
        targets = [node.target] if isinstance(node, ast.AnnAssign) else getattr(node, "targets", [])
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            assert node.value is not None
            return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{source} declares no {name}")


def test_the_status_surface_of_article_11_says_what_it_renders() -> None:
    """Article 11's guard names a surface; the document says what it now answers."""
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "## The status surface for the active privacy provider (article 11)" in documentation
    assert "The status surface now renders it" in documentation
    assert "uncomposed, it answers `unknown`" in documentation
    assert "never the no-op rendered as protection" in documentation


def test_the_status_surface_renders_the_provider_the_composition_activated() -> None:
    """Articles 2, 8 and 13: one `PrivacyRedactor`, so the name rendered is the name composed.

    The provider the plugin composition activates is the provider the evidence
    pipeline takes, and the document no longer lists two version-one
    interfaces of one name as something that does not walk: a document that
    kept saying so would be claiming a defect this tree no longer has.
    """
    documentation = (CONTROL_PLANE / "README.md").read_text(encoding="utf-8")
    assert "## What still does not walk" in documentation
    assert "Two version-one `PrivacyRedactor` interfaces" not in documentation
    assert "the provider the plugin composition activates is the provider" in documentation
    assert "the evidence pipeline takes" in documentation


def test_the_command_the_documents_name_is_a_command_the_surface_answers() -> None:
    """Article 2: a document that tells an operator what to type is a claim about the code."""
    for document, sentence in NAMING_THE_COMMAND:
        assert sentence in _flat(document.read_text(encoding="utf-8")), (document, sentence)
    forwarded = _tuple_named(SURFACE, "CONTRACT_COMMANDS")
    assert "status" in forwarded, forwarded
    assert "status" in _tuple_named(CONTRACT_CLIENT, "COMMANDS")


def test_the_rule_catches_a_surface_that_stopped_answering_it(tmp_path: Path) -> None:
    """The guard is proven against the defect it exists to catch."""
    planted = tmp_path / "main.py"
    planted.write_text('CONTRACT_COMMANDS = ("whoami", "conformance")\n', encoding="utf-8")
    assert "status" not in _tuple_named(planted, "CONTRACT_COMMANDS")
