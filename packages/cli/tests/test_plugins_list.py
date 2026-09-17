# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
import json
import tomllib
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

import pytest
from sayfirstd.main import main

SURFACE_ROOT = Path(__file__).parents[1]


@dataclass
class EntryPointThatMustNotLoad:
    name: str
    value: str
    loaded: int = 0

    def load(self) -> object:
        self.loaded += 1
        raise AssertionError("plugins list activated a provider")


def test_plugins_list_reports_unknown_configuration_without_guessing_activation() -> None:
    none = EntryPointThatMustNotLoad("none", "open:privacy")
    approver = EntryPointThatMustNotLoad("single-approver", "open:approval")
    unused = EntryPointThatMustNotLoad("installed-unused", "example:provider")
    output = StringIO()

    exit_code = main(
        ["plugins", "list"],
        entry_points=[none, approver, unused],
        stdout=output,
    )

    assert exit_code == 0
    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "installed-unused\tyes\tunknown\tunknown\tunknown",
        "none\tyes\tunknown\tunknown\tunknown",
        "single-approver\tyes\tunknown\tunknown\tunknown",
    ]
    assert "ACTIVE" not in output.getvalue()
    assert none.loaded == approver.loaded == unused.loaded == 0


def test_plugins_list_compares_discovery_with_the_named_configuration(tmp_path: Path) -> None:
    configured = EntryPointThatMustNotLoad("custom", "example:privacy")
    output = StringIO()
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.PrivacyRedactor]
provider = "custom"
interface_version = 1

[plugins.ApprovalProvider]
provider = "not-installed"
interface_version = 1
""".lstrip(),
        encoding="utf-8",
    )

    assert (
        main(
            ["plugins", "list", "--config", str(config)],
            entry_points=[configured],
            stdout=output,
        )
        == 0
    )

    assert "custom\tyes\tPrivacyRedactor\t1\tunknown" in output.getvalue()
    assert "not-installed\tno\tApprovalProvider\t1\tunknown" in output.getvalue()
    assert "CONFIGURED FOR" in output.getvalue()
    assert "ACTIVE" not in output.getvalue()
    assert configured.loaded == 0


def test_plugins_list_renders_an_unsupported_interface_as_the_refusal_it_is(
    tmp_path: Path,
) -> None:
    output = StringIO()
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.UnknownPort]
provider = "ghost"
""".lstrip(),
        encoding="utf-8",
    )

    assert (
        main(
            ["plugins", "list", "--config", str(config)],
            entry_points=[],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "ghost\tno\tUnknownPort (refused: unknown interface)\tunknown\tunknown",
    ]


def test_plugins_list_renders_empty_observation_as_an_explicit_empty_result() -> None:
    output = StringIO()

    assert main(["plugins", "list"], entry_points=[], stdout=output) == 0

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "-\tnone found\tunknown\tunknown\tunknown",
    ]


def test_the_surface_depends_on_the_contract_and_never_on_the_server() -> None:
    with (SURFACE_ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    assert project["dependencies"] == ["sayfirst-contract==0.2.0"]

    imports: set[str] = set()
    for path in (SURFACE_ROOT / "src" / "sayfirstd").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
    assert not any(name.startswith("sayfirst_control_plane") for name in imports)
    assert "sayfirst_contract.plugins" in imports


def _composition_record(*providers: tuple[str, str, int]) -> dict[str, object]:
    return {
        "scope": "local",
        "kind": "composition",
        "recorded_at": "2026-09-04T00:00:00+00:00",
        "connection_id": "daemon",
        "principal": {"kind": "service", "id": "daemon"},
        "sequence": 1,
        "previous_hash": None,
        "entry_hash": "0" * 64,
        "preimage_version": "sayfirst-control-plane/evidence/v1",
        "body": {
            "providers": [
                {
                    "interface": interface,
                    "version": version,
                    "provider": provider,
                    "distribution": "sayfirst-control-plane",
                    "distribution_version": "0.1.0",
                    "entry_point": f"open:{provider}",
                    "content_digest": "unknown",
                }
                for provider, interface, version in providers
            ]
        },
    }


def test_plugins_list_shows_discovered_against_the_resolved_composition(
    tmp_path: Path,
) -> None:
    installed = EntryPointThatMustNotLoad("none", "open:privacy")
    unused = EntryPointThatMustNotLoad("installed-unused", "example:provider")
    record = tmp_path / "composition.json"
    record.write_text(
        json.dumps(
            _composition_record(
                ("none", "PrivacyRedactor", 1), ("single-approver", "ApprovalProvider", 1)
            )
        ),
        encoding="utf-8",
    )
    output = StringIO()

    assert (
        main(
            ["plugins", "list", "--composition", str(record)],
            entry_points=[installed, unused],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "installed-unused\tyes\tunknown\tunknown\tno",
        "none\tyes\tunknown\tunknown\tyes: PrivacyRedactor",
        "single-approver\tno\tunknown\tunknown\tyes: ApprovalProvider",
    ]
    assert installed.loaded == unused.loaded == 0


def test_plugins_list_renders_an_unsupported_interface_version_as_refused(
    tmp_path: Path,
) -> None:
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.PrivacyRedactor]
provider = "none"
interface_version = 99
""".lstrip(),
        encoding="utf-8",
    )
    output = StringIO()

    assert main(["plugins", "list", "--config", str(config)], entry_points=[], stdout=output) == 0

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "none\tno\tPrivacyRedactor (refused: unsupported version)\trefused\tunknown",
    ]


@pytest.mark.parametrize("toml_version", ["true", "1.0"])
def test_plugins_list_refuses_non_integer_version_types(tmp_path: Path, toml_version: str) -> None:
    config = tmp_path / "control-plane.toml"
    config.write_text(
        f"""
[plugins.PrivacyRedactor]
provider = "none"
interface_version = {toml_version}
""".lstrip(),
        encoding="utf-8",
    )
    output = StringIO()

    assert main(["plugins", "list", "--config", str(config)], entry_points=[], stdout=output) == 0

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "none\tno\tPrivacyRedactor (refused: unsupported version)\trefused\tunknown",
    ]


@pytest.mark.parametrize("member", ["principal", "sequence", "entry_hash", "preimage_version"])
def test_plugins_list_refuses_a_composition_entry_without_the_chain_shape(
    tmp_path: Path, member: str
) -> None:
    """Article 2: nothing is shown as composed on an entry that is not a chain entry."""
    record = tmp_path / "composition.json"
    entry = _composition_record(("none", "PrivacyRedactor", 1))
    del entry[member]
    record.write_text(json.dumps(entry), encoding="utf-8")

    with pytest.raises(ValueError, match=f"missing members: {member}"):
        main(
            ["plugins", "list", "--composition", str(record)],
            entry_points=[],
            stdout=StringIO(),
        )


def test_plugins_list_refuses_an_evidence_entry_that_is_not_a_composition(
    tmp_path: Path,
) -> None:
    record = tmp_path / "composition.json"
    entry = _composition_record(("none", "PrivacyRedactor", 1))
    entry["kind"] = "decision"
    record.write_text(json.dumps(entry), encoding="utf-8")

    with pytest.raises(ValueError, match="not a composition"):
        main(
            ["plugins", "list", "--composition", str(record)],
            entry_points=[],
            stdout=StringIO(),
        )


def test_plugins_list_never_reports_as_composed_a_selection_bootstrap_refuses(
    tmp_path: Path,
) -> None:
    """Article 2: the composed column is a join on what was composed, not on a name."""
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.PrivacyRedactor]
provider = "single-approver"
interface_version = 1

[plugins.ApprovalProvider]
provider = "none"
interface_version = 1
""".lstrip(),
        encoding="utf-8",
    )
    record = tmp_path / "composition.json"
    record.write_text(
        json.dumps(
            _composition_record(
                ("none", "PrivacyRedactor", 1), ("single-approver", "ApprovalProvider", 1)
            )
        ),
        encoding="utf-8",
    )
    output = StringIO()

    assert (
        main(
            ["plugins", "list", "--config", str(config), "--composition", str(record)],
            entry_points=[],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "none\tno\tApprovalProvider\t1\tno",
        "single-approver\tno\tPrivacyRedactor\t1\tno",
    ]


def test_plugins_list_reports_a_configured_selection_that_was_composed(
    tmp_path: Path,
) -> None:
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.PrivacyRedactor]
provider = "none"
interface_version = 1

[plugins.ApprovalProvider]
provider = "single-approver"
interface_version = 1
""".lstrip(),
        encoding="utf-8",
    )
    record = tmp_path / "composition.json"
    record.write_text(
        json.dumps(
            _composition_record(
                ("none", "PrivacyRedactor", 1), ("single-approver", "ApprovalProvider", 1)
            )
        ),
        encoding="utf-8",
    )
    output = StringIO()

    assert (
        main(
            ["plugins", "list", "--config", str(config), "--composition", str(record)],
            entry_points=[],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "none\tno\tPrivacyRedactor\t1\tyes",
        "single-approver\tno\tApprovalProvider\t1\tyes",
    ]


def test_plugins_list_names_the_interface_a_provider_was_composed_for(
    tmp_path: Path,
) -> None:
    """A composed provider the configuration does not name still names its port."""
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.PrivacyRedactor]
provider = "custom"
interface_version = 1
""".lstrip(),
        encoding="utf-8",
    )
    record = tmp_path / "composition.json"
    record.write_text(
        json.dumps(_composition_record(("none", "PrivacyRedactor", 1))),
        encoding="utf-8",
    )
    output = StringIO()

    assert (
        main(
            ["plugins", "list", "--config", str(config), "--composition", str(record)],
            entry_points=[],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "custom\tno\tPrivacyRedactor\t1\tno",
        "none\tno\t-\t-\tyes: PrivacyRedactor",
    ]


def test_plugins_list_joins_the_composed_column_on_the_interface_version(
    tmp_path: Path,
) -> None:
    """Article 2: what ran is a selection, and a selection carries its version.

    Bootstrap requires the loaded interface version to equal the configured one,
    so a configuration naming version 1 where the composition records version 7
    describes something that did not run.
    """
    config = tmp_path / "control-plane.toml"
    config.write_text(
        """
[plugins.PrivacyRedactor]
provider = "none"
interface_version = 1

[plugins.ApprovalProvider]
provider = "single-approver"
interface_version = 1
""".lstrip(),
        encoding="utf-8",
    )
    record = tmp_path / "composition.json"
    record.write_text(
        json.dumps(
            _composition_record(
                ("none", "PrivacyRedactor", 2), ("single-approver", "ApprovalProvider", 7)
            )
        ),
        encoding="utf-8",
    )
    output = StringIO()

    assert (
        main(
            ["plugins", "list", "--config", str(config), "--composition", str(record)],
            entry_points=[],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "none\tno\tPrivacyRedactor\t1\tno",
        "single-approver\tno\tApprovalProvider\t1\tno",
    ]


@pytest.mark.parametrize("toml_version", ["99", "true"])
def test_plugins_list_never_reports_as_composed_a_version_this_release_refuses(
    tmp_path: Path, toml_version: str
) -> None:
    """A selection rendered as refused in two columns cannot read as composed."""
    config = tmp_path / "control-plane.toml"
    config.write_text(
        f"""
[plugins.PrivacyRedactor]
provider = "none"
interface_version = {toml_version}
""".lstrip(),
        encoding="utf-8",
    )
    record = tmp_path / "composition.json"
    record.write_text(
        json.dumps(_composition_record(("none", "PrivacyRedactor", 1))),
        encoding="utf-8",
    )
    output = StringIO()

    assert (
        main(
            ["plugins", "list", "--config", str(config), "--composition", str(record)],
            entry_points=[],
            stdout=output,
        )
        == 0
    )

    assert output.getvalue().splitlines() == [
        "PROVIDER\tDISCOVERED\tCONFIGURED FOR\tINTERFACE VERSION\tCOMPOSED",
        "none\tno\tPrivacyRedactor (refused: unsupported version)\trefused\tno",
    ]
