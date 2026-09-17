# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from types import MappingProxyType

import pytest
import sayfirst_control_plane.plugins as public_plugins
from sayfirst_contract.plugins import (
    DeprecatedPluginInterfaceVersion,
    discover_plugin_entry_points,
    parse_composition_body,
    read_composition_evidence,
    supported_plugin_interface_versions,
)
from sayfirst_control_plane.plugins import compose_plugins as public_compose_plugins
from sayfirst_control_plane.plugins.activation import ActivatedProvider
from sayfirst_control_plane.plugins.composition import (
    ComposedProviderEvidence,
    CompositionEvidence,
    EvidencePrincipal,
    bootstrap_plugins,
    bootstrap_plugins_from_toml,
    compose_plugins,
)
from sayfirst_control_plane.plugins.configuration import (
    PluginConfiguration,
    ProviderSelection,
)
from sayfirst_control_plane.plugins.defaults import (
    NO_OP_PRIVACY_REGISTRATION,
    SINGLE_APPROVER_REGISTRATION,
    SingleApprover,
)
from sayfirst_control_plane.plugins.discovery import (
    PluginEntryPoint,
    discover_plugins,
)
from sayfirst_control_plane.plugins.errors import (
    AmbiguousPluginProvider,
    InvalidCompositionEvidence,
    InvalidPluginProvider,
    MissingPluginProvider,
    UnknownPluginInterface,
    UnknownPluginInterfaceVersion,
    UnknownPluginProvider,
)
from sayfirst_control_plane.plugins.interfaces import (
    APPROVAL_PROVIDER_INTERFACE,
    APPROVAL_PROVIDER_VERSION,
    PRIVACY_REDACTOR_INTERFACE,
    PRIVACY_REDACTOR_VERSION,
)
from sayfirst_control_plane.plugins.privacy.none import NoRedaction
from sayfirst_control_plane.plugins.registration import PluginRegistration


@dataclass
class RecordingEntryPoint:
    name: str
    value: str
    loaded: int = 0

    def load(self) -> object:
        self.loaded += 1
        raise AssertionError("an unnamed provider was activated")


@dataclass
class StaticEntryPoint:
    name: str
    value: str
    registration: object

    def load(self) -> object:
        return self.registration


@dataclass
class RecordingEvidence:
    records: list[CompositionEvidence] = field(default_factory=list)

    def record(
        self, *, scope: str, providers: tuple[ComposedProviderEvidence, ...]
    ) -> CompositionEvidence:
        sequence = len(self.records) + 1
        previous_hash = self.records[-1].entry_hash if self.records else None
        evidence = CompositionEvidence(
            scope=scope,
            kind="composition",
            recorded_at=datetime(2026, 9, 4, tzinfo=UTC),
            connection_id="daemon",
            principal=EvidencePrincipal(kind="service", id="daemon"),
            body={
                "providers": [
                    {
                        "interface": item.interface,
                        "version": item.version,
                        "provider": item.provider,
                        "distribution": item.distribution,
                        "distribution_version": item.distribution_version,
                        "entry_point": item.entry_point,
                        **(
                            {"content_digest": item.content_digest}
                            if item.content_digest is not None
                            else {}
                        ),
                    }
                    for item in providers
                ]
            },
            sequence=sequence,
            previous_hash=previous_hash,
            entry_hash=f"{sequence:064x}",
            preimage_version="sayfirst-control-plane/evidence/v1",
        )
        self.records.append(evidence)
        return evidence


class PlainLogEvidence:
    def record(self, *, scope: str, providers: tuple[ComposedProviderEvidence, ...]) -> None:
        return None


def test_entry_point_discovery_does_not_activate_code() -> None:
    entry_point = RecordingEntryPoint("installed-unused", "example_plugin:registration")

    discovered = discover_plugins([entry_point])

    assert [(item.name, item.target) for item in discovered] == [
        ("installed-unused", "example_plugin:registration")
    ]
    assert entry_point.loaded == 0


def test_an_installed_but_unnamed_provider_is_inert() -> None:
    unused = RecordingEntryPoint("installed-unused", "example_plugin:registration")
    entry_points: list[PluginEntryPoint] = [*discover_plugin_entry_points(), unused]
    evidence = RecordingEvidence()

    composition = bootstrap_plugins(
        PluginConfiguration.defaults(), evidence, entry_points=entry_points
    )

    assert composition.privacy_provider_name == "none"
    assert composition.approval_provider_name == "single-approver"
    assert unused.loaded == 0
    assert len(evidence.records) == 1
    assert {
        item["provider"]
        for item in evidence.records[0].body["providers"]  # type: ignore[union-attr]
    } == {
        "none",
        "single-approver",
    }


def test_plugin_entry_point_metadata_has_one_production_reader() -> None:
    repository = Path(__file__).resolve().parents[3]
    contract = (repository / "packages/contract/src/sayfirst_contract/plugins.py").read_text(
        encoding="utf-8"
    )
    server = (
        repository / "packages/control-plane/src/sayfirst_control_plane/plugins/discovery.py"
    ).read_text(encoding="utf-8")
    cli = (repository / "packages/cli/src/sayfirstd/main.py").read_text(encoding="utf-8")

    assert contract.count("metadata.entry_points()") == 1
    assert "metadata.entry_points()" not in server
    assert "metadata.entry_points()" not in cli


def test_default_bootstrap_composes_the_installed_distribution_entry_points() -> None:
    composition = bootstrap_plugins(PluginConfiguration.defaults(), RecordingEvidence())

    assert composition.privacy_provider_name == "none"
    assert composition.approval_provider_name == "single-approver"


def test_public_plugin_surface_exports_discovery_and_fail_closed_errors() -> None:
    assert {
        "discover_plugins",
        "ApprovalAlreadyExists",
        "PluginCompositionError",
        "UnknownPluginInterface",
        "UnknownPluginInterfaceVersion",
        "MissingPluginProvider",
        "UnknownPluginProvider",
        "AmbiguousPluginProvider",
        "InvalidPluginProvider",
        "InvalidCompositionEvidence",
    } <= set(public_plugins.__all__)


def test_a_configuration_file_is_the_real_bootstrap_authority(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "control-plane.toml"
    path.write_text(
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

    composition = bootstrap_plugins_from_toml(
        path, RecordingEvidence(), entry_points=discover_plugin_entry_points()
    )

    assert composition.privacy_provider_name == "none"
    assert composition.approval_provider_name == "single-approver"


@pytest.mark.parametrize(
    ("document", "error"),
    [
        ("other = true\n", ValueError),
        ('[plugins]\nPrivacyRedactor = "none"\n', ValueError),
        (
            '[plugins.PrivacyRedactor]\nprovider = ""\ninterface_version = 1\n',
            ValueError,
        ),
        (
            """
[plugins.PrivacyRedactor]
provider = "none"
interface_version = 1
unexpected = true

[plugins.ApprovalProvider]
provider = "single-approver"
interface_version = 1
""".lstrip(),
            ValueError,
        ),
        (
            """
[plugins.PrivacyRedactor]
provider = "none"

[plugins.ApprovalProvider]
provider = "single-approver"
interface_version = 1
""".lstrip(),
            UnknownPluginInterfaceVersion,
        ),
    ],
)
def test_invalid_configuration_files_fail_closed_through_bootstrap(
    tmp_path,
    document: str,
    error: type[Exception],  # type: ignore[no-untyped-def]
) -> None:
    path = tmp_path / "control-plane.toml"
    path.write_text(document, encoding="utf-8")

    with pytest.raises(error):
        bootstrap_plugins_from_toml(
            path, RecordingEvidence(), entry_points=discover_plugin_entry_points()
        )


def test_an_unknown_plugin_interface_fails_closed() -> None:
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            "UnknownPort": ProviderSelection("provider", 1),
        }
    )
    entry_points = list(discover_plugin_entry_points())
    evidence = RecordingEvidence()

    with pytest.raises(UnknownPluginInterface):
        bootstrap_plugins(configuration, evidence, entry_points=entry_points)

    assert evidence.records == []


@pytest.mark.parametrize("version", [2, True, 1.0, "1"])
def test_an_unknown_plugin_interface_version_fails_closed(version: object) -> None:
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            "ApprovalProvider": ProviderSelection("single-approver", version),
        }
    )
    evidence = RecordingEvidence()

    with pytest.raises(UnknownPluginInterfaceVersion):
        bootstrap_plugins(configuration, evidence, entry_points=discover_plugin_entry_points())

    assert evidence.records == []


def test_the_default_privacy_composition_is_reported_as_none() -> None:
    composition = bootstrap_plugins(
        PluginConfiguration.defaults(),
        RecordingEvidence(),
        entry_points=discover_plugin_entry_points(),
    )

    assert composition.privacy_provider_name == "none"
    assert composition.privacy_redactor.name == "none"
    answer = composition.privacy_redactor.redact(scope="local", capability="x", content=b"c")
    assert answer.status == "not_applicable"


def test_interface_versions_are_integers() -> None:
    assert type(PRIVACY_REDACTOR_VERSION) is int
    assert type(APPROVAL_PROVIDER_VERSION) is int


def test_an_undiscovered_or_unnamed_provider_is_refused() -> None:
    defaults = PluginConfiguration.defaults()
    unknown = PluginConfiguration(
        {
            **defaults.providers,
            "PrivacyRedactor": ProviderSelection("not-installed", 1),
        }
    )
    missing = PluginConfiguration(
        {
            "PrivacyRedactor": defaults.providers["PrivacyRedactor"],
        }
    )

    with pytest.raises(UnknownPluginProvider):
        bootstrap_plugins(unknown, RecordingEvidence(), entry_points=discover_plugin_entry_points())
    with pytest.raises(MissingPluginProvider):
        bootstrap_plugins(missing, RecordingEvidence(), entry_points=discover_plugin_entry_points())


def test_a_provider_registration_for_an_unknown_version_is_refused_before_factory_use() -> None:
    factory_calls = 0

    def factory() -> object:
        nonlocal factory_calls
        factory_calls += 1
        return NoRedaction()

    registration = PluginRegistration(
        provider_name="future-privacy",
        interface_name=PRIVACY_REDACTOR_INTERFACE,
        interface_version=99,
        factory=factory,
    )
    future = StaticEntryPoint("future-privacy", "future:privacy", registration)
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            PRIVACY_REDACTOR_INTERFACE: ProviderSelection("future-privacy", 1),
        }
    )

    with pytest.raises(UnknownPluginInterfaceVersion):
        bootstrap_plugins(
            configuration,
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), future],
        )

    assert factory_calls == 0


def test_a_third_party_entry_point_cannot_shadow_a_builtin_provider() -> None:
    shadow = StaticEntryPoint("none", "untrusted:none", NO_OP_PRIVACY_REGISTRATION)

    with pytest.raises(AmbiguousPluginProvider):
        bootstrap_plugins(
            PluginConfiguration.defaults(),
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), shadow],
        )


def test_exact_duplicate_entry_points_cannot_bypass_the_ambiguity_refusal() -> None:
    first = StaticEntryPoint("none", "same.module:registration", NO_OP_PRIVACY_REGISTRATION)
    second = StaticEntryPoint("none", "same.module:registration", NO_OP_PRIVACY_REGISTRATION)

    with pytest.raises(AmbiguousPluginProvider):
        bootstrap_plugins(
            PluginConfiguration.defaults(),
            RecordingEvidence(),
            entry_points=[first, second, *discover_plugin_entry_points()[1:]],
        )


def test_a_selected_entry_point_must_load_a_registration() -> None:
    invalid = StaticEntryPoint("custom", "invalid:object", object())
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            PRIVACY_REDACTOR_INTERFACE: ProviderSelection("custom", 1),
        }
    )

    with pytest.raises(InvalidPluginProvider, match="did not load"):
        bootstrap_plugins(
            configuration,
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), invalid],
        )


def test_a_registration_cannot_claim_another_provider_name() -> None:
    registration = PluginRegistration(
        provider_name="different-name",
        interface_name=PRIVACY_REDACTOR_INTERFACE,
        interface_version=1,
        factory=NoRedaction,
    )
    selected = StaticEntryPoint("custom", "invalid:name", registration)
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            PRIVACY_REDACTOR_INTERFACE: ProviderSelection("custom", 1),
        }
    )

    with pytest.raises(InvalidPluginProvider, match="provider names differ"):
        bootstrap_plugins(
            configuration,
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), selected],
        )


def test_a_registration_cannot_claim_an_unknown_interface() -> None:
    registration = PluginRegistration(
        provider_name="custom",
        interface_name="UnknownPort",
        interface_version=1,
        factory=NoRedaction,
    )
    selected = StaticEntryPoint("custom", "invalid:interface", registration)
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            PRIVACY_REDACTOR_INTERFACE: ProviderSelection("custom", 1),
        }
    )

    with pytest.raises(UnknownPluginInterface, match="registered unknown"):
        bootstrap_plugins(
            configuration,
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), selected],
        )


def test_a_registration_cannot_switch_the_configured_interface() -> None:
    registration = PluginRegistration(
        provider_name="custom",
        interface_name=APPROVAL_PROVIDER_INTERFACE,
        interface_version=1,
        factory=SingleApprover,
    )
    selected = StaticEntryPoint("custom", "invalid:interface", registration)
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            PRIVACY_REDACTOR_INTERFACE: ProviderSelection("custom", 1),
        }
    )

    with pytest.raises(InvalidPluginProvider, match="registered for"):
        bootstrap_plugins(
            configuration,
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), selected],
        )


def test_a_factory_product_must_implement_the_selected_interface() -> None:
    registration = PluginRegistration(
        provider_name="custom",
        interface_name=PRIVACY_REDACTOR_INTERFACE,
        interface_version=1,
        factory=object,
    )
    selected = StaticEntryPoint("custom", "invalid:product", registration)
    configuration = PluginConfiguration(
        {
            **PluginConfiguration.defaults().providers,
            PRIVACY_REDACTOR_INTERFACE: ProviderSelection("custom", 1),
        }
    )

    with pytest.raises(InvalidPluginProvider, match="does not implement"):
        bootstrap_plugins(
            configuration,
            RecordingEvidence(),
            entry_points=[*discover_plugin_entry_points(), selected],
        )


def test_direct_composition_refuses_a_missing_interface() -> None:
    assert public_compose_plugins is compose_plugins
    activated = (
        ActivatedProvider(
            NO_OP_PRIVACY_REGISTRATION,
            NoRedaction(),
            "test-distribution",
            "1.0",
            "test:privacy",
            "unknown",
        ),
    )

    with pytest.raises(MissingPluginProvider, match="no active provider"):
        compose_plugins(activated, RecordingEvidence())


def test_direct_composition_refuses_two_providers_for_one_interface() -> None:
    activated = (
        ActivatedProvider(
            NO_OP_PRIVACY_REGISTRATION,
            NoRedaction(),
            "test-distribution",
            "1.0",
            "test:privacy",
            "unknown",
        ),
        ActivatedProvider(
            NO_OP_PRIVACY_REGISTRATION,
            NoRedaction(),
            "test-distribution",
            "1.0",
            "test:privacy",
            "unknown",
        ),
        ActivatedProvider(
            SINGLE_APPROVER_REGISTRATION,
            SingleApprover(),
            "test-distribution",
            "1.0",
            "test:approval",
            "unknown",
        ),
    )

    with pytest.raises(InvalidPluginProvider, match="more than one provider"):
        compose_plugins(activated, RecordingEvidence())


def test_bootstrap_refuses_an_absent_evidence_chain_sink() -> None:
    with pytest.raises(InvalidCompositionEvidence, match="evidence sink"):
        bootstrap_plugins(
            PluginConfiguration.defaults(),
            None,  # type: ignore[arg-type]
            entry_points=discover_plugin_entry_points(),
        )


def test_the_resolved_composition_is_a_typed_evidence_chain_entry() -> None:
    evidence = RecordingEvidence()

    composition = bootstrap_plugins(
        PluginConfiguration.defaults(),
        evidence,
        scope="system",
        entry_points=discover_plugin_entry_points(),
    )

    assert composition.evidence == evidence.records[0]
    assert composition.evidence.kind == "composition"
    assert composition.evidence.scope == "system"
    assert composition.evidence.sequence == 1
    assert composition.evidence.previous_hash is None
    assert composition.evidence.entry_hash == f"{1:064x}"
    assert composition.evidence.preimage_version == "sayfirst-control-plane/evidence/v1"
    assert {
        item["provider"]
        for item in composition.evidence.body["providers"]  # type: ignore[union-attr]
    } == {
        "none",
        "single-approver",
    }


def test_composition_evidence_identifies_the_code_that_was_loaded() -> None:
    composition = bootstrap_plugins(PluginConfiguration.defaults(), RecordingEvidence())

    providers = composition.evidence.body["providers"]
    assert isinstance(providers, list)
    assert len(providers) == 2
    for provider in providers:
        assert set(provider) == {
            "interface",
            "version",
            "provider",
            "distribution",
            "distribution_version",
            "entry_point",
            "content_digest",
        }
        assert provider["distribution"] == "sayfirst-control-plane"
        assert provider["distribution_version"] == "0.2.0"
        assert provider["entry_point"].startswith("sayfirst_control_plane.plugins.defaults:")
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", provider["content_digest"])


def test_composition_evidence_body_must_be_json_serializable() -> None:
    provider = {
        "interface": "PrivacyRedactor",
        "version": 1,
        "provider": "none",
        "distribution": "sayfirst-control-plane",
        "distribution_version": "0.1.0",
        "entry_point": "example:registration",
        "content_digest": "unknown",
    }

    with pytest.raises(TypeError, match="JSON serializable"):
        CompositionEvidence(
            scope="local",
            kind="composition",
            recorded_at=datetime(2026, 9, 4, tzinfo=UTC),
            connection_id="daemon",
            principal=EvidencePrincipal(kind="service", id="daemon"),
            body=MappingProxyType({"providers": [provider]}),
            sequence=1,
            previous_hash=None,
            entry_hash=f"{1:064x}",
            preimage_version="sayfirst-control-plane/evidence/v1",
        )


def test_a_plain_log_sink_cannot_stand_in_for_an_evidence_chain() -> None:
    with pytest.raises(InvalidCompositionEvidence):
        bootstrap_plugins(
            PluginConfiguration.defaults(),
            PlainLogEvidence(),  # type: ignore[arg-type]
            entry_points=discover_plugin_entry_points(),
        )


def _activated(registration: PluginRegistration, instance: object) -> ActivatedProvider:
    return ActivatedProvider(
        registration, instance, "test-distribution", "1.0", "test:target", "unknown"
    )


def test_direct_composition_refuses_an_unknown_plugin_interface() -> None:
    """Article 8: composition fails closed on an unknown plugin interface."""
    rogue = PluginRegistration("rogue", "UnknownPort", 1, NoRedaction)
    evidence = RecordingEvidence()

    with pytest.raises(UnknownPluginInterface, match="UnknownPort"):
        compose_plugins(
            (
                _activated(NO_OP_PRIVACY_REGISTRATION, NoRedaction()),
                _activated(SINGLE_APPROVER_REGISTRATION, SingleApprover()),
                _activated(rogue, NoRedaction()),
            ),
            evidence,
        )

    assert evidence.records == []


def test_direct_composition_refuses_an_unknown_interface_version() -> None:
    """Article 8: composition fails closed on an unknown plugin interface version."""
    future = PluginRegistration("future", PRIVACY_REDACTOR_INTERFACE, 99, NoRedaction)
    evidence = RecordingEvidence()

    with pytest.raises(UnknownPluginInterfaceVersion, match="99"):
        compose_plugins(
            (
                _activated(future, NoRedaction()),
                _activated(SINGLE_APPROVER_REGISTRATION, SingleApprover()),
            ),
            evidence,
        )

    assert evidence.records == []


def test_direct_composition_refuses_an_instance_that_implements_nothing() -> None:
    """Article 2: composition evidence never claims an interface nothing satisfied."""
    evidence = RecordingEvidence()

    with pytest.raises(InvalidPluginProvider, match="does not implement"):
        compose_plugins(
            (
                _activated(NO_OP_PRIVACY_REGISTRATION, object()),
                _activated(SINGLE_APPROVER_REGISTRATION, SingleApprover()),
            ),
            evidence,
        )

    assert evidence.records == []


def test_an_uncomputable_content_digest_is_declared_unknown_not_omitted() -> None:
    """Article 2: an absence is declared, never dropped from the record."""
    entry_points = [
        StaticEntryPoint("none", "no-such-module", NO_OP_PRIVACY_REGISTRATION),
        StaticEntryPoint("single-approver", "no-such-module-either", SINGLE_APPROVER_REGISTRATION),
    ]
    evidence = RecordingEvidence()

    composition = bootstrap_plugins(
        PluginConfiguration.defaults(), evidence, entry_points=entry_points
    )

    providers = composition.evidence.body["providers"]
    assert isinstance(providers, list)
    assert len(providers) == 2
    for provider in providers:
        assert "content_digest" in provider
        assert provider["content_digest"] == "unknown"
        assert provider["distribution"] == "unknown"


def test_composition_evidence_refuses_a_provider_entry_without_a_digest_member() -> None:
    """Article 2: the chain entry cannot stay silent about the code it names."""
    provider = {
        "interface": PRIVACY_REDACTOR_INTERFACE,
        "version": 1,
        "provider": "none",
        "distribution": "sayfirst-control-plane",
        "distribution_version": "0.1.0",
        "entry_point": "example:registration",
    }

    with pytest.raises(ValueError, match="missing members: content_digest"):
        CompositionEvidence(
            scope="local",
            kind="composition",
            recorded_at=datetime(2026, 9, 4, tzinfo=UTC),
            connection_id="daemon",
            principal=EvidencePrincipal(kind="service", id="daemon"),
            body={"providers": [provider]},
            sequence=1,
            previous_hash=None,
            entry_hash=f"{1:064x}",
            preimage_version="sayfirst-control-plane/evidence/v1",
        )


_WELL_FORMED_EVIDENCE: dict[str, object] = {
    "scope": "local",
    "kind": "composition",
    "recorded_at": datetime(2026, 9, 4, tzinfo=UTC),
    "connection_id": "daemon",
    "principal": EvidencePrincipal(kind="service", id="daemon"),
    "body": {
        "providers": [
            {
                "interface": PRIVACY_REDACTOR_INTERFACE,
                "version": 1,
                "provider": "none",
                "distribution": "sayfirst-control-plane",
                "distribution_version": "0.1.0",
                "entry_point": "example:registration",
                "content_digest": "unknown",
            }
        ]
    },
    "sequence": 1,
    "previous_hash": None,
    "entry_hash": "0" * 64,
    "preimage_version": "sayfirst-control-plane/evidence/v1",
}


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"scope": 7}, id="numeric-scope"),
        pytest.param({"scope": ""}, id="empty-scope"),
        pytest.param({"connection_id": 7}, id="numeric-connection"),
        pytest.param({"principal": "daemon"}, id="untyped-principal"),
        pytest.param({"principal": None}, id="absent-principal"),
        pytest.param({"recorded_at": "2026-09-04T00:00:00+00:00"}, id="textual-instant"),
        pytest.param({"sequence": True}, id="boolean-sequence"),
        pytest.param({"sequence": "1"}, id="textual-sequence"),
        pytest.param({"sequence": 0}, id="zero-sequence"),
        pytest.param({"sequence": 2, "previous_hash": None}, id="orphan-entry"),
        pytest.param({"previous_hash": "0" * 64}, id="first-entry-with-parent"),
        pytest.param({"entry_hash": None}, id="absent-entry-hash"),
        pytest.param({"entry_hash": "0" * 63}, id="short-entry-hash"),
        pytest.param({"preimage_version": 1}, id="numeric-preimage"),
        pytest.param({"preimage_version": ""}, id="empty-preimage"),
        pytest.param({"body": "providers"}, id="textual-body"),
    ],
)
def test_composition_evidence_refuses_an_entry_without_the_chain_shape(
    overrides: dict[str, object],
) -> None:
    """Article 2: the write side cannot construct evidence the reader would refuse."""
    with pytest.raises((TypeError, ValueError)):
        CompositionEvidence(**{**_WELL_FORMED_EVIDENCE, **overrides})  # type: ignore[arg-type]


def test_a_recorded_composition_reads_back_through_the_published_reader(
    tmp_path: Path,
) -> None:
    """Article 8: one composition, one shape — what is recorded is what is read."""
    evidence = RecordingEvidence()
    composition = bootstrap_plugins(
        PluginConfiguration.defaults(), evidence, entry_points=discover_plugin_entry_points()
    )
    entry = tmp_path / "composition.json"
    entry.write_text(json.dumps(composition.evidence.to_document()), encoding="utf-8")

    read_back = read_composition_evidence(entry)

    assert {item.provider for item in read_back} == {"none", "single-approver"}
    assert read_back == parse_composition_body(composition.evidence.body)


def _deprecated_privacy_v1(release: str, on: date) -> dict[str, tuple[int, ...]]:
    deprecation = DeprecatedPluginInterfaceVersion(
        interface_name=PRIVACY_REDACTOR_INTERFACE,
        interface_version=1,
        deprecated_since=date(2026, 1, 1),
        deprecated_in_release="0.1.0",
        announcement="PrivacyRedactor v1 is deprecated.",
    )
    current = {PRIVACY_REDACTOR_INTERFACE: 2, APPROVAL_PROVIDER_INTERFACE: 1}
    return {
        name: supported_plugin_interface_versions(
            name, current=current, on=on, release=release, deprecations=(deprecation,)
        )
        for name in current
    }


def test_a_provider_on_a_deprecated_version_still_composes_inside_its_window() -> None:
    """Article 8: a deprecated version keeps working for the whole window."""
    versions = _deprecated_privacy_v1(release="0.2.0", on=date(2026, 6, 1))
    evidence = RecordingEvidence()

    composition = bootstrap_plugins(
        PluginConfiguration.defaults(),
        evidence,
        entry_points=discover_plugin_entry_points(),
        supported_versions=versions,
    )

    assert composition.privacy_provider_name == "none"
    assert versions[PRIVACY_REDACTOR_INTERFACE] == (2, 1)


def test_a_provider_on_a_version_past_its_window_is_refused() -> None:
    """Article 8: after the window the deprecated version is refused, fail-closed."""
    versions = _deprecated_privacy_v1(release="0.3.0", on=date(2026, 7, 2))
    evidence = RecordingEvidence()

    with pytest.raises(UnknownPluginInterfaceVersion):
        bootstrap_plugins(
            PluginConfiguration.defaults(),
            evidence,
            entry_points=discover_plugin_entry_points(),
            supported_versions=versions,
        )

    assert versions[PRIVACY_REDACTOR_INTERFACE] == (2,)
    assert evidence.records == []
