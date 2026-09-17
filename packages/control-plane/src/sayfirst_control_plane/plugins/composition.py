# SPDX-License-Identifier: Apache-2.0
"""Explicit bootstrap composition, recorded in an evidence chain before use."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from sayfirst_contract.plugins import (
    COMPOSITION_EVIDENCE_KIND,
    ComposedProvider,
    composition_body,
    parse_composition_evidence,
)

from .activation import (
    ActivatedProvider,
    SupportedVersions,
    activate_plugins,
    supported_protocol,
)
from .configuration import PluginConfiguration
from .discovery import PluginEntryPoint, discover_plugins
from .errors import InvalidCompositionEvidence, InvalidPluginProvider, MissingPluginProvider
from .interfaces import (
    APPROVAL_PROVIDER_INTERFACE,
    PRIVACY_REDACTOR_INTERFACE,
    ApprovalProvider,
    PrivacyRedactor,
)

ComposedProviderEvidence = ComposedProvider


@dataclass(frozen=True)
class EvidencePrincipal:
    kind: str
    id: str
    via: tuple[EvidencePrincipal, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not isinstance(self.id, str):
            raise TypeError("principal kind and id are names")
        if not self.kind or not self.id:
            raise ValueError("principal kind and id are required")
        if not all(isinstance(item, EvidencePrincipal) for item in self.via):
            raise TypeError("principal delegation must contain principals")

    def to_document(self) -> dict[str, object]:
        """The principal as the evidence chain records it."""
        return {
            "kind": self.kind,
            "id": self.id,
            "via": [item.to_document() for item in self.via],
        }


@dataclass(frozen=True)
class CompositionEvidence:
    """A composition entry shaped like the generation-one evidence chain."""

    scope: str
    kind: Literal["composition"]
    recorded_at: datetime
    connection_id: str
    principal: EvidencePrincipal
    body: Mapping[str, object]
    sequence: int
    previous_hash: str | None
    entry_hash: str
    preimage_version: str

    def __post_init__(self) -> None:
        if self.kind != COMPOSITION_EVIDENCE_KIND:
            raise ValueError("composition evidence has the wrong entry kind")
        if not isinstance(self.recorded_at, datetime):
            raise TypeError("composition evidence must record an instant")
        if self.recorded_at.tzinfo is None or self.recorded_at.utcoffset() is None:
            raise ValueError("composition evidence time must be offset-aware")
        if not isinstance(self.principal, EvidencePrincipal):
            raise TypeError("composition evidence must name a typed principal")
        parse_composition_evidence(self.to_document())
        json.dumps(self.body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def to_document(self) -> dict[str, object]:
        """The entry as the evidence chain records it, and as the reader reads it.

        Article 2: the write side and the published reader hold one shape, so a
        composition this process could construct is one a later reader can name.
        Serialising it is not verifying it — the chain that would verify the
        hashes is the evidence block's, not this one's.
        """
        return {
            "scope": self.scope,
            "kind": self.kind,
            "recorded_at": self.recorded_at.isoformat(),
            "connection_id": self.connection_id,
            "principal": self.principal.to_document(),
            "body": self.body,
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
            "preimage_version": self.preimage_version,
        }


class CompositionEvidenceSink(Protocol):
    def record(
        self, *, scope: str, providers: tuple[ComposedProviderEvidence, ...]
    ) -> CompositionEvidence:
        """Append and return one resolved composition evidence chain entry."""
        ...


@dataclass(frozen=True)
class PluginComposition:
    privacy_redactor: PrivacyRedactor
    approval_provider: ApprovalProvider
    privacy_provider_name: str
    approval_provider_name: str
    evidence: CompositionEvidence


def compose_plugins(
    activated: tuple[ActivatedProvider, ...],
    evidence_sink: CompositionEvidenceSink,
    *,
    scope: str = "local",
    supported_versions: SupportedVersions | None = None,
) -> PluginComposition:
    """Wire the two named providers and record the complete resolved composition."""
    for item in activated:
        protocol = supported_protocol(item.registration, supported_versions=supported_versions)
        if not isinstance(item.instance, protocol):
            raise InvalidPluginProvider(
                f"provider {item.registration.provider_name!r} does not implement "
                f"{item.registration.interface_name} v{item.registration.interface_version}"
            )
    by_interface = {item.registration.interface_name: item for item in activated}
    missing = {PRIVACY_REDACTOR_INTERFACE, APPROVAL_PROVIDER_INTERFACE} - set(by_interface)
    if missing:
        raise MissingPluginProvider(f"no active provider for {sorted(missing)[0]!r}")
    if len(by_interface) != len(activated):
        raise InvalidPluginProvider("more than one provider is active for an interface")

    privacy = by_interface[PRIVACY_REDACTOR_INTERFACE]
    approval = by_interface[APPROVAL_PROVIDER_INTERFACE]
    providers = tuple(
        ComposedProviderEvidence(
            interface=item.registration.interface_name,
            version=item.registration.interface_version,
            provider=item.registration.provider_name,
            distribution=item.distribution,
            distribution_version=item.distribution_version,
            entry_point=item.entry_point,
            content_digest=item.content_digest,
        )
        for item in sorted(activated, key=lambda item: item.registration.interface_name)
    )
    expected_body = composition_body(providers)
    record = getattr(evidence_sink, "record", None)
    if not callable(record):
        raise InvalidCompositionEvidence("evidence sink cannot record the requested composition")
    evidence = record(scope=scope, providers=providers)
    if (
        not isinstance(evidence, CompositionEvidence)
        or evidence.kind != COMPOSITION_EVIDENCE_KIND
        or evidence.scope != scope
        or evidence.body != expected_body
    ):
        raise InvalidCompositionEvidence(
            "evidence sink did not return the requested composition chain entry"
        )
    return PluginComposition(
        privacy_redactor=cast(PrivacyRedactor, privacy.instance),
        approval_provider=cast(ApprovalProvider, approval.instance),
        privacy_provider_name=privacy.registration.provider_name,
        approval_provider_name=approval.registration.provider_name,
        evidence=evidence,
    )


def bootstrap_plugins(
    configuration: PluginConfiguration,
    evidence_sink: CompositionEvidenceSink,
    *,
    scope: str = "local",
    entry_points: Iterable[PluginEntryPoint] | None = None,
    supported_versions: SupportedVersions | None = None,
) -> PluginComposition:
    """Discover, activate and explicitly compose the configured providers at start."""
    discovered = discover_plugins(entry_points)
    activated = activate_plugins(discovered, configuration, supported_versions=supported_versions)
    return compose_plugins(
        activated, evidence_sink, scope=scope, supported_versions=supported_versions
    )


def bootstrap_plugins_from_toml(
    path: Path,
    evidence_sink: CompositionEvidenceSink,
    *,
    scope: str = "local",
    entry_points: Iterable[PluginEntryPoint] | None = None,
    supported_versions: SupportedVersions | None = None,
) -> PluginComposition:
    """Read the configured authority and compose its providers at bootstrap."""
    return bootstrap_plugins(
        PluginConfiguration.from_toml(path),
        evidence_sink,
        scope=scope,
        entry_points=entry_points,
        supported_versions=supported_versions,
    )
