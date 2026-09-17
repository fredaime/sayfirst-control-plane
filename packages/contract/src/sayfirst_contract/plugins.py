# SPDX-License-Identifier: Apache-2.0
"""Shared public vocabulary for plugin discovery and configuration."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from importlib import metadata
from pathlib import Path
from typing import Protocol

PLUGIN_ENTRY_POINT_GROUP = "sayfirst.plugins"
PRIVACY_REDACTOR_INTERFACE = "PrivacyRedactor"
APPROVAL_PROVIDER_INTERFACE = "ApprovalProvider"
PRIVACY_REDACTOR_VERSION = 1
APPROVAL_PROVIDER_VERSION = 1
PLUGIN_INTERFACE_VERSIONS = {
    PRIVACY_REDACTOR_INTERFACE: PRIVACY_REDACTOR_VERSION,
    APPROVAL_PROVIDER_INTERFACE: APPROVAL_PROVIDER_VERSION,
}
COMPOSITION_EVIDENCE_KIND = "composition"
CONTENT_DIGEST_UNKNOWN = "unknown"
_CONTENT_DIGEST = re.compile(rf"^(sha256:[0-9a-f]{{64}}|{CONTENT_DIGEST_UNKNOWN})$")


class PluginEntryPointMetadata(Protocol):
    """The inert package metadata used to discover a provider."""

    name: str
    value: str

    def load(self) -> object: ...


def discover_plugin_entry_points(
    entry_points: Iterable[PluginEntryPointMetadata] | None = None,
) -> tuple[PluginEntryPointMetadata, ...]:
    """Read and order plugin entry-point metadata without loading provider code."""
    candidates = (
        tuple(entry_points)
        if entry_points is not None
        else tuple(metadata.entry_points().select(group=PLUGIN_ENTRY_POINT_GROUP))
    )
    return tuple(sorted(candidates, key=lambda item: (item.name, item.value)))


@dataclass(frozen=True)
class ProviderSelection:
    provider: str
    interface_version: object


def parse_plugin_configuration(
    document: Mapping[str, object],
) -> dict[str, ProviderSelection]:
    """Parse the common plugin configuration shape without claiming activation."""
    plugins = document.get("plugins")
    if not isinstance(plugins, Mapping):
        raise ValueError("configuration must contain a plugins table")
    providers: dict[str, ProviderSelection] = {}
    for interface_name, raw_selection in plugins.items():
        if not isinstance(interface_name, str) or not isinstance(raw_selection, Mapping):
            raise ValueError("each plugin selection must be a named table")
        unknown_keys = set(raw_selection) - {"provider", "interface_version"}
        if unknown_keys:
            raise ValueError(f"{interface_name} has an unknown configuration key")
        provider = raw_selection.get("provider")
        if not isinstance(provider, str) or not provider:
            raise ValueError(f"{interface_name} must name a provider")
        providers[interface_name] = ProviderSelection(
            provider=provider,
            interface_version=raw_selection.get("interface_version"),
        )
    return providers


def read_plugin_configuration(path: Path) -> dict[str, ProviderSelection]:
    """Read the common plugin configuration shape from a TOML file."""
    with path.open("rb") as stream:
        return parse_plugin_configuration(tomllib.load(stream))


@dataclass(frozen=True)
class ComposedProvider:
    """One resolved provider, as the composition evidence of article 8 records it."""

    interface: str
    version: int
    provider: str
    distribution: str
    distribution_version: str
    entry_point: str
    content_digest: str

    def to_member(self) -> dict[str, object]:
        return {
            "interface": self.interface,
            "version": self.version,
            "provider": self.provider,
            "distribution": self.distribution,
            "distribution_version": self.distribution_version,
            "entry_point": self.entry_point,
            "content_digest": self.content_digest,
        }


COMPOSED_PROVIDER_MEMBERS = frozenset(
    {
        "interface",
        "version",
        "provider",
        "distribution",
        "distribution_version",
        "entry_point",
        "content_digest",
    }
)


def composition_body(providers: Iterable[ComposedProvider]) -> dict[str, object]:
    """The one composition evidence body both the server and the client read."""
    return {"providers": [item.to_member() for item in providers]}


def _check_members(present: Iterable[object], required: frozenset[str], subject: str) -> None:
    """Refuse a member set, naming the fact that is wrong with it.

    A missing member and an unrecognised one are different facts, and a refusal
    that reported the first as the second would send a reader looking for
    something that is not there (article 2).
    """
    names = set(present)
    missing = sorted(required - names)
    if missing:
        raise ValueError(f"{subject} is missing members: {', '.join(missing)}")
    unknown = names - required
    if unknown:
        raise ValueError(f"{subject} has unknown members: {', '.join(sorted(map(str, unknown)))}")


def _parse_composed_provider(member: object) -> ComposedProvider:
    if not isinstance(member, Mapping):
        raise ValueError("a composition provider has unknown members")
    _check_members(member, COMPOSED_PROVIDER_MEMBERS, "a composition provider")
    texts = (
        "interface",
        "provider",
        "distribution",
        "distribution_version",
        "entry_point",
    )
    if (
        any(not isinstance(member[name], str) or not member[name] for name in texts)
        or type(member["version"]) is not int
        or member["version"] < 1
        or not isinstance(member["content_digest"], str)
        or not _CONTENT_DIGEST.fullmatch(member["content_digest"])
    ):
        raise ValueError("a composition provider is invalid")
    return ComposedProvider(
        interface=str(member["interface"]),
        version=int(member["version"]),
        provider=str(member["provider"]),
        distribution=str(member["distribution"]),
        distribution_version=str(member["distribution_version"]),
        entry_point=str(member["entry_point"]),
        content_digest=str(member["content_digest"]),
    )


def parse_composition_body(body: Mapping[str, object]) -> tuple[ComposedProvider, ...]:
    """Read a composition evidence body, refusing a member it cannot name."""
    if set(body) != {"providers"}:
        raise ValueError("composition evidence body must contain only providers")
    providers = body["providers"]
    if not isinstance(providers, list):
        raise ValueError("composition providers must be a list")
    return tuple(_parse_composed_provider(member) for member in providers)


COMPOSITION_EVIDENCE_MEMBERS = frozenset(
    {
        "scope",
        "kind",
        "recorded_at",
        "connection_id",
        "principal",
        "body",
        "sequence",
        "previous_hash",
        "entry_hash",
        "preimage_version",
    }
)
_PRINCIPAL_MEMBERS = frozenset({"kind", "id", "via"})
_ENTRY_HASH = re.compile(r"^[0-9a-f]{64}$")


def _check_principal(principal: object) -> None:
    if not isinstance(principal, Mapping) or not {"kind", "id"} <= set(principal):
        raise ValueError("a composition evidence principal must name a kind and an id")
    if not set(principal) <= _PRINCIPAL_MEMBERS:
        raise ValueError("a composition evidence principal has unknown members")
    for name in ("kind", "id"):
        value = principal[name]
        if not isinstance(value, str) or not value:
            raise ValueError(f"a composition evidence principal {name} must be a name")
    via = principal.get("via", [])
    if not isinstance(via, list):
        raise ValueError("composition evidence principal delegation must be a list")
    for delegate in via:
        _check_principal(delegate)


def _check_instant(recorded_at: object) -> None:
    error = ValueError("composition evidence must record an offset-aware instant")
    if not isinstance(recorded_at, str):
        raise error
    try:
        instant = datetime.fromisoformat(recorded_at)
    except ValueError as invalid:
        raise error from invalid
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise error


def parse_composition_evidence(document: Mapping[str, object]) -> tuple[ComposedProvider, ...]:
    """Read one composition evidence entry, refusing an envelope without the chain shape.

    Article 2: what is shown as a composition is no stronger than the entry that
    records it, so the whole typed envelope is checked before the composition is
    returned — an entry carrying only a kind and a body is not evidence of a
    chain. The hash linkage is *not* verified here: this distribution has no
    evidence chain store to verify it against, and neither this function nor its
    callers may present a well-shaped entry as a verified one.
    """
    if document.get("kind") != COMPOSITION_EVIDENCE_KIND:
        raise ValueError("this evidence entry is not a composition")
    _check_members(document, COMPOSITION_EVIDENCE_MEMBERS, "a composition evidence entry")
    for name in ("scope", "connection_id", "preimage_version"):
        value = document[name]
        if not isinstance(value, str) or not value:
            raise ValueError(f"a composition evidence entry must name its {name}")
    _check_instant(document["recorded_at"])
    _check_principal(document["principal"])
    sequence = document["sequence"]
    if type(sequence) is not int or sequence < 1:
        raise ValueError("composition evidence sequence must be a positive integer")
    previous_hash = document["previous_hash"]
    if sequence == 1:
        if previous_hash is not None:
            raise ValueError("the first composition evidence entry has no previous hash")
    elif not isinstance(previous_hash, str) or not _ENTRY_HASH.fullmatch(previous_hash):
        raise ValueError("a later composition evidence entry needs its previous hash")
    entry_hash = document["entry_hash"]
    if not isinstance(entry_hash, str) or not _ENTRY_HASH.fullmatch(entry_hash):
        raise ValueError("composition evidence entry hash is not a digest")
    body = document["body"]
    if not isinstance(body, Mapping):
        raise ValueError("a composition evidence entry must carry a body")
    return parse_composition_body(body)


def read_composition_evidence(path: Path) -> tuple[ComposedProvider, ...]:
    """Read the resolved composition from a recorded evidence chain entry."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("a composition evidence entry must be an object")
    return parse_composition_evidence(document)


@dataclass(frozen=True)
class DeprecatedPluginInterfaceVersion:
    """A plugin interface version inside the window article 8 grants it."""

    interface_name: str
    interface_version: int
    deprecated_since: date
    deprecated_in_release: str
    announcement: str


PLUGIN_INTERFACE_DEPRECATIONS: tuple[DeprecatedPluginInterfaceVersion, ...] = ()


def supported_plugin_interface_versions(
    interface_name: str,
    *,
    current: Mapping[str, int] = PLUGIN_INTERFACE_VERSIONS,
    on: date,
    release: str,
    deprecations: Iterable[DeprecatedPluginInterfaceVersion] = PLUGIN_INTERFACE_DEPRECATIONS,
) -> tuple[int, ...]:
    """The integer versions of one interface still accepted, current one first.

    Article 8: a deprecated version keeps working for at least two minor releases
    or six months, whichever is longer. The window closes only when both minimums
    have passed; the arithmetic is the one article 13 already uses for generations.
    """
    from .generation import add_months, minor_distance

    if interface_name not in current:
        return ()
    accepted = [current[interface_name]]
    for item in deprecations:
        if item.interface_name != interface_name:
            continue
        six_months_passed = on >= add_months(item.deprecated_since, 6)
        two_minor_releases_passed = minor_distance(item.deprecated_in_release, release) >= 2
        if not (six_months_passed and two_minor_releases_passed):
            accepted.append(item.interface_version)
    return tuple(accepted)


def unannounced_plugin_deprecations(
    changelog: str,
    deprecations: Iterable[DeprecatedPluginInterfaceVersion] = PLUGIN_INTERFACE_DEPRECATIONS,
) -> tuple[DeprecatedPluginInterfaceVersion, ...]:
    """The deprecations whose changelog announcement is missing or misfiled.

    Article 8: the deprecation is announced in the changelog when it begins, so
    the announcement must appear under the release that began it.
    """
    unannounced = []
    for item in deprecations:
        heading = f"## {item.deprecated_in_release}"
        start = changelog.find(heading)
        if start < 0:
            unannounced.append(item)
            continue
        end = changelog.find("\n## ", start + len(heading))
        section = changelog[start:] if end < 0 else changelog[start:end]
        if item.announcement not in section:
            unannounced.append(item)
    return tuple(unannounced)


def _shipped_plugin_interface_versions() -> dict[str, tuple[int, ...]]:
    from .generation import BUILD_DATE, DISTRIBUTION_RELEASE

    return {
        interface_name: supported_plugin_interface_versions(
            interface_name, on=BUILD_DATE, release=DISTRIBUTION_RELEASE
        )
        for interface_name in PLUGIN_INTERFACE_VERSIONS
    }


SUPPORTED_PLUGIN_INTERFACE_VERSIONS: Mapping[str, tuple[int, ...]] = (
    _shipped_plugin_interface_versions()
)


def accepts_plugin_interface_version(
    interface_name: str,
    interface_version: object,
    *,
    supported: Mapping[str, tuple[int, ...]] | None = None,
) -> bool:
    """Whether this release accepts one interface version for one interface.

    Article 8: each plugin interface carries an **integer** version, and a
    provider built for an unknown version is refused. ``True`` is not version 1
    and ``1.0`` is not version 1, however they compare. Article 2: every surface
    that reports a selection asks this one question, so what the command line
    shows cannot differ from what bootstrap does.
    """
    accepted = (SUPPORTED_PLUGIN_INTERFACE_VERSIONS if supported is None else supported).get(
        interface_name
    )
    if accepted is None:
        return False
    return type(interface_version) is int and interface_version in accepted
