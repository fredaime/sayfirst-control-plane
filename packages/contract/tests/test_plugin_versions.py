# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from sayfirst_contract.plugins import (
    PLUGIN_INTERFACE_DEPRECATIONS,
    PLUGIN_INTERFACE_VERSIONS,
    SUPPORTED_PLUGIN_INTERFACE_VERSIONS,
    DeprecatedPluginInterfaceVersion,
    accepts_plugin_interface_version,
    supported_plugin_interface_versions,
    unannounced_plugin_deprecations,
)

REPOSITORY = Path(__file__).resolve().parents[3]

DEPRECATION = DeprecatedPluginInterfaceVersion(
    interface_name="PrivacyRedactor",
    interface_version=1,
    deprecated_since=date(2026, 1, 1),
    deprecated_in_release="0.1.0",
    announcement="PrivacyRedactor v1 is deprecated in favour of PrivacyRedactor v2.",
)
CURRENT = {"PrivacyRedactor": 2, "ApprovalProvider": 1}


@pytest.mark.parametrize(
    ("on", "release"),
    [
        (date(2026, 6, 1), "0.4.0"),
        (date(2026, 7, 2), "0.2.0"),
        (date(2026, 6, 30), "0.3.0"),
    ],
)
def test_a_deprecated_plugin_interface_version_keeps_working_through_its_window(
    on: date, release: str
) -> None:
    """Article 8: two minor releases or six months, whichever is longer."""
    assert supported_plugin_interface_versions(
        "PrivacyRedactor",
        current=CURRENT,
        on=on,
        release=release,
        deprecations=(DEPRECATION,),
    ) == (2, 1)


def test_a_plugin_interface_version_past_its_window_is_refused() -> None:
    """Article 8: the window ends when both minimums have passed, never before."""
    assert supported_plugin_interface_versions(
        "PrivacyRedactor",
        current=CURRENT,
        on=date(2026, 7, 2),
        release="0.3.0",
        deprecations=(DEPRECATION,),
    ) == (2,)


def test_a_deprecation_of_another_interface_never_widens_this_one() -> None:
    """Article 8: an integer version belongs to exactly one plugin interface."""
    assert supported_plugin_interface_versions(
        "ApprovalProvider",
        current=CURRENT,
        on=date(2026, 6, 1),
        release="0.1.0",
        deprecations=(DEPRECATION,),
    ) == (1,)


def test_an_unannounced_deprecation_is_named_by_the_changelog_guard() -> None:
    """Article 8: the deprecation is announced in the changelog when it begins."""
    assert unannounced_plugin_deprecations("# Changelog\n", (DEPRECATION,)) == (DEPRECATION,)
    assert (
        unannounced_plugin_deprecations(
            f"# Changelog\n\n## 0.1.0\n\n- {DEPRECATION.announcement}\n", (DEPRECATION,)
        )
        == ()
    )
    assert unannounced_plugin_deprecations(
        f"# Changelog\n\n## 0.9.9\n\n- {DEPRECATION.announcement}\n", (DEPRECATION,)
    ) == (DEPRECATION,)


def test_every_shipped_plugin_deprecation_is_announced_in_the_changelog() -> None:
    """Article 8: no deprecation ships without its changelog entry."""
    changelog = (REPOSITORY / "CHANGELOG.md").read_text(encoding="utf-8")
    assert unannounced_plugin_deprecations(changelog) == ()


def test_the_shipped_interface_versions_are_supported_by_construction() -> None:
    """Article 8: the current integer version of each interface is always accepted."""
    assert set(SUPPORTED_PLUGIN_INTERFACE_VERSIONS) == set(PLUGIN_INTERFACE_VERSIONS)
    for interface_name, version in PLUGIN_INTERFACE_VERSIONS.items():
        assert SUPPORTED_PLUGIN_INTERFACE_VERSIONS[interface_name][0] == version
    assert PLUGIN_INTERFACE_DEPRECATIONS == ()


@pytest.mark.parametrize("version", [True, False, 1.0, "1", None, 99])
def test_a_plugin_interface_version_that_is_not_an_integer_one_is_refused(
    version: object,
) -> None:
    """Article 8: the version is an integer; ``True`` and ``1.0`` are not version 1."""
    assert accepts_plugin_interface_version("PrivacyRedactor", version) is False


def test_the_shipped_interface_versions_are_accepted_by_the_one_rule() -> None:
    for interface_name, accepted in SUPPORTED_PLUGIN_INTERFACE_VERSIONS.items():
        for version in accepted:
            assert accepts_plugin_interface_version(interface_name, version) is True


def test_an_unknown_interface_accepts_no_version_at_all() -> None:
    assert accepts_plugin_interface_version("UnknownPort", 1) is False
