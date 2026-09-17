# SPDX-License-Identifier: Apache-2.0
"""The PrivacyRedactor v1 conformance suite, as a callable.

One rule, published under two entrances: this callable and the pytest mixin
`sayfirst_control_plane.testing.PrivacyRedactorContract`. The rule itself is
stated once, beside the mixin.
"""

from __future__ import annotations

from collections.abc import Callable

from sayfirst_control_plane.plugins.interfaces import PrivacyRedactor
from sayfirst_control_plane.testing.privacy_redactor_contract import (
    assert_privacy_redactor_conforms,
)


class PrivacyRedactorContract:
    """Assertions every PrivacyRedactor v1 implementation must satisfy."""

    def assert_conforms(self, provider_factory: Callable[[], PrivacyRedactor]) -> None:
        assert_privacy_redactor_conforms(provider_factory)
