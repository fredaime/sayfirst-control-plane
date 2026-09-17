# SPDX-License-Identifier: Apache-2.0
from sayfirst_control_plane.plugins.privacy.none import NoRedaction
from sayfirst_control_plane.testing import PrivacyRedactorContract


class TestNoRedaction(PrivacyRedactorContract):
    """Article 11: the useful open default records configured captures as given."""

    def make_provider(self) -> NoRedaction:
        return NoRedaction()
