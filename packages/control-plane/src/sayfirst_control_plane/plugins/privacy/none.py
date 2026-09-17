# SPDX-License-Identifier: Apache-2.0
"""The default captured-content provider."""

from sayfirst_control_plane.plugins.interfaces import PRIVACY_REDACTOR_VERSION, Redaction


class NoRedaction:
    """Record captured content as it was given.

    The open default article 11 names: provider `none`, which applies nothing
    and says so — every answer is `not_applicable`, never `applied`, so no
    surface can render it as protection (article 2).
    """

    interface_version = PRIVACY_REDACTOR_VERSION
    name = "none"

    def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction:
        return Redaction(content, "not_applicable", self.name)
