# SPDX-License-Identifier: Apache-2.0
"""A second, independent `PrivacyRedactor` version 1: the kit is proven against two.

Article 8: "a provider that does not pass it is not a provider" is a sentence
about the kit, and a kit that has only ever judged the no-op it shipped with
has judged nothing — the no-op is the provider the kit's author wrote, in the
shape the kit's author assumed. This provider is written from the interface's
published shape and nothing else, does something the no-op does not, and
answers both statuses a real provider answers; it is a test fixture, never a
provider a shipped configuration names, and it enters a daemon only through an
entry point a test plants (article 8: discovery is by installed metadata, and
this module installs none).
"""

from __future__ import annotations

import re

from sayfirst_contract.plugins import PRIVACY_REDACTOR_INTERFACE, PRIVACY_REDACTOR_VERSION
from sayfirst_control_plane.plugins.interfaces import Redaction
from sayfirst_control_plane.plugins.registration import PluginRegistration

DIGITS = re.compile(rb"[0-9]")


class DigitMask:
    """Replace every decimal digit of captured content with `#`.

    A capture with a digit in it is answered `applied`, with the digits masked;
    one without is answered `not_applicable`, as given — the honest answer when
    nothing was applied (article 2).
    """

    interface_version = PRIVACY_REDACTOR_VERSION
    name = "digit-mask"

    def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction:
        masked, count = DIGITS.subn(b"#", content)
        if count == 0:
            return Redaction(content, "not_applicable", self.name)
        return Redaction(masked, "applied", self.name)


REGISTRATION = PluginRegistration(
    provider_name=DigitMask.name,
    interface_name=PRIVACY_REDACTOR_INTERFACE,
    interface_version=PRIVACY_REDACTOR_VERSION,
    factory=DigitMask,
)
