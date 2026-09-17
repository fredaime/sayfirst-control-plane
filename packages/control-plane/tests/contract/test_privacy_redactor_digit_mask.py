# SPDX-License-Identifier: Apache-2.0
"""Article 8: the one `PrivacyRedactor` version 1 kit passes a second, independent provider.

`test_privacy_redactor_none.py` runs the shipped no-op through the kit. A kit
proven against the one provider its author wrote proves the kit agrees with
its author; this file runs a provider written from the published shape alone,
through both entrances the kit is published under, so the two entrances are
held to one rule and the rule is held to two implementations.
"""

from __future__ import annotations

from digit_mask_redactor import DigitMask
from sayfirst.testing import PrivacyRedactorContract as PublishedContract
from sayfirst_control_plane.testing import PrivacyRedactorContract


class TestDigitMask(PrivacyRedactorContract):
    """The pytest-mixin entrance, `sayfirst_control_plane.testing`."""

    def make_provider(self) -> DigitMask:
        return DigitMask()


def test_the_second_provider_passes_the_published_entrance() -> None:
    """The callable entrance, `sayfirst.testing`, that article 8 names."""
    PublishedContract().assert_conforms(DigitMask)


def test_the_second_provider_does_what_the_no_op_does_not() -> None:
    """Independence: the fixture exercises a path the shipped default never takes."""
    provider = DigitMask()
    applied = provider.redact(scope="local", capability="example.effect", content=b"card 4242")
    untouched = provider.redact(scope="local", capability="example.effect", content=b"no digits")

    assert (applied.status, applied.content) == ("applied", b"card ####")
    assert (untouched.status, untouched.content) == ("not_applicable", b"no digits")
    assert applied.provider == untouched.provider == "digit-mask"
