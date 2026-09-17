# SPDX-License-Identifier: Apache-2.0
"""The one conformance rule for `PrivacyRedactor` version 1, and its pytest entrance.

Article 8 ships a contract test suite per port and says a provider that does not
pass it is not a provider. The rule lives here once; `sayfirst.testing` offers
it as a callable and this module offers it as a pytest mixin, so the two
entrances cannot judge by two rules. What is judged (article 2, article 11):

- the provider satisfies the published protocol, is built for the version the
  contract distribution registers, and carries a non-empty name;
- `redact` answers a `Redaction` whose content is bytes, whose provider is the
  provider's own name and whose status is `applied`, `not_applicable` or
  `failed`;
- the status is true of the content: `applied` means the content differs from
  what was read, `not_applicable` means it is as given — a no-op that answers
  `applied` claims a redaction nothing applied, and the kit fails it;
- an empty capture yields an empty capture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from sayfirst_control_plane.plugins.interfaces import (
    PRIVACY_REDACTOR_VERSION,
    PrivacyRedactor,
    Redaction,
)

#: A capture with something in it a provider might act on; nothing about it is
#: private, and the kit asserts nothing about *what* a provider changes.
PROBE = b"account 4242 private input"
STATUSES = frozenset({"applied", "not_applicable", "failed"})


def _redaction_of(provider: PrivacyRedactor, content: bytes) -> Redaction:
    result = provider.redact(scope="conformance", capability="example.effect", content=content)
    if not isinstance(result, Redaction):
        raise AssertionError("redact must return a Redaction")
    if type(result.content) is not bytes:
        raise AssertionError("a redaction's content must be bytes")
    if result.provider != provider.name:
        raise AssertionError("a redaction must carry the provider's own name")
    if result.status not in STATUSES:
        raise AssertionError(f"unknown redaction status {result.status!r}")
    return result


def assert_privacy_redactor_conforms(provider_factory: Callable[[], PrivacyRedactor]) -> None:
    """Every assertion a `PrivacyRedactor` version 1 implementation must satisfy."""
    provider = provider_factory()
    if not isinstance(provider, PrivacyRedactor):
        raise AssertionError(
            f"provider does not implement PrivacyRedactor v{PRIVACY_REDACTOR_VERSION}"
        )
    if type(provider.interface_version) is not int:
        raise AssertionError("interface_version must be an integer")
    if provider.interface_version != PRIVACY_REDACTOR_VERSION:
        raise AssertionError(
            f"provider is built for interface version {provider.interface_version!r}, "
            f"this kit judges version {PRIVACY_REDACTOR_VERSION}"
        )
    if not isinstance(provider.name, str) or not provider.name:
        raise AssertionError("name must be a non-empty string")

    probed = _redaction_of(provider, PROBE)
    if probed.status == "applied" and probed.content == PROBE:
        raise AssertionError(
            "answered `applied` and returned the content as given: a no-op cannot claim protection"
        )
    if probed.status == "not_applicable" and probed.content != PROBE:
        raise AssertionError("answered `not_applicable` and changed the content")

    emptied = _redaction_of(provider, b"")
    if emptied.content != b"":
        raise AssertionError("an empty capture must yield an empty capture")


class PrivacyRedactorContract(ABC):
    """Subclass this suite and return a fresh provider from ``make_provider``."""

    @abstractmethod
    def make_provider(self) -> PrivacyRedactor:
        raise NotImplementedError

    def test_the_provider_passes_the_published_rule(self) -> None:
        assert_privacy_redactor_conforms(self.make_provider)
