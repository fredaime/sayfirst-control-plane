# SPDX-License-Identifier: Apache-2.0
"""Article 11: a digest of the arguments travels, never the arguments.

The digest is also a CONDITION the control plane pins on a grant, so two
boundaries that disagree about how to compute it would disagree about which
grants still apply. The canonicalisation is therefore pinned here by example,
not left to a JSON encoder's defaults.
"""

from __future__ import annotations

import re

import pytest
from sayfirst_boundary.digest import arguments_digest

SHAPE = re.compile(r"^sha256:[0-9a-f]{64}$")


def test_the_digest_has_the_shape_the_control_plane_validates() -> None:
    assert SHAPE.fullmatch(arguments_digest({"to": "someone@example.test"}))


def test_key_order_does_not_change_the_digest() -> None:
    assert arguments_digest({"a": 1, "b": 2}) == arguments_digest({"b": 2, "a": 1})


def test_a_different_value_changes_the_digest() -> None:
    assert arguments_digest({"amount": 100}) != arguments_digest({"amount": 101})


def test_a_string_and_a_number_are_not_the_same_argument() -> None:
    assert arguments_digest({"amount": 100}) != arguments_digest({"amount": "100"})


def test_nesting_is_canonical_too() -> None:
    assert arguments_digest({"x": {"a": 1, "b": 2}}) == arguments_digest({"x": {"b": 2, "a": 1}})


def test_no_arguments_still_yields_a_digest() -> None:
    assert SHAPE.fullmatch(arguments_digest({}))


def test_the_empty_digest_is_not_the_digest_of_something() -> None:
    assert arguments_digest({}) != arguments_digest({"a": 1})


def test_a_value_the_wire_cannot_carry_is_refused_rather_than_coerced() -> None:
    with pytest.raises(TypeError):
        arguments_digest({"when": object()})


# The canonicalisation, pinned by example rather than by property. Each value
# below was measured against the implementation AND against three mutations of
# it: spaced separators, escaped non-ASCII, and unsorted keys each produce a
# different digest. That is what makes these three assertions load-bearing —
# the tests above check only relative properties (order-independence, and that
# a change changes something), and every one of them passes under all three
# mutations. Two boundaries agreeing on those properties could still compute
# different digests for the same call, which is the one thing the control plane
# cannot tolerate, because it compares this string exactly as a grant condition.
def test_the_empty_digest_is_pinned() -> None:
    assert arguments_digest({}) == (
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )


def test_a_simple_digest_is_pinned() -> None:
    assert arguments_digest({"to": "someone@example.test"}) == (
        "sha256:16a9d6fcebce4fbf933ec484945c9fdf7a4c7815499f218b714be3932fb1fe8b"
    )


def test_a_non_ascii_value_travels_unescaped() -> None:
    """Pins `ensure_ascii=False`. Escaping would silently change every digest
    of every argument set containing a character outside ASCII."""
    assert arguments_digest({"nom": "Frédéric"}) == (
        "sha256:ccf5583b48d3244bb20029567f98f14609067138766ce70944eb54bbead90801"
    )
