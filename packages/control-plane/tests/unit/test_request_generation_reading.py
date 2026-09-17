# SPDX-License-Identifier: Apache-2.0
"""Article 13: the surface reads `contract_generation` the way its schema does.

JSON has one number type. The published `decision-ask-request` schema says
`"type": "integer"`, and JSON Schema 6.1.1 says an integer is a number with a
zero fractional part — so `1.0` and `1` are the same generation, and the
checker this daemon runs says so, deliberately and with the section cited in
its own source.

In front of that checker the route asked Python instead: `isinstance(generation,
int)`. `1.0` is not a Python `int`, so a request the daemon's own checker
accepts was answered 400 `generation_unreadable`. That is the D1 divergence
`fix/schema-differential` closed inside the checker, reinstated one layer up,
and it is the thing article 13 forbids by name: a server not implementable from
the contract it publishes.

The named cases are here; `test_published_schema_differential.py` drives the
generated corpus through the same path, so the next layer that reads the schema
a second way has to survive both.
"""

from __future__ import annotations

import pytest
from handler_bytes import HandlerHost, answer_inline, request_bytes
from sayfirst_control_plane.domain.published_schema import is_published_integer, refused_by


@pytest.fixture
def surface():  # type: ignore[no-untyped-def]
    made = HandlerHost()
    try:
        yield made
    finally:
        made.close()


def test_an_integral_json_number_is_the_generation_it_names(surface) -> None:  # type: ignore[no-untyped-def]
    """`handler_demos.py`: the checker accepted it and the route refused it."""
    document = {"contract_generation": 1.0, "capability": "storage.write", "scope": "local"}
    assert refused_by(document, "decision-ask-request") is None

    run = answer_inline(surface, request_bytes(generation=1.0))

    assert run.status() == 200, run.document()
    assert run.document()["outcome"] == "allow", run.document()


@pytest.mark.parametrize(
    "generation",
    [1.5, "1", True, False, [1], {"generation": 1}],
    ids=["fraction", "text", "true", "false", "array", "object"],
)
def test_a_generation_that_is_not_a_number_of_the_schema_is_unreadable(surface, generation) -> None:  # type: ignore[no-untyped-def]
    """The published code keeps its meaning: "contract_generation is not an integer"."""
    run = answer_inline(surface, request_bytes(generation=generation))

    assert run.document()["code"] == "generation_unreadable", run.document()


def test_a_generation_this_server_does_not_speak_is_unsupported(surface) -> None:  # type: ignore[no-untyped-def]
    """An integer is readable whatever its value; whether it is spoken is the next question."""
    for generation in (0, 7, 7.0):
        run = answer_inline(surface, request_bytes(generation=generation))
        assert run.document()["code"] == "generation_unsupported", (generation, run.document())


def test_an_absent_generation_is_still_missing_and_not_malformed(surface) -> None:  # type: ignore[no-untyped-def]
    """The three generation problems the binding publishes keep their three meanings."""
    from handler_bytes import ABSENT

    run = answer_inline(surface, request_bytes(generation=ABSENT))

    assert run.document()["code"] == "generation_missing", run.document()


def test_the_reading_is_the_checker_s_own_and_not_a_second_spelling() -> None:
    """One rule, one place: the route asks the module that holds 6.1.1."""
    assert is_published_integer(1) is True
    assert is_published_integer(1.0) is True
    assert is_published_integer(2.0) is True
    assert is_published_integer(1.5) is False
    assert is_published_integer(True) is False
    assert is_published_integer("1") is False
    assert is_published_integer(None) is False
