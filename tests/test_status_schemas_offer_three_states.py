# SPDX-License-Identifier: Apache-2.0
"""Article 2: a two-valued status fails, wherever it is added.

One rule per file (`CONTRIBUTING.md`, article 16). The rule here is the second
sentence of article 2's Guard: a status surface carries an explicit unknown
value, and a two-valued status fails the contract tests. Before the audit of
2026-09-06 that sentence was held by tests naming particular fields, so a new
healthy/unhealthy member could be added to a published schema and the whole
contract suite stayed green — a partial inventory presented as universal
coverage.

Every published schema is walked instead, and each state-bearing field must
offer a third state: an enum member that means "did not look", or absence,
which the client renders as unknown when the member or an object above it is
optional. A field that offers two states and nothing else is either a defect or
not a status; the second is said here, once, with its reason — `resolution` is
an instruction the caller sends, not a state the system reports — and a stale
declaration fails as loudly as a missing one.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
CONTRACTS = REPOSITORY / "packages" / "contract" / "src" / "sayfirst_contract" / "_contracts"

#: Members that mean "did not look", as against a fact that was established.
UNKNOWN_MEANING = frozenset(
    {"unknown", "unverified", "unverifiable", "not_reported", "unspecified"}
)

#: A field whose name says it reports a state. Article 2 asks these for an
#: explicit unknown value however many states they otherwise carry.
STATUS_NAMES = ("status", "state", "health", "grade", "condition")

#: Two-state fields that report no state, with the reason each is not one.
#: A path here that the walk no longer finds fails: a register that outlives
#: its subject stops describing the contract (article 2).
NOT_A_STATUS = {
    "approval-resolve-request/resolution": (
        "an instruction the caller sends, not a state the system reports; a "
        "resolution that means 'did not look' is a request that asks nothing"
    ),
    "whoami-result/mode": (
        "the deployment mode the daemon was started in, which it always knows "
        "of itself; a daemon that could not say would not have started"
    ),
    "grant-signal/kind": (
        "which message this is, not how anything is; a signal of unknown kind "
        "is a signal the reader must discard rather than render"
    ),
    "evidence-verdict/declared_gaps/items/reason": (
        "why a gap that is already declared was declared; the unknown case is "
        "the absence of the declaration, which the condition member reports"
    ),
    "evidence-entry/$defs/capture/oneOf/truncated": (
        "whether the bytes that were captured were cut, established by the "
        "capturer that cut them; the unknown case is the absent capture member "
        "that article 11 makes the default"
    ),
    "evidence-entry-writer/$defs/capture/oneOf/truncated": (
        "the same captured-bytes flag on the new-writer shape, established by the "
        "capturer that cut them; the absent capture member is still the default"
    ),
    "evidence-entry/$defs/effect-body/oneOf/correlation_source": (
        "who chose the bytes of the correlation member, the boundary or nobody; "
        "provenance the daemon establishes by reading the request, and the unknown "
        "case is the historical body without the member, which the reader admits"
    ),
    "evidence-entry-writer/$defs/effect-body/correlation_source": (
        "the same provenance mark on the new-writer shape, which requires it: a "
        "writer of this shape read the request and knows who chose the bytes"
    ),
    "evidence-verdict/covers_an_entry": (
        "whether the verified range held an entry at all, which the verifier "
        "establishes by reading it; the unread case is condition 'unverifiable'"
    ),
}


def _schema_name(source: Path) -> str:
    return source.name.removesuffix(".json").removesuffix(".schema")


def _fields(node: object, path: str, *, optional_above: bool) -> list[tuple[str, dict, bool]]:
    """Every enum-bearing or boolean field in one schema, with its path.

    `optional_above` carries whether this field, or any object member on the
    way to it, may be absent: absence is the third state a client renders as
    unknown, and a required member has no such state to fall back on.
    """
    found: list[tuple[str, dict, bool]] = []
    if isinstance(node, list):
        for item in node:
            found.extend(_fields(item, path, optional_above=optional_above))
        return found
    if not isinstance(node, dict):
        return found
    if isinstance(node.get("enum"), list) or node.get("type") == "boolean":
        found.append((path, node, optional_above))
    for key, value in node.items():
        if key == "properties" and isinstance(value, dict):
            required = set(node.get("required", []))
            for name, sub in value.items():
                found.extend(
                    _fields(
                        sub,
                        f"{path}/{name}",
                        optional_above=optional_above or name not in required,
                    )
                )
        elif key not in ("enum", "required"):
            found.extend(_fields(value, f"{path}/{key}", optional_above=optional_above))
    return found


def surveyed(
    schemas: Iterable[tuple[str, dict]] | None = None,
) -> dict[str, tuple[dict, bool]]:
    """Every state-bearing field of every published schema, keyed by its path.

    The schemas may be supplied so that the same discovery can be run over a
    planted one below. A walk that can only be pointed at the contract that
    passes cannot be shown to notice the field that was added without an
    unknown state, which is the whole defect it exists for.
    """
    found: dict[str, tuple[dict, bool]] = {}
    if schemas is not None:
        for name, schema in schemas:
            for path, field, optional in _fields(schema, name, optional_above=False):
                found[path] = (field, optional)
        return found
    for source in sorted(CONTRACTS.rglob("*.json")):
        document = json.loads(source.read_text(encoding="utf-8"))
        components = document.get("components", {}).get("schemas")
        roots = components.items() if components else ((_schema_name(source), document),)
        for name, schema in roots:
            for path, field, optional in _fields(schema, name, optional_above=False):
                found[path] = (field, optional)
    return found


def _states(field: dict) -> list[object]:
    return list(field["enum"]) if isinstance(field.get("enum"), list) else [True, False]


def _two_valued(fields: dict[str, tuple[dict, bool]]) -> dict[str, list[object]]:
    return {
        path: _states(field)
        for path, (field, optional) in fields.items()
        if len(_states(field)) == 2 and not optional and path not in NOT_A_STATUS
    }


def _without_unknown(fields: dict[str, tuple[dict, bool]]) -> dict[str, list[object]]:
    without = {}
    for path, (field, optional) in fields.items():
        name = path.rsplit("/", 1)[-1]
        if not any(marker in name for marker in STATUS_NAMES):
            continue
        if optional or set(_states(field)) & UNKNOWN_MEANING:
            continue
        without[path] = _states(field)
    return without


#: A schema carrying a two-valued status member and no unknown state, written
#: the way the audit of 2026-09-06 wrote its probe 18. It is planted below on
#: every run; it is never written into the published contracts.
PLANTED_STATUS_SCHEMA = {
    "type": "object",
    "required": ["audit_health"],
    "properties": {
        "audit_health": {
            "type": "string",
            "enum": ["healthy", "unhealthy"],
        }
    },
}


def test_no_published_status_offers_two_states_and_no_third() -> None:
    """Article 2: "looked and found nothing" and "did not look" are different facts."""
    two_valued = _two_valued(surveyed())
    assert two_valued == {}, two_valued
    # Anti-vacuity: a walk that reached few fields would pass by having found
    # nothing, and a reason recorded against a field the contract no longer
    # publishes describes nothing.
    assert len(surveyed()) >= 15, len(surveyed())
    assert set(NOT_A_STATUS) <= set(surveyed()), set(NOT_A_STATUS) - set(surveyed())


def test_every_field_that_reports_a_state_carries_an_explicit_unknown() -> None:
    """Article 2: an absence is never rendered as a negative fact or a healthy one."""
    without = _without_unknown(surveyed())
    assert without == {}, without
    # Anti-vacuity: the names above must match something this contract publishes.
    assert any(
        any(marker in path.rsplit("/", 1)[-1] for marker in STATUS_NAMES) for path in surveyed()
    )


def test_this_guard_still_catches_a_planted_two_valued_status() -> None:
    """Article 2: a walk that cannot be shown to fail has checked nothing.

    The member this reports on success is the one it *would* have reported had
    the plant been real. It is not a live violation: the schema it names is
    never written to the contracts directory.
    """
    fields = surveyed([("status-result", PLANTED_STATUS_SCHEMA)])
    two_valued = _two_valued(fields)
    assert two_valued, (
        "FAIL the planted two-valued status was not caught: this guard cannot fail. "
        "The walk read a schema with a required member offering only 'healthy' and "
        "'unhealthy', and reported no failure."
    )
    assert "status-result/audit_health" in two_valued, two_valued
    without = _without_unknown(fields)
    assert "status-result/audit_health" in without, without
