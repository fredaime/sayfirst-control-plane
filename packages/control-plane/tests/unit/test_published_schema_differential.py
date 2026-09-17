# SPDX-License-Identifier: Apache-2.0
"""The checker judged by documents no author chose, against a real validator.

Article 2: "this checker holds the published schema" is a claim, and the
evidence offered for it was a corpus of documents its author wrote down. A
corpus one author chose is a blind spot by construction: it holds the cases
that author thought of, so the defects that survive it are the ones nobody
thought of. The evidence here is generated instead — the schema itself says
where its boundaries are, and a seeded generator walks them.

The generator is schema-directed and deterministic. For each published request
schema it reads the keywords of every node and builds values that sit *on* the
edges those keywords draw: the empty string, one code point under and over
`maxLength`, a string within the code-point bound and past the UTF-8 bound
`x-max-bytes` publishes beside it, a witness built by expanding the published
`pattern` and near-misses of that witness, one item under and over `minItems`
and `maxItems`, a repeated item, a required member absent, a member of the
right name at the wrong type, an unpublished member, and a value nested one
level past the depth the schema publishes. Uniformly random documents would
almost all be refused for the first reason any reader finds, and would never
land where two readers differ.

Every generated document is put to both readers — the checker the daemon runs,
and `jsonschema`, a development dependency and never a runtime one (articles 13
and 14) — and the two must agree on accept or refuse. Where they disagree the
checker is wrong whichever way round it is: too lax accepts a request the
contract refuses, which is the defect this module exists to close; too strict
refuses a request a client generated from the published contract may send, so
the daemon is not implementable from its own contract (article 13).

`tests/unit/test_published_schema.py` keeps the hand-written corpus, and the
named cases below it; this file does not replace either, because a named case
says what a rule *is* and a generated one only says that two readers agree.

Runtime is named here so this stays a gate somebody runs: about ten seconds,
most of it the eleven anti-vacuity runs.
"""

from __future__ import annotations

import copy
import json
import random
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Final

import pytest
from sayfirst_contract.artifacts import domain_schema
from sayfirst_control_plane.domain import published_schema
from sayfirst_testing.schemas import document_is_valid, jsonschema_accepts

#: Fixed, so a disagreement this run reports is reproducible from the report.
SEED: Final[int] = 20260904

#: The request schemas the daemon checks with this module, and nothing else:
#: what a route publishes is what a route can be asked.
ROOTS: Final[tuple[str, ...]] = ("decision-ask-request", "approval-resolve-request")

#: Documents per root. Large enough that the run is evidence rather than a
#: gesture, small enough that the gate stays something a person waits for.
DOCUMENTS: Final[int] = 3000

#: A shorter run for each proof that the harness can fail; eleven of them run.
#: Not so short that a proof passes on a handful of documents: one that fires
#: rarely says the harness *can* catch the keyword, not that it does.
DOCUMENTS_FOR_ANTI_VACUITY: Final[int] = 1000


# ---------------------------------------------------------------------------
# Expanding a published pattern, so the generator can produce a string one
# matches and then miss it narrowly.
# ---------------------------------------------------------------------------

_REPETITIONS: Final[dict[str, tuple[int, int]]] = {"*": (0, 3), "+": (1, 3), "?": (0, 1)}


class PatternBeyondThisGenerator(ValueError):
    """A published pattern uses more regex than this generator can expand.

    Raised rather than worked around: a generator that silently produced no
    matching string for a pattern would drive refusals only through that
    member, and the run would look like evidence while covering nothing.
    """


def _character_class(body: str) -> str:
    """Every character `[body]` admits, ranges expanded."""
    if body.startswith("^"):
        raise PatternBeyondThisGenerator(f"a negated class, [^{body[1:]}]")
    admitted: list[str] = []
    index = 0
    while index < len(body):
        if body[index] == "\\":
            admitted.append(body[index + 1])
            index += 2
        elif index + 2 < len(body) and body[index + 1] == "-":
            first, last = ord(body[index]), ord(body[index + 2])
            admitted.extend(chr(point) for point in range(first, last + 1))
            index += 3
        else:
            admitted.append(body[index])
            index += 1
    return "".join(admitted)


def _parse(pattern: str, index: int = 0, closing: str = "") -> tuple[list[list[Any]], int]:
    """`pattern` read as atoms `[kind, payload, fewest, most]`, from `index`."""
    atoms: list[list[Any]] = []
    while index < len(pattern):
        character = pattern[index]
        if character == closing:
            return atoms, index
        if character == "|":
            raise PatternBeyondThisGenerator(f"alternation, in {pattern!r}")
        if character in "^$":
            index += 1
            continue
        if character == "\\":
            atoms.append(["characters", pattern[index + 1], 1, 1])
            index += 2
        elif character == "[":
            close = pattern.index("]", index + 1)
            atoms.append(["characters", _character_class(pattern[index + 1 : close]), 1, 1])
            index = close + 1
        elif character == "(":
            start = index + 3 if pattern.startswith("(?:", index) else index + 1
            inner, index = _parse(pattern, start, ")")
            atoms.append(["group", inner, 1, 1])
            index += 1
        else:
            atoms.append(["characters", character, 1, 1])
            index += 1
        index = _read_repetition(pattern, index, atoms[-1])
    return atoms, index


def _read_repetition(pattern: str, index: int, atom: list[Any]) -> int:
    """Apply the quantifier at `index`, if there is one, to the atom just read."""
    if index >= len(pattern):
        return index
    if pattern[index] in _REPETITIONS:
        atom[2], atom[3] = _REPETITIONS[pattern[index]]
        return index + 1
    if pattern[index] != "{":
        return index
    close = pattern.index("}", index)
    bounds = pattern[index + 1 : close].split(",")
    atom[2] = int(bounds[0])
    # `{n}` is exact, `{n,m}` is bounded, `{n,}` is open and gets a small ceiling.
    atom[3] = atom[2] if len(bounds) == 1 else int(bounds[1]) if bounds[1] else atom[2] + 2
    return close + 1


def _emit(atoms: Sequence[Sequence[Any]], rng: random.Random, how: str) -> str:
    """A string the atoms match, each repeated `how` many times."""
    written: list[str] = []
    for kind, payload, fewest, most in atoms:
        times = fewest if how == "fewest" else most if how == "most" else rng.randint(fewest, most)
        for _ in range(times):
            one = rng.choice(payload) if kind == "characters" else _emit(payload, rng, how)
            written.append(one)
    return "".join(written)


def _near_misses(witness: str, rng: random.Random) -> list[str]:
    """Strings a hair away from one the pattern matches."""
    if not witness:
        return ["x", " "]
    position = rng.randrange(len(witness))
    return [
        witness + "\n",
        "\n" + witness,
        witness + " ",
        " " + witness,
        witness.upper(),
        witness[:-1],
        witness + witness,
        witness[:position] + "!" + witness[position + 1 :],
        witness[:position] + "é" + witness[position + 1 :],
    ]


# ---------------------------------------------------------------------------
# The generator.
# ---------------------------------------------------------------------------

#: Single letters to build length-boundary strings from: one byte each, then
#: two, four and six in UTF-8, then the ones a careless reader mishandles.
_LETTERS: Final[tuple[str, ...]] = (
    "a",
    "A",
    "0",
    ".",
    "-",
    "/",
    " ",
    "\n",
    "\x00",
    "é",
    "😀",
    "क्",
    "\ud800",
)

#: Values of the wrong shape entirely, including one nested past any published
#: depth, put where a member of the right name is published.
_FOREIGN: Final[tuple[Any, ...]] = (
    None,
    True,
    False,
    0,
    1,
    -1,
    1.0,
    2.0,
    0.5,
    10**20,
    "",
    "x",
    [],
    {},
    [1],
    {"a": 1},
    [[1]],
    {"chain": [{"kind": {"kind": "user"}}]},
)

#: Member names the published schemas do not publish, for the extra member.
_UNPUBLISHED: Final[tuple[str, ...]] = ("principal", "x", "", "Capability", "scope ", "chain")


#: How a mutation lands, by what it lands on. Drawing one mutation for every
#: shape wasted most of the draws — "repeat" on a string did nothing, so the
#: run reached one item past `maxItems` about six times in four hundred
#: documents, and an anti-vacuity proof that fires six times in four hundred is
#: one rng draw away from proving nothing. `replace` is drawn most often in
#: each: a boundary value in the right place is where readers part company.
_MUTATIONS: Final[dict[str, tuple[str, ...]]] = {
    "array": ("replace", "replace", "delete", "deepen", "repeat", "repeat", "respell", "drop_item"),
    "unique": ("respell", "respell", "respell", "repeat", "replace", "drop_item"),
    "object": ("replace", "replace", "replace", "delete", "unpublished", "unpublished", "deepen"),
    "scalar": ("replace", "replace", "replace", "replace", "delete", "deepen"),
}


class Generator:
    """Documents that sit on the boundaries a published schema draws.

    A document is built by satisfying the schema and then moving one or two
    values onto an edge of it. Building each value independently at random
    produced documents refused for the first reason any reader finds — the
    corpus was 3000 documents and one of them was accepted — so nothing past
    that first reason was ever reached, and a checker blind to `minLength`
    went unnoticed. Starting from a document the schema accepts and moving one
    value puts the mutation where the readers can differ over it.
    """

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self._strings: dict[str, tuple[str, ...]] = {}
        self._numbers: dict[str, tuple[Any, ...]] = {}
        self._sharp: dict[str, tuple[str, ...]] = {}

    # -- a document ---------------------------------------------------------

    def document(self, root: str) -> dict[str, object]:
        """One generated document for the published schema named `root`."""
        schema = domain_schema(root)
        if self.rng.random() < 0.12:
            # A minority built value by value, so the corpus is not only ever
            # one or two steps from something the schema accepts.
            value = self.boundary(schema, depth=0, foreign=False)
        else:
            value = self.valid(schema)
            for _ in range(self.rng.choices((0, 1, 2, 3), weights=(20, 50, 22, 8))[0]):
                value = self.mutate(value, schema)
        if not isinstance(value, dict):
            value = {"contract_generation": value}
        return value

    def mutate(self, document: object, schema: Mapping[str, object]) -> object:
        """`document` with one value moved onto an edge of `schema`."""
        places = list(_walk(document, schema))
        path, node = self.rng.choice(places)
        here = _at(document, path)
        if isinstance(here, list):
            shape = "unique" if node.get("uniqueItems") is True else "array"
        else:
            shape = "object" if isinstance(here, Mapping) else "scalar"
        how = self.rng.choice(_MUTATIONS[shape])
        if how == "delete" and path:
            return _without_path(document, path)
        if how == "unpublished" and isinstance(here, Mapping):
            member = self.rng.choice(_UNPUBLISHED)
            return _replace(document, path, {**here, member: self.boundary(node, len(path))})
        if how == "deepen":
            wrapped = self.rng.choice(({"chain": here}, [here]))
            return _replace(document, path, wrapped)
        if how == "repeat" and isinstance(here, list) and here:
            # Enough copies to land one past `maxItems`, which is where the
            # keyword can be told from its absence; one more never got there.
            most = node.get("maxItems")
            extra = max(1, most + 1 - len(here)) if isinstance(most, int) else 2
            copies = [copy.deepcopy(here[0]) for _ in range(extra)]
            return _replace(document, path, [*here, *copies])
        if how == "respell" and isinstance(here, list) and here:
            # The same JSON value written another way. An exact copy is refused
            # by anything comparing spellings as readily as by anything
            # comparing values, so repeating one says nothing about which a
            # checker does; `1` beside `1.0`, or two objects written in a
            # different order, is the pair that tells them apart. It replaces
            # rather than appends where there is room, so the array stays
            # inside `maxItems` and `uniqueItems` is all that can refuse it.
            again = _spelled_again(here[0])
            paired = [*here[:-1], again] if len(here) > 1 else [*here, again]
            return _replace(document, path, paired)
        if how == "drop_item" and isinstance(here, list) and here:
            return _replace(document, path, here[:-1])
        return _replace(document, path, self.boundary(node, len(path)))

    # -- a document the schema accepts --------------------------------------

    def valid(self, schema: Mapping[str, object], depth: int = 0) -> object:
        """A value the published schema accepts, to move one edge of later."""
        schema = _resolve(schema)
        if "const" in schema:
            return schema["const"]
        allowed = schema.get("enum")
        if isinstance(allowed, list) and allowed:
            return copy.deepcopy(self.rng.choice(allowed))
        declared = schema.get("type")
        names = declared if isinstance(declared, list) else [declared]
        name = str(self.rng.choice(names))
        if name == "object":
            published = schema.get("properties") or {}
            assert isinstance(published, Mapping)
            return {member: self.valid(sub, depth + 1) for member, sub in published.items()}
        if name == "array":
            items = schema.get("items")
            fewest = schema.get("minItems")
            most = schema.get("maxItems")
            length = max(1, fewest if isinstance(fewest, int) else 1)
            if isinstance(most, int):
                length = min(length, most)
            if not isinstance(items, Mapping):
                return ["a"] * length
            return [self.valid(items, depth + 1) for _ in range(length)]
        if name == "string":
            return self.valid_string(schema)
        if name in ("integer", "number"):
            floor = schema.get("minimum")
            return floor if isinstance(floor, int) and not isinstance(floor, bool) else 1
        if name == "boolean":
            return True
        return None

    def valid_string(self, schema: Mapping[str, object]) -> str:
        """A string satisfying every bound and pattern this node publishes."""
        fewest = schema.get("minLength")
        floor = fewest if isinstance(fewest, int) else 0
        pattern = schema.get("pattern")
        candidates: list[str] = []
        if isinstance(pattern, str):
            atoms, _ = _parse(pattern)
            candidates = [_emit(atoms, self.rng, how) for how in ("fewest", "any", "most")]
        else:
            documented = schema.get("x-documented-values")
            if isinstance(documented, list) and documented:
                candidates = [str(item) for item in documented]
            candidates.append("a" * max(1, floor))
        for candidate in candidates:
            if _within(schema, candidate):
                return candidate
        raise PatternBeyondThisGenerator(f"no string this builds satisfies {dict(schema)}")

    # -- a value on an edge --------------------------------------------------

    def boundary(self, schema: Mapping[str, object], depth: int, foreign: bool = True) -> object:
        """A value on or just past an edge this node draws."""
        schema = _resolve(schema)
        if depth > 5:
            return None
        if foreign and self.rng.random() < 0.22:
            return copy.deepcopy(self.rng.choice(_FOREIGN))
        if "const" in schema:
            return self.rng.choice((schema["const"], "x", None, True, 1, 0))
        allowed = schema.get("enum")
        if isinstance(allowed, list):
            near = [f"{item}x" for item in allowed] + [str(item).upper() for item in allowed]
            return copy.deepcopy(self.rng.choice([*allowed, *near, "", None, 1, True]))
        declared = schema.get("type")
        names = declared if isinstance(declared, list) else [declared]
        name = str(self.rng.choice(names))
        if name == "object":
            return self.object(schema, depth)
        if name == "array":
            return self.array(schema, depth)
        if name == "string":
            return self.string(schema)
        if name in ("integer", "number"):
            return self.rng.choice(self.numbers(schema))
        if name == "boolean":
            return self.rng.choice((True, False))
        return None

    def string(self, schema: Mapping[str, object]) -> str:
        """One string, drawn from a pool weighted towards the sharpest edges.

        A node with a `maxLength` of 128 draws a pool of about a hundred and
        ten, of which the empty string is one; dropping `minLength` from the
        checker then showed up three times in two thousand documents, which
        says the harness *can* catch it rather than that it does. The handful
        of values exactly on an edge are drawn as often as all the rest.
        """
        sharp = self.sharp(schema)
        if sharp and self.rng.random() < 0.4:
            return self.rng.choice(sharp)
        return self.rng.choice(self.strings(schema))

    def sharp(self, schema: Mapping[str, object]) -> tuple[str, ...]:
        """The few strings exactly on, and exactly one past, this node's edges."""
        key = _key(schema)
        cached = self._sharp.get(key)
        if cached is not None:
            return cached
        pool = [""]
        for bound in (schema.get("minLength"), schema.get("maxLength")):
            if isinstance(bound, int):
                pool.extend("a" * count for count in (bound - 1, bound, bound + 1) if count >= 0)
        byte_bound = schema.get("x-max-bytes")
        if isinstance(byte_bound, int):
            # Inside the code-point bound and one code point past the byte one.
            pool.extend(["é" * (byte_bound // 2), "é" * (byte_bound // 2 + 1), "\ud800"])
        self._sharp[key] = tuple(dict.fromkeys(pool))
        return self._sharp[key]

    def object(self, schema: Mapping[str, object], depth: int) -> dict[str, object]:
        published = schema.get("properties") or {}
        assert isinstance(published, Mapping)
        document: dict[str, object] = {}
        for member, subschema in published.items():
            # A member is sometimes absent, so a required one sometimes is too.
            if self.rng.random() < 0.85:
                assert isinstance(subschema, Mapping)
                document[member] = self.boundary(subschema, depth + 1)
        if self.rng.random() < 0.15:
            document[self.rng.choice(_UNPUBLISHED)] = copy.deepcopy(self.rng.choice(_FOREIGN))
        return document

    def array(self, schema: Mapping[str, object], depth: int) -> list[object]:
        items = schema.get("items")
        counts = {0, 1, 2}
        for bound in (schema.get("minItems"), schema.get("maxItems")):
            if isinstance(bound, int):
                counts.update({bound - 1, bound, bound + 1})
        length = self.rng.choice(sorted(count for count in counts if 0 <= count <= 6))
        value = [
            self.boundary(items, depth + 1)
            if isinstance(items, Mapping)
            else copy.deepcopy(self.rng.choice(_FOREIGN))
            for _ in range(length)
        ]
        if length > 1 and self.rng.random() < 0.4:
            # A repeated item, for a schema that publishes uniqueItems. Two
            # items equal as JSON but not as Python — `1` and `1.0`, or two
            # objects written in a different order — are the pair a checker
            # comparing spellings calls unique.
            value[-1] = self.rng.choice((copy.deepcopy(value[0]), _spelled_again(value[0])))
        return value

    def strings(self, schema: Mapping[str, object]) -> tuple[str, ...]:
        """The string boundaries this node draws, built once per node."""
        key = _key(schema)
        cached = self._strings.get(key)
        if cached is not None:
            return cached
        pool = ["", "a", " ", "\n", "\x00", "é", "😀"]
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            atoms, _ = _parse(pattern)
            for how in ("fewest", "most", "any", "any"):
                witness = _emit(atoms, self.rng, how)
                pool.append(witness)
                pool.extend(_near_misses(witness, self.rng))
        for letter in _LETTERS:
            pool.extend(letter * count for count in self._counts(schema, letter))
        documented = schema.get("x-documented-values")
        if isinstance(documented, list):
            pool.extend(str(item) for item in documented)
            pool.extend(f"{item}x" for item in documented)
        self._strings[key] = tuple(dict.fromkeys(pool))
        return self._strings[key]

    @staticmethod
    def _counts(schema: Mapping[str, object], letter: str) -> set[int]:
        """Repetition counts of `letter` that straddle this node's bounds."""
        width = len(letter.encode("utf-8", "surrogatepass"))
        counts = {0, 1, 2}
        for bound in (schema.get("minLength"), schema.get("maxLength")):
            if isinstance(bound, int):
                counts.update({bound - 1, bound, bound + 1})
        byte_bound = schema.get("x-max-bytes")
        if isinstance(byte_bound, int):
            # The code-point counts either side of the published byte bound:
            # within `maxLength` and past `x-max-bytes` is the gap between them.
            counts.update({byte_bound // width, byte_bound // width + 1})
        return {count for count in counts if 0 <= count <= 2048}

    def numbers(self, schema: Mapping[str, object]) -> tuple[Any, ...]:
        """The numeric boundaries this node draws, built once per node."""
        key = _key(schema)
        cached = self._numbers.get(key)
        if cached is not None:
            return cached
        pool: list[Any] = [0, 1, -1, 2, 0.0, 1.0, 2.0, 0.5, -0.5, 10**20, True, False, "1"]
        for bound in (schema.get("minimum"), schema.get("maximum")):
            if isinstance(bound, int | float) and not isinstance(bound, bool):
                # Under, on and over the bound, as an integer and as a number
                # of the same value, which JSON Schema calls an integer too.
                pool.extend([bound - 1, bound, bound + 1, float(bound), bound + 0.5, bound - 0.5])
        self._numbers[key] = tuple(dict.fromkeys(pool))
        return self._numbers[key]


def _spelled_again(value: object) -> object:
    """The same JSON value written another way, where there is another way."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, Mapping):
        return dict(reversed(list(value.items())))
    return copy.deepcopy(value)


def _key(schema: Mapping[str, object]) -> str:
    """What a schema node says, as one hashable string.

    A pool is cached against this and not against `id(schema)`: the published
    schemas are read fresh from their artefact on every call, so an address
    identifies nothing that outlives the call and is handed out again to the
    next node the allocator sees.
    """
    return json.dumps(schema, sort_keys=True, default=str)


def _within(schema: Mapping[str, object], value: str) -> bool:
    """Whether `value` sits inside the length bounds this node publishes."""
    fewest, most = schema.get("minLength"), schema.get("maxLength")
    byte_bound = schema.get("x-max-bytes")
    if isinstance(fewest, int) and len(value) < fewest:
        return False
    if isinstance(most, int) and len(value) > most:
        return False
    return not (isinstance(byte_bound, int) and len(value.encode()) > byte_bound)


# ---------------------------------------------------------------------------
# Reaching into a generated document, so a mutation can land anywhere in one.
# ---------------------------------------------------------------------------


def _walk(
    document: object, schema: Mapping[str, object], path: tuple[object, ...] = ()
) -> Iterator[tuple[tuple[object, ...], Mapping[str, object]]]:
    """Every place in `document` a mutation can land, with the schema for it."""
    schema = _resolve(schema)
    yield path, schema
    if isinstance(document, Mapping):
        published = schema.get("properties") or {}
        assert isinstance(published, Mapping)
        for member, item in document.items():
            subschema = published.get(member)
            if isinstance(subschema, Mapping):
                yield from _walk(item, subschema, (*path, member))
    elif isinstance(document, list):
        items = schema.get("items")
        if isinstance(items, Mapping):
            for index, item in enumerate(document):
                yield from _walk(item, items, (*path, index))


def _at(document: object, path: Sequence[object]) -> object:
    for step in path:
        document = document[step]  # type: ignore[index]
    return document


def _replace(document: object, path: Sequence[object], value: object) -> object:
    """`document` with `value` at `path`, sharing nothing that changed."""
    if not path:
        return value
    step, rest = path[0], path[1:]
    if isinstance(document, Mapping):
        return {**document, step: _replace(document[step], rest, value)}  # type: ignore[index]
    assert isinstance(document, list)
    index = int(step)  # type: ignore[call-overload]
    return [*document[:index], _replace(document[index], rest, value), *document[index + 1 :]]


def _without_path(document: object, path: Sequence[object]) -> object:
    """`document` with whatever `path` names taken out of it."""
    if len(path) > 1:
        return _replace(document, path[:-1], _without_path(_at(document, path[:-1]), path[-1:]))
    step = path[0]
    if isinstance(document, Mapping):
        return {member: item for member, item in document.items() if member != step}
    assert isinstance(document, list)
    index = int(step)  # type: ignore[call-overload]
    return [*document[:index], *document[index + 1 :]]


def _resolve(schema: Mapping[str, object]) -> Mapping[str, object]:
    """Follow a published `$ref`, spelled here so the generator is not the checker."""
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.endswith(".schema.json"):
        return _resolve(domain_schema(reference.removesuffix(".schema.json")))
    return schema


# ---------------------------------------------------------------------------
# Putting one document to both readers, and shrinking what disagrees.
# ---------------------------------------------------------------------------


def _checker_accepts(document: object, root: str) -> bool | str:
    """What the daemon's checker says, or how it failed to say anything."""
    try:
        return published_schema.refused_by(document, root) is None  # type: ignore[arg-type]
    except Exception as failure:
        return f"raised {type(failure).__name__}: {failure}"


def _disagreement(document: object, root: str) -> str | None:
    """How the two readers differ over `document`, or `None` if they do not."""
    checker = _checker_accepts(document, root)
    published = document_is_valid(document, root)  # type: ignore[arg-type]
    if checker is published:
        return None
    if isinstance(checker, str):
        return f"the checker {checker}, where the published schema says {published}"
    return (
        "the checker accepts what the published schema refuses"
        if checker
        else "the checker refuses what the published schema accepts"
    )


def _simplifications(value: object) -> Iterator[object]:
    """Documents smaller than `value`, the most aggressive cut first."""
    if isinstance(value, Mapping):
        for member in value:
            yield {key: item for key, item in value.items() if key != member}
        for member, item in value.items():
            for smaller in _simplifications(item):
                yield {**value, member: smaller}
    elif isinstance(value, list):
        for index in range(len(value)):
            yield [*value[:index], *value[index + 1 :]]
        for index, item in enumerate(value):
            for smaller in _simplifications(item):
                yield [*value[:index], smaller, *value[index + 1 :]]
    elif isinstance(value, str) and value:
        yield ""
        yield value[: len(value) // 2]
        yield value[:-1]
    elif isinstance(value, int | float) and not isinstance(value, bool) and value not in (0, 1):
        yield 0
        yield 1


def _reported(found: Mapping[str, object], where: str) -> str:
    """The disagreements, smallest first, so the shrunk cases are the ones read."""
    smallest = sorted(found, key=lambda case: (len(case), case))[:20]
    return f"{where}:\n" + "\n".join(smallest)


def _shrink(document: object, root: str) -> object:
    """The smallest document reachable from `document` that still disagrees."""
    for _ in range(2000):
        for candidate in _simplifications(document):
            if _disagreement(candidate, root) is not None:
                document = candidate
                break
        else:
            break
    return document


def _corpus(root: str, documents: int, seed: int = SEED) -> list[dict[str, object]]:
    """The generated corpus, built once per (root, count, seed) and reused."""
    key = (root, documents, seed)
    if key not in _CORPORA:
        generator = Generator(random.Random(seed))
        _CORPORA[key] = [generator.document(root) for _ in range(documents)]
    return _CORPORA[key]


_CORPORA: dict[tuple[str, int, int], list[dict[str, object]]] = {}


def _disagreements(
    root: str, documents: int, seed: int = SEED, shrink_at_most: int = 20
) -> dict[str, object]:
    """One entry per distinct disagreement, keyed by its smallest document."""
    found: dict[str, object] = {}
    shrunk = 0
    for document in _corpus(root, documents, seed):
        complaint = _disagreement(document, root)
        if complaint is None:
            continue
        smallest: object = document
        if shrunk < shrink_at_most:
            smallest = _shrink(document, root)
            shrunk += 1
        found.setdefault(f"{root}: {complaint}: {smallest!r}", smallest)
    return found


# ---------------------------------------------------------------------------
# The differential.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root", ROOTS)
def test_the_checker_answers_what_a_validator_answers_on_generated_documents(root: str) -> None:
    """Article 13: the published schema is the arbiter, and this reads it as one does."""
    found = _disagreements(root, DOCUMENTS)
    assert not found, _reported(found, f"seed {SEED}, {DOCUMENTS} documents")


@pytest.mark.parametrize("root", ROOTS)
def test_the_generated_corpus_holds_both_answers_and_reaches_every_published_member(
    root: str,
) -> None:
    """Anti-vacuity: a corpus that was all one answer, or all one member, proves nothing."""
    accepted, reached = 0, set()
    for document in _corpus(root, DOCUMENTS):
        reached.update(document)
        accepted += document_is_valid(document, root)
    published = domain_schema(root)["properties"]
    assert isinstance(published, dict)
    assert accepted >= DOCUMENTS // 20, accepted
    assert DOCUMENTS - accepted >= DOCUMENTS // 20, accepted
    assert set(published) <= reached, set(published) - reached


def test_the_generator_can_still_produce_a_string_every_published_pattern_matches() -> None:
    """A pattern this generator cannot expand would drive refusals only, in silence."""
    rng = random.Random(SEED)
    patterns = _published_patterns()
    assert patterns, "no published request schema carries a pattern"
    for where, pattern in patterns.items():
        atoms, _ = _parse(pattern)
        for how in ("fewest", "most", "any"):
            witness = _emit(atoms, rng, how)
            assert re.search(pattern, witness) is not None, (where, pattern, witness)


def _published_patterns() -> dict[str, str]:
    found: dict[str, str] = {}

    def walk(schema: Mapping[str, object], where: str) -> None:
        schema = _resolve(schema)
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            found[where] = pattern
        properties = schema.get("properties") or {}
        assert isinstance(properties, Mapping)
        for member, subschema in properties.items():
            assert isinstance(subschema, Mapping)
            walk(subschema, f"{where}.{member}")
        items = schema.get("items")
        if isinstance(items, Mapping):
            walk(items, f"{where}[]")

    for root in ROOTS:
        walk(domain_schema(root), root)
    return found


# ---------------------------------------------------------------------------
# Anti-vacuity: the harness catches a checker that drops a keyword.
# ---------------------------------------------------------------------------

#: Every keyword the published request schemas assert with. Dropping one is
#: exactly the defect this module was written to close — the hand-written check
#: it replaced had dropped `maxLength` from two members — so the harness has to
#: catch each one going missing, or it is not evidence about any of them.
DROPPABLE: Final[tuple[str, ...]] = (
    "type",
    "enum",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "minItems",
    "maxItems",
    "required",
    "additionalProperties",
    "x-max-bytes",
)


def _without(schema: object, keyword: str, names: bool = False) -> object:
    """`schema` with every assertion by `keyword` removed; `names` for a member map."""
    if isinstance(schema, Mapping):
        return {
            member: _without(value, keyword, names=(not names and member == "properties"))
            for member, value in schema.items()
            if names or member != keyword
        }
    if isinstance(schema, list):
        return [_without(item, keyword) for item in schema]
    return schema


@pytest.mark.parametrize("keyword", DROPPABLE)
def test_the_differential_catches_a_checker_blind_to_one_keyword(
    monkeypatch: pytest.MonkeyPatch, keyword: str
) -> None:
    """Anti-vacuity: a harness that cannot fail is not evidence that anything holds.

    A checker blind to one keyword is made by handing the checker — and only
    the checker — the published schema with that keyword removed. The published
    readers still read the real one, so the two have to part company, and the
    generated corpus has to be the thing that notices.
    """
    monkeypatch.setattr(
        published_schema,
        "domain_schema",
        lambda name: _without(domain_schema(name), keyword),
    )
    found = {
        case
        for root in ROOTS
        for case in _disagreements(root, DOCUMENTS_FOR_ANTI_VACUITY, shrink_at_most=1)
    }
    assert found, f"dropping {keyword!r} went unnoticed by the generated documents"


# ---------------------------------------------------------------------------
# What the byte bound is, and what a generic validator does with it.
# ---------------------------------------------------------------------------


def test_the_published_byte_bound_is_an_assertion_a_generic_validator_cannot_make() -> None:
    """Article 13: `x-max-bytes` is published, so it is part of what a request must satisfy.

    JSON Schema has no byte-length keyword, so `maxLength` — the weaker
    code-point bound — is all a generic validator checks, and the delegation
    schema says so in its own description. A string within the code-point bound
    and past the byte bound is therefore accepted by `jsonschema` alone and
    refused by the published schema read whole, and the daemon's checker has to
    answer the second and not the first.
    """
    over = {
        "contract_generation": 1,
        "capability": "a.b",
        "delegation": {"chain": [{"kind": "é" * 33, "name": None, "uid": 0, "via": "scheduler"}]},
    }
    assert jsonschema_accepts(over, "decision-ask-request")
    assert not document_is_valid(over, "decision-ask-request")
    assert published_schema.refused_by(over, "decision-ask-request") is not None


# ---------------------------------------------------------------------------
# The second axis: schemas the contract does not publish yet, built from the
# keywords this checker says it holds.
# ---------------------------------------------------------------------------
#
# `_audit` refuses to run against a schema carrying a keyword the checker does
# not implement, which is a claim about the whole keyword set and not only
# about the two requests published today. Today's two reach nine of the fifteen
# — nothing published is a `number`, nothing publishes `uniqueItems` or `const`,
# and no `enum` publishes anything but strings — so a corpus of requests, chosen
# or generated, says nothing about the other six. A contract generation that
# grew one of them would have found out in production. So the schemas are
# generated too, and the documents against them.


#: Patterns for a planted string schema. Every one is a shape the published
#: patterns already use, so the expander above is what produces the witnesses.
_PLANTED_PATTERNS: Final[tuple[str, ...]] = (
    "^a+$",
    "^[a-z]{2,4}$",
    "^x[0-9]*$",
    "^[A-Za-z0-9._-]{1,8}$",
    "^(ab)+$",
    "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$",
)

#: Values a planted `enum` or `const` publishes. `1` and `1.0` are one JSON
#: value, `true` is not `1`, and an object is its members and not their order.
_PLANTED_VALUES: Final[tuple[Any, ...]] = (
    1,
    1.0,
    0,
    True,
    False,
    None,
    "1",
    "a",
    "",
    [],
    [1],
    [1, 2],
    {},
    {"a": 1},
    {"a": 1, "b": 2},
)


class SchemaGenerator:
    """Schemas built from the keywords the checker claims to hold."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def schema(self, depth: int = 0) -> dict[str, Any]:
        name = self.rng.choice(
            ("object", "array", "string", "integer", "number", "boolean", "null")
            if depth < 2
            else ("string", "integer", "number", "boolean", "null")
        )
        schema: dict[str, Any] = {"type": name}
        if self.rng.random() < 0.12:
            return {"enum": list(self.rng.sample(_PLANTED_VALUES, self.rng.randint(1, 4)))}
        if self.rng.random() < 0.08:
            return {"const": copy.deepcopy(self.rng.choice(_PLANTED_VALUES))}
        if name == "string":
            self.bound_string(schema)
        elif name in ("integer", "number"):
            self.bound_number(schema)
        elif name == "array":
            self.bound_array(schema, depth)
        elif name == "object":
            self.bound_object(schema, depth)
        return schema

    def bound_string(self, schema: dict[str, Any]) -> None:
        if self.rng.random() < 0.4:
            # A pattern and a length bound together can publish a string no
            # generator can build; each on its own always can.
            schema["pattern"] = self.rng.choice(_PLANTED_PATTERNS)
            return
        if self.rng.random() < 0.6:
            schema["minLength"] = self.rng.choice((0, 1, 2))
        if self.rng.random() < 0.6:
            schema["maxLength"] = self.rng.choice((0, 1, 3, 8))

    def bound_number(self, schema: dict[str, Any]) -> None:
        if self.rng.random() < 0.7:
            schema["minimum"] = self.rng.choice((0, 1, -1, 0.5, 1.5, -0.5))
        if self.rng.random() < 0.5:
            schema["maximum"] = self.rng.choice((0, 1, 4, 0.5, 2.5, 10))

    def bound_array(self, schema: dict[str, Any], depth: int) -> None:
        schema["items"] = self.schema(depth + 1)
        unique = self.rng.random() < 0.5 and self.rng.choice((True, False))
        if unique:
            schema["uniqueItems"] = True
        elif self.rng.random() < 0.3:
            schema["uniqueItems"] = False
        if self.rng.random() < 0.5:
            schema["minItems"] = self.rng.choice((0, 1, 2))
        if self.rng.random() < 0.5:
            # A `uniqueItems` beside a `maxItems` of one can never refuse
            # anything, so a schema publishing both tests neither reading of it.
            schema["maxItems"] = self.rng.choice((2, 3) if unique else (1, 2, 3))

    def bound_object(self, schema: dict[str, Any], depth: int) -> None:
        members = ("a", "b", "c")[: self.rng.randint(1, 3)]
        schema["properties"] = {member: self.schema(depth + 1) for member in members}
        if self.rng.random() < 0.6:
            schema["required"] = list(self.rng.sample(members, self.rng.randint(0, len(members))))
        if self.rng.random() < 0.6:
            schema["additionalProperties"] = self.rng.choice((True, False))


#: A planted schema is consistent by construction, but a `maxLength` of 0 with
#: a `minLength` of 2 is not, and neither is `minItems` above `maxItems`; a seed
#: no document satisfies is dropped rather than driven, and counted.
_PLANTED_SCHEMAS: Final[int] = 400
_PLANTED_DOCUMENTS: Final[int] = 8


def _planted_disagreements(
    seed: int = SEED, blind: str | None = None, schemas_driven: int = _PLANTED_SCHEMAS
) -> tuple[dict[str, object], int, int]:
    """Drive generated documents at generated schemas; the disagreements, and how many ran.

    `blind` hands the checker — and only the checker — each schema with that
    keyword taken out of it, which is what a checker that did not implement the
    keyword would answer.
    """
    import jsonschema

    rng = random.Random(seed)
    schemas = SchemaGenerator(rng)
    generator = Generator(rng)
    found: dict[str, object] = {}
    driven, unsatisfiable = 0, 0
    for _ in range(schemas_driven):
        schema = schemas.schema()
        validator = jsonschema.Draft202012Validator(schema)
        try:
            seeds = [generator.valid(schema) for _ in range(_PLANTED_DOCUMENTS)]
        except PatternBeyondThisGenerator:
            unsatisfiable += 1
            continue
        if not all(validator.is_valid(seed) for seed in seeds):
            # `uniqueItems` beside a `minItems` of three over a boolean is a
            # schema nothing satisfies; a mutation of a seed the schema already
            # refuses says nothing about either reader.
            unsatisfiable += 1
            continue
        documents = []
        for index, document in enumerate(seeds):
            for _ in range(rng.randint(1, 2) if index else 0):
                document = generator.mutate(document, schema)
            documents.append(document)
        documents += [generator.boundary(schema, depth=0) for _ in range(_PLANTED_DOCUMENTS)]
        for document in documents:
            driven += 1
            seen = schema if blind is None else _without(schema, blind)
            assert isinstance(seen, Mapping)
            checker = _checker_against(seen, document)
            published = validator.is_valid(document)
            if checker is published:
                continue
            found.setdefault(f"{schema}: {document!r}: checker said {checker}", document)
    return found, driven, unsatisfiable


def _checker_against(schema: Mapping[str, object], document: object) -> bool | str:
    """What the checker says about `document`, with `schema` published under a name."""
    real = published_schema.domain_schema

    def planted(asked: str) -> Mapping[str, object]:
        return dict(schema) if asked == "planted" else real(asked)

    published_schema.domain_schema = planted  # type: ignore[assignment]
    try:
        return _checker_accepts(document, "planted")
    finally:
        published_schema.domain_schema = real  # type: ignore[assignment]


def test_the_checker_answers_what_a_validator_answers_on_generated_schemas() -> None:
    """Article 2: the checker refuses a schema it cannot hold, so it claims all of these."""
    found, driven, _ = _planted_disagreements()
    assert not found, _reported(found, f"seed {SEED}, {driven} documents")


def test_the_generated_schemas_reach_every_keyword_the_checker_claims() -> None:
    """Anti-vacuity: a keyword no generated schema publishes is a keyword nothing tested."""
    rng = random.Random(SEED)
    schemas = SchemaGenerator(rng)
    reached: set[str] = set()

    def walk(schema: object) -> None:
        if isinstance(schema, Mapping):
            reached.update(schema)
            for value in schema.values():
                walk(value)
        elif isinstance(schema, list):
            for item in schema:
                walk(item)

    for _ in range(_PLANTED_SCHEMAS):
        walk(schemas.schema())
    claimed = set(published_schema._ASSERTIONS) - {"$ref", "x-max-bytes"}
    assert claimed <= reached, claimed - reached


def test_the_generated_schemas_hold_both_answers_and_are_mostly_satisfiable() -> None:
    """Anti-vacuity: schemas nothing satisfies would agree with any checker at all."""
    _, driven, unsatisfiable = _planted_disagreements()
    assert driven >= _PLANTED_SCHEMAS * _PLANTED_DOCUMENTS, driven
    assert unsatisfiable <= _PLANTED_SCHEMAS // 4, unsatisfiable


#: The keywords the checker claims that no published request reaches, so the
#: generated schemas are the only evidence there is about any of them.
UNREACHED_BY_ANY_REQUEST: Final[tuple[str, ...]] = (
    "const",
    "uniqueItems",
    "items",
    "maximum",
    "minimum",
    "enum",
    "additionalProperties",
)


@pytest.mark.parametrize("keyword", UNREACHED_BY_ANY_REQUEST)
def test_the_generated_schemas_catch_a_checker_blind_to_one_keyword(keyword: str) -> None:
    """Anti-vacuity, for the half of the keyword set no published request can reach."""
    found, _, _ = _planted_disagreements(blind=keyword, schemas_driven=120)
    assert found, f"dropping {keyword!r} went unnoticed by the generated schemas"


# ---------------------------------------------------------------------------
# The same differential, over the whole request path.
# ---------------------------------------------------------------------------
#
# Everything above judges one function. What a caller meets is the route: the
# framing, the member sweep, the generation guards, the delegation reader, and
# only then the checker. A guard in front of the checker can refuse what the
# checker accepts and no comparison of the checker against `jsonschema` would
# notice — which is precisely what happened. `contract_generation: 1.0` is one
# JSON number with a zero fractional part, the schema publishes `integer`, the
# checker reads it as the schema does and accepts it, and the route demanded a
# Python `int` in front of the checker and answered 400 `generation_unreadable`
# to a request generated from the published contract (article 13).
#
# So the corpus is driven through `RequestHandler` too, and the two-sided
# property is stated over what the daemon does with a whole request:
#
#   * a document the published schema refuses is never *served* — no answer
#     with a decision in it comes back for it; and
#   * a document the published schema accepts is never refused *for being
#     malformed* — `request_malformed`, `member_unknown`, `generation_missing`
#     and `generation_unreadable` are the four codes that say "this request is
#     not one the contract defines", and none of them may be the answer.
#
# The second clause is stated over those four codes rather than over "any
# refusal", because a request the schema accepts may still be refused for
# something the schema says nothing about: `generation_unsupported` for a
# generation this server does not speak, `delegation_invalid` for a
# declaration outside its bounds. Those are answers about the world, not about
# the shape of the document.

from handler_bytes import HandlerHost, answer_inline  # noqa: E402

#: The four codes that say "this is not a request of this contract". A document
#: the published schema accepts may meet none of them.
MALFORMED_CODES: Final[frozenset[str]] = frozenset(
    {"request_malformed", "member_unknown", "generation_missing", "generation_unreadable"}
)

#: Documents driven through the whole surface. Smaller than `DOCUMENTS`
#: because each one is a socket pair, a handler and an answer read back;
#: large enough that it is the generated corpus and not a sample of it.
REQUESTS: Final[int] = 1200


def _served_or_refused(host: HandlerHost, document: object) -> tuple[bool, str | None]:
    """Whether the daemon served a decision, and the problem code if it did not."""
    run = answer_inline(host, _request_of(document))
    if run.status() == 200:
        return True, None
    try:
        return False, str(run.document().get("code"))
    except ValueError:  # pragma: no cover - an answer with no document at all
        return False, None


def _request_of(document: object) -> bytes:
    body = json.dumps(document).encode()
    return b"\r\n".join(
        (
            b"POST /decisions HTTP/1.1",
            b"Host: sayfirst",
            b"Content-Type: application/json",
            b"Content-Length: " + str(len(body)).encode(),
            b"",
            body,
        )
    )


def _route_disagreements(host: HandlerHost, documents: Sequence[object]) -> dict[str, object]:
    """One entry per way the route and the published schema differ over a document."""
    found: dict[str, object] = {}
    for document in documents:
        accepted = document_is_valid(document, "decision-ask-request")  # type: ignore[arg-type]
        served, code = _served_or_refused(host, document)
        if not accepted and served:
            found.setdefault(f"served what the schema refuses: {document!r}", document)
        if accepted and code in MALFORMED_CODES:
            found.setdefault(
                f"answered {code!r} to what the schema accepts: {document!r}", document
            )
    return found


@pytest.fixture
def surface():  # type: ignore[no-untyped-def]
    """A composed decision surface that answers every well-formed ask."""
    made = HandlerHost()
    try:
        yield made
    finally:
        made.close()


def test_the_whole_request_path_answers_what_the_published_schema_answers(surface) -> None:  # type: ignore[no-untyped-def]
    """Article 13: the daemon is implementable from the contract it publishes."""
    found = _route_disagreements(surface, _corpus("decision-ask-request", REQUESTS))

    assert not found, _reported(found, f"seed {SEED}, {REQUESTS} requests through the surface")


def test_the_request_path_differential_holds_both_answers(surface) -> None:  # type: ignore[no-untyped-def]
    """Anti-vacuity: a corpus the daemon refused entirely would prove nothing."""
    served = 0
    for document in _corpus("decision-ask-request", REQUESTS):
        served += _served_or_refused(surface, document)[0]

    assert served >= REQUESTS // 50, served
    assert REQUESTS - served >= REQUESTS // 50, served


def test_the_request_path_differential_catches_a_guard_in_front_of_the_checker(
    surface,  # type: ignore[no-untyped-def]
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """Anti-vacuity, and the defect itself: the guard that was there, put back.

    The reading restored here is the one the route carried — a Python `int`,
    and never a JSON number with a zero fractional part. It is the whole of the
    divergence the first outside read executed, and this harness must be the
    thing that finds it.
    """
    from sayfirst_control_plane.adapters import http_surface

    monkeypatch.setattr(
        http_surface,
        "is_published_integer",
        lambda value: isinstance(value, int) and not isinstance(value, bool),
    )

    found = _route_disagreements(surface, [{"contract_generation": 1.0, "capability": "a.b"}])

    assert found, "a guard that refuses an integral JSON number went unnoticed"
