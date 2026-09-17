# SPDX-License-Identifier: Apache-2.0
"""Article 15: every resolved dependency carries a licence from the closed list,
and ships the text of it.

A rule of the repository, not of one package: the environment every package here
resolves into is one environment, and article 15 closes the list of licences it
may contain. One rule per file, so a new rule arrives as a new file and a new
file never conflicts (`CONTRIBUTING.md`, article 16) — this file holds two rules
because they are one rule read twice: the article's sentence is "a dependency
without an identifiable licence text is refused", and the identifier alone is
not the text.

**Why the second rule exists.** A classifier is a string a packager typed. It is
not a grant, it does not name a copyright holder, and it does not say what the
terms are; a redistribution that carries it and no `LICENSE` file has published
somebody else's code with no licence attached to it. The article says so
directly, and adds the way back: a dependency whose metadata is defective is
admitted only by an entry in the exception register naming the licence text
actually found.

A `License-Expression` is treated as the article treats it — as the metadata
saying what the licence is — and the text is still required. The distinction the
second rule draws is about EVIDENCE, not about which field was used, and it is
not conditional on a claim: what is refused is a distribution that ships no
licence text, whether its metadata claims a licence or claims nothing at all. A
dependency that says nothing about its terms has given a redistributor even less
to stand on than one whose classifier is unbacked, and article 15's sentence —
"a dependency without an identifiable licence text is refused" — makes the text
the subject rather than the claim.
"""

from __future__ import annotations

import importlib.metadata
import re
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
REGISTER = REPOSITORY / "docs" / "exceptions.md"

#: Article 15's closed list, written here as the article writes it.
ALLOWED = frozenset(
    {
        "MIT",
        "MIT-0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "ISC",
        "PSF-2.0",
        "Zlib",
    }
)

#: The classifiers this project reads as an SPDX identifier, for a distribution
#: whose metadata predates licence expressions.
CLASSIFIER_IDENTIFIERS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}

#: The file names a licence text goes by. Matched case-insensitively, with or
#: without a suffix, so `LICENSE`, `LICENSE.txt`, `LICENCE.md` and `COPYING` are
#: all the text this rule is looking for.
LICENCE_TEXT_NAME = re.compile(r"^(LICEN[CS]E|COPYING)([._-].*)?$", re.IGNORECASE)

#: Distributions admitted despite shipping no licence text. Article 15 allows
#: exactly one way in: an entry in the exception register naming the licence
#: text actually found. Empty, and the test below holds every name in it to a
#: heading in that register, so a name added here without an entry is red.
ADMITTED_WITHOUT_LICENCE_TEXT: frozenset[str] = frozenset()

#: This module, so that the register clause can be shown refusing an admission
#: the register does not carry. The constant above is empty and must stay
#: empty; a clause proved only by iterating nothing is a clause nobody has seen
#: work, which is the finding this repository keeps making about other people's
#: guards (article 2).
_THIS_MODULE = sys.modules[__name__]


def _licence_identifiers(distribution: importlib.metadata.Distribution) -> set[str]:
    identifiers, _ = identifiers_and_source(distribution)
    return identifiers


def identifiers_and_source(
    distribution: importlib.metadata.Distribution,
) -> tuple[set[str], str]:
    """The SPDX identifiers this distribution declares, and where they came from."""
    expression = distribution.metadata.get("License-Expression")
    if expression:
        return set(re.findall(r"[A-Za-z0-9.-]+", expression)) - {"AND", "OR", "WITH"}, "expression"
    classifiers = set(distribution.metadata.get_all("Classifier", []))
    return (
        {
            identifier
            for classifier, identifier in CLASSIFIER_IDENTIFIERS.items()
            if classifier in classifiers
        },
        "classifier",
    )


def licence_texts(distribution: importlib.metadata.Distribution) -> list[str]:
    """Every licence text this distribution actually ships, by file name.

    Two places, because packaging has used both: `License-File` in the metadata,
    and a file under the `.dist-info/licenses/` directory of the archive. A
    distribution that has either has the text; one that has neither has a claim
    and nothing behind it.
    """
    found = list(distribution.metadata.get_all("License-File") or [])
    for item in distribution.files or ():
        name = str(item).rsplit("/", 1)[-1]
        if LICENCE_TEXT_NAME.match(name):
            found.append(str(item))
    return sorted(set(found))


def test_every_dependency_carries_a_licence_from_the_closed_list() -> None:
    """Article 15: every resolved development dependency has an allowed licence."""
    distributions = tuple(importlib.metadata.distributions())
    assert len(distributions) >= 2
    failures = {
        distribution.metadata["Name"]: _licence_identifiers(distribution)
        for distribution in distributions
        if not _licence_identifiers(distribution)
        or not _licence_identifiers(distribution) <= ALLOWED
    }
    assert failures == {}


def test_every_dependency_ships_the_text_of_its_licence() -> None:
    """Article 15: "a dependency without an identifiable licence text is refused".

    Every resolved distribution, whether or not its metadata claims a licence:
    the text is what a redistribution carries, and metadata claiming nothing
    leaves a redistributor with less than an unbacked classifier does. The
    failure names where each one's identifier came from, or that it has none, so
    a reader can tell an unbacked claim from silence.
    """
    distributions = tuple(importlib.metadata.distributions())
    assert len(distributions) >= 2
    failures = {
        distribution.metadata["Name"]: identifiers_and_source(distribution)[1]
        for distribution in distributions
        if not licence_texts(distribution)
        and distribution.metadata["Name"] not in ADMITTED_WITHOUT_LICENCE_TEXT
    }
    assert failures == {}, (
        f"these distributions ship no licence text, and are refused whether or not "
        f"their metadata claims a licence: {failures}. Article 15 refuses one, and "
        f"admits a defective one only by an entry in docs/exceptions.md naming the "
        f"licence text actually found."
    )


def test_the_rule_refuses_a_classifier_with_no_licence_text() -> None:
    """WATCHED FIRING, on the exact defect the audit named.

    A rule whose only evidence is that every installed distribution happens to
    satisfy it is a rule that would also pass if it had stopped applying — and
    the distributions here do all satisfy it today, so the proof has to be
    planted. The double is the smallest thing that answers the two questions
    this rule asks.
    """

    class _Metadata(dict):  # type: ignore[type-arg]
        def get_all(self, name, failobj=None):  # type: ignore[no-untyped-def]
            return {"Classifier": ["License :: OSI Approved :: MIT License"]}.get(name, failobj)

    class _Claimed:
        metadata = _Metadata(Name="claims-a-licence", **{"License-Expression": ""})
        files = ()

    class _Shipped:
        metadata = _Metadata(Name="ships-the-text", **{"License-Expression": ""})
        files = ("ships_the_text-1.0.dist-info/licenses/LICENSE",)

    claimed, shipped = _Claimed(), _Shipped()
    assert identifiers_and_source(claimed) == ({"MIT"}, "classifier")
    assert licence_texts(claimed) == []
    assert licence_texts(shipped) == ["ships_the_text-1.0.dist-info/licenses/LICENSE"]


def admissions_with_no_entry() -> list[str]:
    """Every name admitted above that the exception register does not carry.

    Both readings happen at call time, from the constant and from the file, so
    the planted admissions below are refused and admitted by the same code path
    a real one would take.
    """
    register = REGISTER.read_text(encoding="utf-8") if REGISTER.is_file() else ""
    return [name for name in sorted(ADMITTED_WITHOUT_LICENCE_TEXT) if name not in register]


def test_every_admitted_distribution_has_an_entry_in_the_exception_register() -> None:
    """Article 15 and article 0: the way in is the register, never this constant.

    An allow-list that could grow without an entry would be an exception with no
    stated reason, no compensating evidence and no way back — which article 0
    calls an amendment and treats as one.
    """
    unregistered = admissions_with_no_entry()
    assert unregistered == [], (
        f"{unregistered} are admitted here and named in no entry of docs/exceptions.md"
    )


def test_the_register_clause_refuses_an_admission_the_register_does_not_carry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WATCHED FIRING, against the register that really ships.

    The constant is empty, as it should be, so the clause above iterates
    nothing and would read exactly the same if it had stopped applying. One
    temporary admission is what makes it a guard: a name nobody registered is
    reported, by name, from the real `docs/exceptions.md`.
    """
    unregistered = "a-distribution-nobody-registered"
    register = REGISTER.read_text(encoding="utf-8")
    assert unregistered not in register, "pick a name the register does not carry"
    monkeypatch.setattr(_THIS_MODULE, "ADMITTED_WITHOUT_LICENCE_TEXT", frozenset({unregistered}))
    assert admissions_with_no_entry() == [unregistered], (
        "FAIL an admission named in no entry of the register was accepted: "
        "this clause cannot fail, and the allow-list is a way in of its own."
    )


def test_the_register_clause_admits_one_the_register_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """WATCHED NOT FIRING. Article 15 leaves exactly one way in, and a clause
    that refused every admission would close it while looking like a guard. The
    register is planted here as well, because the real one carries no such
    entry — correctly: nothing has tripped."""
    register = tmp_path / "exceptions.md"
    register.write_text(
        "## 5 — a-distribution-nobody-registered ships no licence text\n\n"
        "The text found is the MIT licence, in the source archive.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(_THIS_MODULE, "REGISTER", register)
    monkeypatch.setattr(
        _THIS_MODULE,
        "ADMITTED_WITHOUT_LICENCE_TEXT",
        frozenset({"a-distribution-nobody-registered"}),
    )
    assert admissions_with_no_entry() == []
