# SPDX-License-Identifier: Apache-2.0
"""Article 2: what an index shows about these distributions is held, not remembered.

A package page is read by people who hold nothing of this project, and every
field on it is a claim this project makes: who wrote the code, which
interpreters it runs under, how far along it is. The URLs of that page have a
guard of their own (`tests/test_pointers_survive_publication.py`); the fields
beside them had none, which left two ways for the page to start lying with the
suite green. A distribution added next month ships no author and no
classifiers, because nothing asks it to. And the supported-version floor moves
— one line in one file — while the classifiers that advertise the old floor
stay where they are, so the page names an interpreter the distribution refuses
to install under.

So the rule is the agreement rather than the list: the Python classifiers are
DERIVED from each distribution's own `requires-python` and compared, which is
the one reading that cannot go stale when the floor moves.

The two absences are held too, because both are refusals rather than omissions.
No licence classifier: the licence is declared as an expression, and an index
refuses a distribution that carries both. No typing classifier: these
distributions ship no marker file that would make the claim true.

One rule per file (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]

#: The identity every commit of this repository is signed off under, and the
#: one the index shows as the author (article 15's sign-off, article 16's
#: maintainer-led project). A display name for the index is a decision the
#: publication checklist carries as an act of the operator; what this guard
#: holds is that the seven distributions agree, whatever it is.
AUTHORS = [{"name": "fredaime", "email": "frederic.aime@gmail.com"}]

#: The development status these distributions claim, one spelling of it.
DEVELOPMENT_STATUS = "Development Status :: 4 - Beta"

#: The classifier that says "Python 3" and names no minor version.
ANY_PYTHON_THREE = "Programming Language :: Python :: 3"

#: A `requires-python` of the shape every project file here carries: an
#: inclusive floor and an exclusive ceiling, both in the 3.x series. A
#: specifier this guard cannot read is one it refuses to vouch for rather than
#: one it passes.
SPECIFIER = re.compile(r">=\s*3\.(\d+)\s*,\s*<\s*3\.(\d+)")

#: Classifiers this project refuses to carry, and the reason each is refused.
REFUSED = {
    "License :: ": "the licence is declared as an expression, and an index refuses both",
    "Typing :: ": "no distribution here ships a typing marker that would make the claim true",
}

DISTRIBUTIONS = tuple(sorted(item for item in (REPOSITORY / "packages").iterdir() if item.is_dir()))


def project(package: Path) -> dict:
    """The `[project]` table of the distribution at `package`."""
    return tomllib.loads((package / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def minor_versions(requires_python: str) -> list[int]:
    """Every 3.x this specifier admits, read from the specifier itself."""
    found = SPECIFIER.fullmatch(requires_python.strip())
    if not found:
        raise ValueError(f"this guard cannot read the specifier {requires_python!r}")
    floor, ceiling = int(found[1]), int(found[2])
    if not floor < ceiling:
        raise ValueError(f"the specifier {requires_python!r} admits no version")
    return list(range(floor, ceiling))


def expected_classifiers(requires_python: str) -> set[str]:
    """The classifiers a distribution admitting exactly these interpreters owes."""
    return {
        DEVELOPMENT_STATUS,
        ANY_PYTHON_THREE,
        *(f"{ANY_PYTHON_THREE}.{minor}" for minor in minor_versions(requires_python)),
    }


def disagreements(package: Path) -> list[str]:
    """Every way this distribution's classifiers and its own specifier disagree."""
    table = project(package)
    found = set(table.get("classifiers") or [])
    owed = expected_classifiers(table["requires-python"])
    return sorted(
        [f"claims but does not admit: {item}" for item in sorted(found - owed)]
        + [f"admits but does not claim: {item}" for item in sorted(owed - found)]
    )


def test_the_walk_finds_the_distributions_this_rule_is_about() -> None:
    """ANTI-VACUITY. A glob that matched nothing would make every assertion
    below pass by absence, which is the failure this repository keeps finding."""
    assert len(DISTRIBUTIONS) == 7, DISTRIBUTIONS
    for package in DISTRIBUTIONS:
        assert (package / "pyproject.toml").is_file(), package


@pytest.mark.parametrize("package", DISTRIBUTIONS, ids=lambda p: p.name)
def test_every_distribution_names_the_identity_its_commits_are_signed_off_under(
    package: Path,
) -> None:
    """Article 2: a page with no author attributes the code to nobody."""
    table = project(package)
    assert table.get("authors") == AUTHORS, (package.name, table.get("authors"))


@pytest.mark.parametrize("package", DISTRIBUTIONS, ids=lambda p: p.name)
def test_every_distribution_claims_the_interpreters_its_specifier_admits(package: Path) -> None:
    """The classifiers are read against the distribution's own `requires-python`.

    A floor that moves and classifiers that do not is the defect this holds:
    the page keeps advertising an interpreter the installer refuses.
    """
    found = disagreements(package)
    assert found == [], (package.name, project(package)["requires-python"], found)


@pytest.mark.parametrize("package", DISTRIBUTIONS, ids=lambda p: p.name)
def test_no_distribution_carries_a_classifier_this_project_refuses(package: Path) -> None:
    """Both absences are decisions, so both are held rather than remembered."""
    for classifier in project(package).get("classifiers") or ():
        for prefix, reason in REFUSED.items():
            assert not classifier.startswith(prefix), (package.name, classifier, reason)


def test_the_rule_fires_on_a_classifier_the_specifier_does_not_cover(tmp_path: Path) -> None:
    """WATCHED FIRING. A rule whose only evidence is that the seven files agree
    today would also pass if it had stopped applying — and they do all agree, so
    the proof has to be planted. This is the defect the floor moving leaves
    behind: one interpreter claimed that the specifier no longer admits.
    """
    package = tmp_path / "planted"
    package.mkdir()
    (package / "pyproject.toml").write_text(
        '[project]\nname = "planted"\nversion = "0.0.0"\n'
        'requires-python = ">=3.12,<3.14"\n'
        "classifiers = [\n"
        f'  "{DEVELOPMENT_STATUS}",\n'
        f'  "{ANY_PYTHON_THREE}",\n'
        f'  "{ANY_PYTHON_THREE}.12",\n'
        f'  "{ANY_PYTHON_THREE}.13",\n'
        f'  "{ANY_PYTHON_THREE}.14",\n'
        "]\n",
        encoding="utf-8",
    )
    found = disagreements(package)
    assert found == [f"claims but does not admit: {ANY_PYTHON_THREE}.14"], found


def test_the_rule_fires_on_an_interpreter_admitted_and_not_claimed(tmp_path: Path) -> None:
    """WATCHED FIRING, on the other direction of the same disagreement: a
    ceiling raised and no classifier added is a page that under-states what the
    distribution installs under."""
    package = tmp_path / "planted"
    package.mkdir()
    (package / "pyproject.toml").write_text(
        '[project]\nname = "planted"\nversion = "0.0.0"\n'
        'requires-python = ">=3.12,<3.15"\n'
        "classifiers = [\n"
        f'  "{DEVELOPMENT_STATUS}",\n'
        f'  "{ANY_PYTHON_THREE}",\n'
        f'  "{ANY_PYTHON_THREE}.12",\n'
        f'  "{ANY_PYTHON_THREE}.13",\n'
        "]\n",
        encoding="utf-8",
    )
    assert disagreements(package) == [f"admits but does not claim: {ANY_PYTHON_THREE}.14"]


def test_the_rule_reads_the_specifier_the_seven_files_really_carry() -> None:
    """WATCHED NOT FIRING. The derivation is only worth anything if it produces
    the list the tree actually holds: `>=3.12,<3.15` is 3.12, 3.13 and 3.14, and
    a reader that produced anything else would make the four cases above agree
    with each other and with nothing else."""
    assert minor_versions(">=3.12,<3.15") == [12, 13, 14]
    assert expected_classifiers(">=3.12,<3.15") == {
        DEVELOPMENT_STATUS,
        ANY_PYTHON_THREE,
        f"{ANY_PYTHON_THREE}.12",
        f"{ANY_PYTHON_THREE}.13",
        f"{ANY_PYTHON_THREE}.14",
    }


def test_a_specifier_this_guard_cannot_read_is_refused_rather_than_passed() -> None:
    """Article 2: a reader that shrugged at an unfamiliar specifier would report
    a green about a comparison it never made."""
    for unreadable in (">=3.12", "", ">=3.12,<3.12", "~=3.12"):
        with pytest.raises(ValueError):
            minor_versions(unreadable)
