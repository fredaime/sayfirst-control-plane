# SPDX-License-Identifier: Apache-2.0
"""Articles 0 and 2: no pointer this repository publishes sends a reader nowhere.

`SECURITY.md` records that the private repository this tree was reviewed in is
**never made public**: article 0 offers a fresh repository or a review of the
existing record, and the second path was closed by measurement — a pre-redaction
object survives in a pull-request reference that no rewrite reaches. The public
repository is created fresh, under a name the operator chose, and the URL is
written in the same act.

Until that act, the names below are a decision rather than a page. Writing them
down early is what gives the act one thing to check instead of a search to make,
and what keeps a distribution from shipping a link that resolves for nobody.

Two rules, both about the OPERATION rather than the name. A local sibling path
is not a promise that a reader can open a page, and the gate has to keep naming
the checkout it reads — so what is refused is a **URL**. And every URL this
project publishes about itself points at one of the two public repositories —
at the repository, and, where the URL names a file inside it, at a file this
repository really tracks. The base was the whole of the second rule once, which
left a renamed package directory publishing a dead link on the index with the
guard still green: the base survives every rename, and the path is the half a
rename moves.

One rule per file (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]

#: The private repository this tree was reviewed in, which the lead decided is
#: never made public. Named once, here, so a reader can see what the rule is about.
NEVER_PUBLISHED = "sf-control-plane-lt"

#: The open client's repository, likewise never made public under that name.
NEVER_PUBLISHED_CLIENT = "sf-cli-lt"

#: The two public repositories, decided by the operator.
PUBLIC_CONTROL_PLANE = "https://github.com/fredaime/sayfirst-control-plane"
PUBLIC_CLIENT = "https://github.com/fredaime/sayfirst-cli"

#: A hyperlink to a hosting platform, in any of the forms these documents use.
#: The scheme is what makes it a promise that something is reachable, so the
#: scheme is what this matches — a bare path is deliberately outside it.
_URL = re.compile(r"https?://[^\s)>\]\"']+")

#: A URL that names a file of this repository: the public base, the hosting
#: platform's own `blob/<ref>/` prefix, and then a path inside the tree. A URL
#: that matches nothing here names the repository itself and has no path to
#: resolve.
_TREE_FILE = re.compile(r"^https?://[^\s/]+/[^\s/]+/[^\s/]+/blob/[^\s/]+/(?P<path>[^\s#?]+)")

DISTRIBUTIONS = tuple(sorted(item for item in (REPOSITORY / "packages").iterdir() if item.is_dir()))


def project_urls(package: Path) -> dict[str, str]:
    """The `[project.urls]` table of the distribution at `package`, or an empty one."""
    project = tomllib.loads((package / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return dict(project.get("urls") or {})


def file_named_by(url: str) -> str | None:
    """The repository path this URL promises a reader, or None if it names none."""
    found = _TREE_FILE.match(url)
    return found["path"] if found else None


def tracked_files(root: Path = REPOSITORY) -> frozenset[str]:
    """Every path this repository publishes, as the index would resolve it.

    Tracked rather than merely present on disk: a file the repository does not
    carry is one the public repository will not carry either, whatever a local
    checkout happens to hold. The fallback walk is for a tree read without git,
    and reads the same thing one level less exactly.
    """
    if (root / ".git").exists() and shutil.which("git") is not None:
        listed = subprocess.run(
            ("git", "ls-files", "-z"),
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return frozenset(name for name in listed.split("\0") if name)
    return frozenset(
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and ".git" not in item.relative_to(root).parts
    )


def _reader_facing() -> list[Path]:
    """Every document a person outside the project reads.

    Walked, never enumerated: a governance file added next month is covered
    without anyone remembering to add it here. Test sources are excluded — this
    module has to be able to name the thing it forbids.
    """
    found = [path for path in sorted(REPOSITORY.glob("*.md")) if path.is_file()]
    found += [path for path in sorted(REPOSITORY.glob("docs/**/*.md")) if path.is_file()]
    found += [path for path in sorted(REPOSITORY.glob("packages/*/README.md")) if path.is_file()]
    notice = REPOSITORY / "NOTICE"
    if notice.is_file():
        found.append(notice)
    return found


DOCUMENTS = _reader_facing()


def test_the_walk_finds_the_documents_and_the_distributions_this_rule_is_about() -> None:
    """ANTI-VACUITY. A glob that matched nothing would make every assertion
    below pass by absence."""
    names = {path.name for path in DOCUMENTS}
    assert len(DOCUMENTS) >= 8, f"only {len(DOCUMENTS)} reader-facing documents found"
    for required in ("README.md", "NOTICE", "SECURITY.md", "CONSTITUTION.md"):
        assert required in names, f"{required} is not being scanned by this rule"
    assert len(DISTRIBUTIONS) == 7, DISTRIBUTIONS


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.as_posix())
def test_no_reader_facing_link_points_at_a_repository_that_is_never_published(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    offenders = [
        url for url in _URL.findall(text) if NEVER_PUBLISHED in url or NEVER_PUBLISHED_CLIENT in url
    ]
    assert not offenders, (
        f"{path.relative_to(REPOSITORY)} links to a repository article 0's fresh-repository "
        f"path means is never made public: {offenders}. A reader outside the project cannot "
        f"open it. Name the repository without a URL until the public one exists, and write "
        f"the URL in the act that creates it."
    )


@pytest.mark.parametrize("package", DISTRIBUTIONS, ids=lambda p: p.name)
def test_every_published_url_of_every_distribution_is_the_public_repository(package: Path) -> None:
    """A package page is read by people who hold nothing of this project."""
    urls = project_urls(package)
    assert set(urls) == {"Repository", "Documentation", "Changelog"}, (package.name, urls)
    for name, url in urls.items():
        assert url.startswith(PUBLIC_CONTROL_PLANE), (package.name, name, url)


@pytest.mark.parametrize("package", DISTRIBUTIONS, ids=lambda p: p.name)
def test_every_published_url_that_names_a_file_resolves_to_one_this_tree_tracks(
    package: Path,
) -> None:
    """A page whose Documentation link is a 404 is worse than one with none.

    The base is the half a rename leaves alone, so it is the path that has to
    be read: `packages/<dir>/README.md` moves the day the directory does, and
    the index keeps serving the old link for as long as the release lives.
    """
    tracked = tracked_files()
    assert tracked, "nothing was read as tracked: this rule would vouch for anything"
    for name, url in project_urls(package).items():
        path = file_named_by(url)
        if path is None:
            continue
        assert path in tracked, (
            f"{package.name}'s {name} URL names {path}, which this repository does not track: "
            f"a reader of the index follows it to nothing. A renamed file or directory is a "
            f"change to every project file that points at it, in one commit."
        )


def test_the_rule_fires_on_a_published_url_naming_a_path_that_moved(tmp_path: Path) -> None:
    """WATCHED FIRING, on the rename the base alone cannot see.

    Read through the same reader the seven real distributions are read through,
    and resolved against the same tracked set, so what it proves is that this
    run's check would have caught it.
    """
    package = tmp_path / "planted"
    package.mkdir()
    (package / "pyproject.toml").write_text(
        '[project]\nname = "planted"\nversion = "0.0.0"\n'
        "[project.urls]\n"
        f'Documentation = "{PUBLIC_CONTROL_PLANE}/blob/main/packages/renamed/README.md"\n',
        encoding="utf-8",
    )
    urls = project_urls(package)
    assert urls, "the reader saw no table: the probe proves nothing"
    dead = file_named_by(urls["Documentation"])
    assert dead == "packages/renamed/README.md"
    assert dead not in tracked_files(), (
        "FAIL a planted dead path resolved to a tracked file: this guard cannot fail."
    )


def test_the_rule_leaves_the_repository_url_alone() -> None:
    """WATCHED NOT FIRING. `Repository` names no file, so there is no path to
    resolve and a rule that demanded one would refuse every distribution."""
    assert file_named_by(PUBLIC_CONTROL_PLANE) is None
    assert file_named_by(f"{PUBLIC_CONTROL_PLANE}/blob/main/CHANGELOG.md") == "CHANGELOG.md"


def test_the_rule_fires_on_a_project_url_outside_the_public_repository(tmp_path: Path) -> None:
    """WATCHED FIRING, for the second half: a distribution whose page would point
    a reader at the repository that is never published, read through the same
    reader the seven real distributions are read through."""
    package = tmp_path / "planted"
    package.mkdir()
    (package / "pyproject.toml").write_text(
        '[project]\nname = "planted"\nversion = "0.0.0"\n'
        "[project.urls]\n"
        f'Repository = "https://github.com/fredaime/{NEVER_PUBLISHED}"\n',
        encoding="utf-8",
    )
    urls = project_urls(package)
    assert urls, "the reader saw no table: the probe proves nothing"
    assert not all(url.startswith(PUBLIC_CONTROL_PLANE) for url in urls.values())


def test_the_rule_fires_on_the_link_that_would_break_at_publication() -> None:
    """WATCHED FIRING, on the form this project's own documents used to carry."""
    historical = f"[`CONSTITUTION.md`](https://github.com/fredaime/{NEVER_PUBLISHED}/blob/main/CONSTITUTION.md)"
    assert [url for url in _URL.findall(historical) if NEVER_PUBLISHED in url]


def test_the_rule_leaves_a_local_sibling_path_alone() -> None:
    """WATCHED NOT FIRING. The client's gate documents the checkout it reads and
    must keep being able to: a detector that flagged every mention of the name
    would pass the probe above and mean nothing."""
    gate_line = f"$ SAYFIRST_CONTRACT_SOURCE=../{NEVER_PUBLISHED} ./scripts/gate.sh"
    assert not [url for url in _URL.findall(gate_line) if NEVER_PUBLISHED in url]
