# SPDX-License-Identifier: Apache-2.0
"""Article 0: the decided name is the only name, and the placeholder never returns.

Article 0 held the project's public name open behind a placeholder and forbade
publishing anything under it until the name was decided. The name was decided;
the placeholder was replaced in one act, which article 0 authorised in advance.
What that act leaves behind is a hole a later commit can fall into: the
placeholder was written three ways, because Core Metadata cannot carry an angle
bracket, so a distribution name and an import package each needed a spelling of
their own, and any of the three could be typed again from memory, copied out of
an old design note, or reintroduced by a merge.

So the three spellings are guarded together, by shape rather than by list: the
angle-bracketed placeholder, the hyphenated distribution prefix and the
underscored import prefix are one pattern, matched without regard to case, in
every tracked path and in every tracked file's bytes. The pattern is assembled
from pieces here so that this guard is not itself the occurrence it forbids
(the idiom of `tests/test_public_vocabulary.py`).

A guard that only forbids proves nothing about what replaced it, so the decided
name is asserted where it has to appear: every distribution this repository
builds is named for it, and so is the one console script it installs.

That console script is `sayfirstd`, not the bare word. The operator settled a
collision between two repositories on 2026-09-05: `sayfirst` in all three forms
— distribution, import package, console script — is the product command-line
interface's, and the operator surface that inspects this repository's daemon
takes the daemon's own form of the decided name. So the decided name is still
the only name here, in the two shapes a daemon and its distributions take:
`sayfirst-` as a prefix, and `sayfirstd` for the binary. Which distribution
holds which name is `tests/test_client_distribution_names.py`; this file only
requires that whatever they are, they are the decided name and nothing else.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from collections.abc import Iterator
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]

#: The name the operator decided on 2026-09-04. It is one word, so the
#: distribution prefix and the import prefix are the same string.
DECIDED_NAME = "sayfirst"

#: The decided name in the form a daemon and its operator surface take: the
#: conventional Unix suffix, so that the daemon and the commands that inspect it
#: share one binary (the operator's decision of 2026-09-05).
DAEMON_NAME = f"{DECIDED_NAME}d"

#: Directories a non-git enumeration must not walk into.
UNTRACKED_DIRECTORIES = frozenset({".git", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache"})

#: The retired placeholder and the two prefixes it was rendered as, assembled
#: from pieces so that this file does not contain what it forbids. `<...>` is
#: optional because the bare renderings — the buildable distribution prefix and
#: the importable package prefix — are occurrences in their own right, and the
#: separator is either character because both renderings existed.
_STEM = "oss" + "[-_]" + "brand"
RETIRED_NAME = re.compile("<?" + _STEM + ">?", re.IGNORECASE)


def _tracked_files(root: Path) -> list[Path]:
    """Every file this repository publishes, as repository-relative paths."""
    if (root / ".git").exists() and shutil.which("git") is not None:
        listed = subprocess.run(
            ("git", "ls-files", "-z"),
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return [Path(name) for name in listed.split("\0") if name]
    return sorted(
        item.relative_to(root)
        for item in root.rglob("*")
        if item.is_file() and not UNTRACKED_DIRECTORIES & set(item.relative_to(root).parts)
    )


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _occurrences(root: Path) -> Iterator[tuple[Path, str]]:
    """Yield (file, matched text) for every occurrence of the retired name."""
    for item in _tracked_files(root):
        in_path = RETIRED_NAME.search(item.as_posix())
        if in_path is not None:
            yield item, in_path.group(0)
        content = _read(root / item)
        if content is None:
            continue
        in_content = RETIRED_NAME.search(content)
        if in_content is not None:
            yield item, in_content.group(0)


def _distributions(root: Path) -> dict[Path, dict[str, object]]:
    """The `[project]` table of every distribution the workspace builds."""
    found = {}
    for manifest in sorted(root.glob("packages/*/pyproject.toml")):
        table = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
        found[manifest.relative_to(root)] = table
    return found


def test_no_tracked_file_carries_the_retired_name() -> None:
    """Article 0: the placeholder and both of its renderings are gone from the tree."""
    tracked = _tracked_files(REPOSITORY)
    # Anti-vacuity floor: an enumeration that found nothing cannot pass.
    assert len(tracked) >= 40, tracked
    assert sorted(set(_occurrences(REPOSITORY))) == []


def _carries_the_decided_name(name: str) -> bool:
    """Whether a published name is the decided name, in one of its two shapes."""
    return name in (DECIDED_NAME, DAEMON_NAME) or name.startswith(f"{DECIDED_NAME}-")


def test_every_distribution_and_the_command_carry_the_decided_name() -> None:
    """Article 0: what replaced the placeholder is one word, used everywhere."""
    distributions = _distributions(REPOSITORY)
    assert len(distributions) >= 5, distributions
    for manifest, table in distributions.items():
        name = table["name"]
        assert isinstance(name, str)
        assert _carries_the_decided_name(name), (manifest, name)
        for script in table.get("scripts", {}):
            assert _carries_the_decided_name(script), (manifest, script)
    workspace = tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))
    assert workspace["project"]["name"].startswith(DECIDED_NAME)
    command = {
        script
        for table in distributions.values()
        for script in table.get("scripts", {})
        if script in (DECIDED_NAME, DAEMON_NAME)
    }
    assert command == {DAEMON_NAME}, distributions


def test_the_decided_name_is_required_in_a_shape_it_could_fail() -> None:
    """Article 2: the two accepted shapes are two, not "anything starting with it".

    A predicate widened to admit `sayfirstd` would hold nothing if it admitted
    every suffix, and the accident this repository has already had — a blanket
    substring replacement welding the name into a longer word — is exactly the
    shape that would slip through.
    """
    assert _carries_the_decided_name(DECIDED_NAME)
    assert _carries_the_decided_name(DAEMON_NAME)
    assert _carries_the_decided_name(f"{DECIDED_NAME}-contract")
    assert not _carries_the_decided_name(f"{DECIDED_NAME}ory")
    assert not _carries_the_decided_name(f"{DAEMON_NAME}aemon")
    assert not _carries_the_decided_name(f"{DECIDED_NAME}_cli")
    assert not _carries_the_decided_name("sf-cli")


def test_the_guard_catches_each_spelling_of_the_retired_name(tmp_path: Path) -> None:
    """Article 0: the guard is proven against a planted occurrence of every spelling.

    One planted file per spelling, in a tree of its own, because the guard reads
    a whole repository and a passing run has to be able to say which spelling it
    would have caught.
    """
    separator = {"distribution": "-", "import": "_"}
    for rendering, character in separator.items():
        rendered = "oss" + character + "brand"
        for spelling, text in (
            ("bare", rendered),
            ("placeholder", "<" + rendered + ">"),
            ("shouted", rendered.upper()),
        ):
            planted = tmp_path / "planted.md"
            planted.write_text(f"The prefix is {text} here.\n", encoding="utf-8")
            found = list(_occurrences(tmp_path))
            assert found == [(Path("planted.md"), text)], (rendering, spelling, found)
            planted.unlink()

        # A content-only guard would let a module return under the retired
        # import prefix without a sentence ever naming it, so the path is
        # checked as well.
        at_path = tmp_path / "src" / f"{rendered}_control_plane"
        at_path.mkdir(parents=True)
        (at_path / "__init__.py").write_text("", encoding="utf-8")
        assert [item for item, _ in _occurrences(tmp_path)] == [
            Path("src") / f"{rendered}_control_plane" / "__init__.py"
        ], rendering
        shutil.rmtree(tmp_path / "src")
