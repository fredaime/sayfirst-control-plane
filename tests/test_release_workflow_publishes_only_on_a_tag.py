# SPDX-License-Identifier: Apache-2.0
"""Article 0: nothing is published before the operator's own act.

Article 0 forbids anything under the decided name — no package on an index, no
public repository, no announcement — until the marks are filed. The act that
publishes is therefore the operator's tag and nothing else, and this guard is
what keeps the workflow from acquiring a second one by accident: a `branches:`
added under `push` for convenience, a `pull_request:` added to « test the
release path », a publish step that stops needing the build that checked the
tag.

Read as text rather than as parsed YAML. This repository installs no YAML
reader, and adding a dependency in order to check a file of a hundred lines
would be a worse trade than reading the lines (article 15 keeps the dependency
list closed and short). Every assertion below names the exact line it wants, so
a reformatting that breaks it fails loudly rather than passing vacuously — with
one deliberate exception: the two triggers this file exists to keep out are
matched **by shape**, because they have more than one spelling and an exact line
would bite on only one of them. Both shape predicates are planted against a
mutated copy of the real file, since a `not in` assertion is proven by a
mutation and by nothing else.

One rule per file (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY / ".github" / "workflows" / "release.yml"

#: The step that uploads, however it is pinned.
PUBLISH_ACTION = re.compile(r"pypa/gh-action-pypi-publish@\S+")

#: The only pinning this repository accepts for it: a release of the action,
#: named in full, like the uv version and the artefact checker beside it. A
#: branch ref — the form the action's own documentation offers — is whatever it
#: points at on the day the tag is cut.
PINNED_RELEASE = re.compile(r"pypa/gh-action-pypi-publish@v\d+\.\d+\.\d+")


def _lines() -> list[str]:
    return WORKFLOW.read_text(encoding="utf-8").splitlines()


def _publish_refs(lines: list[str]) -> list[str]:
    """Every reference to the publishing action, as this workflow pins it.

    Comment lines are not references: the comment beside the step explains the
    pinning, and a guard that read its own explanation as a use would be
    reporting on prose.
    """
    return [
        found
        for line in lines
        if not line.strip().startswith("#")
        for found in PUBLISH_ACTION.findall(line)
    ]


def _keys(lines: list[str], *names: str) -> list[str]:
    """Every line that opens one of these mapping keys, in any spelling of its value.

    By shape rather than by exact line, because `branches: [main]` — the form
    GitHub's own documentation uses, and the form a convenience edit takes —
    and `branches:` with a block under it are the same defect. Comment lines
    are not keys: this workflow's own header names both of the keys it refuses
    to carry.
    """
    return [
        line
        for line in lines
        if not line.strip().startswith("#")
        and line.strip().startswith(tuple(f"{name}:" for name in names))
    ]


def _branch_filters(lines: list[str]) -> list[str]:
    """Anything that attaches this workflow to a branch rather than to a tag."""
    return _keys(lines, "branches", "branches-ignore")


def _ordinary_traffic_triggers(lines: list[str]) -> list[str]:
    """Anything that starts this workflow on traffic no operator asked for."""
    return _keys(lines, "pull_request", "pull_request_target")


def _owned_by(lines: list[str], header: str) -> list[str]:
    """The lines a mapping key owns: those indented deeper, to the next sibling.

    What makes "and nothing else" assertable about a permission block: the
    scope that is present can be read from a substring, and the scope that is
    absent only from the whole block.
    """
    start = lines.index(header)
    indent = len(header) - len(header.lstrip())
    owned = []
    for line in lines[start + 1 :]:
        if not line.strip() or line.strip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        owned.append(line)
    return owned


def _publish_job(lines: list[str]) -> list[str]:
    """The publish job's own lines, so its keys are never read from another job's."""
    body = lines[lines.index("  publish:") + 1 :]
    end = next(
        (
            number
            for number, line in enumerate(body)
            if line.strip() and not line.startswith("    ")
        ),
        len(body),
    )
    return body[:end]


def test_the_release_workflow_exists_and_is_read_by_this_guard() -> None:
    """ANTI-VACUITY. A missing file would make every assertion below pass."""
    assert WORKFLOW.is_file(), WORKFLOW
    assert len(_lines()) >= 40


def test_it_does_nothing_on_a_push_to_a_branch_or_on_a_pull_request() -> None:
    """Article 0: a release path that runs on ordinary traffic is a release path
    that will one day publish on ordinary traffic."""
    lines = _lines()
    assert _ordinary_traffic_triggers(lines) == []
    assert _branch_filters(lines) == [], "a branch filter under push means this runs on a branch"
    assert '    tags: ["v*"]' in lines


def test_the_guard_still_catches_a_branch_filter_added_for_convenience() -> None:
    """Plant: `branches: [main]` is the spelling a convenience edit takes.

    The `tags:` assertion above does not backstop it — the tags line survives
    that edit — so this planted copy of the real file is the whole proof that
    the refusal bites.
    """
    planted = WORKFLOW.read_text(encoding="utf-8").replace(
        '    tags: ["v*"]', '    tags: ["v*"]\n    branches: [main]'
    )
    assert planted != WORKFLOW.read_text(encoding="utf-8"), "the plant changed nothing"
    caught = _branch_filters(planted.splitlines())
    assert caught == ["    branches: [main]"], (
        f"FAIL a planted inline branch filter was not caught: {caught}"
    )
    assert _branch_filters('    branches-ignore: ["wip"]'.splitlines()), "the ignore form too"


def test_the_guard_still_catches_a_pull_request_trigger_added_to_try_the_path() -> None:
    """Plant: the other way a release path acquires a second act that starts it."""
    planted = WORKFLOW.read_text(encoding="utf-8").replace(
        "  workflow_dispatch:", "  pull_request:\n  workflow_dispatch:"
    )
    assert planted != WORKFLOW.read_text(encoding="utf-8"), "the plant changed nothing"
    caught = _ordinary_traffic_triggers(planted.splitlines())
    assert caught == ["  pull_request:"], (
        f"FAIL a planted pull-request trigger was not caught: {caught}"
    )


def test_the_dispatch_defaults_to_a_dry_run_and_one_asking_to_publish_is_refused() -> None:
    """The mechanics are proven before the marks are filed rather than after.

    The input defaults off; and because an input that reads like a switch is a
    trap for the next operator, a dispatch that asks to publish is refused by
    name before anything is built rather than ignored. `inputs.publish` and not
    `github.event.inputs.publish`: the input is declared a boolean, and the
    latter is the string "false", which is true.
    """
    lines = _lines()
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "  workflow_dispatch:" in text
    assert "      publish:" in text
    assert "        default: false" in text
    assert "        if: github.event_name == 'workflow_dispatch' && inputs.publish" in lines
    assert "::error::a dispatch publishes nothing" in text
    assert "          exit 1" in lines


def test_the_publish_job_runs_only_for_a_tag_and_only_after_the_build() -> None:
    """The build is what checks that the tag names the version; a publish that
    did not need it would publish a tag nothing had read."""
    lines = _lines()
    assert "    needs: build" in lines
    assert "    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" in lines


def test_the_publish_job_uses_trusted_publishing_into_a_named_environment() -> None:
    """No token is stored anywhere: the index verifies the workflow's identity.

    Whether the environment demands a reviewer is a setting of the repository,
    which no file here can read — so this test does not claim it, the workflow
    says so in its own words, and the publication checklist carries it. That is
    the same honesty article 16's own Guard keeps about a required status.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "      name: pypi" in text
    assert "      id-token: write" in text
    assert _publish_refs(_lines()), "no step of this workflow uploads anything"
    assert "password:" not in text, "a stored token is not trusted publishing"


def test_no_job_holds_a_permission_it_does_not_need() -> None:
    """A publishing job that could also push is a different job.

    The two scopes are asserted as whole blocks and not as substrings: what
    matters about the publish job is the scope it does *not* hold, and a
    `contents: write` added beside `id-token: write` satisfies every assertion
    that only asks what is present.
    """
    lines = _lines()
    assert _owned_by(lines, "permissions:") == ["  contents: read"]
    assert _owned_by(_publish_job(lines), "    permissions:") == ["      id-token: write"]


def test_the_build_checks_the_tag_against_the_version_and_the_artefacts() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'python scripts/release_version.py --expect "${GITHUB_REF_NAME#v}"' in text
    assert "uv build --all-packages --out-dir dist" in text
    assert "uvx twine@7.0.0 check dist/*" in text


def test_the_tools_that_cut_a_release_are_pinned_to_one_version() -> None:
    """A release whose own toolchain is whichever version resolved that day is
    a release nobody can cut twice.

    Three of them. The artefact checker is the only thing standing between a
    build and the index; the uv the distributions are built with decides what
    they are; and the step that uploads is the one that reaches the index at
    all, so a moving ref there is a release cut by whatever that ref pointed at
    that morning. All three are therefore named with a version here. The gate
    workflow is deliberately not held to this — it reports on the tree under
    the toolchain of the day, which is what a gate is for.
    """
    lines = _lines()
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "      - uses: astral-sh/setup-uv@v5" in lines
    assert '          version: "0.12.5"' in lines
    assert "uvx twine check dist/*" not in text, "an unpinned checker is whatever is served today"
    refs = _publish_refs(lines)
    assert refs, "the step that uploads is not named here at all"
    for ref in refs:
        assert PINNED_RELEASE.fullmatch(ref), (
            f"{ref} is not a release of the publishing action: a moving ref is not a pin"
        )


def test_the_guard_still_catches_a_moving_ref_on_the_step_that_uploads() -> None:
    """Plant: the branch ref this step carried, which is the form the action's
    own documentation offers and the form a copied snippet brings back.

    Planted over the real file, so what it proves is that this run's check
    would have caught it; the substitution is written against the action's name
    rather than against today's version, so the plant keeps meaning the same
    thing at the next bump.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    planted = PUBLISH_ACTION.sub("pypa/gh-action-pypi-publish@release/v1", text)
    assert planted != text, "the plant changed nothing: the step is already on a branch ref"
    caught = [
        ref for ref in _publish_refs(planted.splitlines()) if not PINNED_RELEASE.fullmatch(ref)
    ]
    assert caught == ["pypa/gh-action-pypi-publish@release/v1"], (
        f"FAIL a planted branch ref on the publishing step was not caught: {caught}"
    )


def test_the_version_is_read_by_the_toolchain_this_workflow_installs() -> None:
    """Never the runner's own `python`, whose version is whatever the image ships.

    The reader needs the standard library's TOML module, which arrived in 3.11,
    and a workflow that trusts the image for that is a workflow whose release
    check can disappear under a runner upgrade. Both invocations therefore go
    through `uv run`, which pins the interpreter this repository declares — and
    both carry `--frozen`, so the environment is the one `uv.lock` records, and
    `--all-packages`, so the workspace is installed.
    `tests/test_public_gate_runs_the_suite.py` holds those two flags of every
    step in this repository's workflows that collects or runs the suite, and
    exempts the formatter steps in its own words; this asks them of the two
    lines a release turns on, where a re-resolved or uninstalled run would not
    fail the release but pass it on an environment nobody recorded.
    """
    invocations = [
        line
        for line in _lines()
        if "scripts/release_version.py" in line and not line.strip().startswith("#")
    ]
    assert len(invocations) == 2, invocations
    for line in invocations:
        assert "uv run --frozen --all-packages python scripts/release_version.py" in line, line
