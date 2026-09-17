# SPDX-License-Identifier: Apache-2.0
"""Article 9's anti-vacuity gate: the verifier inspected every pack that ships.

Article 9 asks for "the verifier run against every shipped pack in the public
gate, failing unless it inspected each one", and says why in as many words: "A
verifier added now would succeed by checking nothing, which this article calls
a failure". The assertion lives in THIS repository rather than in the client
distribution's own gate because that gate stands no daemon up, and what is
asserted here is about a chain a daemon wrote.

**The two sets come from two places, and neither of them is the command line.**
The shipped set is read off the client's package data — the directories its
`packs` tree holds, each recognised by carrying a `pack.toml`. The inspected
set is read off the verifier's own report, which the proof harness derives from
the points it actually watched for; its own words for why are that "a set
copied from the invocation would satisfy that assertion without having watched
anything". The invocation is then built FROM the first set, so every pack that
ships is designated, run against, and required to appear in the second.

**What is read, and what is never imported.** Each pack's own `pack.toml` is
read here with `tomllib`. Article 14 keeps this repository from depending on
the client distribution, and a declaration is a file: reading one is not a
dependency, while importing the client's reader would be. The three members
read — a point's module, its attribute and its capability — are the three the
verifier itself reads for each point, which is what lets one table below say
how a point is walked and the policy say what is allowed.

**Where a pack is walked from.** Each point is walked by the program's own
code, after the launcher has handed over. The launcher leaves a measured window
between the segments of a dotted name, named in the client distribution's own
packs document; a target that walked a point from inside that window would be
establishing something about the hand-off rather than about a program, which is
not what this gate is for. The program below is one file named as a script, so
it has no second segment and no such window at all — the choice is deliberate,
not incidental.

**A skip, reported, and never a pass.** The client checkout is a sibling on
disk and not a dependency, so these cases are skipped where it is absent — on
the marks `test_the_chain_governs_a_program.py` already carries, reported as
skips by the gate's own `-rs`. A skip that is read is the honest answer for a
tree that holds no client; what nothing here does is report green about a pack
nothing inspected, which is the one failure article 9 names for this gate.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from _daemon import _Daemon, _rule
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_control_plane.domain.published_schema import refused_by
from test_the_chain_governs_a_program import (
    SUBPROCESS_PACK,
    _client_environment,
)
from test_the_chain_governs_a_program import (
    pytestmark as pytestmark,
)

#: What a pack directory declares itself in. A directory carrying one is a
#: pack; nothing else under the packs tree is one, which is what keeps a
#: bytecode cache and the package's own `__init__.py` out of the shipped set.
DECLARATION = "pack.toml"

#: The directory the client's package data keeps its packs in, taken from the
#: one pack `test_the_chain_governs_a_program.py` already locates rather than
#: spelled a second time here: two spellings of one path are two answers to
#: "where does this client keep its packs" from the day one of them moves.
SHIPPED_PACKS = SUBPROCESS_PACK.parent

#: How long a verification may take, program and daemon included. A bound
#: rather than none, so a run that never ends is a red test and not a session
#: that hangs. The verifier has a far longer bound of its own; this one is
#: about three points walked against a daemon that is already up.
VERIFY_SECONDS = 180

#: The scope every question in this module is asked in, which is the scope
#: `_daemon.py`'s own rules are written for.
SCOPE = "local"

#: The published schema the daemon refuses a question by, named here the way
#: `packages/control-plane/tests/unit/test_published_schema_differential.py`
#: names it. A capability outside it is one no policy of this plane can allow,
#: because no question about it can be put in the first place.
ASK_SCHEMA = "decision-ask-request"

#: How one point is walked, keyed by the module and the attribute a pack
#: declares. `{reading}` is a file this run wrote for the purpose, so the
#: network point is walked with nothing leaving the host (article 17): the one
#: seam the interpreter offers covers every scheme `urllib.request` handles,
#: and a `file:` address is asked under the same capability an `http:` one is.
#:
#: A table and not a rule, because "walk this point" is not derivable from a
#: declaration: the three calls take three unrelated kinds of argument. A point
#: with no line here fails by name below rather than being left out of the
#: program, because a pack the program silently never walked is exactly the
#: vacuous proof this file exists to refuse.
WALKED: dict[tuple[str, str], str] = {
    ("sqlite3", "connect"): 'sqlite3.connect(":memory:").close()',
    ("urllib.request", "urlopen"): "urllib.request.urlopen({reading!r}).close()",
    ("subprocess", "Popen"): 'subprocess.run(["true"], check=True)',
}


def _shipped_packs() -> list[Path]:
    """Every pack the client checkout ships, read off its package data.

    Sorted, so the program below walks the points in one order and the set the
    report carries can be compared with this one as it stands.
    """
    return sorted(item for item in SHIPPED_PACKS.iterdir() if (item / DECLARATION).is_file())


def _declared(pack: Path) -> dict[str, Any]:
    """What one pack says about itself, read from its own `pack.toml`."""
    return tomllib.loads((pack / DECLARATION).read_text(encoding="utf-8"))


def _points_of(pack: Path) -> list[dict[str, Any]]:
    """Every point one pack declares, and never none of them."""
    points = _declared(pack)["point"]
    assert points, f"{pack} declares no point: a pack with none would prove nothing"
    return list(points)


def _names_of(packs: Sequence[Path]) -> list[str]:
    """The name each pack gives itself, which is the name the report spells.

    Read from the declaration rather than from the directory, because the
    report's `inspected` names packs the way the verifier read them and the two
    spellings agreeing is not something this file may assume.
    """
    return sorted(str(_declared(pack)["pack"]["name"]) for pack in packs)


def _capabilities_of(packs: Sequence[Path]) -> list[str]:
    """Every capability these packs declare, each one once.

    A set, then sorted: the same capability declared by two points is one
    question the daemon has to have a rule for, and a policy naming it twice
    would be two rules for one question.
    """
    return sorted({str(point["capability"]) for pack in packs for point in _points_of(pack)})


def _askable(capability: str) -> bool:
    """Whether the published contract can carry a question about this capability.

    Asked of the contract's own checker over the published ask schema, and
    never of a pattern spelled here: article 13 makes that schema what the
    daemon accepts, so this is the same rule the far end applies rather than a
    second copy of it that could drift from it.
    """
    document = {
        "contract_generation": CONTRACT_GENERATION,
        "capability": capability,
        "scope": SCOPE,
    }
    return refused_by(document, ASK_SCHEMA) is None


def _unaskable(capabilities: Sequence[str]) -> list[str]:
    """Those of these the published contract refuses to carry a question about.

    A capability here is one this plane can never allow: the policy loader
    refuses the rule, so a daemon given one does not start, and even a daemon
    that had the rule would refuse the question. It is read rather than assumed
    because a pack ships its own declaration, and nothing between the two
    repositories holds one against the other yet.
    """
    return [capability for capability in capabilities if not _askable(capability)]


def _allowing(capabilities: Sequence[str]) -> str:
    """One `allow` rule per capability this plane can be asked about.

    Scope `local`, the principal `_daemon.py` bakes into `_rule`, no digest
    pinned — the way `test_the_boundary_holds_a_real_grant.py` builds a one-off
    rule rather than this file adding a second table of them. The identifier is
    derived from the capability, so a policy this function writes can neither
    name two rules the same nor name a capability the packs do not declare.

    A capability the published schema refuses is LEFT OUT rather than written,
    because the policy loader refuses such a rule and a daemon given one never
    starts — which would report this gate as a daemon that would not come up
    instead of as the pack it is about. What keeps the omission from being
    silent is that the case it makes impossible carries it as its own reason,
    read out at import. An expected failure is counted in every run, and its
    reason is printed by every run that asks for one: `-rxX`, which this
    repository configures in `pyproject.toml`, and which a `-r` on a command
    line replaces rather than adds to.
    """
    return "\n".join(
        _rule(f"allow-{capability.replace('.', '-')}", capability, "allow")
        for capability in capabilities
        if _askable(capability)
    )


def _a_file_to_read(root: Path) -> Path:
    """A local file for the network point to read, so nothing leaves the host."""
    reading = root / "a-file-to-read.txt"
    reading.write_text("read me\n", encoding="utf-8")
    return reading


def _a_program_exercising(packs: Sequence[Path], root: Path) -> str:
    """A program that walks one point of every pack named, and nothing else.

    Built from what each pack declares, so a fourth pack joining the
    distribution arrives here as a program with a fourth call in it — or, if
    nothing says how to walk its point, as the failure below rather than as a
    pack this gate quietly left alone.
    """
    imports: list[str] = []
    walks: list[str] = []
    reading = _a_file_to_read(root).as_uri()
    for pack in packs:
        for point in _points_of(pack):
            module, attribute = str(point["module"]), str(point["attribute"])
            walked = WALKED.get((module, attribute))
            assert walked is not None, (
                f"{pack.name} declares a point on {module}.{attribute} that nothing here "
                f"knows how to walk: the pack would be reported not-exercised and this "
                f"gate would have nothing to say about it"
            )
            if f"import {module}" not in imports:
                imports.append(f"import {module}")
            walks.append(walked.format(reading=reading))
    return "\n".join([*imports, "", *walks, ""])


def _verify(
    running: _Daemon,
    packs: Sequence[Path],
    program: Path,
    *,
    json_output: bool = False,
    ungoverned: bool = False,
) -> subprocess.CompletedProcess[str]:
    """`sayfirst instrument verify ...`, over the packs designated here.

    Run as `test_the_chain_governs_a_program.py` runs `instrument run`, in the
    environment that module composes: `-c "from sayfirst_cli.main import run;
    run()"` and never `-m sayfirst_cli.main`, for the reason it gives beside
    its own invocation — the second form supplies the working directory as the
    head of the import path, which is the very thing the launcher under test
    has to supply itself.
    """
    argv = [
        sys.executable,
        "-c",
        "from sayfirst_cli.main import run; run()",
        "instrument",
        "verify",
    ]
    for pack in packs:
        argv += ["--pack", str(pack)]
    argv += ["--socket", str(running.socket_path), "--scope", SCOPE]
    if ungoverned:
        argv.append("--ungoverned")
    if json_output:
        argv.append("--json")
    argv += ["--", str(program)]
    return subprocess.run(
        argv, env=_client_environment(), capture_output=True, text=True, timeout=VERIFY_SECONDS
    )


def _the_unaskable_this_client_ships() -> list[str]:
    """The shipped capabilities this plane can never be asked about, read at import.

    Read here, and not inside the case it decides, because it is the case's own
    reason: a pack whose capability the published schema refuses can never be
    reported `governed`, so the case below is expected to fail for a named
    cause rather than to fail unexplained. The condition is read from the packs
    at import, so there is no mark anyone must remember to delete: a repaired
    sibling makes the list empty, the mark does not apply, and the case is a
    live green assertion — the reason retires with the next reading of this
    file rather than with a red run demanding it. The mark is strict for the
    other half: while such a pack is on disk, a run in which this case passes
    is a run that proved something it could not have, and fails as such.

    An absent client checkout answers with an empty list: the marks above skip
    every case in this file, and a reading that cannot be taken is not a
    finding about what the client ships.
    """
    try:
        return _unaskable(_capabilities_of(_shipped_packs()))
    except OSError:
        return []


#: The capabilities read from the packs on disk that no policy of this plane
#: can allow, and the sentence the case below fails with while there is one.
UNASKABLE = _the_unaskable_this_client_ships()
NO_POLICY_CAN_ALLOW = (
    "a pack this client ships declares a capability the published ask schema refuses, so no "
    "policy rule of this plane can name it, no question about it can be put, and no run can "
    f"report every point governed: {', '.join(UNASKABLE)}"
)


@pytest.mark.xfail(bool(UNASKABLE), strict=True, reason=NO_POLICY_CAN_ALLOW)
def test_the_verifier_inspects_every_pack_the_client_ships(daemon, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Every shipped pack designated, walked, governed, and named in the report.

    The first assertion is the anti-vacuity floor of the whole file: a checkout
    that ships no pack would satisfy every set comparison below by comparing
    two empty sets, which is the proof by finding nothing article 9 calls a
    failure.
    """
    shipped = _shipped_packs()
    assert shipped, "the client checkout ships no pack: this gate would prove nothing"
    names = _names_of(shipped)
    program = tmp_path / "app.py"
    program.write_text(_a_program_exercising(shipped, tmp_path), encoding="utf-8")
    running = daemon(_allowing(_capabilities_of(shipped)))

    finished = _verify(running, shipped, program, json_output=True)

    assert finished.returncode == 0, (finished.returncode, finished.stdout, finished.stderr)
    report = json.loads(finished.stdout)["result"]
    assert sorted(report["inspected"]) == names, (report, names)
    assert {point["verdict"] for point in report["points"]} == {"governed"}, report
    assert all(point["unjudged"] == 0 for point in report["points"]), report


def test_the_ungoverned_verdict_is_watched_firing(daemon, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A gate that has never been seen to fail is not known to be a gate.

    `--ungoverned` runs the same program bare — nothing in front of its
    effects — against the same chain, so the first point it walks must come
    back `ungoverned`. Without this case the assertion above could be
    satisfied by a verifier that reports `governed` unconditionally.

    Only the FIRST point can be asserted on, and that is a property of the
    mechanism rather than a weakness of the case: the verifier does not report
    an ungoverned effect after the fact, it aborts it inside the program, so
    the program dies at its first ungoverned call and the points after it were
    never reached. What is asserted is therefore the verdict and the code, and
    not a count of them.
    """
    shipped = _shipped_packs()
    assert shipped, "the client checkout ships no pack: this gate would prove nothing"
    program = tmp_path / "app.py"
    program.write_text(_a_program_exercising(shipped, tmp_path), encoding="utf-8")
    running = daemon(_allowing(_capabilities_of(shipped)))
    # The point the program walks first, derived the way the program derives
    # its own first line rather than spelled here. It is the one the verdict
    # below is about: the abort happens inside the call, so nothing after it
    # was reached to have a finding of its own.
    walked_first = shipped[0]
    named = str(_declared(walked_first)["pack"]["name"])
    capability = str(_points_of(walked_first)[0]["capability"])

    finished = _verify(running, shipped, program, ungoverned=True)

    assert finished.returncode == 6, (finished.returncode, finished.stdout, finished.stderr)
    assert f"ungoverned {named}" in finished.stdout, (finished.stdout, finished.stderr)
    # The effect was stopped inside the program rather than reported after it:
    # the raise the hook makes is what a shell sees on the error stream.
    assert f"ungoverned effect: {capability}" in finished.stderr, finished.stderr


def test_a_pack_the_client_ships_and_the_target_never_exercises_is_never_a_pass(
    daemon,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """`not-exercised` is a third value where a reader might expect two (article 2).

    The program walks one pack's point and leaves the others alone, so the run
    establishes nothing about them — and a run that reported that green would
    be the vacuous proof article 9 names. The inspected set is unchanged: every
    shipped pack was still designated and still watched for, which is what
    tells "this program walked no such path" from "this pack was never looked
    at".
    """
    shipped = _shipped_packs()
    assert len(shipped) > 1, "this case needs a pack the program can leave alone"
    names = _names_of(shipped)
    program = tmp_path / "app.py"
    program.write_text(_a_program_exercising(shipped[:1], tmp_path), encoding="utf-8")
    running = daemon(_allowing(_capabilities_of(shipped)))

    finished = _verify(running, shipped, program, json_output=True)

    assert finished.returncode == 7, (finished.returncode, finished.stdout, finished.stderr)
    report = json.loads(finished.stdout)["result"]
    assert sorted(report["inspected"]) == names, (report, names)
    assert "not-exercised" in {point["verdict"] for point in report["points"]}, report
