# SPDX-License-Identifier: Apache-2.0
"""The CLI's reads meet the daemon, and the contract verifies its evidence.

The walk also drives `sayfirst approvals`: a suspend rule, read through
`show`, ended through `approve`, and the next ask running the body once.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from copy import deepcopy
from pathlib import Path

import pytest
from _daemon import ALLOW, ARGUMENTS, DENY, REPOSITORY, SOURCES, SUSPEND, _Daemon
from sayfirst_boundary import Denied, Suspended
from sayfirst_contract.client import Answered, Refused
from sayfirst_contract.decisions import Outcome
from sayfirst_contract.evidence import (
    ChainCondition,
    manifest_hash,
    verify_chain,
    verify_export,
)
from sayfirst_contract.transport.socket_client import (
    SocketClientProblem,
    SocketProfile,
    VerifiedConnection,
    connect,
)


def _act_once(running: _Daemon) -> str:
    boundary, _, _ = running.boundary()
    with closing(boundary), boundary.request("example.effect", ARGUMENTS) as grant:
        return grant.decision_ref


def _three_acts(running: _Daemon) -> set[str]:
    boundary, client, _ = running.boundary()
    with closing(boundary):
        with boundary.request("example.effect", ARGUMENTS) as grant:
            allowed_ref = grant.decision_ref
        with pytest.raises(Denied) as raised, boundary.request("example.refused", ARGUMENTS):
            pytest.fail("a denied act ran its body")
        with boundary.request("example.effect", ARGUMENTS) as grant:
            assert grant.decision_ref == allowed_ref
        assert client.by_capability == {"example.effect": 1, "example.refused": 1}
    references = {allowed_ref, raised.value.decision_ref}
    assert len(references) == 2, references
    return references


#: How long anything this daemon writes asynchronously has to appear.
POLL_SECONDS = 15


def _profile(running: _Daemon) -> SocketProfile:
    """This daemon's address, as the transport's profile names it."""
    return SocketProfile(str(running.socket_path), mode="per_user", daemon_user=None, scope="local")


def _until[T](probe: Callable[[], T | None], describe: Callable[[], object]) -> T:
    """Poll until `probe` answers, or fail at the deadline with what `describe` says.

    `None` means « not yet », and so does a `SocketClientProblem`: a dial
    refused while the daemon is still coming up — after a restart, say — is
    what the deadline is for and never a verdict. Written once because it was
    written twice, identically, and the second copy of a deadline is where a
    deadline gets dropped.
    """
    deadline = time.monotonic() + POLL_SECONDS
    while True:
        refused: SocketClientProblem | None = None
        try:
            answer = probe()
        except SocketClientProblem as failure:
            answer, refused = None, failure
        if answer is not None:
            return answer
        assert time.monotonic() < deadline, (describe(), refused)
        time.sleep(0.05)


def _wait_for_decisions(
    connection: VerifiedConnection, references: set[str]
) -> Mapping[str, object]:
    """The write is asynchronous; an empty or incomplete chain proves nothing."""
    seen: list[Mapping[str, object]] = []

    def complete() -> Mapping[str, object] | None:
        result = connection.read_evidence("local", 1)
        assert isinstance(result, Answered), result
        page = result.value
        seen.append(page)
        recorded = {
            entry["body"]["decision_id"] for entry in page["entries"] if entry["kind"] == "effect"
        }
        return page if recorded == references else None

    return _until(complete, lambda: (references, seen[-1:]))


def _highest(page: Mapping[str, object]) -> int:
    """The last sequence a page of evidence carried, as an export bound.

    An empty page is not a bound of zero: it is a page this read cannot take a
    bound from, and `max()` of nothing is a `ValueError` out of the middle of a
    test rather than a statement about the daemon (article 2).
    """
    entries = page["entries"]
    assert isinstance(entries, list) and entries, (
        "this read needs a page with at least one entry to bound an export by"
    )
    return max(int(entry["sequence"]) for entry in entries)


def test_a_decision_the_boundary_was_given_can_be_read_back(daemon) -> None:  # type: ignore[no-untyped-def]
    """A missing route, unreadable record, wrong reference or outcome fails here."""
    running = daemon(ALLOW)
    ref = _act_once(running)
    looked: list[object] = []

    # The record lands after the answer is on the wire; a read that arrives
    # first is « not found », so the read is polled to a deadline like every
    # other read of something the daemon writes asynchronously.
    def read_back() -> Answered | None:
        with closing(connect(_profile(running))) as connection:
            result = connection.read_decision("local", ref)
        looked.append(result)
        return result if isinstance(result, Answered) else None

    result = _until(read_back, lambda: looked[-1:])
    assert result.value.decision_ref == ref
    assert result.value.outcome is Outcome.ALLOW


def test_an_unknown_decision_is_a_refusal_by_name(daemon) -> None:  # type: ignore[no-untyped-def]
    """The route's decision_not_found reaches the caller as a refusal, by its code.

    Article 1 forbids writing « could not ask » as « denied » and forbids the
    reverse, and a case title is the one place a reader scanning a test run
    sees which of the two a read of a missing record is. It is a refusal: the
    daemon was asked, consulted its store, and answered that it holds no
    decision with that reference in that scope — the class the registry
    publishes for the code, read by both clients of the contract.
    """
    running = daemon(ALLOW)
    with closing(connect(_profile(running))) as connection:
        result = connection.read_decision("local", "missing")
    assert type(result) is Refused, result
    assert result.problem.code == "decision_not_found"


def test_the_served_verdict_and_the_local_one_agree_on_an_intact_chain(daemon) -> None:  # type: ignore[no-untyped-def]
    """Missing effects or disagreement between the two verifiers fails here."""
    running = daemon(ALLOW + "\n" + DENY)
    references = _three_acts(running)
    with closing(connect(_profile(running))) as connection:
        page = _wait_for_decisions(connection, references)
    verdict = verify_chain(page["entries"], scope="local", from_sequence=1)
    assert verdict.condition is ChainCondition.intact, (verdict, page)
    assert page["verification"]["condition"] == "intact", page


def test_an_export_verifies_with_the_contract_alone(daemon) -> None:  # type: ignore[no-untyped-def]
    """An export whose chain or manifest cannot be verified independently fails here."""
    running = daemon(ALLOW + "\n" + DENY)
    references = _three_acts(running)
    with closing(connect(_profile(running))) as connection:
        page = _wait_for_decisions(connection, references)
        # Bounded at what the poll actually read. The writer appends while this
        # case runs — a grade, a composition — so an unbounded export takes
        # whatever the head is at read time, and then the bundle is not the
        # range the assertions below reason about.
        result = connection.export_evidence("local", 1, to_sequence=_highest(page))
    assert isinstance(result, Answered), result
    bundle = result.value
    verdict = verify_export(bundle)
    assert verdict.manifest_hash_recomputes is True, (verdict, bundle)
    assert verdict.chain is not None, (verdict, bundle)
    assert verdict.chain.condition is ChainCondition.intact, (verdict, bundle)
    assert bundle["manifest_hash"] == manifest_hash(bundle, version=bundle["manifest_version"]), (
        bundle
    )


def test_a_tampered_export_is_caught_locally(daemon) -> None:  # type: ignore[no-untyped-def]
    """Changing one capability character must break its entry and its manifest hash."""
    running = daemon(ALLOW + "\n" + DENY)
    references = _three_acts(running)
    with closing(connect(_profile(running))) as connection:
        page = _wait_for_decisions(connection, references)
        # Start this served bundle at an effect: earlier entries describe the
        # composition and grade and have no capability to change.
        first_effect = next(entry for entry in page["entries"] if entry["kind"] == "effect")
        # Bounded at what the poll read, for the reason given in the export case
        # above: entries appended after it would be in the bundle and not in
        # the page the tampering is chosen from.
        result = connection.export_evidence(
            "local", int(first_effect["sequence"]), to_sequence=_highest(page)
        )
    assert isinstance(result, Answered), result
    bundle = result.value
    intact = verify_export(bundle)
    assert intact.manifest_hash_recomputes is True, (intact, bundle)
    assert intact.chain is not None and intact.chain.condition is ChainCondition.intact, (
        intact,
        bundle,
    )

    tampered = deepcopy(bundle)
    entries = tampered["entries"]
    capability = entries[0]["body"]["capability"]
    entries[0]["body"]["capability"] = ("x" if capability[0] != "x" else "y") + capability[1:]
    verdict = verify_export(tampered)
    assert verdict.chain is not None, verdict
    assert verdict.chain.condition is ChainCondition.broken_at, verdict
    assert verdict.chain.sequence == entries[0]["sequence"]
    assert verdict.manifest_hash_recomputes is False, verdict


def test_policy_status_names_the_loaded_version(daemon) -> None:  # type: ignore[no-untyped-def]
    """The unchanged policy's status must name the version used by the read-back decision."""
    running = daemon(ALLOW)
    ref = _act_once(running)
    with closing(connect(_profile(running))) as connection:
        decision = connection.read_decision("local", ref)
        status = connection.read_policy_status()
    assert isinstance(decision, Answered), decision
    assert decision.value.decision_ref == ref
    assert decision.value.outcome is Outcome.ALLOW
    assert isinstance(status, Answered), status
    assert status.value.policy_version == decision.value.policy_version


def test_two_reads_are_answered_on_one_connection_without_a_reconnect(daemon) -> None:  # type: ignore[no-untyped-def]
    """Rule C4: the daemon keeps a connection a document answer left good.

    The daemon closed after ANY answer an adapter wrote, reads included, so the
    case above had to re-verify the address between two reads that ask nothing
    of each other. This is the same pair with the re-verification taken out and
    the connection itself asserted: `LocalHttpConnection` has `auto_open` off,
    so a far end that closed would make the second read « could not ask »
    rather than silently re-open the address — which is what makes the absence
    of a `reconnect()` a proof and not an omission.
    """
    running = daemon(ALLOW)
    ref = _act_once(running)
    with closing(connect(_profile(running))) as connection:
        opened = connection.http.sock
        assert isinstance(connection.read_decision("local", ref), Answered)
        assert isinstance(connection.read_policy_status(), Answered)
        assert isinstance(connection.read_approval("local", "approval-nobody-opened"), Refused)
        assert isinstance(connection.read_evidence("local", 1), Answered)
        assert connection.http.sock is opened, "the transport opened a second connection"
        assert connection.verified


# ---------------------------------------------------------------------------
# The published client's reads, against this daemon. Everything above holds the
# transport directly; the case below holds nothing — it runs the open command
# the way a person runs it, and reads its streams and its exit code. A client
# and a server that were only ever tested apart agree about the wire here or
# nowhere.
# ---------------------------------------------------------------------------

#: The open command-line client lives in its own repository, beside this one.
#: It is invoked as a SUBPROCESS for the reason written beside the same constant
#: in `test_the_boundary_holds_a_real_grant.py`: the client depends on the
#: contract and never on the server (article 13), and a process boundary is the
#: honest way to exercise it from here without pretending otherwise.
CLIENT_REPO = REPOSITORY.parent / "sf-cli-lt"

#: The modules the case below drives, beyond the `ask` the boundary case drives.
#: A checkout that ships `ask` alone answers `explain` with a usage error, which
#: is a red case rather than an honest skip — so the guard names what is run.
READ_COMMANDS = ("explain.py", "trace.py", "evidence.py")
CLIENT_MODULES = CLIENT_REPO / "src" / "sayfirst_cli"
CLIENT_PRESENT = (CLIENT_MODULES / "ask.py").is_file()
READS_PRESENT = all((CLIENT_MODULES / name).is_file() for name in READ_COMMANDS)
#: `approvals` is not one of the four reads above — it also acts,
#: once, to end a wait — so a checkout that ships the reads and not it is a
#: skip of its own rather than a failure of `READS_PRESENT`.
APPROVALS_PRESENT = (CLIENT_MODULES / "approvals.py").is_file()


def _client_environment() -> dict[str, str]:
    """The client's sources first, then this repository's — as the `ask` cases compose it."""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(CLIENT_REPO / "src"),
            *(str(item) for item in SOURCES),
            *filter(None, [os.environ.get("PYTHONPATH")]),
        ]
    )
    return environment


def _client(*argv: str) -> subprocess.CompletedProcess[str]:
    """Run the published command once, exactly as its console script would."""
    return subprocess.run(
        [
            sys.executable,
            # The published entry point is the console script, which resolves to
            # `main:run`. `-m sayfirst_cli.main` imports the module and exits 0
            # in silence — there is no `__main__` guard — so invoking it that way
            # would test nothing while looking like a pass.
            "-c",
            "from sayfirst_cli.main import run; run()",
            *argv,
        ],
        env=_client_environment(),
        capture_output=True,
        text=True,
        timeout=60,
    )


def _spoke(finished: subprocess.CompletedProcess[str], *lines: str) -> str:
    """A read that succeeded: exit 0, stdout says these things, stderr says nothing.

    The empty stderr is half the assertion. A client that writes a warning
    beside a successful answer has made the answer ambiguous to every caller
    that treats stderr as the failure channel.
    """
    assert finished.returncode == 0, (finished.returncode, finished.stdout, finished.stderr)
    assert finished.stderr == "", finished.stderr
    for line in lines:
        assert line in finished.stdout, (line, finished.stdout)
    return finished.stdout


def _two_acts(running: _Daemon) -> tuple[str, str]:
    """One allow and one denial through the boundary, keeping both references."""
    boundary, _, _ = running.boundary()
    with closing(boundary):
        with boundary.request("example.effect", ARGUMENTS) as grant:
            allowed = grant.decision_ref
        with pytest.raises(Denied) as raised, boundary.request("example.refused", ARGUMENTS):
            pytest.fail("a denied act ran its body")
    refused = raised.value.decision_ref
    assert allowed != refused, (allowed, refused)
    return allowed, refused


def _traced(socket: str, reference: str) -> subprocess.CompletedProcess[str]:
    """`trace`, retried until the chain write lands — or the deadline says it never did.

    The effect entry is written asynchronously, so `chain: not found` is a true
    statement about a chain that has not caught up yet. It stops being one at
    the deadline, and the last attempt is returned either way so the failure
    shows what the client actually printed.
    """
    # Its own loop, not `_until`: this one RETURNS its last attempt at the
    # deadline instead of failing, so the failure shows what the client printed.
    deadline = time.monotonic() + POLL_SECONDS
    while True:
        finished = _client("trace", "--scope", "local", "--decision", reference, "--socket", socket)
        if "chain: sequence " in finished.stdout or time.monotonic() >= deadline:
            return finished
        time.sleep(0.1)


def _closed_epoch_end(running: _Daemon) -> int:
    """The `through_sequence` of the `clean_stop` the restart wrote, once it is readable.

    A bundle proves coverage only for a range inside an epoch the daemon closed,
    and the daemon attaches the closure as `recovery_context` only when the
    range stops before the head. This number is therefore the whole reason the
    export below can come back `confirmed` rather than `unverifiable`.
    """
    seen: list[Mapping[str, object]] = []

    def closure() -> int | None:
        entries: list[Mapping[str, object]] = []
        with closing(connect(_profile(running))) as connection:
            start: int | None = 1
            while start is not None:
                result = connection.read_evidence("local", start)
                assert isinstance(result, Answered), result
                entries.extend(result.value["entries"])
                following = result.value.get("next_from")
                # A page that does not advance is a daemon defect, not a
                # reason to walk forever; the client's own reader refuses it.
                assert following is None or int(following) > start, (start, following)
                start = None if following is None else int(following)
        seen[:] = entries
        closures = [
            entry
            for entry in entries
            if entry["kind"] == "recovery" and entry["body"].get("event") == "clean_stop"
        ]
        return int(closures[-1]["body"]["through_sequence"]) if closures else None

    return _until(closure, lambda: seen)


@pytest.mark.skipif(
    not CLIENT_PRESENT,
    reason="the open command-line client is not checked out beside this repository",
)
@pytest.mark.skipif(
    not READS_PRESENT,
    reason="the sibling client checkout does not ship the read commands",
)
def test_the_published_client_reads_and_checks_this_daemons_record(daemon, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """`explain`, `trace` and the four `evidence` reads, against a daemon that decided.

    The client's own gate drives a canned daemon, which proves its rendering and
    its exit codes. This proves the two agree about the wire, and — for the
    export rows — that a bundle this daemon served verifies with the contract
    the client carries and nothing else.

    It is one case rather than several because it is one walk: the export rows
    depend on a restart that must follow the acts, and the two `exports` rows
    depend on what the directory held when each ran.

    Two mutations were run against this case on 2026-09-15, each with
    `pytest tests/e2e/test_the_reads_answer_from_a_real_daemon.py -k
    published_client_reads` after changing the daemon's evidence reads, and the
    results are what is claimed for them here. Serving `next_from` as the
    request's own start instead of `None` at the end of the chain failed the
    `history` row: exit 4, and « answer_unreadable: evidence page member
    next_from does not advance the read ». Serving an empty `recovery_context`
    on an export bundle failed the closed-export row: `local_check:
    unverifiable`, `issue: coverage_unknown`, exit 7.
    """
    running = daemon(ALLOW + "\n" + DENY)
    allowed, refused = _two_acts(running)
    socket = str(running.socket_path)
    # Both effects on the chain before the restart closes the epoch: a decision
    # the writer had not reached yet would land in the NEXT epoch, and the
    # export below would then be short of the record it claims to cover.
    with closing(connect(_profile(running))) as connection:
        _wait_for_decisions(connection, {allowed, refused})

    # -- explain ------------------------------------------------------------
    _spoke(
        _client("explain", "--scope", "local", "--decision", allowed, "--socket", socket),
        "outcome: allow",
        "policy_version: ",
    )
    _spoke(
        _client("explain", "--scope", "local", "--decision", refused, "--socket", socket),
        "outcome: deny",
        "reason: policy_denies",
    )
    missing = _client(
        "explain", "--scope", "local", "--decision", "nothing-here", "--socket", socket
    )
    # An unknown decision is a question the daemon received and rejected: it
    # consulted its store and answered that it holds no such record. The
    # registry's class column publishes `decision_not_found` as a refusal
    # (`test_an_unknown_decision_is_a_refusal_by_name` above asserts the same of
    # the same read), and the client renders a refusal as 3; 4 is reserved for a
    # question no answer exists about.
    assert missing.returncode == 3, (missing.returncode, missing.stdout, missing.stderr)
    assert missing.stdout == "", missing.stdout
    assert "decision_not_found" in missing.stderr, missing.stderr

    # -- trace --------------------------------------------------------------
    traced = _spoke(_traced(socket, allowed), "chain: sequence ", f"decision_ref: {allowed}")
    assert "chain: not found" not in traced, traced

    # -- evidence history and audit -----------------------------------------
    history = _spoke(
        _client(
            "evidence", "history", "--scope", "local", "--socket", socket, "--from", "1", "--all"
        ),
        "next_from: none",
    )
    numbered = [line for line in history.splitlines() if re.match(r"\d", line)]
    assert len(numbered) >= 2, history
    audited = _spoke(
        _client("evidence", "audit", "--scope", "local", "--socket", socket, "--from", "1"),
        "verification: intact",
        "local_check: intact",
    )
    assert "finding:" not in audited, audited

    # -- the export rows, which need an epoch the daemon closed --------------
    running.restart()
    through = _closed_epoch_end(running)
    bundle = tmp_path / "bundle.json"
    #: The three exports below differ only in their bounds and their destination.
    export = ("evidence", "export", "--scope", "local", "--socket", socket)
    _spoke(
        _client(*export, "--from", "1", "--to", str(through), "--out", str(bundle)),
        "local_check: confirmed",
        f"saved: {bundle}",
    )
    _spoke(
        _client("evidence", "audit", "--file", str(bundle)),
        "coverage: complete",
        "manifest: recomputes",
    )
    listed = _spoke(_client("evidence", "exports", str(tmp_path)))
    rows = [line for line in listed.splitlines() if line.startswith("bundle.json ")]
    assert len(rows) == 1, listed
    assert "local:confirmed" in rows[0], listed

    # -- and the honest opposite: the open epoch cannot be proven -----------
    still_open = tmp_path / "open.json"
    opened = _client(*export, "--from", "1", "--out", str(still_open))
    assert opened.returncode == 7, (opened.returncode, opened.stdout, opened.stderr)
    assert "issue: coverage_unknown" in opened.stdout, opened.stdout
    # Saved anyway: a bundle whose coverage cannot be established is still the
    # record the daemon served, and withholding it would hide the evidence
    # rather than qualify it.
    saved = still_open.read_text(encoding="utf-8")
    assert saved, still_open

    both = _client("evidence", "exports", str(tmp_path))
    assert both.returncode == 7, (both.returncode, both.stdout, both.stderr)
    assert "local:confirmed" in both.stdout, both.stdout
    assert "local:unverifiable" in both.stdout, both.stdout

    # -- and it refuses to write over what it already wrote ------------------
    again = _client(*export, "--from", "1", "--out", str(still_open))
    assert again.returncode == 64, (again.returncode, again.stdout, again.stderr)
    assert again.stdout == "", again.stdout
    assert still_open.read_text(encoding="utf-8") == saved, still_open


# ---------------------------------------------------------------------------
# `sayfirst approvals`: a suspend rule, read and ended through the
# published client, and the grant its resolution mints. Held apart from the
# case above because it drives the boundary as well as the transport, which
# none of the four reads do.
# ---------------------------------------------------------------------------


def _suspended(running: _Daemon, capability: str = "example.waits") -> Suspended:
    """One ask through the boundary the policy suspends, and the reference it names."""
    boundary, _, _ = running.boundary()
    with (
        closing(boundary),
        pytest.raises(Suspended) as raised,
        boundary.request(capability, ARGUMENTS),
    ):
        pytest.fail("a suspended effect ran its body")
    assert raised.value.approval_ref, "a suspension the daemon keeps names its wait"
    return raised.value


def _explained(socket: str, reference: str) -> subprocess.CompletedProcess[str]:
    """`explain`, retried until the decision record lands — or the deadline says it never did.

    Mirrors `_traced` above: its own loop, not `_until`, so a failure shows
    what the client actually printed rather than an assertion from inside a
    probe.
    """
    deadline = time.monotonic() + POLL_SECONDS
    while True:
        finished = _client(
            "explain", "--scope", "local", "--decision", reference, "--socket", socket
        )
        if finished.returncode == 0 or time.monotonic() >= deadline:
            return finished
        time.sleep(0.1)


@pytest.mark.skipif(
    not CLIENT_PRESENT,
    reason="the open command-line client is not checked out beside this repository",
)
@pytest.mark.skipif(
    not APPROVALS_PRESENT,
    reason="the sibling client checkout does not ship sayfirst approvals",
)
def test_the_published_client_shows_and_resolves_an_approval(daemon) -> None:  # type: ignore[no-untyped-def]
    """`sayfirst approvals show` and `approve` meet a real suspension, end to end.

    The boundary asks a suspend rule; `show` renders the pending wait; `approve
    --reason ok` ends it and renders the approved record; the next ask through
    the SAME boundary allows with the grant that approval minted, so the body
    runs once (article 10 — a grant answers the question it was minted for
    without a second ask, and `counting.by_capability` is what actually
    measures that, not a read of the daemon's own record). A third ask, on a
    fresh boundary so it is not answered from the grant the second one holds,
    suspends anew on a new reference — and resolving the FIRST, already-spent
    reference again is refused.

    That refusal is `approval_resolved`, and the registry's class column
    publishes it as a refusal — the daemon was asked to end a wait that was
    already over and answered that it will not, which is a verdict on the act
    and not a missing answer — so the published client renders it as exit 3.
    """
    running = daemon(SUSPEND)
    socket = str(running.socket_path)
    suspended = _suspended(running)
    reference = suspended.approval_ref

    _spoke(
        _client(
            "approvals", "show", "--scope", "local", "--approval", reference, "--socket", socket
        ),
        f"approval: {reference}",
        "state: pending",
    )

    approved = _client(
        "approvals",
        "approve",
        "--scope",
        "local",
        "--approval",
        reference,
        "--socket",
        socket,
        "--reason",
        "ok",
    )
    _spoke(approved, "state: approved", "reason: ok")

    holder, counting, _ = running.boundary()
    with closing(holder):
        with holder.request("example.waits", ARGUMENTS) as grant:
            allowed = grant.decision_ref
        # The same question again, on the same boundary: answered from the
        # grant the first ask minted, which is what makes the body run once.
        with holder.request("example.waits", ARGUMENTS) as again:
            assert again.decision_ref == allowed
        assert counting.by_capability == {"example.waits": 1}

    _spoke(_explained(socket, allowed), "outcome: allow", "reason: approval_granted")

    # One resolution authorises one execution: a fresh boundary's ask of the
    # same question finds the approval spent and waits anew, on a new reference.
    anew = _suspended(running)
    assert anew.approval_ref != reference

    spent = _client(
        "approvals", "approve", "--scope", "local", "--approval", reference, "--socket", socket
    )
    assert spent.returncode == 3, (spent.returncode, spent.stdout, spent.stderr)
    assert spent.stdout == "", spent.stdout
    assert "approval_resolved" in spent.stderr, spent.stderr
