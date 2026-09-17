# SPDX-License-Identifier: Apache-2.0
"""Articles 1, 3, 10 and 13: a daemon explains, after a restart, a decision it took before it.

The product's central promise, held here end to end: decide, stop, start,
explain. The decision is read back whole from the durable authority the
previous daemon wrote; the chain the new daemon appends to is the chain the
old one left; the export of that chain and the contract wheel alone are
enough for an independent reader to re-derive the recorded answer from the
policy bytes the decision named. Nothing survives a restart that should not:
no grant, no connection, no resolution of a suspended decision.

Two harnesses. The composed-daemon fixture composes a second daemon over the
first one's root inside this process, which is where the seams between the
blocks are cheapest to drive. The last case stops and restarts a real daemon
process through the published command, because a restart is a process
boundary and an in-process double of one proves less.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import pwd
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from itertools import pairwise
from pathlib import Path

from composed_daemon import policy_document
from sayfirst_contract.evidence import MANIFEST_V3, Rederivation, verify_export
from sayfirst_testing.guard_gates import OS_REAL_PLATFORMS
from sayfirst_testing.platforms import requires_platforms
from sayfirst_testing.schemas import validate_document

REPOSITORY = Path(__file__).resolve().parents[4]
SOURCES = (
    REPOSITORY / "packages" / "contract" / "src",
    REPOSITORY / "packages" / "control-plane" / "src",
)
ME = os.geteuid()
MY_NAME = pwd.getpwuid(ME).pw_name
DIGEST = "sha256:" + "3" * 64


def _chain(root: Path, scope: str = "local") -> list[dict]:
    """Read the chain the way the store's own reader does.

    The daemon is appending while this reads, and `_write` in
    `adapters/file/evidence_store.py` loops over `os.write` until its buffer is
    drained — so between two of those calls a partial line is on disk and
    visible. The store's reader handles that by dropping an UNTERMINATED TAIL
    (`raw.splitlines() if raw.endswith(b"\\n") else raw.splitlines()[:-1]`),
    and the store also records a `gap` with `reason: "torn"` when it finds one
    on reopening, so a torn write is a case the design knows about rather than
    corruption.

    This reader did neither, and `json.loads` on the half-written tail raised.
    Measured before fixing: the module failed roughly one run in three on its
    own, and surfaced in a full-suite run where the extra load changed the
    timing. The flakiness was never about what the test asserts.
    """
    path = root / "evidence" / f"{scope}.jsonl"
    if not path.exists():
        return []
    raw = path.read_bytes()
    lines = raw.splitlines() if raw.endswith(b"\n") else raw.splitlines()[:-1]
    return [json.loads(line) for line in lines if line]


def _wait_for(session, holding: Callable[[list[dict]], bool]) -> list[dict]:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + 5.0
    entries = _chain(session.root)
    while not holding(entries) and time.monotonic() < deadline:
        session.flush()
        time.sleep(0.01)
        entries = _chain(session.root)
    assert holding(entries), [item["kind"] for item in entries]
    return entries


def _effects(entries: list[dict]) -> list[dict]:
    return [item for item in entries if item["kind"] == "effect"]


def _export(session, from_sequence: int = 1):  # type: ignore[no-untyped-def]
    status, bundle = session.request(
        "GET",
        f"/scopes/local/evidence/export?contract_generation=1&from_sequence={from_sequence}",
    )
    assert status == 200, bundle
    validate_document(bundle, "evidence-export-result")
    return bundle


# -- decide, stop, start, explain ----------------------------------------------------


def test_decision_evidence_and_baseline_survive_process_restart(composed) -> None:
    """S1, S2, G17: the record, the chain and the archive are the previous daemon's."""
    first = composed(rules=[("allow", "example.effect")])
    _, decision = first.ask(arguments_digest=DIGEST, correlation="gate-1")
    assert decision["outcome"] == "allow"
    before = _wait_for(first, lambda entries: len(_effects(entries)) == 1)
    _, stored = first.request(
        "GET", f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local"
    )
    first.close()

    second = composed(root=first.root, rewrite_policy=False)
    status, read = second.request(
        "GET", f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local"
    )
    assert status == 200, read
    validate_document(read, "decision-record")
    # The whole document, not just the outcome (G11): the reason, the rule, the
    # digest, the correlation and its source, the references, the recipe.
    assert read == stored
    assert read["reason"] == "policy_allows"
    assert read["rule_id"] == "rule-0"
    assert read["arguments_digest"] == DIGEST
    assert read["correlation"] == "gate-1"
    assert read["correlation_source"] == "boundary_supplied"
    assert read["principal_references"] == ["user:alice"]
    assert read["evaluation_recipe"] == "sayfirst/policy-evaluation/v1"

    # The chain continues after the recovered head: the first life's clean
    # stop, then the new composition, each linked to what precedes it, never a
    # new chain.
    after = _wait_for(
        second,
        lambda entries: any(item["kind"] == "composition" for item in entries[len(before) :]),
    )
    assert after[: len(before)] == before
    new = after[len(before) :]
    assert [item["kind"] for item in new][:3] == ["grade", "recovery", "composition"]
    assert new[1]["body"]["event"] == "clean_stop"
    for previous, entry in pairwise(after):
        assert entry["previous_hash"] == previous["entry_hash"]
    assert new[2]["body"]["recording_epoch"] != before[0]["body"]["recording_epoch"]

    # Connections, cached groups and the grant registry end with the process (S4, S5).
    assert second.services.decisions.grants.connection_count == 0


def test_the_export_after_a_restart_lets_an_independent_reader_re_derive_the_decision(
    composed,
) -> None:
    """V3, H1: the export and the contract wheel alone confirm the recorded answer."""
    first = composed(rules=[("allow", "example.effect")])
    _, decision = first.ask(correlation="gate-1")
    _wait_for(first, lambda entries: len(_effects(entries)) == 1)
    policy_bytes = first.policy_path.read_bytes()
    first.close()

    second = composed(root=first.root, rewrite_policy=False)
    bundle = _export(second)
    assert bundle["manifest_version"] == MANIFEST_V3
    attachment = bundle["policy_versions"][decision["policy_version"]]
    assert base64.b64decode(attachment["content"]) == policy_bytes

    verdict = verify_export(bundle)
    assert verdict.manifest_hash_recomputes is True
    assert verdict.chain is not None and verdict.chain.condition.value == "intact"
    assert verdict.rederived_decision_ids == (decision["decision_ref"],)
    assert verdict.confirmed_decision_ids == (decision["decision_ref"],)
    by_id = {item.decision_id: item for item in verdict.rederivations}
    assert by_id[decision["decision_ref"]].verdict is Rederivation.confirmed
    assert by_id[decision["decision_ref"]].evaluation_recipe == "sayfirst/policy-evaluation/v1"
    # The whole chain includes the second life's epoch, which is still open, so
    # the coverage is honestly unknown and the whole-bundle verdict stays short
    # of `confirmed` (H2, H3); the closed epoch alone is confirmed below.
    assert verdict.coverage == "unknown"
    assert "coverage_unknown" in verdict.issues
    assert verdict.overall is Rederivation.unverifiable

    # The read decision's shared facts equal the exported effect's (S8).
    effect = next(item for item in bundle["entries"] if item["kind"] == "effect")
    _, read = second.request(
        "GET", f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local"
    )
    for member in ("reason", "rule_id", "arguments_digest", "correlation", "principal_references"):
        assert effect["body"][member] == read[member], member
    assert effect["body"]["decision_id"] == read["decision_ref"]
    assert effect["body"]["policy_version"] == read["policy_version"]


def test_a_recorded_answer_the_archived_bytes_contradict_is_reported_as_differs(
    composed,
) -> None:
    """Article 2, H3: the verifier reports what the bytes yield; a contradiction stays visible."""
    first = composed(rules=[("allow", "example.effect")])
    _, decision = first.ask()
    _wait_for(first, lambda entries: len(_effects(entries)) == 1)
    first.close()
    second = composed(root=first.root, rewrite_policy=False)
    bundle = _export(second)
    # A reader handed an export whose recorded outcome someone rewrote — the
    # chain then says `broken_at`, and the entry is untrusted, not re-derived.
    forged = json.loads(json.dumps(bundle))
    effect = next(item for item in forged["entries"] if item["kind"] == "effect")
    effect["body"]["outcome"] = "deny"
    verdict = verify_export(forged)
    assert verdict.chain is not None and verdict.chain.condition.value == "broken_at"
    assert verdict.manifest_hash_recomputes is False
    assert verdict.rederivations[0].cause == "entry_untrusted"
    # And a bundle whose attached bytes are another version's: the entry is
    # trusted, the bytes are damaged, and nothing is confirmed against them.
    other = json.loads(json.dumps(bundle))
    version = decision["policy_version"]
    other["policy_versions"][version] = {
        "state": "present",
        "content": base64.b64encode(
            policy_document([("deny", "example.effect")]).encode()
        ).decode(),
    }
    verdict = verify_export(other)
    assert verdict.rederivations[0].cause == "policy_damaged"
    assert verdict.confirmed_decision_ids == ()


def test_restart_derives_no_resolution_for_a_suspended_decision(composed) -> None:
    """S6, G21: a suspension waits for a human; a restart is not one."""
    first = composed(rules=[("suspend", "example.effect")])
    _, decision = first.ask()
    assert decision["outcome"] == "suspend"
    first.close()
    second = composed(root=first.root, rewrite_policy=False)
    status, read = second.request(
        "GET", f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local"
    )
    assert status == 200, read
    assert read["outcome"] == "suspend"
    assert read["reason"] == "policy_requires_review"
    assert "approval_ref" not in read or read["approval_ref"] is None


def test_policy_changed_while_down_is_reread_and_projection_rebuilt(composed) -> None:
    """S3, G18: the current policy is the file; the archived version stays what it was."""
    first = composed(rules=[("allow", "example.effect")])
    _, old = first.ask()
    _wait_for(first, lambda entries: len(_effects(entries)) == 1)
    old_bytes = first.policy_path.read_bytes()
    first.close()

    first.policy_path.write_text(
        policy_document([("deny", "example.effect")], reason="changed while down"),
        encoding="utf-8",
    )
    os.chmod(first.policy_path, 0o600)
    second = composed(root=first.root, rewrite_policy=False)
    _, new = second.ask()
    assert new["outcome"] == "deny"
    assert new["policy_version"] != old["policy_version"]
    _, status = second.request("GET", "/policy/status?contract_generation=1")
    assert status["policy_version"] == new["policy_version"]
    assert status["projection"]["in_step"] == "yes"
    archive = second.services.archive
    assert archive is not None
    assert archive.read(old["policy_version"]).content == old_bytes
    assert archive.read(new["policy_version"]).content == first.policy_path.read_bytes()
    _wait_for(second, lambda entries: len(_effects(entries)) == 2)
    verdict = verify_export(_export(second))
    assert set(verdict.confirmed_decision_ids) == {old["decision_ref"], new["decision_ref"]}
    assert set(verdict.policy_versions) == {old["policy_version"], new["policy_version"]}


def test_restart_ends_grants_but_preserves_prepared_grant_id(composed) -> None:
    """S5, G20: a graceful stop signals the held stream; the record keeps the grant id."""
    first = composed(rules=[("allow", "example.effect")])
    held = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    held.settimeout(10)
    held.connect(first.daemon.settings.socket_path)
    body = json.dumps({"contract_generation": 1, "capability": "example.effect", "scope": "local"})
    held.sendall(
        (
            "POST /decisions HTTP/1.1\r\nHost: sayfirst\r\nAccept: text/event-stream\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
        ).encode()
    )
    frames = b""
    while b"event: decision" not in frames or not frames.endswith(b"\n\n"):
        chunk = held.recv(65536)
        assert chunk, frames
        frames += chunk
    decision_frame = frames.split(b"event: decision\ndata: ", 1)[1].split(b"\n\n", 1)[0]
    decision = json.loads(decision_frame)
    assert decision["grant"] is not None
    grant_id = decision["grant"]["grant_id"]
    # The frame is written before the grant is registered (article 10), so the
    # boundary holding it is ahead of the registry by one scheduling of the
    # daemon's thread: this case is the stop of a grant that is held, and it
    # waits for that state rather than asserting it at the instant the frame
    # arrived. The stop that lands inside that instant is its own case,
    # `test_a_stop_that_lands_between_the_answer_and_the_registration_still_signals_the_grant`.
    grants = first.services.decisions.grants
    deadline = time.monotonic() + 5.0
    while grants.connection_count != 1 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert grants.connection_count == 1

    first.close()
    ended = frames
    while b"grant_ended" not in ended:
        chunk = held.recv(65536)
        if not chunk:
            break
        ended += chunk
    held.close()
    assert b"event: grant_ended" in ended, ended
    signal_document = json.loads(ended.split(b"event: grant_ended\ndata: ", 1)[1].split(b"\n\n")[0])
    assert signal_document["reason"] == "daemon_stopping"
    assert signal_document["grant_id"] == grant_id

    second = composed(root=first.root, rewrite_policy=False)
    assert second.services.decisions.grants.connection_count == 0
    _, read = second.request(
        "GET", f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local"
    )
    # Preparation only, never receipt or use (C2).
    assert read["grant_id"] == grant_id


# -- a real process boundary --------------------------------------------------------

_POLICY = f"""format = 1

[revision]
reason = "the durable decision lifecycle"

[[rule]]
id = "scenario-0"
capability = "example.effect"
scope = "local"
principals = ["user:{MY_NAME}"]
outcome = "allow"
reason = "the composed daemon decides"
"""


def _ask_process(socket_path: Path, method: str, target: str, document: object | None = None):  # type: ignore[no-untyped-def]
    connection = http.client.HTTPConnection("sayfirst")
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(10)
    connection.sock.connect(str(socket_path))
    body = None if document is None else json.dumps(document)
    connection.request(
        method,
        target,
        body=body,
        headers={} if body is None else {"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    parsed = json.loads(response.read() or b"{}")
    connection.close()
    return response.status, parsed


def _start(config: Path) -> subprocess.Popen[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [*(str(item) for item in SOURCES), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "sayfirst_control_plane.cli", "serve", "--config", str(config)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline()
    assert ready.startswith("serving "), (ready, process.stderr.read() if process.stderr else "")
    return process


def _stop(process: subprocess.Popen[str]) -> None:
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=20) == 0, process.stderr.read() if process.stderr else ""


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_decision_taken_by_one_daemon_process_is_explained_by_the_next(tmp_path: Path) -> None:
    """Decide, stop the process, start another over the same root, explain, verify offline."""
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    policy = run / "policy.toml"
    policy.write_text(_POLICY, encoding="utf-8")
    os.chmod(policy, 0o600)
    socket_path = run / "daemon.sock"
    config = run / "daemon.toml"
    config.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "[socket]\n"
        'mode = "per_user"\n'
        f'path = "{socket_path}"\n'
        "[policy]\n"
        f'path = "{policy}"\n'
        "[evidence]\n"
        f'path = "{run / "evidence"}"\n',
        encoding="utf-8",
    )
    process = _start(config)
    try:
        status, decision = _ask_process(
            socket_path,
            "POST",
            "/decisions",
            {
                "contract_generation": 1,
                "capability": "example.effect",
                "scope": "local",
                "arguments_digest": DIGEST,
                "correlation": "gate-1",
            },
        )
        assert status == 200, decision
        assert decision["outcome"] == "allow"
        deadline = time.monotonic() + 5.0
        while not _effects(_chain(run)) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _effects(_chain(run)), "the effect never reached the chain"
    finally:
        _stop(process)
    assert not socket_path.exists()

    process = _start(config)
    try:
        status, read = _ask_process(
            socket_path,
            "GET",
            f"/decisions/{decision['decision_ref']}?contract_generation=1&scope=local",
        )
        assert status == 200, read
        validate_document(read, "decision-record")
        assert (read["outcome"], read["reason"], read["rule_id"]) == (
            "allow",
            "policy_allows",
            "scenario-0",
        )
        assert read["arguments_digest"] == DIGEST
        assert read["correlation"] == "gate-1"
        assert read["grant_id"] is None
        status, bundle = _ask_process(
            socket_path,
            "GET",
            "/scopes/local/evidence/export?contract_generation=1&from_sequence=1",
        )
        assert status == 200, bundle
    finally:
        _stop(process)

    verdict = verify_export(bundle)
    assert verdict.manifest_hash_recomputes is True
    assert verdict.rederived_decision_ids == (decision["decision_ref"],)
    assert verdict.confirmed_decision_ids == (decision["decision_ref"],)
    assert verdict.chain is not None and verdict.chain.condition.value == "intact"
    compositions = [item for item in bundle["entries"] if item["kind"] == "composition"]
    assert len(compositions) == 2, "the second life appended to the first life's chain"


# -- the epoch closes cleanly, or its loss is declared --------------------------------


def _the_process_is_gone(record):  # type: ignore[no-untyped-def]
    raise OSError(5, "the process is gone")


def _crash(session) -> None:  # type: ignore[no-untyped-def]
    """End a composed daemon the way a dead process does: nothing drains, nothing closes.

    The listener goes away and the root lock is released, because a dead
    process holds neither; the emitter, the grants and the journal are left
    exactly as they were, so no clean marker is written and the epoch stays
    open for the next start to find.

    A dead process cannot still be draining. Its drain thread cannot be
    killed here, so the store is taken away under the emitter's own lock in
    the same breath as `_closing` is set: whether the thread is parked on
    the condition or mid-unit inside an append, every append it attempts
    from here on raises, so nothing the dead life did not already write
    before the crash can land after it.
    """
    daemon = session.daemon
    server = daemon._server
    if server is not None:
        server.shutdown()
        server.server_close()
        daemon._server = None
    with suppress(OSError):
        os.unlink(daemon.settings.socket_path)
    daemon._stopped = True
    session._thread.join(timeout=10)
    emitter = session.services.emitter
    with emitter._condition:
        session.services.store.append = _the_process_is_gone
        emitter._closing = True
        emitter._condition.notify_all()
    session.services.decision_store.close()


def test_a_graceful_stop_closes_the_epoch_and_the_export_through_its_marker_is_confirmed(
    composed,
) -> None:
    """T1 in substance, H2, H3: the pre-restart epoch, through its clean marker, is complete."""
    first = composed(rules=[("allow", "example.effect")])
    _, decision = first.ask(arguments_digest=DIGEST, correlation="gate-1")
    _wait_for(first, lambda entries: len(_effects(entries)) == 1)
    first.close()
    after_stop = _chain(first.root)
    marker = after_stop[-1]
    assert marker["kind"] == "recovery" and marker["body"]["event"] == "clean_stop"
    assert marker["body"]["from_sequence"] == 1
    assert marker["body"]["through_sequence"] == marker["sequence"] - 1

    second = composed(root=first.root, rewrite_policy=False)
    bundle = _export(second)
    whole = verify_export(bundle)
    # The whole chain includes the second life's open epoch: honestly unknown.
    assert whole.coverage == "unknown"
    status, bundle = second.request(
        "GET",
        "/scopes/local/evidence/export?contract_generation=1&from_sequence=1"
        f"&to_sequence={marker['sequence']}",
    )
    assert status == 200, bundle
    verdict = verify_export(bundle)
    assert verdict.coverage == "complete"
    assert verdict.issues == ()
    assert verdict.overall is Rederivation.confirmed
    assert verdict.rederived_decision_ids == (decision["decision_ref"],)
    assert verdict.confirmed_decision_ids == (decision["decision_ref"],)
    # The context carries the closure of a range that stops short of it (V3).
    status, partial = second.request(
        "GET",
        "/scopes/local/evidence/export?contract_generation=1&from_sequence=1"
        f"&to_sequence={marker['sequence'] - 1}",
    )
    assert status == 200, partial
    assert [item["sequence"] for item in partial["recovery_context"]] == [marker["sequence"]]
    verdict = verify_export(partial)
    assert verdict.coverage == "complete"
    assert verdict.overall is Rederivation.confirmed


def test_a_decision_whose_effect_never_reached_the_chain_is_declared_at_the_next_start(
    composed,
) -> None:
    """T2 in substance, C4: the loss is named by identity; the decision is still explained."""
    from sayfirst_control_plane.domain.evidence_chain import EvidenceRecord

    first = composed(rules=[("allow", "example.effect")])
    _, kept = first.ask()
    _wait_for(first, lambda entries: len(_effects(entries)) == 1)

    honest = first.services.store.append

    def stall(record: EvidenceRecord):  # type: ignore[no-untyped-def]
        if record.kind == "effect":
            # The process dies before any byte of this effect is written.
            raise OSError(5, "the daemon died here")
        return honest(record)

    first.services.store.append = stall  # type: ignore[method-assign]
    _, lost = first.ask()
    assert lost["outcome"] == "allow"
    _crash(first)

    second = composed(root=first.root, rewrite_policy=False)
    status, read = second.request(
        "GET", f"/decisions/{lost['decision_ref']}?contract_generation=1&scope=local"
    )
    assert status == 200, read
    assert read["outcome"] == "allow"
    entries = _chain(first.root)
    unclean = next(item for item in entries if item["body"].get("event") == "unclean_stop")
    gaps = [item for item in entries if item["kind"] == "gap"]
    named = [item for item in gaps if item["body"].get("decision_ids") == [lost["decision_ref"]]]
    assert len(named) == 1, gaps  # the loss is declared once, by identity
    gap = named[0]
    assert gap["body"]["reason"] == "unflushed"
    assert gap["body"]["accounting"] == "decision"
    assert unclean["sequence"] < gap["sequence"]
    # Anything else in the chain is, at most, the emitter's own truthful account of
    # that SAME loss: event-accounted, id-less, and bounded to the one effect —
    # never a second loss, never an id-less claim about a decision.
    others = [item for item in gaps if item is not gap]
    assert all(
        item["body"]["reason"] == "dropped"
        and item["body"]["accounting"] == "event"
        and item["body"]["kinds"] == {"effect": 1}
        and "decision_ids" not in item["body"]
        for item in others
    ), others
    assert sum(item["body"]["count"] for item in others) <= 1, others
    _, status_document = second.request("GET", "/status")
    reconciliation = next(
        item
        for item in status_document["decision_store"]["reconciliations"]
        if item["scope"] == "local"
    )
    assert reconciliation["state"] == "agrees"
    assert reconciliation["unflushed_declared"] == 1
    assert reconciliation["unknown_event_coverage"] is True
    assert reconciliation["effects_without_decision"] == 0
    verdict = verify_export(_export(second))
    assert verdict.declared_missing_decision_ids == (lost["decision_ref"],)
    assert lost["decision_ref"] not in verdict.rederived_decision_ids
    assert kept["decision_ref"] in verdict.confirmed_decision_ids
    assert verdict.chain is not None and verdict.chain.condition.value == "intact"
    assert verdict.coverage == "incomplete"
    assert verdict.overall is Rederivation.unverifiable
