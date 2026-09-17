# SPDX-License-Identifier: Apache-2.0
"""What the one composition root composes, and what it refuses to start without.

Article 4: every block published a port and an adapter behind it, and none of
them published a composition. These cases hold the composition itself — that it
is the deployment's choice, that a deployment which asks for one and cannot
have it does not start, and that nothing is composed by guessing.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from digit_mask_redactor import REGISTRATION, DigitMask
from sayfirst_contract.plugins import discover_plugin_entry_points
from sayfirst_control_plane.adapters.memory.evidence_store import InMemoryEvidenceStore
from sayfirst_control_plane.bootstrap import (
    _ChainCompositionEvidence,
    _system_evidence_root,
    compose,
)
from sayfirst_control_plane.domain.evidence_chain import (
    EvidenceEntry,
    EvidenceRecord,
    Principal,
    preimage,
)
from sayfirst_control_plane.plugins.composition import CompositionEvidence
from sayfirst_control_plane.plugins.errors import InvalidCompositionEvidence
from sayfirst_control_plane.settings import StartRefused, read_settings
from sayfirst_testing.privileges import requires_unprivileged

ME = os.geteuid()
_POLICY = 'format = 1\n[revision]\nreason = "composition"\n'


def _entry_hash_of(record: CompositionEvidence) -> str:
    """The hash of the record over its own body, at the position it states."""
    return sha256(
        preimage(
            scope=record.scope,
            sequence=record.sequence,
            kind=record.kind,
            recorded_at=record.recorded_at,
            connection_id=record.connection_id,
            principal=Principal(record.principal.kind, record.principal.id),
            body=record.body,
            previous_hash=record.previous_hash,
        )
    ).hexdigest()


class _AnotherRecordStore(InMemoryEvidenceStore):
    """A store that appends what it was given and answers about something else."""

    def append(self, record: EvidenceRecord) -> EvidenceEntry:
        super().append(record)
        return super().append(
            replace(
                record,
                body={"providers": [{"interface": "SomethingElse", "version": 1, "provider": "x"}]},
            )
        )


def _settings(root: Path, **sections: object):  # type: ignore[no-untyped-def]
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    document: dict[str, object] = {
        "socket": {"mode": "per_user", "path": str(root / "daemon.sock")},
        **sections,
    }
    return read_settings(document, platform="linux")


def _authority(root: Path) -> Path:
    path = root / "policy.toml"
    path.write_text(_POLICY, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_a_deployment_that_names_no_authority_composes_nothing(tmp_path: Path) -> None:
    """Article 2: composing nothing is a state the surface can say out loud."""
    assert compose(_settings(tmp_path / "run"), daemon_uid=ME) is None


def test_the_running_composition_never_passes_overflow_ids() -> None:
    """Article 2: a real start reads its own host — nothing composed invents it.

    `overflow_ids` on `Daemon.__init__` exists only for a test simulating
    another platform (rule L8). Grepped rather than driven: a composition that
    happened to choose not to pass it would still pass a driven assertion, and
    the source is what proves no path a real deployment takes ever does.
    """
    import inspect
    from pathlib import Path as _Path

    from sayfirst_control_plane import bootstrap as bootstrap_module
    from sayfirst_control_plane.adapters import socket_server

    assert "overflow_ids" not in _Path(bootstrap_module.__file__).read_text(encoding="utf-8")
    assert "overflow_ids" not in inspect.getsource(socket_server.assemble)


def test_a_deployment_that_names_an_authority_composes_every_block(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    services = compose(
        _settings(
            root,
            policy={"path": str(_authority(root))},
            evidence={"path": str(root / "evidence")},
        ),
        daemon_uid=ME,
    )

    assert services is not None
    try:
        assert services.policy.status().authority == "file"
        assert services.composition.privacy_provider_name == "none"
        assert services.composition.approval_provider_name == "single-approver"
        assert services.emitter.store_location.kind == "file"
        assert services.decision_routes.decisions is services.decisions
        # Where a suspension waits, reached the way the grant registry is
        # reached: through the decision service that holds it. The reads and
        # the sweep that follow need this one store and not a second.
        assert services.decisions.approvals is not None
        assert services.decisions.approvals.pending() == ()
        # And the provider the service puts a suspension to is the provider the
        # registry composed and the composition record names, on that same
        # store: one daemon, one name (article 2), and not a chain entry
        # naming a provider nothing calls.
        assert services.decisions.approval_provider is services.composition.approval_provider
        assert services.decisions.approvals is services.composition.approval_provider.store
    finally:
        services.close()


_SUSPEND_POLICY = (
    "format = 1\n"
    "[revision]\n"
    'reason = "composition"\n'
    "[[rule]]\n"
    'id = "waits"\n'
    'capability = "example.waits"\n'
    'principals = ["user:build"]\n'
    'outcome = "suspend"\n'
    'reason = "one person reviews this"\n'
    "review_deadline_seconds = 60\n"
)


def test_the_clock_this_deployment_composes_is_the_clock_a_wait_is_measured_by(
    tmp_path: Path,
) -> None:
    """Article 2: one clock behind the deadline a decision records and the wait it names.

    A plugin registration's factory takes no arguments, so the shipped approval
    provider is built before this root can say which clock the deployment runs
    on. If it kept a store of its own on a clock of its own, a deployment that
    composes a clock would record one deadline and measure the wait by another,
    and a reader could be told a wait had run out that the decision says is
    still open. The clock goes in at `compose` and comes back out of a wait's
    own deadline.
    """
    # The two `Principal`s of this tree meet in this module, so the policy one
    # is imported where it is used, as the durable-decision case below does.
    from sayfirst_contract.decisions import DecisionAsk, Outcome
    from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal

    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    authority = root / "policy.toml"
    authority.write_text(_SUSPEND_POLICY, encoding="utf-8")
    os.chmod(authority, 0o600)
    composed_at = datetime(2026, 9, 15, 12, tzinfo=UTC)
    services = compose(
        _settings(
            root,
            policy={"path": str(authority)},
            evidence={"path": str(root / "evidence")},
        ),
        daemon_uid=ME,
        clock=lambda: composed_at,
    )
    assert services is not None
    try:
        answer = services.decisions.ask(
            DecisionQuestion(
                DecisionAsk("example.waits", scope="local"),
                Principal("process", 1001, "build", (2001,), ("ci",)),
            )
        )
        decision = getattr(answer, "decision", None)
        assert decision is not None and decision.outcome is Outcome.SUSPEND
        assert decision.approval_ref is not None
        kept = services.decisions.approvals is not None and services.decisions.approvals.read(
            "local", decision.approval_ref
        )
        assert kept
        assert kept.requested_at == composed_at
        assert kept.deadline == composed_at + timedelta(seconds=60)
        # And the act on that wait is dated by the same clock. The provider
        # keeps none of its own and writes nothing — the store is the core's,
        # and the core is its one writer — so the instant a person's act is
        # written at is the instant this store measures its waits by. Two
        # clocks would refuse an act as late by one and accept it by the other.
        from sayfirst_control_plane.application.approvals import write_resolution
        from sayfirst_control_plane.plugins.interfaces import (
            ApprovalAction,
            ApprovalRequest,
            ApprovalResolution,
        )

        provider = services.composition.approval_provider
        suspension = provider.suspend(
            ApprovalRequest(
                approval_ref=kept.approval_ref,
                decision_ref=kept.decision_ref,
                scope="local",
                capability=kept.capability,
                requested_at=kept.requested_at,
                deadline=kept.deadline,
            )
        )
        judged = provider.resume(
            suspension,
            ApprovalAction(
                approval_ref=kept.approval_ref,
                scope="local",
                person="user:reviewer",
                resolution=ApprovalResolution.APPROVE,
                reason=None,
            ),
        )
        write_resolution(services.decisions.approvals, judged)
        resolved = services.decisions.approvals.read("local", decision.approval_ref)
        assert resolved.resolved_at == composed_at
    finally:
        services.close()


def test_an_authority_that_is_absent_refuses_the_start_rather_than_deciding(
    tmp_path: Path,
) -> None:
    """Article 3: a daemon that cannot read its authority serves nobody."""
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(root / "absent.toml")},
        evidence={"path": str(root / "evidence")},
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=ME)

    assert refusal.value.reason == "policy_unavailable_at_start"


def test_an_authority_a_stranger_can_replace_refuses_the_start(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    path = _authority(root)
    os.chmod(path, 0o606)
    settings = _settings(
        root, policy={"path": str(path)}, evidence={"path": str(root / "evidence")}
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=ME)

    assert refusal.value.reason == "policy_unavailable_at_start"
    assert "other_write" in refusal.value.detail


@requires_unprivileged()
def test_an_authority_the_composing_account_cannot_read_is_refused_naming_that_account(
    tmp_path: Path,
) -> None:
    """Articles 2 and 3, rule L2a: the start check is made as the account that will read.

    In system mode the daemon composes after the drop, so the account that
    reads here is the one that will read for every decision, and a file it
    cannot read is refused at start — naming the file and the account, not
    served for a lifetime of "unavailable, retryable". Gated to an unprivileged
    tester because root reads a file with no mode bits at all; under root the
    same layout is a readable authority and there is nothing to refuse.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    path = _authority(root)
    os.chmod(path, 0o000)
    settings = _settings(
        root, policy={"path": str(path)}, evidence={"path": str(root / "evidence")}
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=ME)

    assert refusal.value.reason == "policy_unavailable_at_start"
    assert str(path) in refusal.value.detail
    assert "unreadable" in refusal.value.detail
    assert f"uid {ME}" in refusal.value.detail, refusal.value.detail


def test_in_system_mode_an_evidence_root_the_packager_did_not_create_refuses_the_start(
    tmp_path: Path,
) -> None:
    """Article 7, rule L2a: in system mode the store's directory is the packager's.

    The daemon composes as `run_as`, under a parent it does not own, so a
    directory it created there would be one it could not create at all — or
    one whose parent lets someone else replace it. The rule is the same as the
    socket's: the packager creates the evidence root, owned by the daemon's
    account, and the daemon refuses to stand in for the packager. The refusal
    says so, so the operator reads a layout to fix and not a permission error.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = read_settings(
        {
            "socket": {
                "mode": "system",
                "group": "operators",
                "run_as": "sayfirst",
                "path": str(root / "daemon.sock"),
            },
            "policy": {"path": str(_authority(root))},
            "evidence": {"path": str(root / "evidence")},
        },
        platform="linux",
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=4242, administrator_gid=900)

    assert refusal.value.reason == "evidence_root_unusable"
    assert str(root / "evidence") in refusal.value.detail
    assert "packager" in refusal.value.detail, refusal.value.detail
    assert "sayfirst" in refusal.value.detail, refusal.value.detail


def test_a_per_user_daemon_creates_its_evidence_root_at_0700_whatever_the_umask(
    tmp_path: Path,
) -> None:
    """Article 7, rules L2 and L2a: what the daemon creates, it creates protected.

    A per-user store is forgeable by the one account that shares it — that is
    observability grade — but a level created at `0777 & ~umask` under a
    permissive umask is a store every account can replace, which is a grade
    below the one the daemon reports.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(_authority(root))},
        evidence={"path": str(root / "deep" / "evidence")},
    )
    before = os.umask(0o000)
    try:
        services = compose(settings, daemon_uid=ME)
    finally:
        os.umask(before)
    assert services is not None
    services.close()

    assert os.stat(root / "deep").st_mode & 0o777 == 0o700
    assert os.stat(root / "deep" / "evidence").st_mode & 0o777 == 0o700


def test_an_authority_named_without_a_place_to_record_is_refused(tmp_path: Path) -> None:
    """Article 10: a daemon that decides and records nowhere is not composed."""
    root = tmp_path / "run"
    root.mkdir(mode=0o700)

    with pytest.raises(StartRefused) as refusal:
        _settings(root, policy={"path": str(_authority(root))})

    assert refusal.value.reason == "mode_invalid"
    assert "evidence.path is required" in refusal.value.detail


def test_a_provider_registered_for_another_interface_refuses_the_start(tmp_path: Path) -> None:
    """Article 8: a provider is composed for the interface it registered, never another.

    `single-approver` registers `ApprovalProvider`; a deployment that names it
    for `PrivacyRedactor` is told at start, rather than served a pipeline with
    an approver where a redactor was asked for.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(_authority(root))},
        evidence={"path": str(root / "evidence")},
        plugins={
            "PrivacyRedactor": {"provider": "single-approver", "interface_version": 1},
            "ApprovalProvider": {"provider": "single-approver", "interface_version": 1},
        },
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=ME)

    assert refusal.value.reason == "plugin_composition_refused"
    assert "registered for ApprovalProvider, not PrivacyRedactor" in refusal.value.detail


def test_the_composition_is_on_the_chain_in_the_shape_the_chain_publishes(
    tmp_path: Path,
) -> None:
    """Articles 8, 11 and 13: recorded before anything is served, minimised as published.

    The composition the contract distribution shapes carries four members more
    than the published `composition` entry body accepts, and neither shape is
    derivable from the other. The entry that is kept is the published one; the
    value handed back to the plugin composition is that block's own shape, and
    this daemon neither persists nor serves it.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    services = compose(
        _settings(
            root,
            policy={"path": str(_authority(root))},
            evidence={"path": str(root / "evidence")},
        ),
        daemon_uid=ME,
    )
    assert services is not None
    try:
        lines = (root / "evidence" / "local.jsonl").read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in lines if line]
    finally:
        services.close()

    assert [item["kind"] for item in entries] == ["composition"]
    assert entries[0]["sequence"] == 1
    assert all(
        set(provider) == {"interface", "version", "provider"}
        for provider in entries[0]["body"]["providers"]
    )
    assert {provider["provider"] for provider in entries[0]["body"]["providers"]} == {
        "none",
        "single-approver",
    }


def test_the_composition_record_states_the_position_the_chain_gave_it(tmp_path: Path) -> None:
    """Articles 2 and 3: a record that states a position it did not read is not evidence.

    The entry that is kept is the store's; the value handed back to the plugin
    composition is the other published shape of the same composition, and it
    carries a sequence and a previous hash of its own. A daemon starting on a
    chain that already holds entries is at some position other than the first,
    and asserting the first is the defect article 2 names in the one place it
    costs the most: the evidence chain is where a claim is worth what its
    provenance is worth, and a position nobody read has no provenance at all.

    So the second start below is the case: the store places the composition
    after the first start's entries and its clean stop, and the record must
    say so.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(_authority(root))},
        evidence={"path": str(root / "evidence")},
    )

    first = compose(settings, daemon_uid=ME)
    assert first is not None
    first.close()
    second = compose(settings, daemon_uid=ME)
    assert second is not None
    try:
        entries = [
            json.loads(line)
            for line in (root / "evidence" / "local.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
    finally:
        second.close()

    # The first start's composition, its clean stop (the daemon's grade and the
    # marker, block 2.7), then the second start's composition at the head.
    assert [item["sequence"] for item in entries] == [1, 2, 3, 4]
    assert [item["kind"] for item in entries] == ["composition", "grade", "recovery", "composition"]
    record = second.composition.evidence
    assert record.sequence == entries[-1]["sequence"]
    assert record.previous_hash == entries[-1]["previous_hash"] == entries[-2]["entry_hash"]
    assert record.entry_hash == _entry_hash_of(record)


def test_a_store_that_answers_with_another_record_refuses_the_start(tmp_path: Path) -> None:
    """Article 3: the position is read from the store's answer, or there is no record.

    The sequence and the previous hash come from what the store said it
    appended. A store that answers with an entry for some other record has not
    told this daemon where its composition landed, and a record derived from
    that answer would state a position taken from somewhere else. There is no
    third option between reading the position and refusing to hand one back.
    """
    store = _AnotherRecordStore()
    sink = _ChainCompositionEvidence(store, clock=lambda: datetime(2026, 9, 4, tzinfo=UTC))

    with pytest.raises(InvalidCompositionEvidence) as refused:
        sink.record(scope="local", providers=())

    assert "did not answer" in str(refused.value)


# -- rule L2a, the evidence root's layout in system mode ----------------------
#
# The rule says what the packager owes: owned by `run_as` and its own group at
# mode 0700. A daemon that checked only "is a directory" accepted three layouts
# the rule refuses — a root the governed principal owns, a root every account
# can write, a root carrying the admission group and the setgid bit — and each
# started and served (the codex review of this branch executed all three). The
# refusal is decided by what other principals can effectively do with the
# directory, not by the owner alone (article 7).

MY_GID = os.getegid()


def _system(root: Path, evidence_root: Path):  # type: ignore[no-untyped-def]
    return read_settings(
        {
            "socket": {
                "mode": "system",
                "group": "operators",
                "run_as": "sayfirst",
                "path": str(root / "daemon.sock"),
            },
            "policy": {"path": str(_authority(root))},
            "evidence": {"path": str(evidence_root)},
        },
        platform="linux",
    )


def _system_refusal(root: Path, evidence_root: Path, *, daemon_uid: int, daemon_gid: int) -> str:
    with pytest.raises(StartRefused) as refusal:
        compose(
            _system(root, evidence_root),
            daemon_uid=daemon_uid,
            daemon_gid=daemon_gid,
            administrator_gid=900,
        )
    assert refusal.value.reason == "evidence_root_unusable"
    assert str(evidence_root) in refusal.value.detail
    assert "sayfirst" in refusal.value.detail, refusal.value.detail
    assert "packager" in refusal.value.detail, refusal.value.detail
    return refusal.value.detail


def test_in_system_mode_an_evidence_root_another_account_owns_refuses_the_start_by_name(
    tmp_path: Path,
) -> None:
    """Article 7, rule L2a: the root is `run_as`'s, and a root somebody else owns is named."""
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)

    detail = _system_refusal(root, evidence_root, daemon_uid=ME + 1, daemon_gid=MY_GID)

    assert f"owned by uid {ME}" in detail, detail
    assert f"uid {ME + 1}" in detail, detail


def test_in_system_mode_an_evidence_root_carrying_another_group_refuses_the_start_by_name(
    tmp_path: Path,
) -> None:
    """Article 7, rule L2a: the root carries `run_as`'s own group, never another.

    A root carrying the admission group with the setgid bit hands every chain
    file the daemon creates to the governed principals' group; the group is
    named because the layout is what the operator reads to fix.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)

    detail = _system_refusal(root, evidence_root, daemon_uid=ME, daemon_gid=MY_GID + 1)

    assert f"group {MY_GID}" in detail, detail
    assert f"gid {MY_GID + 1}" in detail, detail


@pytest.mark.parametrize("mode", [0o777, 0o2700, 0o750, 0o500])
def test_in_system_mode_an_evidence_root_not_at_mode_0700_refuses_the_start_by_name(
    tmp_path: Path, mode: int
) -> None:
    """Article 7, rule L2a: mode 0700, read literally, and the mode found is named.

    Owner and group right, mode wrong, and the article 7 sentence — "no
    principal but that one and root can write or replace the store" — is one
    mode bit from untrue: `0777` lets everyone in, `02700` gives every chain
    file the directory's group, `0750` reads as a store shared with a group,
    and `0500` is one the daemon cannot create a chain in at all.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)
    os.chmod(evidence_root, mode)

    detail = _system_refusal(root, evidence_root, daemon_uid=ME, daemon_gid=MY_GID)

    assert f"mode {oct(mode)}" in detail, detail
    assert "0700" in detail, detail


@requires_unprivileged()
def test_in_system_mode_an_evidence_parent_the_daemon_cannot_traverse_refuses_the_start_by_name(
    tmp_path: Path,
) -> None:
    """Articles 2 and 3, rule L2a: a fact that could not be established is named as such.

    With the evidence root laid out correctly under a parent the dropped
    account cannot traverse, `stat` is refused. That is not "not a directory"
    — the daemon does not know what is there — and it is not a traceback at
    exit 1 either: it is one more layout the packager owes, refused by name,
    exit 78, naming the directory and the account that could not look.
    Unprivileged because root traverses anything.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    parent = root / "lib"
    parent.mkdir(mode=0o700)
    evidence_root = parent / "evidence"
    evidence_root.mkdir(mode=0o700)
    os.chmod(parent, 0o000)
    try:
        detail = _system_refusal(root, evidence_root, daemon_uid=ME, daemon_gid=MY_GID)
    finally:
        os.chmod(parent, 0o700)

    assert "access could not be established" in detail, detail
    assert f"uid {ME}" in detail, detail
    assert "not a directory" not in detail, detail


@pytest.mark.parametrize(
    ("mode", "fact"),
    [
        (0o777, "an ancestor is writable by anyone and not sticky"),
        (0o770, "an ancestor is writable by a group and not sticky"),
    ],
)
def test_in_system_mode_an_evidence_root_under_a_replaceable_parent_refuses_the_start_by_name(
    tmp_path: Path, mode: int, fact: str
) -> None:
    """Articles 7 and 2, rules L2a and S4: the parents decide whether the store can be replaced.

    Article 7 names "every parent directory that would allow it to be
    replaced", and rule S4 walks them for the socket directory. The evidence
    root here is exactly the layout the packager owes, under a parent anyone
    (or a group) may write, which is the one grant needed to rename the store
    away and put another at its path. The second review of this branch
    executed that rename as a governed principal while the daemon served. The
    same walk refuses it, naming the parent and the fact.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    parent = root / "lib"
    parent.mkdir(mode=0o700)
    evidence_root = parent / "evidence"
    evidence_root.mkdir(mode=0o700)
    os.chmod(parent, mode)

    detail = _system_refusal(root, evidence_root, daemon_uid=ME, daemon_gid=MY_GID)

    assert str(parent) in detail, detail
    assert fact in detail, detail


def test_in_system_mode_a_sticky_parent_is_the_exemption_rule_s4_grants(tmp_path: Path) -> None:
    """Rule S4, the one exemption, held here because it is the same rule.

    A sticky ancestor bars everyone but an entry's owner, the directory's
    owner and root from renaming what is under it, so write on it does not
    reach the store. The evidence root's check passes under one.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    parent = root / "lib"
    parent.mkdir(mode=0o700)
    evidence_root = parent / "evidence"
    evidence_root.mkdir(mode=0o700)
    os.chmod(parent, 0o1777)

    _system_evidence_root(
        evidence_root,
        _system(root, evidence_root),
        daemon_uid=ME,
        daemon_gid=MY_GID,
        platform="linux",
    )


# -- rule L2a, what one successful append does not prove ----------------------
#
# The composition record is the first append of the daemon's life, and one
# append through a creation descriptor proves neither that the file can be
# reopened, nor that a chain can be created for any other scope, nor that a
# chain already there for a scope the policy names is one the daemon can append
# to. The codex review of this branch executed all three: a chain left at mode
# 000 by a permissive umask, an `audit.jsonl` root owned while `audit` allows
# were served, and a `0500` root no `audit.jsonl` could be created in. None of
# the three repairs itself, so none is a matter for a retry (article 10).


def _authority_reaching(root: Path, *scopes: str) -> Path:
    """A policy whose rules reach `scopes`, one allow rule per scope."""
    rules = "".join(
        f'[[rule]]\nid = "rule-{index}"\ncapability = "example.effect"\nscope = "{scope}"\n'
        'principals = ["user:somebody"]\noutcome = "allow"\nreason = "the allow rule"\n'
        for index, scope in enumerate(scopes)
    )
    path = root / "policy.toml"
    path.write_text(f'format = 1\n[revision]\nreason = "composition"\n{rules}', encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_the_chain_the_daemon_creates_holds_mode_0600_whatever_the_umask(tmp_path: Path) -> None:
    """Articles 7 and 10, rule L2a: created at 0600 is a mode held, not a mode asked for.

    `open(..., O_CREAT, 0o600)` applies the mode through the umask, and under
    `umask 0777` the first chain arrived at mode 000: appendable through the
    descriptor that created it and through nothing else, so the composition
    was recorded and no decision after it ever was.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(_authority(root))},
        evidence={"path": str(root / "evidence")},
    )
    before = os.umask(0o777)
    try:
        services = compose(settings, daemon_uid=ME)
    finally:
        os.umask(before)
    assert services is not None
    services.close()

    chain = root / "evidence" / "local.jsonl"
    assert os.stat(chain).st_mode & 0o7777 == 0o600, oct(os.stat(chain).st_mode)
    assert os.access(chain, os.W_OK), "the daemon cannot reopen the chain it created"


def test_a_chain_is_created_at_start_for_every_scope_the_policy_reaches(tmp_path: Path) -> None:
    """Article 10, rule L2a: a scope the policy can decide for is a chain the daemon can keep.

    The composition proves the `local` chain and nothing else. Every scope the
    policy's rules name is a scope a decision can be served for, so each one's
    chain is created — at 0600, as the daemon's own — before anything is
    served, and a root that refuses the creation refuses the start.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(_authority_reaching(root, "audit", "local"))},
        evidence={"path": str(root / "evidence")},
    )
    services = compose(settings, daemon_uid=ME)
    assert services is not None
    services.close()

    audit = root / "evidence" / "audit.jsonl"
    assert audit.is_file(), sorted(path.name for path in (root / "evidence").iterdir())
    assert os.stat(audit).st_mode & 0o7777 == 0o600
    assert audit.read_bytes() == b"", "a chain created at start holds no entry yet"


@requires_unprivileged()
def test_an_existing_chain_the_composing_account_cannot_append_to_refuses_the_start_by_name(
    tmp_path: Path,
) -> None:
    """Articles 2 and 10, rule L2a: a chain that is there and cannot be appended to is named.

    `audit.jsonl` exists, the policy allows `audit`, and the daemon cannot open
    it for append. Serving the allow records nothing, and no retry changes the
    file's mode; so the start is refused, naming the file, the scope and the
    account. Unprivileged because root opens a file with no mode bits.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)
    blocked = evidence_root / "audit.jsonl"
    blocked.touch(mode=0o600)
    os.chmod(blocked, 0o000)
    settings = _settings(
        root,
        policy={"path": str(_authority_reaching(root, "audit"))},
        evidence={"path": str(evidence_root)},
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=ME)

    assert refusal.value.reason == "evidence_root_unusable"
    assert str(blocked) in refusal.value.detail, refusal.value.detail
    assert "'audit'" in refusal.value.detail, refusal.value.detail
    assert f"uid {ME}" in refusal.value.detail, refusal.value.detail


@requires_unprivileged()
def test_an_evidence_root_no_chain_can_be_created_in_refuses_the_start_by_name(
    tmp_path: Path,
) -> None:
    """Articles 2 and 10, rule L2a: a root the daemon can append in but not create in is named.

    The `local` chain exists and takes the composition; `audit` is allowed by
    the policy and its chain does not exist; the root is `0500`. The first
    `audit` decision would be served and never recorded. Unprivileged because
    root creates a file in any directory.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)
    (evidence_root / "local.jsonl").touch(mode=0o600)
    os.chmod(evidence_root, 0o500)
    settings = _settings(
        root,
        policy={"path": str(_authority_reaching(root, "audit"))},
        evidence={"path": str(evidence_root)},
    )
    try:
        with pytest.raises(StartRefused) as refusal:
            compose(settings, daemon_uid=ME)
    finally:
        os.chmod(evidence_root, 0o700)

    assert refusal.value.reason == "evidence_root_unusable"
    assert str(evidence_root / "audit.jsonl") in refusal.value.detail, refusal.value.detail
    assert "creat" in refusal.value.detail, refusal.value.detail
    assert f"uid {ME}" in refusal.value.detail, refusal.value.detail


@requires_unprivileged()
def test_a_chain_already_in_the_store_for_a_scope_no_rule_names_refuses_the_start_by_name(
    tmp_path: Path,
) -> None:
    """Articles 2 and 10, rule L2a: what is proved at start is what is in the store.

    The scope is the caller's field, not the policy's: a request may name a
    scope no rule reaches, is answered with a deny, and is owed a record on
    that scope's chain. So a start check over the policy's scopes left
    `audit.jsonl` — there, and not appendable — unproved whenever no rule
    named `audit`, and the second review of this branch executed exactly that:
    the daemon started, served the deny, and the chain stayed empty for good.
    Every chain already in the root is proved now, whatever scope it belongs
    to, and refused naming the file, the scope and the account. Unprivileged
    because root opens a file with no mode bits.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)
    blocked = evidence_root / "audit.jsonl"
    blocked.touch(mode=0o600)
    os.chmod(blocked, 0o000)
    settings = _settings(
        root,
        policy={"path": str(_authority_reaching(root, "local"))},
        evidence={"path": str(evidence_root)},
    )

    with pytest.raises(StartRefused) as refusal:
        compose(settings, daemon_uid=ME)

    assert refusal.value.reason == "evidence_root_unusable"
    assert str(blocked) in refusal.value.detail, refusal.value.detail
    assert "'audit'" in refusal.value.detail, refusal.value.detail
    assert f"uid {ME}" in refusal.value.detail, refusal.value.detail


def test_a_file_in_the_store_that_is_not_a_chain_is_not_proved_as_one(tmp_path: Path) -> None:
    """Article 2, rule L2a: the claim is about chains, and a chain is named by a scope.

    A file whose name is not a scope's is a file no request can name and no
    record is ever owed to, so the start says nothing about it: it is neither
    opened nor refused. A file that is named by a scope and is not appendable
    is refused (the guard above); the two are the two sides of one sentence.
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir(mode=0o700)
    stray = evidence_root / "not a scope.jsonl"
    stray.touch(mode=0o000)
    (evidence_root / "README").touch(mode=0o000)
    settings = _settings(
        root,
        policy={"path": str(_authority_reaching(root, "local"))},
        evidence={"path": str(evidence_root)},
    )

    services = compose(settings, daemon_uid=ME)
    assert services is not None
    services.close()
    assert os.stat(stray).st_mode & 0o7777 == 0


@dataclass
class StaticEntryPoint:
    """Entry-point metadata a test plants, loading a registration it already holds."""

    name: str
    value: str
    registration: object

    def load(self) -> object:
        return self.registration


def _entry_points_with(*planted: object) -> list[object]:
    """The installed entry points, plus the ones a test plants beside them."""
    return [*discover_plugin_entry_points(), *planted]


def test_a_real_privacy_provider_named_by_configuration_is_composed_into_the_pipeline(
    tmp_path: Path,
) -> None:
    """Article 8: bootstrap composes the provider the configuration names, not one it picks.

    The provider is a second, independent implementation of the one
    `PrivacyRedactor` version 1, planted through an entry point the way an
    installed distribution would register it. What the composition evidence
    records, what the status surface renders and what the pipeline hands a
    capture to are one and the same provider (article 2).
    """
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    services = compose(
        _settings(
            root,
            policy={"path": str(_authority(root))},
            evidence={"path": str(root / "evidence")},
            plugins={
                "PrivacyRedactor": {"provider": "digit-mask", "interface_version": 1},
                "ApprovalProvider": {"provider": "single-approver", "interface_version": 1},
            },
        ),
        daemon_uid=ME,
        entry_points=_entry_points_with(
            StaticEntryPoint("digit-mask", "digit_mask_redactor:REGISTRATION", REGISTRATION)
        ),
    )

    assert services is not None
    try:
        assert services.composition.privacy_provider_name == "digit-mask"
        assert services.emitter.privacy_provider == "digit-mask"
        assert isinstance(services.composition.privacy_redactor, DigitMask)
        lines = (root / "evidence" / "local.jsonl").read_text(encoding="utf-8").splitlines()
        recorded = {
            item["interface"]: item["provider"]
            for item in json.loads(lines[0])["body"]["providers"]
        }
        assert recorded["PrivacyRedactor"] == "digit-mask"
    finally:
        services.close()


def test_a_privacy_provider_whose_name_disagrees_with_its_registration_is_refused(
    tmp_path: Path,
) -> None:
    """Article 2: the name on the chain, on the status surface and in the capture is one name.

    The composition evidence records the registration's name; the status
    surface and every capture record render the instance's. A provider that
    registers as one and answers as another would put two names on one
    daemon, so it is refused before anything is served.
    """

    class Renamed(DigitMask):
        name = "not-digit-mask"

    registration = replace(REGISTRATION, factory=Renamed)
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root,
        policy={"path": str(_authority(root))},
        evidence={"path": str(root / "evidence")},
        plugins={
            "PrivacyRedactor": {"provider": "digit-mask", "interface_version": 1},
            "ApprovalProvider": {"provider": "single-approver", "interface_version": 1},
        },
    )

    with pytest.raises(StartRefused) as refusal:
        compose(
            settings,
            daemon_uid=ME,
            entry_points=_entry_points_with(
                StaticEntryPoint("digit-mask", "digit_mask_redactor:REGISTRATION", registration)
            ),
        )

    assert refusal.value.reason == "plugin_composition_refused"
    assert "not-digit-mask" in refusal.value.detail


# -- block 2.7: production composes the durable authority and the archive --


def test_policy_enabled_composition_uses_file_decisions_and_recovery(tmp_path: Path) -> None:
    """R1, G10: wherever a policy can decide, the decision authority is the file store."""
    from sayfirst_control_plane.adapters.file.decision_store import FileDecisionStore
    from sayfirst_control_plane.adapters.file.policy_archive import FilePolicyArchive

    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    services = compose(
        _settings(
            root,
            policy={"path": str(_authority(root))},
            evidence={"path": str(root / "evidence")},
        ),
        daemon_uid=ME,
    )
    assert services is not None
    try:
        assert isinstance(services.decisions.decisions, FileDecisionStore)
        assert isinstance(services.decisions.archive, FilePolicyArchive)
        assert services.decisions.decisions.location().root == root / "evidence" / "decisions"
        # The start version is archived before anything is served (A1).
        kept = services.decisions.archive.read(services.policy.current_version)
        assert kept.content == _POLICY.encode()
        assert services.recording_epoch
    finally:
        services.close()


def test_a_durable_decision_is_readable_from_a_second_composition(tmp_path: Path) -> None:
    """G11: decide, close, compose again over the same root, read the whole document back."""
    from sayfirst_contract.decisions import DecisionAsk
    from sayfirst_control_plane.application.decisions import DecisionAnswer
    from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal

    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    policy = root / "policy.toml"
    policy.write_text(
        'format = 1\n[revision]\nreason = "durable"\n'
        '[[rule]]\nid = "rule-0"\ncapability = "example.effect"\nscope = "local"\n'
        'principals = ["user:alice"]\noutcome = "allow"\nreason = "allow"\n',
        encoding="utf-8",
    )
    os.chmod(policy, 0o600)
    settings = _settings(
        root, policy={"path": str(policy)}, evidence={"path": str(root / "evidence")}
    )
    first = compose(settings, daemon_uid=ME)
    assert first is not None
    try:
        answer = first.decisions.ask(
            DecisionQuestion(
                DecisionAsk("example.effect", correlation="gate-1"),
                Principal("user", ME, "alice", (ME,), ("alice",)),
            )
        )
        assert isinstance(answer, DecisionAnswer)
        taken = first.decisions.decisions.get("local", answer.decision.decision_ref)
    finally:
        first.close()
    second = compose(settings, daemon_uid=ME)
    assert second is not None
    try:
        read = second.decisions.decisions.get("local", answer.decision.decision_ref)
    finally:
        second.close()
    assert taken is not None and read is not None
    assert read.to_document() == taken.to_document()
    assert read.to_document()["reason"] == "policy_allows"
    assert read.to_document()["rule_id"] == "rule-0"
    assert read.to_document()["correlation_source"] == "boundary_supplied"


def test_a_root_another_writer_holds_refuses_the_start_by_name(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    settings = _settings(
        root, policy={"path": str(_authority(root))}, evidence={"path": str(root / "evidence")}
    )
    first = compose(settings, daemon_uid=ME)
    assert first is not None
    try:
        with pytest.raises(StartRefused) as refusal:
            compose(settings, daemon_uid=ME)
        assert refusal.value.reason == "decision_store_unusable"
    finally:
        first.close()
