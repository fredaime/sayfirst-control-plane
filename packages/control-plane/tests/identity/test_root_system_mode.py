# SPDX-License-Identifier: Apache-2.0
"""System mode as root: the guards no unprivileged runner can hold.

`assemble()` refuses system mode below uid 0 (rule M3), so on an ordinary
runner every claim about what system mode *does* is a claim about code that
never ran. These guards run it: a real daemon on a real address, dropped to a
real account, answering real peers whose credentials the kernel supplied.

Each carries two gates. `requires_platform("linux")` because the drop, the
admission group and `/proc/<pid>/status` are Linux's here;
`requires_root()` because a root container is the only place they can be held
at all. `scripts/require_platform_guards.py --privilege=root` makes that
container owe them, and `test_platform_coverage.py` names them, so a guard
that quietly stopped running is a failure and not a silence (article 2).

The recipe for the container is `docs/testing/root-container.md`.
"""

from __future__ import annotations

import os

from root_system_mode import (
    CLIENT,
    GROUP,
    OUTSIDER,
    call,
    call_as,
    credentials_of,
    daemon_in_a_child,
    deployment_root,
    lay_out,
    refused_start,
    required_account,
    required_group,
    wait_for_decision,
)
from sayfirst_testing.platforms import requires_platform
from sayfirst_testing.privileges import requires_root

ASK = {"contract_generation": 1, "capability": "example.effect", "scope": "local"}


@requires_platform("linux")
@requires_root()
def test_the_dropped_daemon_does_not_take_the_admission_group_as_its_own() -> None:
    """Article 7: the daemon's group is its own account's, never the governed one.

    The admission list is what the socket's group grants; the daemon needs
    nothing from it once the socket is `chown`ed, which rule M3 puts before the
    drop. A daemon whose primary group *is* the admitted principals' group
    shares a group with every program it governs, and article 7's "no principal
    but that one and root can write or replace the store" is then one mode bit
    from untrue.

    Read from `/proc/<pid>/status`, so what is asserted is what the kernel
    recorded and not what the process was asked to become.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        with daemon_in_a_child(deployment) as pid:
            recorded = credentials_of(pid)
    assert recorded["uid"] == deployment.run_as.uid
    assert recorded["gid"] == deployment.run_as.gid, (
        "the daemon dropped to the admission group instead of its own account's group"
    )
    assert deployment.admission_gid != deployment.run_as.gid, (
        "this guard proves nothing unless the two groups differ"
    )
    # The membership the account really holds survives the drop: `initgroups`
    # is asked for the account's own group, so the list is the directory's
    # answer for that account and not a list the daemon invented.
    assert deployment.run_as.gid in recorded["groups"]  # type: ignore[operator]


@requires_platform("linux")
@requires_root()
def test_a_decision_request_from_root_is_refused_on_the_connection() -> None:
    """Article 8: no decision for a principal that could rewrite the policy.

    "In consequence a program run as root or as the administrator group obtains
    no decision in system mode." Root can write every policy there is, so the
    refusal is per connection and it names the component that decided it, while
    the administrative command on the same daemon is admitted and graded.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        with daemon_in_a_child(deployment):
            assert os.geteuid() == 0
            administrative, whoami = call(deployment.socket_path, "GET", "/whoami")
            decision, refusal = call(deployment.socket_path, "POST", "/decisions", ASK)
    assert administrative == 200, whoami
    assert whoami["peer"]["uid"] == 0
    assert decision == 403, refusal
    assert refusal["code"] == "policy_writable_by_principal", refusal
    assert str(deployment.policy_path) in refusal["message"], refusal
    assert refusal["retryable"] is False


@requires_platform("linux")
@requires_root()
def test_a_governed_principal_is_served_a_decision_by_the_same_daemon() -> None:
    """Article 8: the refusal is of the writer, not of everyone.

    The control for the guard above. Without it, a daemon that refused every
    decision would pass that one, and "root obtains no decision" would be
    indistinguishable from "nobody does".
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        with daemon_in_a_child(deployment):
            answer = call_as(client, deployment.socket_path, "POST", "/decisions", ASK)
    assert "error" not in answer, answer
    assert answer["status"] == 200, answer
    assert answer["document"]["outcome"] == "allow", answer


# -- article 8, the configuration's own two protections ------------------------
#
# The policy authority's checks above are about the file whose rules decide
# outcomes. These are about the file that chooses which file that is, and which
# address is bound, which group is admitted, where the evidence is kept and
# which plugins are composed. They live here for the same reason as the rest:
# `assemble()` refuses system mode below uid 0, and the expectation the start
# applies admits root as the only owner, so no ordinary runner can lay out a
# configuration that passes it. `test_configuration_access.py` holds the walk
# and the wiring on every runner; what only this container can hold is a real
# daemon starting, or refusing to, on a real root-owned file.


@requires_platform("linux")
@requires_root()
def test_a_configuration_a_stranger_can_write_refuses_the_start_by_name() -> None:
    """Article 8: "at start, the daemon refuses a configuration that anyone but root
    or its administrator group could write or replace".

    The deployment is otherwise exactly the one that starts and serves below —
    the same policy, the same store, the same accounts — and the one difference
    is a mode bit on the configuration. So what the refusal is about is the
    configuration and nothing else, and the refusal says so by its own name.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(
            root,
            principal=client.name,
            packager_owns_the_store=True,
            configuration_mode=0o666,
        )
        refusal = refused_start(deployment)
    assert "configuration_unprotected" in refusal, refusal
    assert str(deployment.configuration_path) in refusal, refusal
    assert "other_write" in refusal, refusal
    assert deployment.run_as.name in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_a_configuration_only_root_and_the_administrator_group_can_write_starts() -> None:
    """Article 8: the refusal is of the exposed configuration, not of every configuration.

    The control for the guard above, and the only place it can be held: a
    `root:<admission> 0640` file is protected against the expectation the start
    applies, which no file an ordinary runner can create ever is. The daemon
    listens on it and serves a decision to a governed principal, so "a
    configuration anyone can write does not start" is told apart from "none
    does".
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        assert oct(deployment.configuration_path.stat().st_mode)[-3:] == "640"
        with daemon_in_a_child(deployment):
            answer = call_as(client, deployment.socket_path, "POST", "/decisions", ASK)
    assert "error" not in answer, answer
    assert answer["status"] == 200, answer
    assert answer["document"]["outcome"] == "allow", answer


@requires_platform("linux")
@requires_root()
def test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted() -> None:
    """Article 8: "a program run as root or as the administrator group obtains no
    decision in system mode", and its administrative commands are still served.

    The configuration is `root:<admission> 0660`, which starts: the
    administrator group is exactly who article 8 allows to write it. So every
    program running as that group can write its own configuration, and article
    8 draws the consequence in as many words. The same program run as its own
    group — the guard above — is served, and the one difference between the two
    is the group the program runs as.

    The other half of the article's sentence is held beside it: "administrative
    commands from such a principal are admitted and graded (article 7)". The
    refusal is of decisions, on the connection, and not of the connection: the
    same program reads `whoami` and a graded `status` over the same address.

    What this establishes is about the group the program **runs as**, which is
    the group the peer credential carries and the group the check receives. A
    named supplementary membership does not reach the check today, because the
    principal a decision is evaluated against carries the credential's own
    group and the gids the directory could not name, and nothing else; that is
    equally true of the policy authority's own per-connection check and is not
    this guard's to claim otherwise.
    """
    client = required_account(CLIENT)
    admission = required_group(GROUP)
    with deployment_root() as root:
        deployment = lay_out(
            root,
            principal=client.name,
            packager_owns_the_store=True,
            configuration_mode=0o660,
        )
        with daemon_in_a_child(deployment):
            decision = call_as(
                client, deployment.socket_path, "POST", "/decisions", ASK, gid=admission
            )
            whoami = call_as(client, deployment.socket_path, "GET", "/whoami", gid=admission)
            status = call_as(client, deployment.socket_path, "GET", "/status", gid=admission)
    assert decision.get("status") == 403, decision
    refusal = decision["document"]
    assert refusal["code"] == "configuration_writable_by_principal", refusal
    assert str(deployment.configuration_path) in refusal["message"], refusal
    assert refusal["retryable"] is False, refusal
    assert whoami.get("status") == 200, whoami
    assert whoami["document"]["peer"]["uid"] == client.uid, whoami
    assert status.get("status") == 200, status
    assert status["document"]["integrity_grade"]["grade"], status


@requires_platform("linux")
@requires_root()
def test_an_account_outside_the_admission_group_is_refused_by_the_kernel() -> None:
    """Article 6: the socket's permissions are the admission list, and it holds.

    The daemon restates the list from the credential, but the first refusal is
    the kernel's at `connect()`: an outsider never reaches a handler at all.
    """
    client = required_account(CLIENT)
    outsider = required_account(OUTSIDER)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        with daemon_in_a_child(deployment):
            answer = call_as(outsider, deployment.socket_path, "GET", "/whoami")
    assert answer.get("error", "").startswith("PermissionError"), answer


@requires_platform("linux")
@requires_root()
def test_the_composed_evidence_store_is_owned_by_the_account_that_must_append_to_it() -> None:
    """Articles 7 and 10, rule L2a: the store is the running daemon's, file and all.

    The packager creates the evidence root, owned by the account the daemon
    drops to; the chain file inside it is created by the daemon itself, after
    the drop, as that account. Executed the other way round in the first root
    run, the file arrived `0600 root:root` inside a directory the packager had
    laid out correctly, the dropped daemon could not append to it, and the one
    decision it served was never recorded — a pipeline with a permanent gap.
    So this asks for a decision as a governed principal and reads the store:
    the file is the daemon account's, and the decision is on the chain after
    the composition entry, appended by the dropped daemon.

    "The decision" means the `effect` entry that records it — by kind, by the
    decision id the daemon answered with, by scope and outcome — and not a
    second entry of any kind: a `grade` entry arrives beside every decision,
    and a guard that waited for two entries passed with every `effect` record
    dropped (article 2; the codex review of this branch ran that mutation).
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        store = deployment.evidence_root / "local.jsonl"
        with daemon_in_a_child(deployment):
            assert store.exists(), "the composition entry was never written"
            owner = os.stat(store)
            answer = call_as(client, deployment.socket_path, "POST", "/decisions", ASK)
            assert answer.get("status") == 200, answer
            decision_ref = answer["document"]["decision_ref"]
            entries = wait_for_decision(store, decision_ref)
    assert answer["document"]["outcome"] == "allow", answer
    assert owner.st_uid == deployment.run_as.uid, (
        f"{store} is owned by uid {owner.st_uid}; the daemon runs as "
        f"{deployment.run_as.uid} after the drop and cannot append to it"
    )
    assert owner.st_gid == deployment.run_as.gid
    kinds = [entry["kind"] for entry in entries]
    assert kinds[0] == "composition", kinds
    effects = [entry for entry in entries if entry["kind"] == "effect"]
    assert effects, f"the decision the dropped daemon served was never appended: {kinds}"
    effect = effects[-1]
    assert effect["body"]["decision_id"] == decision_ref, effect
    assert effect["body"]["outcome"] == "allow", effect
    assert effect["body"]["capability"] == ASK["capability"], effect
    assert effect["scope"] == ASK["scope"], effect
    assert effect["principal"] == {"kind": "user", "id": client.name, "via": []}, effect
    assert effect["sequence"] > entries[0]["sequence"], entries


@requires_platform("linux")
@requires_root()
def test_a_policy_the_dropped_daemon_cannot_read_refuses_the_start_by_name() -> None:
    """Articles 2 and 3, rule L2a: the start check is made by the account that will read.

    `root:root 0600` is what an operator gets by copying a policy file into
    place as root, and the first root run started on it: the check ran as
    root, passed, the daemon dropped, and every decision for the rest of its
    life was "unavailable, retryable". A check that proves something the drop
    invalidates is a claim outrunning its evidence. Now the check is made after
    the drop, by the account that will read for every decision, and a file it
    cannot read is refused before `listen()` with the path and the account.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(
            root,
            principal=client.name,
            packager_owns_the_store=True,
            policy_readable_after_the_drop=False,
        )
        refusal = refused_start(deployment)
    assert "policy_unavailable_at_start" in refusal, refusal
    assert str(deployment.policy_path) in refusal, refusal
    assert "unreadable" in refusal, refusal
    assert deployment.run_as.name in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_an_evidence_root_the_packager_did_not_create_refuses_the_start_by_name() -> None:
    """Article 7, rule L2a: the evidence root is the packager's, never the daemon's.

    A daemon that created it as root, before the drop, created a directory the
    dropped daemon could not write into; a daemon that creates it after the
    drop, under a parent root owns, cannot create it at all. The rule is the
    socket's: the packager creates the directory, owned by the daemon's own
    account, and the daemon refuses to stand in for the packager — naming the
    directory and the account it must belong to, so the operator reads a
    layout to fix.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=False)
        refusal = refused_start(deployment)
        assert not deployment.evidence_root.exists(), "the daemon created the packager's directory"
    assert "evidence_root_unusable" in refusal, refusal
    assert str(deployment.evidence_root) in refusal, refusal
    assert "packager" in refusal, refusal
    assert deployment.run_as.name in refusal, refusal


# -- rule L2a, the layouts the packager can get wrong and the daemon must name --
#
# The rule says the evidence root is owned by `run_as` and its own group at
# mode `0700`. A check that established only "is a directory" started and served
# on each of the three layouts below (the codex review of this branch executed
# them). What decides each refusal is what other principals can effectively do
# with the directory — write it, inherit its group into every chain — and not
# the owner alone (article 7); the refusal names the directory and the account
# it must belong to, so the operator reads a layout to fix (article 3).


def _refused_evidence_root(deployment) -> str:  # type: ignore[no-untyped-def]
    refusal = refused_start(deployment)
    assert "evidence_root_unusable" in refusal, refusal
    assert str(deployment.evidence_root) in refusal, refusal
    assert deployment.run_as.name in refusal, refusal
    assert "packager" in refusal, refusal
    return refusal


@requires_platform("linux")
@requires_root()
def test_an_evidence_root_a_governed_principal_owns_refuses_the_start_by_name() -> None:
    """Article 7, rule L2a: a store the governed principal owns is not the daemon's."""
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        os.chown(deployment.evidence_root, client.uid, client.gid)
        os.chmod(deployment.evidence_root, 0o777)
        refusal = _refused_evidence_root(deployment)
    assert f"owned by uid {client.uid}" in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_an_evidence_root_every_account_can_write_refuses_the_start_by_name() -> None:
    """Article 7, rule L2a: owned by the right account and writable by all is not `0700`."""
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        os.chmod(deployment.evidence_root, 0o777)
        refusal = _refused_evidence_root(deployment)
    assert "mode 0o777" in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_an_evidence_root_carrying_the_admission_group_refuses_the_start_by_name() -> None:
    """Article 7, rule L2a: the root carries the daemon's own group, never the admission list.

    With the setgid bit, every chain file the daemon creates inherits the
    directory's group, and a group held by every governed principal is one mode
    bit from writing the store; the first root run of this layout created the
    chain with the admission gid.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        os.chown(deployment.evidence_root, deployment.run_as.uid, deployment.admission_gid)
        os.chmod(deployment.evidence_root, 0o2700)
        refusal = _refused_evidence_root(deployment)
    assert f"group {deployment.admission_gid}" in refusal, refusal
    assert deployment.admission_gid == required_group(
        os.environ.get("SAYFIRST_ROOT_GUARD_GROUP", "sayfirst-admitted")
    )


@requires_platform("linux")
@requires_root()
def test_an_evidence_parent_the_dropped_daemon_cannot_traverse_refuses_the_start_by_name() -> None:
    """Articles 2 and 3, rule L2a: what could not be looked at is refused as that fact.

    The evidence root is laid out exactly right, under a parent root owns at
    `0700`. After the drop the daemon cannot `stat` it. That is not "not a
    directory" and it is not a traceback at exit 1: it is `evidence_root_unusable`
    naming the directory, the fact that access could not be established, and
    the account that could not look.

    The parent that is closed is the store's own and not the deployment root,
    which also holds the configuration: a root the dropped account cannot
    traverse is a *configuration* it cannot look at either, and article 8
    refuses that start first and by another name. One layout, one defect, so
    the deployment here is wrong in exactly the way this guard is about.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=False)
        parent = root / "lib"
        parent.mkdir()
        deployment.evidence_root = parent / "evidence"
        deployment.evidence_root.mkdir()
        os.chown(deployment.evidence_root, deployment.run_as.uid, deployment.run_as.gid)
        os.chmod(deployment.evidence_root, 0o700)
        os.chmod(parent, 0o700)
        refusal = _refused_evidence_root(deployment)
    assert "access could not be established" in refusal, refusal
    assert f"uid {deployment.run_as.uid}" in refusal, refusal
    assert "not a directory" not in refusal, refusal


# -- rule L2a, what one successful append does not prove -----------------------
#
# The composition record is one append through a creation descriptor. The three
# guards below are the three things it does not prove, each executed by the
# codex review of this branch against a daemon that served regardless: that the
# chain can be reopened, that a chain already there for a scope the policy
# allows can be appended to, and that a chain can be created at all.


@requires_platform("linux")
@requires_root()
def test_the_chain_the_dropped_daemon_creates_holds_mode_0600_whatever_the_umask() -> None:
    """Articles 7 and 10, rule L2a: "created at 0600" is a mode held, not one asked for.

    Under `umask 0777` the first chain arrived at mode 000: the composition
    went through the descriptor that created the file, the daemon announced
    `serving`, served an allow, and could never open the file again. Now the
    file is `0600` whatever the umask, and the decision is on it.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        store = deployment.evidence_root / "local.jsonl"
        with daemon_in_a_child(deployment, umask=0o777):
            mode = os.stat(store).st_mode & 0o7777
            answer = call_as(client, deployment.socket_path, "POST", "/decisions", ASK)
            assert answer.get("status") == 200, answer
            entries = wait_for_decision(store, answer["document"]["decision_ref"])
    assert mode == 0o600, f"{store} was created at {oct(mode)} under umask 0777"
    kinds = [entry["kind"] for entry in entries]
    assert "effect" in kinds, f"the decision served under umask 0777 was never appended: {kinds}"


@requires_platform("linux")
@requires_root()
def test_an_existing_chain_the_dropped_daemon_cannot_append_to_refuses_the_start_by_name() -> None:
    """Articles 2 and 10, rule L2a: a chain that is there, for an allowed scope, and closed.

    `audit.jsonl` exists as `root:root 0600`; the policy allows `audit`; the
    root is laid out exactly right. The daemon that checked only `local`
    announced `serving`, returned `200 allow` for `audit`, and the `audit`
    chain stayed empty for good. The start is refused naming the file.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(
            root, principal=client.name, packager_owns_the_store=True, scope="audit"
        )
        blocked = deployment.evidence_root / "audit.jsonl"
        blocked.touch(mode=0o600)
        os.chown(blocked, 0, 0)
        os.chmod(blocked, 0o600)
        refusal = refused_start(deployment)
        assert blocked.stat().st_size == 0
    assert "evidence_root_unusable" in refusal, refusal
    assert str(blocked) in refusal, refusal
    assert "'audit'" in refusal, refusal
    assert deployment.run_as.name in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_an_evidence_root_no_chain_can_be_created_in_refuses_the_start_by_name() -> None:
    """Articles 2 and 10, rule L2a: a root the daemon can append in and not create in.

    The root is `0500`, `local.jsonl` exists and is the daemon's, the policy
    allows `audit`. The composition succeeded, `serving` was announced, an
    `audit` allow was served, and `audit.jsonl` could not be created. Refused
    at start — for the mode, which is not `0700`, before any chain is tried —
    and the daemon leaves nothing behind.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(
            root, principal=client.name, packager_owns_the_store=True, scope="audit"
        )
        seed = deployment.evidence_root / "local.jsonl"
        seed.touch(mode=0o600)
        os.chown(seed, deployment.run_as.uid, deployment.run_as.gid)
        os.chmod(deployment.evidence_root, 0o500)
        refusal = _refused_evidence_root(deployment)
        assert not (deployment.evidence_root / "audit.jsonl").exists()
    assert "mode 0o500" in refusal, refusal


# -- rule L2a, the store as a whole: the ancestors, and the chains present ------
#
# The second review of this branch executed two more cases against a daemon
# that served on both. A correctly owned root under a world-writable parent,
# which a governed principal renamed away while the daemon ran — article 7
# names "every parent directory that would allow it to be replaced", and rule
# S4 already walks them for the socket directory. And a root-owned chain for a
# scope no rule names: the scope is the caller's field, not the policy's, so a
# start check over the policy's scopes left a chain the daemon would be owed a
# record on unproved, and the deny it served for that scope was never recorded.


@requires_platform("linux")
@requires_root()
def test_an_evidence_root_under_a_world_writable_parent_refuses_the_start_by_name() -> None:
    """Articles 7 and 2, rules L2a and S4: the parents decide whether the store can be replaced.

    The evidence root is laid out exactly right, under a parent at `0777`.
    Executed on the branch as reviewed, the daemon served, and `sayfirst-client`
    renamed the store away and put its own directory at the path while it did.
    The walk that refuses this for the socket directory refuses it here — the
    same rule, called twice — naming the parent and the fact.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=False)
        parent = root / "lib"
        parent.mkdir()
        os.chmod(parent, 0o777)
        deployment.evidence_root = parent / "evidence"
        deployment.evidence_root.mkdir()
        os.chown(deployment.evidence_root, deployment.run_as.uid, deployment.run_as.gid)
        os.chmod(deployment.evidence_root, 0o700)
        refusal = _refused_evidence_root(deployment)
    assert str(parent) in refusal, refusal
    assert "an ancestor is writable by anyone and not sticky" in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_a_chain_already_in_the_store_for_a_scope_no_rule_names_refuses_the_start_by_name() -> None:
    """Articles 2 and 10, rule L2a: every chain already in the store is proved, named or not.

    `audit.jsonl` exists as `root:root 0600`; no rule names `audit`; the root
    is laid out exactly right. Executed on the branch as reviewed, the daemon
    started, answered `200 deny` for `audit`, and the chain stayed empty for
    good — the same layout as the guard above this section, one step to the
    left of a check that proved the policy's scopes. What is proved now is
    what is there: every chain in the root, whatever scope it belongs to.
    """
    client = required_account(CLIENT)
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        blocked = deployment.evidence_root / "audit.jsonl"
        blocked.touch(mode=0o600)
        os.chown(blocked, 0, 0)
        os.chmod(blocked, 0o600)
        refusal = refused_start(deployment)
        assert blocked.stat().st_size == 0
    assert "evidence_root_unusable" in refusal, refusal
    assert str(blocked) in refusal, refusal
    assert "'audit'" in refusal, refusal
    assert deployment.run_as.name in refusal, refusal


@requires_platform("linux")
@requires_root()
def test_a_decision_in_a_scope_no_rule_names_is_recorded_on_a_chain_created_on_first_use() -> None:
    """Articles 7 and 10, rule L2a: a scope no chain was proved for is served, and recorded.

    The policy names `local` only; a governed principal asks for `audit`. No
    start check can enumerate the scope a caller will name, so none claims
    to: what the start proved is the directory — owned by the dropped account
    at `0700`, no other principal able to write or replace it — and the chain
    for `audit` is created on first use under that rule, as the dropped
    account, at `0600`, with the deny on it. The sentence in
    `docs/deployment.md` says exactly this, and this is what holds it.
    """
    client = required_account(CLIENT)
    ask = {**ASK, "scope": "audit"}
    with deployment_root() as root:
        deployment = lay_out(root, principal=client.name, packager_owns_the_store=True)
        chain = deployment.evidence_root / "audit.jsonl"
        with daemon_in_a_child(deployment):
            assert not chain.exists(), "a chain was created at start for a scope no rule names"
            answer = call_as(client, deployment.socket_path, "POST", "/decisions", ask)
            assert answer.get("status") == 200, answer
            decision_ref = answer["document"]["decision_ref"]
            entries = wait_for_decision(chain, decision_ref)
            owner = os.stat(chain)
    assert answer["document"]["outcome"] == "deny", answer
    assert owner.st_uid == deployment.run_as.uid, f"{chain} is owned by uid {owner.st_uid}"
    assert owner.st_gid == deployment.run_as.gid, f"{chain} carries gid {owner.st_gid}"
    assert owner.st_mode & 0o7777 == 0o600, f"{chain} was created at {oct(owner.st_mode)}"
    effects = [entry for entry in entries if entry["kind"] == "effect"]
    kinds = [entry["kind"] for entry in entries]
    assert effects, f"the deny served for a scope no rule names was never appended: {kinds}"
    effect = effects[-1]
    assert effect["body"]["decision_id"] == decision_ref, effect
    assert effect["body"]["outcome"] == "deny", effect
    assert effect["scope"] == "audit", effect
    assert effect["principal"] == {"kind": "user", "id": client.name, "via": []}, effect
