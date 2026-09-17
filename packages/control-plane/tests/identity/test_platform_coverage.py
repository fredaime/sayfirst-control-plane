# SPDX-License-Identifier: Apache-2.0
"""Article 6: the guards of the host boundary bind Linux and macOS alike.

The spec's Guards preamble says the identity tests run on both in CI, and that
only the ones reading a facility one operating system has are gated to it —
with the reason string that says which host runs them. A guard quietly pinned
to Linux is a guard macOS never holds, and the Darwin adapter has nowhere else
to be proved.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sayfirst_testing.guard_gates import gated_guards as kit_gated_guards
from sayfirst_testing.guard_gates import guards_required_on, privilege_gated_guards
from sayfirst_testing.platforms import OS_REAL_PLATFORMS

REPOSITORY = Path(__file__).resolve().parents[4]
IDENTITY_TREES = (
    REPOSITORY / "packages" / "control-plane" / "tests" / "identity",
    REPOSITORY / "packages" / "contract" / "tests" / "identity",
)
WORKFLOW = REPOSITORY / ".github" / "workflows" / "ci.yml"

# Each of these reads a facility that only one operating system has, and says
# so where it is written. Everything else the host boundary defines runs on
# both.
LINUX_ONLY = {
    # SO_PEERCRED, and the conformance run of the Linux adapter itself.
    "test_peer_credentials_are_read_through_the_platform_adapter",
    "test_a_credential_the_os_did_not_deliver_is_unavailable",
    # `socket.SO_PEERCRED` is defined on Linux alone, so only Linux can hold
    # that the adapter reads the number the platform defines.
    "test_the_linux_adapter_asks_for_the_option_number_the_platform_defines",
    # Both establish a peer over a real socket pair with the Linux adapter
    # selected, so the kernel's SO_PEERCRED answer is what they read; the
    # rules they hold (the clock port supplies the captured instant; a uid the
    # kernel maps to nobody is unavailable) run on macOS through the static
    # peer identity elsewhere in these trees.
    "test_the_captured_instant_comes_from_the_clock_port",
    "test_a_kernel_no_identity_uid_is_unavailable",
    # The abstract namespace exists on Linux alone.
    "test_an_abstract_or_unnamed_socket_is_refused",
    # /proc/sys/kernel/overflow*; macOS has no user namespaces (rule L8).
    "test_the_overflow_ids_are_read_at_start_or_the_daemon_does_not_start",
    # `system.posix_acl_access` and the reader for it are Linux's; rule S6
    # records that macOS holds no ACL item of the directory rules at all.
    "test_an_ancestor_named_in_an_access_control_list_is_refused",
    # System mode as root: the drop, the admission group and
    # `/proc/<pid>/status` are Linux's. Each is gated to root as well, so an
    # ordinary Linux runner is not asked for them — see ROOT_ONLY below.
    "test_the_dropped_daemon_does_not_take_the_admission_group_as_its_own",
    "test_a_decision_request_from_root_is_refused_on_the_connection",
    "test_a_governed_principal_is_served_a_decision_by_the_same_daemon",
    "test_an_account_outside_the_admission_group_is_refused_by_the_kernel",
    # Article 8's own two protections of the configuration, which is the file
    # that chooses which file the policy authority is: the start refuses one a
    # stranger could write, a protected one starts and serves, and a principal
    # that could write it obtains no decision while its administrative commands
    # are still admitted and graded. The expectation the start applies admits
    # root as the only owner, so no ordinary runner can lay one out that passes.
    "test_a_configuration_a_stranger_can_write_refuses_the_start_by_name",
    "test_a_configuration_only_root_and_the_administrator_group_can_write_starts",
    "test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted",
    # Rule L2a: what the dropped daemon must be able to do is checked as the
    # dropped daemon. The store it appends to, and the two layouts it refuses.
    "test_the_composed_evidence_store_is_owned_by_the_account_that_must_append_to_it",
    "test_a_policy_the_dropped_daemon_cannot_read_refuses_the_start_by_name",
    "test_an_evidence_root_the_packager_did_not_create_refuses_the_start_by_name",
    # Rule L2a, enforced: the three layouts the rule refuses, the parent it
    # cannot look through, and the three things one append does not prove.
    "test_an_evidence_root_a_governed_principal_owns_refuses_the_start_by_name",
    "test_an_evidence_root_every_account_can_write_refuses_the_start_by_name",
    "test_an_evidence_root_carrying_the_admission_group_refuses_the_start_by_name",
    "test_an_evidence_parent_the_dropped_daemon_cannot_traverse_refuses_the_start_by_name",
    "test_the_chain_the_dropped_daemon_creates_holds_mode_0600_whatever_the_umask",
    "test_an_existing_chain_the_dropped_daemon_cannot_append_to_refuses_the_start_by_name",
    "test_an_evidence_root_no_chain_can_be_created_in_refuses_the_start_by_name",
    # Rule L2a, the store as a whole: the parents it can be replaced through,
    # and the chains present for a scope no rule names.
    "test_an_evidence_root_under_a_world_writable_parent_refuses_the_start_by_name",
    "test_a_chain_already_in_the_store_for_a_scope_no_rule_names_refuses_the_start_by_name",
    "test_a_decision_in_a_scope_no_rule_names_is_recorded_on_a_chain_created_on_first_use",
}
DARWIN_ONLY = {"test_peer_credentials_are_read_through_the_darwin_adapter"}

# -- the second axis: which privilege can hold a guard, not which platform ----
#
# `assemble()` refuses system mode below uid 0, so an ordinary runner cannot
# reach the code these hold at all; a throwaway root container can, and
# `docs/testing/root-container.md` is the recipe. They are named here for the
# same reason the macOS guards are: a guard that stopped running everywhere is
# a failure, not a silence (article 2).
ROOT_ONLY = {
    "test_the_dropped_daemon_does_not_take_the_admission_group_as_its_own",
    "test_a_decision_request_from_root_is_refused_on_the_connection",
    "test_a_governed_principal_is_served_a_decision_by_the_same_daemon",
    "test_an_account_outside_the_admission_group_is_refused_by_the_kernel",
    # Article 8's own two protections of the configuration, which is the file
    # that chooses which file the policy authority is: the start refuses one a
    # stranger could write, a protected one starts and serves, and a principal
    # that could write it obtains no decision while its administrative commands
    # are still admitted and graded. The expectation the start applies admits
    # root as the only owner, so no ordinary runner can lay one out that passes.
    "test_a_configuration_a_stranger_can_write_refuses_the_start_by_name",
    "test_a_configuration_only_root_and_the_administrator_group_can_write_starts",
    "test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted",
    # Rule L2a. The first of these was recorded debt — a strict `xfail` — until
    # the composition moved after the drop; the other two hold the refusals
    # that rule names, which only a daemon that really drops can make.
    "test_the_composed_evidence_store_is_owned_by_the_account_that_must_append_to_it",
    "test_a_policy_the_dropped_daemon_cannot_read_refuses_the_start_by_name",
    "test_an_evidence_root_the_packager_did_not_create_refuses_the_start_by_name",
    # Rule L2a, enforced. Each is a layout or a umask only a daemon that really
    # drops can be refused on, or served under: the codex review of this branch
    # executed every one in the root container, and each served.
    "test_an_evidence_root_a_governed_principal_owns_refuses_the_start_by_name",
    "test_an_evidence_root_every_account_can_write_refuses_the_start_by_name",
    "test_an_evidence_root_carrying_the_admission_group_refuses_the_start_by_name",
    "test_an_evidence_parent_the_dropped_daemon_cannot_traverse_refuses_the_start_by_name",
    "test_the_chain_the_dropped_daemon_creates_holds_mode_0600_whatever_the_umask",
    "test_an_existing_chain_the_dropped_daemon_cannot_append_to_refuses_the_start_by_name",
    "test_an_evidence_root_no_chain_can_be_created_in_refuses_the_start_by_name",
    # Rule L2a, the store as a whole. The second review executed both against
    # a daemon that served: a governed principal renamed a correctly owned
    # root away through its `0777` parent, and a root-owned chain for a scope
    # no rule named was left unproved and never written. The third holds what
    # the documents now say of a scope no rule names: served, and recorded on
    # a chain created on first use.
    "test_an_evidence_root_under_a_world_writable_parent_refuses_the_start_by_name",
    "test_a_chain_already_in_the_store_for_a_scope_no_rule_names_refuses_the_start_by_name",
    "test_a_decision_in_a_scope_no_rule_names_is_recorded_on_a_chain_created_on_first_use",
}

# The other direction: a guard whose premise is that the tester is *not* root.
# One reads uid 0 as a stranger, which is false when root is the daemon's own
# account; the other relies on `chown` failing for want of privilege, and under
# root it instead completes the irreversible `setuid` in the test process and
# takes the rest of the run down with it. Both were found by executing the
# suite as root; neither is a convenience gate.
UNPRIVILEGED_ONLY = {
    "test_the_per_user_daemon_refuses_root_over_the_wire",
    "test_the_directory_check_uses_the_account_the_daemon_will_run_as",
    # System mode refuses to start below uid 0; there is no such refusal to
    # drive when the tester is uid 0.
    "test_a_system_daemon_that_is_not_root_does_not_start",
    # Every refusal it drives is the host denying the tester something, and the
    # host denies root nothing.
    "test_a_start_the_host_refuses_exits_with_the_documented_code_and_reason",
    # The impostor binds the address as the tester, and the profile expects the
    # daemon to be root: a root tester is the account being checked for, so
    # there is no impostor left to refuse.
    "test_an_impostor_bound_at_the_path_is_refused_by_the_client",
    "test_the_command_refuses_an_impostor_and_sends_it_nothing",
}


def gated_guards() -> dict[str, frozenset[str]]:
    """Every platform-gated guard of the identity trees, read from its source."""
    return kit_gated_guards(*IDENTITY_TREES)


def privilege_gates() -> dict[str, str]:
    """Every privilege-gated guard of the identity trees, read from its source."""
    return privilege_gated_guards(*IDENTITY_TREES)


def both_platform_guards() -> set[str]:
    return {
        name for name, platforms in gated_guards().items() if platforms == set(OS_REAL_PLATFORMS)
    }


def test_no_guard_of_the_host_boundary_is_quietly_pinned_to_one_platform() -> None:
    """Article 6: only a guard reading one platform's own facility names it."""
    gates = gated_guards()
    assert gates, "no platform-gated guard was found at all"
    pinned_to_linux = {name for name, platforms in gates.items() if platforms == {"linux"}}
    pinned_to_darwin = {name for name, platforms in gates.items() if platforms == {"darwin"}}
    assert pinned_to_linux == LINUX_ONLY, pinned_to_linux ^ LINUX_ONLY
    assert pinned_to_darwin == DARWIN_ONLY, pinned_to_darwin ^ DARWIN_ONLY
    assert len(both_platform_guards()) >= 12


def test_the_macos_leg_names_the_guards_it_must_run() -> None:
    """Article 6: not runnable here is reported; never silently skipped there."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    import re

    inner = workflow.partition("OS_REAL_GUARDS_BEGIN")[2].partition("OS_REAL_GUARDS_END")[0]
    named = set(re.findall(r"- (test_\w+)", inner))
    assert named == both_platform_guards(), named ^ both_platform_guards()
    assert "macos-latest" in workflow
    assert "-rs" in workflow


def test_each_runner_owes_the_guards_only_it_can_hold() -> None:
    """Article 6: the runner that alone can prove an adapter is required to.

    The Darwin credential guard is the only OS-real proof that the Darwin
    `struct xucred` is Darwin's, and macOS is the only runner that can hold it,
    so macOS owes it. The list above says which guards both runners owe; this
    says the single-platform ones are owed too, and by whom.

    Privilege is the second axis. An ordinary Linux runner is not asked for a
    guard only a root container can hold — requiring it there would fail every
    ordinary run over a skip that runner was right to report — and the root
    container is asked for those and for everything the ordinary one owes.
    """
    owed_on_darwin = guards_required_on("darwin", *IDENTITY_TREES)
    owed_on_linux = guards_required_on("linux", *IDENTITY_TREES)
    assert owed_on_darwin == both_platform_guards() | DARWIN_ONLY
    assert owed_on_linux == (both_platform_guards() | LINUX_ONLY) - ROOT_ONLY
    assert "test_peer_credentials_are_read_through_the_darwin_adapter" in owed_on_darwin

    owed_in_a_root_container = guards_required_on("linux", *IDENTITY_TREES, privilege="root")
    assert owed_in_a_root_container == (both_platform_guards() | LINUX_ONLY) - UNPRIVILEGED_ONLY
    # A guard with no privilege gate is owed by whichever runner meets it, so
    # the two Linux runners differ by exactly the two privilege-gated sets: the
    # root container owes the root guards and is excused the unprivileged ones.
    assert owed_in_a_root_container - owed_on_linux == ROOT_ONLY
    assert owed_on_linux - owed_in_a_root_container == UNPRIVILEGED_ONLY & (
        both_platform_guards() | LINUX_ONLY
    )


def test_every_privilege_gated_guard_is_named_here() -> None:
    """Article 2: a guard that can only ever skip is debt, and debt is written down.

    A guard gated to root that nobody lists is a guard that skips on every
    runner the project actually has, and a run of skips exits 0. These two
    lists are that guard's only reader: adding a gate without adding a name
    fails here, by name.
    """
    gates = privilege_gates()
    root = {name for name, privilege in gates.items() if privilege == "root"}
    unprivileged = {name for name, privilege in gates.items() if privilege == "unprivileged"}
    assert root == ROOT_ONLY, root ^ ROOT_ONLY
    assert unprivileged == UNPRIVILEGED_ONLY, unprivileged ^ UNPRIVILEGED_ONLY
    # Every root guard is gated to Linux too, which is what puts it in the set
    # the gate step reads: a root guard with no platform gate is one no runner
    # is ever required to hold, and a guard nobody is required to hold is a
    # guard that only ever skips.
    assert ROOT_ONLY <= LINUX_ONLY


def test_the_root_container_leg_runs_the_guards_only_it_can_hold() -> None:
    """Article 2: the debt is registered where a run can discharge it.

    A root-gated guard with no runner is a skip on every machine the project
    owns. The workflow gains a leg that is root — a container job runs as root
    — and the gate step there is told so, which is what makes the skip of one
    of these guards a failure somewhere.
    """
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "--privilege=root" in workflow, (
        "no leg requires the root-container guards; they would skip everywhere"
    )
    assert "ROOT_CONTAINER_GUARDS_BEGIN" in workflow
    import re

    inner = workflow.partition("ROOT_CONTAINER_GUARDS_BEGIN")[2].partition(
        "ROOT_CONTAINER_GUARDS_END"
    )[0]
    named = set(re.findall(r"- (test_\w+)", inner))
    assert named == ROOT_ONLY, named ^ ROOT_ONLY


def test_the_macos_listener_enumeration_the_spec_names_exists() -> None:
    """Article 6: the guard enumerates endpoints with the tool each platform has."""
    source = (IDENTITY_TREES[0] / "test_daemon_process.py").read_text(encoding="utf-8")
    guard = source.partition("def test_the_daemon_listens_only_on_the_socket")[2]
    # The guard and the two enumerations it dispatches to, up to the next guard.
    guard = guard.partition("\n@")[0]
    assert "_linux_listeners" in guard and "_darwin_listeners" in guard
    assert "/proc/net/tcp" in guard and "/proc/net/tcp6" in guard
    assert "/proc/net/unix" in guard
    assert '"lsof", "-p", str(pid), "-a", "-i", "-P", "-n"' in guard
    assert '"lsof", "-p", str(pid), "-a", "-U"' in guard


# -- the gate that makes "a skip is a failure" true ---------------------------

REQUIRE = REPOSITORY / "scripts" / "require_platform_guards.py"


def _plant(tree: Path, gate: str) -> None:
    """A tree holding one guard gated to `gate`, and one gated to nothing."""
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "test_planted.py").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "from sayfirst_testing.platforms import requires_platform\n"
        "\n"
        "\n"
        f'@requires_platform("{gate}")\n'
        "def test_a_guard_only_one_runner_can_hold() -> None:\n"
        "    assert True\n"
        "\n"
        "\n"
        "def test_a_guard_every_runner_holds() -> None:\n"
        "    assert True\n",
        encoding="utf-8",
    )


def _run_the_gate(tree: Path, platform: str) -> subprocess.CompletedProcess[str]:
    """Really run the planted tree, then judge the run the way CI judges its own."""
    report = tree / "report.xml"
    environment = {
        **os.environ,
        "PYTHONPATH": str(REPOSITORY / "packages" / "testing" / "src"),
    }
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-rs",
            "--no-header",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={report}",
            "test_planted.py",
        ],
        cwd=tree,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    return subprocess.run(
        [
            sys.executable,
            str(REQUIRE),
            f"--junit={report}",
            f"--platform={platform}",
            f"--tree={tree}",
        ],
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_planted_skip_fails_the_step_that_calls_a_skip_a_failure(tmp_path: Path) -> None:
    """Article 2: the step's claim is no stronger than the check behind it.

    `-rs` reports a skip; it does not fail on one, and a run in which every
    named guard skipped exits 0. This plants exactly that run — a guard gated
    to a platform this host is not — and requires the gate to refuse it, by
    name.
    """
    tree = tmp_path / "planted"
    _plant(tree, "no_such_platform")
    refused = _run_the_gate(tree, "no_such_platform")
    assert refused.returncode != 0, refused.stdout + refused.stderr
    assert "test_a_guard_only_one_runner_can_hold" in refused.stdout + refused.stderr
    assert "test_a_guard_every_runner_holds" not in refused.stdout + refused.stderr


def test_the_gate_passes_a_run_that_held_every_guard_it_owes(tmp_path: Path) -> None:
    """Article 2: and no stronger the other way — a held run is not a failure."""
    tree = tmp_path / "held"
    _plant(tree, sys.platform)
    held = _run_the_gate(tree, sys.platform)
    assert held.returncode == 0, held.stdout + held.stderr
    # The same run, judged for the runner that does not owe that guard: the
    # guard is not required there, so its skip is reported and not a failure.
    other = _run_the_gate(tree, "no_such_platform")
    assert other.returncode == 0, other.stdout + other.stderr


def test_the_workflow_calls_the_gate_on_both_runners() -> None:
    """Article 2: the step that names the claim is the step that runs the check."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/require_platform_guards.py" in workflow
    assert "--junitxml=" in workflow
    assert REQUIRE.exists()
