# SPDX-License-Identifier: Apache-2.0
"""Article 8: the configuration's effective access, at start and per decision request.

Article 8 protects the configuration twice in system mode, "by effective access
(mode bits, access control lists, parent directories) and never by who owns the
file": at start the daemon refuses a configuration anyone but root or its
administrator group could write or replace, and per connection it refuses a
decision request from a principal with effective write access to it or to a
directory that would let it be replaced.

The check is the one the policy authority already receives — the whole-name walk
of `access/effective_access.py`, held on the authority by
`packages/control-plane/tests/unit/test_policy_authority_protection.py` — and
what is new here is the *file* it is applied to and the two places it is applied
from. Nothing is re-implemented: `FileConfiguration` hands the same walk the
configured name, and the verdicts are the authority's own.

**What this file can hold, and what it cannot.**
`ProtectionExpectation.system` admits root as the only owner, so on a runner
that is not root every file this process creates is exposed whatever its mode,
and "a protected system-mode configuration starts" is not a claim an ordinary
runner can make. The cases below therefore hold what every runner can hold: the
walk's verdict about the configured name — protected where only this account
and root may write it, exposed at a stranger's write and at a parent that would
let the file be replaced, and the same verdict the policy authority's adapter
gives for the same name; that the start path applies it and refuses under a
name of its own, before anything else that start could refuse over; and that
the decision path refuses the writer, refuses the principal that could replace
the file through its directory, serves everyone else, and does it under a code a
reader can tell from the policy authority's.

The two claims about a real system-mode daemon are held where they can be, in
the root container: `test_a_configuration_a_stranger_can_write_refuses_the_start_by_name`
and `test_a_configuration_only_root_and_the_administrator_group_can_write_starts`,
with `test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted`
for the per-connection half and the administrative command beside it.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.problems import ProblemCode, problem_class
from sayfirst_control_plane.adapters.file.configuration import FileConfiguration
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.decisions import (
    DecisionAnswer,
    DecisionProblem,
    DecisionService,
)
from sayfirst_control_plane.application.events import MemoryEvents
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.bootstrap import compose
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal
from sayfirst_control_plane.ports.policy_store import ProtectionExpectation, ProtectionState
from sayfirst_control_plane.settings import StartRefused, read_settings

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX effective access")

ME = os.geteuid()
MY_GID = os.getegid()
NOW = datetime(2026, 9, 4, tzinfo=UTC)

#: A uid nobody on this host is, so "can this principal write it" is a question
#: about the bits and never about who is running the suite. The same number the
#: naming-path cases of this directory use, for the same reason.
FOREIGN_UID = 23456
FOREIGN_GID = 23456

_POLICY = (
    "format = 1\n"
    "[revision]\n"
    'reason = "the configuration access cases"\n'
    "[[rule]]\n"
    'id = "rule-0"\n'
    'capability = "example.effect"\n'
    'scope = "local"\n'
    'principals = ["user:alice"]\n'
    'outcome = "allow"\n'
    'reason = "the allow rule"\n'
)

_CONFIGURATION = "# SPDX-License-Identifier: Apache-2.0\n[socket]\nmode = 'system'\n"


class Deployment:
    """A laid-out deployment: a configuration, a policy, and a document naming both.

    The two files sit in directories of their own, so a case that opens one
    directory says something about one file. Sharing a parent made every case
    about the configuration's parent a case about the policy's as well, and the
    policy is checked first — so the refusal under test never arrived.
    """

    def __init__(self, root: Path, *, mode: str = "system") -> None:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = root
        self.configuration_directory = root / "etc"
        self.configuration_directory.mkdir(mode=0o700)
        self.configuration = self.configuration_directory / "daemon.toml"
        self.configuration.write_text(_CONFIGURATION, encoding="utf-8")
        os.chmod(self.configuration, 0o600)
        policy_directory = root / "var"
        policy_directory.mkdir(mode=0o700)
        self.policy_path = policy_directory / "policy.toml"
        self.policy_path.write_text(_POLICY, encoding="utf-8")
        os.chmod(self.policy_path, 0o600)
        socket_section: dict[str, object] = {
            "mode": mode,
            "path": str(root / "daemon.sock"),
        }
        if mode == "system":
            socket_section["group"] = "sayfirst-operators"
        self.document: dict[str, object] = {
            "socket": socket_section,
            "identity": {},
            "policy": {"path": str(self.policy_path)},
            "evidence": {"path": str(root / "evidence")},
        }

    def settings(self, *, configuration_path: str | None = None):  # type: ignore[no-untyped-def]
        return read_settings(
            self.document,
            platform="linux",
            configuration_path=(
                str(self.configuration) if configuration_path is None else configuration_path
            ),
        )


def _mine() -> ProtectionExpectation:
    """The expectation an ordinary runner can satisfy: this account and root."""
    return ProtectionExpectation.per_user(ME)


# -- the walk, applied to the configured name --------------------------------


def test_a_configuration_only_its_administrators_can_write_is_protected(tmp_path: Path) -> None:
    """Article 8: the file and every parent a writer could replace it through."""
    deployment = Deployment(tmp_path / "run")

    verdict = FileConfiguration(deployment.configuration).protection_at_start(_mine())

    assert verdict.kind is ProtectionState.PROTECTED, verdict


def test_a_configuration_a_stranger_can_write_is_exposed_at_the_file(tmp_path: Path) -> None:
    """Article 8: the mode bits decide, and the owner never excuses them."""
    deployment = Deployment(tmp_path / "run")
    os.chmod(deployment.configuration, 0o606)

    verdict = FileConfiguration(deployment.configuration).protection_at_start(_mine())

    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.component == deployment.configuration.resolve()
    assert verdict.reason == "other_write"


def test_a_directory_that_would_let_the_configuration_be_replaced_exposes_it(
    tmp_path: Path,
) -> None:
    """Article 8: "or replace" is a question about the parents, not about the file."""
    deployment = Deployment(tmp_path / "run")
    os.chmod(deployment.configuration_directory, 0o707)

    verdict = FileConfiguration(deployment.configuration).protection_at_start(_mine())

    assert verdict.kind is ProtectionState.EXPOSED
    assert verdict.component == deployment.configuration_directory.resolve()
    assert verdict.reason == "other_write"


def test_the_configuration_walk_is_the_one_the_policy_authority_receives(tmp_path: Path) -> None:
    """Article 8: one check, two files; a second reading would be a second answer.

    The two adapters are handed the same name and answer the same thing about
    it, because the walk is `access/effective_access.py`'s and neither holds a
    copy of it. A `FileConfiguration` that drifted into a reading of its own —
    the file's own bits alone, say — passes every case above and fails this one.
    """
    deployment = Deployment(tmp_path / "run")
    os.chmod(deployment.configuration_directory, 0o777)

    configured = FileConfiguration(deployment.configuration).protection_at_start(_mine())
    authority = FilePolicyStore(deployment.configuration).protection_at_start(_mine())

    assert configured.kind is authority.kind is ProtectionState.EXPOSED
    assert configured.component == authority.component
    assert configured.reason == authority.reason


# -- the start path ----------------------------------------------------------


def test_a_system_mode_start_refuses_an_unprotected_configuration_by_its_own_name(
    tmp_path: Path,
) -> None:
    """Article 8: the refusal is the configuration's, and it names the file and the rule.

    The evidence root of this deployment does not exist, which rule L2a refuses
    in system mode — so a start that reported *that* would be a start that never
    asked article 8's question. The configuration is asked about first, because
    whoever can write it chooses every other file the start then checks.

    On a runner that is not root the rule that fires is the ownership one: the
    expectation admits root as the only owner of a system-mode configuration,
    and this account is not root. The bits rule is held above, against an
    expectation this runner can satisfy, and in the root container against the
    real one.
    """
    deployment = Deployment(tmp_path / "run")

    with pytest.raises(StartRefused) as refusal:
        compose(
            deployment.settings(),
            daemon_uid=ME,
            daemon_gid=MY_GID,
            administrator_gid=MY_GID,
            platform="linux",
        )

    assert refusal.value.reason == "configuration_unprotected"
    assert str(deployment.configuration) in refusal.value.detail
    assert "owner" in refusal.value.detail
    assert not (deployment.root / "evidence").exists()


def test_a_per_user_start_makes_no_claim_about_the_configuration(tmp_path: Path) -> None:
    """Article 8: the two protections are system mode's, and the rule says so.

    The negative control of the case above. Without it, a check that refused
    every configuration would pass that one, and "a system-mode configuration
    anyone can write does not start" would be indistinguishable from "none
    does".
    """
    deployment = Deployment(tmp_path / "run", mode="per_user")
    os.chmod(deployment.configuration, 0o666)

    services = compose(deployment.settings(), daemon_uid=ME, platform="linux")

    assert services is not None
    services.close()


def test_a_start_given_no_configuration_file_claims_nothing_about_one(tmp_path: Path) -> None:
    """Article 2: a daemon started without `--config` holds no path, and says so by silence."""
    deployment = Deployment(tmp_path / "run", mode="per_user")
    settings = deployment.settings(configuration_path="")

    assert settings.configuration_path == ""
    services = compose(settings, daemon_uid=ME, platform="linux")

    assert services is not None
    services.close()


def test_a_system_mode_start_that_named_no_policy_authority_still_asks_about_the_configuration(
    tmp_path: Path,
) -> None:
    """Article 8: the question is asked before the early return a bare deployment takes.

    A deployment that names no policy authority composes nothing — `compose`
    answers `None`, and the surface answers the operations that would need one
    as operations it does not serve. It has still read a configuration, and
    that configuration still chose the address, the admission group and the
    plugins, so the check is applied before that early return rather than
    after it. The ordering case above names a policy authority, so without
    this one the clause specifically about the early return would be held by
    reading only.
    """
    deployment = Deployment(tmp_path / "run")
    bare: dict[str, object] = {"socket": dict(deployment.document["socket"])}  # type: ignore[arg-type]
    named = read_settings(bare, platform="linux", configuration_path=str(deployment.configuration))
    assert named.policy_path == ""

    with pytest.raises(StartRefused) as refusal:
        compose(
            named,
            daemon_uid=ME,
            daemon_gid=MY_GID,
            administrator_gid=MY_GID,
            platform="linux",
        )

    assert refusal.value.reason == "configuration_unprotected"
    assert str(deployment.configuration) in refusal.value.detail
    # And the early return really is what such a deployment otherwise reaches,
    # so the refusal above came from before it and not from somewhere else.
    assert (
        compose(
            read_settings(bare, platform="linux"),
            daemon_uid=ME,
            daemon_gid=MY_GID,
            administrator_gid=MY_GID,
            platform="linux",
        )
        is None
    )


# -- the decision path -------------------------------------------------------


def _service(deployment: Deployment, *, system_mode: bool = True):  # type: ignore[no-untyped-def]
    events = MemoryEvents()
    authority = FilePolicyStore(deployment.policy_path, clock=lambda: NOW)
    policy = PolicyService(authority, (MemoryPolicyProjection(),), events=events, clock=lambda: NOW)
    policy.start(_mine())
    guard = FileConfiguration(deployment.configuration)
    service = DecisionService(
        policy,
        authority,
        MemoryDecisionStore(),
        GrantConnections(events=events, clock=lambda: NOW),
        system_mode=system_mode,
        configuration_access=guard.write_access_of,
        configuration_path=str(deployment.configuration),
        events=events,
        clock=lambda: NOW,
        id_factory=iter(f"id-{index}" for index in range(100)).__next__,
    )
    return service, events


def _question(uid: int, gids: tuple[int, ...]) -> DecisionQuestion:
    return DecisionQuestion(
        DecisionAsk("example.effect", scope="local"),
        Principal("process", uid, "alice", gids, ()),
    )


def test_a_decision_request_from_a_principal_that_could_write_the_configuration_is_refused(
    tmp_path: Path,
) -> None:
    """Article 8: "a governed program that could write its own configuration could
    activate the plugin that frees it"."""
    deployment = Deployment(tmp_path / "run")
    os.chmod(deployment.configuration, 0o666)
    service, events = _service(deployment)

    answer = service.ask(_question(FOREIGN_UID, (FOREIGN_GID,)))

    assert isinstance(answer, DecisionProblem), answer
    assert answer.problem.code is ProblemCode.CONFIGURATION_WRITABLE_BY_PRINCIPAL
    assert answer.problem.retryable is False
    assert str(deployment.configuration) in answer.problem.message
    assert "other_write" in answer.problem.message
    refused = events.of_kind("decision.refused")
    assert [record.details["problem_code"] for record in refused] == [
        "configuration_writable_by_principal"
    ]


def test_a_directory_that_would_let_the_configuration_be_replaced_refuses_a_decision(
    tmp_path: Path,
) -> None:
    """Article 8: "or to a directory that would let it be replaced"."""
    deployment = Deployment(tmp_path / "run")
    os.chmod(deployment.configuration_directory, 0o777)
    service, _ = _service(deployment)

    answer = service.ask(_question(FOREIGN_UID, (FOREIGN_GID,)))

    assert isinstance(answer, DecisionProblem), answer
    assert answer.problem.code is ProblemCode.CONFIGURATION_WRITABLE_BY_PRINCIPAL
    assert str(deployment.configuration) in answer.problem.message
    assert str(deployment.configuration_directory) in answer.problem.message


def test_a_principal_that_can_write_neither_file_is_served_a_decision(tmp_path: Path) -> None:
    """Article 8: the refusal is of the writer, not of everyone.

    The control for the two cases above. A service that refused every decision
    would pass both, and "the configuration's writer obtains none" would be
    indistinguishable from "nobody does".
    """
    deployment = Deployment(tmp_path / "run")
    service, _ = _service(deployment)

    answer = service.ask(_question(FOREIGN_UID, (FOREIGN_GID,)))

    assert isinstance(answer, DecisionAnswer), answer
    assert answer.decision.outcome.value == "allow"


def test_a_per_user_composition_asks_nothing_about_the_configuration(tmp_path: Path) -> None:
    """Article 8: per connection means per connection of a system daemon."""
    deployment = Deployment(tmp_path / "run")
    os.chmod(deployment.configuration, 0o666)
    service, _ = _service(deployment, system_mode=False)

    answer = service.ask(_question(FOREIGN_UID, (FOREIGN_GID,)))

    assert isinstance(answer, DecisionAnswer), answer


def test_the_two_files_are_refused_under_two_codes_a_reader_can_tell_apart(
    tmp_path: Path,
) -> None:
    """Articles 2 and 8: two different facts, so two codes, both refusals.

    One code for both would tell an operator that a principal could write "the
    policy" when what it could write was the file that chooses which file the
    policy is. Both are verdicts the daemon reached on the question it was
    given, so both are `refused` and neither is retryable.

    Each file is opened up after the service has started, because the start
    refuses an exposed authority outright (article 3) — which is itself the
    point: the per-connection check exists because a file protected when the
    daemon started can be opened up while it serves.
    """
    deployment = Deployment(tmp_path / "run")
    service, _ = _service(deployment)

    os.chmod(deployment.policy_path, 0o606)
    on_the_policy = service.ask(_question(FOREIGN_UID, (FOREIGN_GID,)))

    os.chmod(deployment.policy_path, 0o600)
    os.chmod(deployment.configuration, 0o606)
    on_the_configuration = service.ask(_question(FOREIGN_UID, (FOREIGN_GID,)))

    assert isinstance(on_the_policy, DecisionProblem), on_the_policy
    assert on_the_policy.problem.code is ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL
    assert isinstance(on_the_configuration, DecisionProblem), on_the_configuration
    assert on_the_configuration.problem.code is ProblemCode.CONFIGURATION_WRITABLE_BY_PRINCIPAL
    for code in (
        ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL,
        ProblemCode.CONFIGURATION_WRITABLE_BY_PRINCIPAL,
    ):
        assert problem_class(code) == "refused"
