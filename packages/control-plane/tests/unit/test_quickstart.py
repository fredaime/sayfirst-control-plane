# SPDX-License-Identifier: Apache-2.0
"""What `sayfirst-daemon up --quickstart` writes, and what it never writes over.

The starter files are read back here by the readers the daemon itself uses —
the policy by `parse_policy` and `evaluate`, the configuration by
`read_settings` — because a starter that only looks right is a claim, and a
starter the daemon would refuse is a first run that fails (article 2).
"""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path

import pytest
from sayfirst_contract.decisions import DecisionAsk, Outcome, Reason
from sayfirst_control_plane.domain.policy import (
    DecisionQuestion,
    Policy,
    Principal,
    evaluate,
    parse_policy,
)
from sayfirst_control_plane.settings import read_settings
from sayfirst_quickstart import launcher as quickstart

ACCOUNT = "example"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _question(capability: str) -> DecisionQuestion:
    return DecisionQuestion(
        DecisionAsk(capability), Principal("user", 1000, ACCOUNT, (1000,), (ACCOUNT,))
    )


def _starter_policy() -> Policy:
    parsed = parse_policy(quickstart.starter_policy(ACCOUNT).encode())
    assert isinstance(parsed, Policy), parsed
    return parsed


def test_the_layout_is_one_private_directory_under_the_home_directory(tmp_path: Path) -> None:
    layout = quickstart.layout(str(tmp_path))
    assert layout.root == tmp_path / ".sayfirst" / "quickstart"
    assert layout.policy == layout.root / "policy.toml"
    assert layout.configuration == layout.root / "daemon.toml"
    assert layout.evidence == layout.root / "evidence"
    assert {layout.log.parent, layout.record.parent} == {layout.root}


def test_everything_is_created_private_whatever_the_umask_says(tmp_path: Path) -> None:
    layout = quickstart.layout(str(tmp_path))
    before = os.umask(0)
    try:
        created = quickstart.prepare(layout, account=ACCOUNT)
    finally:
        os.umask(before)
    assert created == [layout.policy, layout.configuration]
    for directory in (tmp_path / ".sayfirst", layout.root, layout.evidence):
        assert directory.is_dir() and _mode(directory) == 0o700, directory
    for written in (layout.policy, layout.configuration):
        assert written.is_file() and _mode(written) == 0o600, written


def test_the_starter_policy_shows_all_three_outcomes_without_an_edit() -> None:
    policy = _starter_policy()
    spawn = evaluate(policy, _question("process.spawn"))
    assert (spawn.outcome, spawn.reason) == (Outcome.ALLOW, Reason.POLICY_ALLOWS)
    egress = evaluate(policy, _question("net.egress"))
    assert (egress.outcome, egress.reason) == (Outcome.SUSPEND, Reason.POLICY_REQUIRES_REVIEW)
    unnamed = evaluate(policy, _question("database.open"))
    assert (unnamed.outcome, unnamed.reason) == (Outcome.DENY, Reason.POLICY_ABSENT)


def test_the_starter_policy_is_for_the_account_it_was_written_for_and_no_other() -> None:
    policy = _starter_policy()
    assert {str(ref) for rule in policy.rules for ref in rule.principals} == {f"user:{ACCOUNT}"}


def test_the_starter_policy_says_in_words_how_to_change_it() -> None:
    """It is a file a person opens: the three outcomes and the way back are in it."""
    text = quickstart.starter_policy(ACCOUNT)
    for word in ('"allow"', '"deny"', '"suspend"', "policy_absent", "never overwritten"):
        assert word in text, word


def test_an_account_name_toml_would_misread_is_written_so_it_reads_back() -> None:
    awkward = 'o"dd\\name'
    document = tomllib.loads(quickstart.starter_policy(awkward))
    assert document["rule"][0]["principals"] == [f"user:{awkward}"]


def test_the_starter_configuration_is_per_user_and_names_no_address(tmp_path: Path) -> None:
    layout = quickstart.layout(str(tmp_path))
    document = tomllib.loads(quickstart.starter_configuration(layout))
    assert document == {
        "socket": {"mode": "per_user"},
        "policy": {"path": str(layout.policy)},
        "evidence": {"path": str(layout.evidence)},
    }
    settings = read_settings(document, platform="linux", environ={}, home=str(tmp_path))
    assert settings.mode == "per_user"
    assert settings.socket_path == f"{tmp_path}/.sayfirst/run/daemon.sock"
    assert settings.policy_path == str(layout.policy)
    assert settings.evidence_root == str(layout.evidence)


def test_a_second_preparation_writes_over_nothing(tmp_path: Path) -> None:
    layout = quickstart.layout(str(tmp_path))
    quickstart.prepare(layout, account=ACCOUNT)
    layout.policy.write_text("# mine now\n", encoding="utf-8")
    layout.configuration.write_text("# mine too\n", encoding="utf-8")
    assert quickstart.prepare(layout, account=ACCOUNT) == []
    assert layout.policy.read_text(encoding="utf-8") == "# mine now\n"
    assert layout.configuration.read_text(encoding="utf-8") == "# mine too\n"


def test_only_the_file_that_is_missing_is_written_again(tmp_path: Path) -> None:
    layout = quickstart.layout(str(tmp_path))
    quickstart.prepare(layout, account=ACCOUNT)
    layout.configuration.write_text("# mine\n", encoding="utf-8")
    layout.policy.unlink()
    assert quickstart.prepare(layout, account=ACCOUNT) == [layout.policy]
    assert layout.policy.read_text(encoding="utf-8") == quickstart.starter_policy(ACCOUNT)
    assert layout.configuration.read_text(encoding="utf-8") == "# mine\n"


def test_a_policy_that_is_a_dangling_link_is_somebodys_and_is_left_alone(tmp_path: Path) -> None:
    """`exists()` follows a link and says no; the name is still taken."""
    layout = quickstart.layout(str(tmp_path))
    quickstart.prepare(layout, account=ACCOUNT)
    layout.policy.unlink()
    layout.policy.symlink_to(tmp_path / "elsewhere.toml")
    assert quickstart.prepare(layout, account=ACCOUNT) == []
    assert layout.policy.is_symlink()
    assert not (tmp_path / "elsewhere.toml").exists()


def test_a_quickstart_directory_others_can_reach_is_refused_and_not_repaired(
    tmp_path: Path,
) -> None:
    layout = quickstart.layout(str(tmp_path))
    layout.root.mkdir(parents=True)
    layout.root.chmod(0o755)
    with pytest.raises(quickstart.QuickstartRefused, match="chmod 700"):
        quickstart.prepare(layout, account=ACCOUNT)
    assert _mode(layout.root) == 0o755
    assert not layout.policy.exists()


def test_a_quickstart_directory_that_is_a_link_is_refused(tmp_path: Path) -> None:
    layout = quickstart.layout(str(tmp_path))
    (tmp_path / "elsewhere").mkdir(mode=0o700)
    layout.root.parent.mkdir(mode=0o700)
    layout.root.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(quickstart.QuickstartRefused, match="not a directory of its own"):
        quickstart.prepare(layout, account=ACCOUNT)


def test_the_quickstart_is_an_ordinary_accounts_and_refuses_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run through a privilege tool it would leave root's files in somebody's home,
    and a daemon for several accounts is system mode, which it is not."""
    import io

    monkeypatch.setattr(quickstart.os, "geteuid", lambda: 0)
    out, err = io.StringIO(), io.StringIO()
    code = quickstart.up(
        home=str(tmp_path),
        read_settings_from=lambda path: pytest.fail("nothing is read for root"),
        out=out,
        err=err,
    )
    assert code == 78
    assert "root" in err.getvalue() and "system mode" in err.getvalue()
    assert out.getvalue() == ""
    assert not (tmp_path / ".sayfirst").exists()
