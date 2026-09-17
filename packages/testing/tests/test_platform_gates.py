# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from sayfirst_testing.platforms import identity_summary, skip_reason


def test_a_skip_names_the_host_that_runs_the_guard() -> None:
    """Article 2: a guard this host cannot run says so in one sentence."""
    assert skip_reason("darwin") == "not runnable on this host (requires darwin)"
    assert skip_reason("linux") == "not runnable on this host (requires linux)"


def test_a_skip_is_reported_and_never_counted_as_a_pass() -> None:
    """Article 2: not runnable is a third value beside held and broken."""
    summary = identity_summary(passed=7, skipped=3, failed=0)
    assert "7 held" in summary
    assert "3 not runnable on this host" in summary
    assert "0 broken" in summary
    assert "10 held" not in summary


def test_a_guard_that_runs_on_either_operating_system_says_so() -> None:
    """Article 6: the guards of the host boundary bind Linux and macOS alike."""
    from sayfirst_testing.platforms import OS_REAL_PLATFORMS, skip_reason_for

    assert OS_REAL_PLATFORMS == ("linux", "darwin")
    assert skip_reason_for(("linux", "darwin")) == (
        "not runnable on this host (requires linux or darwin)"
    )
    assert skip_reason_for(("darwin",)) == "not runnable on this host (requires darwin)"
