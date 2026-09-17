# SPDX-License-Identifier: Apache-2.0
"""Article 8: every provider in this repository passes its port's own suite."""

from __future__ import annotations

import os
import pwd

import pytest
from sayfirst_control_plane.adapters.nss_directory import NssAccountDirectory
from sayfirst_control_plane.ports.clock import SystemClock
from sayfirst_testing.account_directory_contract import (
    run_the_account_directory_contract,
)
from sayfirst_testing.clock_contract import run_the_clock_contract
from sayfirst_testing.doubles import FixedClock, StaticAccountDirectory

ME = os.geteuid()
MY_GID = os.getegid()
ABSENT_UID = 4_000_000_001
ABSENT_GID = 4_000_000_002


def _host_group_name() -> str:
    import grp

    return grp.getgrgid(MY_GID).gr_name


@pytest.mark.parametrize("clock", [SystemClock(), FixedClock()], ids=["system", "fixed"])
def test_every_clock_provider_passes_the_port_contract(clock) -> None:  # type: ignore[no-untyped-def]
    """Article 8: the real clock and the double answer the same promises."""
    run_the_clock_contract(clock)


def test_the_name_service_directory_passes_the_port_contract() -> None:
    """Article 8: the provider the daemon ships with passes its own suite."""
    run_the_account_directory_contract(
        NssAccountDirectory(),
        known_uid=ME,
        known_name=pwd.getpwuid(ME).pw_name,
        known_primary_gid=MY_GID,
        known_group_name=_host_group_name(),
        absent_uid=ABSENT_UID,
        absent_gid=ABSENT_GID,
    )


def test_the_scripted_directory_passes_the_port_contract() -> None:
    """Article 8: the kit's double is held to the contract it stands in for."""
    run_the_account_directory_contract(
        StaticAccountDirectory(
            accounts={ME: ("alice", MY_GID)},
            memberships={"alice": (MY_GID, 90000)},
            group_names={MY_GID: "Ops ", 90000: "operators"},
        ),
        known_uid=ME,
        known_name="alice",
        known_primary_gid=MY_GID,
        known_group_name="Ops ",
        absent_uid=ABSENT_UID,
        absent_gid=ABSENT_GID,
    )


def test_a_provider_that_invents_an_account_does_not_pass() -> None:
    """Article 2: the suite is what makes "no entry" mean no entry."""

    class _Inventing(StaticAccountDirectory):
        def account(self, uid: int):  # type: ignore[no-untyped-def]
            from sayfirst_control_plane.ports.account_directory import Account

            return super().account(uid) or Account("nobody", 65534)

    with pytest.raises(AssertionError):
        run_the_account_directory_contract(
            _Inventing(accounts={ME: ("alice", MY_GID)}, group_names={MY_GID: "alice"}),
            known_uid=ME,
            known_name="alice",
            known_primary_gid=MY_GID,
            known_group_name="alice",
            absent_uid=ABSENT_UID,
            absent_gid=ABSENT_GID,
        )


def test_a_clock_without_an_offset_does_not_pass() -> None:
    """Article 2: an instant no other host can read is not an instant."""
    from datetime import datetime

    class _Naive:
        VERSION = 1

        def now(self) -> datetime:
            return datetime.now()

    with pytest.raises(AssertionError):
        run_the_clock_contract(_Naive())


def test_the_kit_ships_a_suite_for_every_port_this_block_names() -> None:
    """Article 8: a contract test suite per port, not per convenient port."""
    import importlib
    import re
    from pathlib import Path

    from test_ports import SPECIFIED_PORTS

    kit = Path(importlib.import_module("sayfirst_testing").__file__).parent  # type: ignore[arg-type]
    suites = {source.stem for source in kit.glob("*_contract.py")}
    expected = {
        re.sub(r"(?<!^)(?=[A-Z])", "_", port).lower() + "_contract" for port in SPECIFIED_PORTS
    }
    assert expected <= suites, expected - suites
    for suite in expected:
        module = importlib.import_module(f"sayfirst_testing.{suite}")
        entry = [name for name in vars(module) if name.startswith("run_the_")]
        assert entry, f"{suite} has no entry point a provider can run"
