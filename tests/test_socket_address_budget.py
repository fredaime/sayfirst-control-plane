# SPDX-License-Identifier: Apache-2.0
"""Article 13: this repository's own run fits inside `sun_path`, with room named.

Article 13 publishes the contract so that a third party can implement it, and
the acceptance suite is the form that publication takes. A suite that binds its
addresses at the kernel's exact limit is implementable on the host it was
measured on and nowhere else: one more character in `TMPDIR`, one more digit in
a run counter, or a platform whose `sun_path` is four bytes shorter, and the
run stops with `OSError: AF_UNIX path too long` from inside a fixture.

So the run root is chosen against a budget, and this is the guard on the
budget. It is a rule of the repository rather than of one package — every
package's tests bind below the same root — so it lives in one file of its own,
and a new rule arrives as a new file (`CONTRIBUTING.md`, article 16).
"""

from __future__ import annotations

import pytest
from sayfirst_contract.binding.http_unix_socket.addresses import (
    ADDRESS_MARGIN_BYTES,
    FIXTURE_LEAF_BYTES,
    SUN_PATH_LIMITS,
    address_budget,
    address_bytes,
    root_leaves_the_margin,
    scenario_address,
    sun_path_limit,
)
from sayfirst_contract.golden import load_scenarios


@pytest.mark.parametrize("platform", sorted(SUN_PATH_LIMITS))
def test_the_run_root_leaves_the_named_margin_on_every_supported_platform(
    platform: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Article 13: the root this run binds below fits every platform, not this host."""
    root = tmp_path_factory.getbasetemp()
    assert root_leaves_the_margin(root, platform=platform), (
        f"{root} costs {address_bytes(root)} bytes; a test below it may reach "
        f"{address_budget(root)}, which leaves "
        f"{sun_path_limit(platform) - address_budget(root)} bytes on {platform} "
        f"and the margin is {ADDRESS_MARGIN_BYTES}"
    )


def test_every_shipped_scenario_is_served_at_an_address_inside_the_leaf_budget(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """Article 13: no shipped fixture's name is what decides whether it can be replayed."""
    names = tuple(load_scenarios())
    addresses = {name: scenario_address(tmp_path, name) for name in names}
    assert len({address.name for address in addresses.values()}) == len(names)
    over_budget = {
        name: address
        for name, address in addresses.items()
        if address_bytes(address) - address_bytes(tmp_path) > FIXTURE_LEAF_BYTES
    }
    assert not over_budget


def test_the_longest_scenario_name_costs_no_more_than_the_shortest() -> None:
    """Article 13: the leaf is the same size whatever the fixture is called."""
    root = "/x"
    sizes = {len(scenario_address(root, name).name) for name in load_scenarios()}
    assert len(sizes) == 1
