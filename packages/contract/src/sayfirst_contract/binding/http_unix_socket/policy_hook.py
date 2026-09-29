# SPDX-License-Identifier: Apache-2.0
"""Arrange a scenario's policy change through a command the deployment names.

`grant_miss_after_policy_version_change` asks the same question twice and must be
answered the second time under a policy that denies it. A daemon this replayer did not
build has no hook it can be asked to move, and the replayer never writes a policy file
of anyone's: so the deployment names a command, the replayer runs it once between the
two asks, and reads its exit status. The command returns once the daemon reads the new
policy; how it knows that is the deployment's own rule.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

from ...golden import Scenario


class PolicyChangeFailed(RuntimeError):
    """The deployment's policy-change command did not report success."""


def policy_change_command(
    command: str, *, timeout: float = 30.0
) -> Callable[[Scenario, Mapping[str, object]], None]:
    """A `change_policy` callback that runs `command`, split without a shell."""
    argv = shlex.split(command)
    if not argv:
        raise ValueError("--change-policy-command names no command")

    def change(scenario: Scenario, policy: Mapping[str, object]) -> None:
        environment = dict(os.environ)
        environment["SAYFIRST_CONFORMANCE_SCENARIO"] = scenario.name
        environment["SAYFIRST_CONFORMANCE_POLICY"] = json.dumps(
            {str(key): str(value) for key, value in policy.items()}, sort_keys=True
        )
        try:
            finished = subprocess.run(
                argv,
                env=environment,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
        except FileNotFoundError:
            raise PolicyChangeFailed(
                f"the policy-change command {argv[0]!r} was not found"
            ) from None
        except PermissionError:
            raise PolicyChangeFailed(
                f"the policy-change command {argv[0]!r} could not be run"
            ) from None
        except subprocess.TimeoutExpired:
            raise PolicyChangeFailed(
                f"the policy-change command did not finish within {timeout:g} seconds"
            ) from None
        if finished.returncode != 0:
            said = (finished.stderr or finished.stdout).strip().splitlines()
            tail = f": {said[-1]}" if said else ""
            raise PolicyChangeFailed(
                f"the policy-change command exited {finished.returncode}{tail}"
            )

    return change


def require_a_policy_change_command(
    sockets: Mapping[str, Path],
    scenarios: Mapping[str, Scenario],
    command: str | None,
) -> None:
    """Refuse a run that could only fail: a policy-change scenario with nothing to change it."""
    if command is not None:
        return
    needing = sorted(
        name
        for name in sockets
        if name in scenarios and scenarios[name].given.policy_changes_to is not None
    )
    if needing:
        raise ValueError(
            f"{', '.join(needing)} scripts a policy change between two asks: name the "
            "deployment's command with --change-policy-command, or declare the scenario "
            "with --expected-absent"
        )


__all__ = ["PolicyChangeFailed", "policy_change_command", "require_a_policy_change_command"]
