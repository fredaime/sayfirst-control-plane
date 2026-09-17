# SPDX-License-Identifier: Apache-2.0
"""The operation that reports the principal as the host boundary saw it.

It reads the identity already bound to the connection and looks nothing up
of its own, so it can only ever report what the accept path saw (rule W1).
"""

from __future__ import annotations

from sayfirst_contract.whoami import WhoAmI

from ..domain.connection import ConnectionIdentity


def whoami(identity: ConnectionIdentity, *, generation: int, group_lifetime_seconds: int) -> WhoAmI:
    """What one connection reports about itself."""
    return identity.whoami(generation=generation, group_lifetime_seconds=group_lifetime_seconds)
