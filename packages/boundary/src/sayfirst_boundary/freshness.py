# SPDX-License-Identifier: Apache-2.0
"""Whether a held grant covers the next act, and if not, which ending applies.

Three of the four endings article 10 names are decided by `grant_use`, which the
contract distribution publishes so that a third-party boundary and this control
plane cannot disagree about what a grant still covers. This module calls it. It
adds the two things that rule cannot see:

* **silence** — "a boundary that ... has not heard from it within the grant's
  lifetime treats its grants as expired". `grant_use` takes no such input, and
  `grant_state` in the control plane, the only code implementing it, has no
  caller outside its own tests. So the clause is honoured here or nowhere.
* **an ending already read off the stream** — a `grant_ended` signal has decided
  the matter, and the holder that read it is not entitled to re-derive a
  different answer from arithmetic.

Precedence is the control plane's own order, taken from `grant_state`, whose
docstring calls it the constitutional one. Two checks come before the delegation
because they make the rest moot: a grant whose channel is gone, or which a
signal has already ended, is not a grant with a lifetime left to consult. Silence
comes **after** the delegation, not before it — see `ending` for why that
distinction is the whole difference between naming the right cause and the wrong
one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.grants import Grant, GrantEndReason, GrantUse, grant_use


class Ending(StrEnum):
    """What a held grant answers, `LIVE` being the only answer that permits acting."""

    LIVE = "live"
    CONNECTION_LOST = "connection_lost"
    EXPIRED = "expired"
    SILENT = "silent"
    POLICY_VERSION_CHANGED = "policy_version_changed"
    CONDITIONS_DIFFER = "conditions_differ"
    ARGUMENTS_CHANGED = "arguments_changed"


#: How a read signal's reason renders as an ending. `DAEMON_STOPPING` ends the
#: grant as surely as the other two; it is reported as a lost connection because
#: that is what the holder is about to have, and the record the daemon keeps has
#: the precise reason either way.
_BY_SIGNAL: dict[GrantEndReason, Ending] = {
    GrantEndReason.POLICY_VERSION_CHANGED: Ending.POLICY_VERSION_CHANGED,
    GrantEndReason.EXPIRED: Ending.EXPIRED,
    GrantEndReason.DAEMON_STOPPING: Ending.CONNECTION_LOST,
}

#: The verdicts that are decided before silence is even considered. Both are
#: facts about the grant itself rather than about the channel's chatter: the
#: channel is gone, or the lifetime is spent. A silent plane cannot make either
#: of them less true, and reporting silence instead would name the wrong cause.
_OUTRANKS_SILENCE: frozenset[GrantUse] = frozenset({GrantUse.CONNECTION_LOST, GrantUse.EXPIRED})

_BY_USE: dict[GrantUse, Ending] = {
    GrantUse.HIT: Ending.LIVE,
    GrantUse.CONNECTION_LOST: Ending.CONNECTION_LOST,
    GrantUse.EXPIRED: Ending.EXPIRED,
    GrantUse.CONDITIONS_DIFFER: Ending.CONDITIONS_DIFFER,
    GrantUse.ARGUMENTS_CHANGED: Ending.ARGUMENTS_CHANGED,
}


@dataclass(frozen=True)
class Held:
    """One grant, with what its connection has told us since it was issued."""

    grant: Grant
    last_heard_at: datetime
    connection_live: bool
    ended_by: GrantEndReason | None = None


def ending(
    held: Held,
    ask: DecisionAsk,
    principal_reference: str,
    *,
    now: datetime,
) -> Ending:
    """Name what this grant answers about this ask.

    The order is the control plane's own, and it is not the order this module
    was first written with. `grant_state` in the control plane's domain — the
    function whose docstring says "render state in the constitutional precedence
    order" — tests **expiry before silence**. The first draft here tested
    silence before delegating at all, which made expiry unreportable: at exactly
    one lifetime, a grant is both expired and unheard-from, and the caller was
    told the plane had gone quiet when in fact the grant had simply run out.

    So the published rule is consulted first, and the two endings it decides
    that outrank silence — a channel that is gone, a lifetime that is spent —
    are returned as it names them. Silence is tested only on a grant that rule
    would otherwise honour, which is the only case where silence is what is
    actually wrong.
    """
    if not held.connection_live:
        return Ending.CONNECTION_LOST
    if held.ended_by is not None:
        return _BY_SIGNAL.get(held.ended_by, Ending.CONNECTION_LOST)
    use = grant_use(
        held.grant,
        ask,
        principal_reference,
        now=now,
        connection_live=True,
    )
    if use in _OUTRANKS_SILENCE:
        return _BY_USE[use]
    if now - held.last_heard_at >= timedelta(seconds=held.grant.lifetime_seconds):
        return Ending.SILENT
    return _BY_USE[use]
