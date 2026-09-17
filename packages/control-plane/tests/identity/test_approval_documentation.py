# SPDX-License-Identifier: Apache-2.0
"""Article 2 and article 12: what an operator must be told about approvals, held as a test.

Three facts about this version's approvals are less than an operator would
assume, and each is the kind of fact a deployment is planned around: who may end
a wait, what a restart does to one, and what the daemon's own record of an act
is worth. `docs/deployment.md` states all three. A document is the only place
they can be stated — no code path refuses a deployment that assumed otherwise —
so a guard on the document is what keeps them from being edited away by someone
tidying prose (the same duty `tests/identity/test_documentation.py` holds for
article 6).

It is a guard on the facts, not on the style: each case asserts the sentence
that carries one, and names the passage it looked in when it is gone.
"""

from __future__ import annotations

import re
from pathlib import Path

from sayfirst_control_plane.application.events import DEFAULT_EVENT_CAPACITY

REPOSITORY = Path(__file__).resolve().parents[4]
DEPLOYMENT = REPOSITORY / "docs" / "deployment.md"

#: The passages this guard reads, by the bold lead-in the document titles them
#: with. They are lead-ins rather than headings, so the section splitter of
#: `test_documentation.py` does not reach them.
RESOLVING = "Who may resolve a suspended effect."
RESTART = "What a restart loses."

_LEAD_IN = re.compile(r"^\*\*[^*]+\*\*", re.MULTILINE)


def _flat(text: str) -> str:
    """One line, so a fact written as a sentence survives Markdown's wrapping."""
    return " ".join(text.split())


def _passage(lead_in: str) -> str:
    """The passage under one bold lead-in, flattened, or "" when the lead-in is gone."""
    text = DEPLOYMENT.read_text(encoding="utf-8")
    start = text.find(f"**{lead_in}**")
    if start < 0:
        return ""
    following = _LEAD_IN.search(text, start + 1)
    end = following.start() if following is not None else len(text)
    return _flat(text[start:end])


def test_the_deployment_documentation_says_every_admitted_principal_may_resolve_any_wait() -> None:
    """Article 12: there is no designation here, so the document must not imply one.

    The daemon checks nothing about who acts beyond admission, and an operator
    who believed otherwise would deploy a system daemon where a per-user one was
    the only safe form. The remedy is compositional and the document carries it.
    """
    passage = _passage(RESOLVING)
    assert passage, f"the document no longer carries the passage «{RESOLVING}»"
    assert "Every principal the socket admits may resolve any wait in any scope" in passage, (
        f"«{RESOLVING}» no longer states who may end a wait"
    )
    assert "checks nothing about them" in passage
    assert "designation" in passage


def test_the_deployment_documentation_says_a_restart_loses_every_pending_wait() -> None:
    """Article 2: the store is in memory, and the consequence is the operator's to plan for."""
    passage = _passage(RESTART)
    assert passage, f"the document no longer carries the passage «{RESTART}»"
    assert "A restart therefore loses every pending wait" in passage, (
        f"«{RESTART}» no longer states what a restart does to a wait"
    )
    assert "`read_approval` on it says `approval_unknown`" in passage
    assert "suspends anew with a new reference" in passage


def test_the_deployment_documentation_says_what_the_event_sink_is_and_is_not() -> None:
    """Articles 2, 3 and 10: a readable sink is a new claim, so it carries its own limits.

    The daemon composes a bounded sink now, which is a fact an operator will
    plan around unless the document says what it is: bounded at a number they
    can size against, dropping the oldest past that bound, gone at a restart,
    not served over the socket, and an observation rather than the evidence the
    chain holds.

    The number is read from the code rather than spelled twice, so a bound
    changed in `application/events.py` and not in the document fails here
    instead of leaving an operator sizing against a figure that moved.
    """
    passage = _passage(RESOLVING)
    assert passage, f"the document no longer carries the passage «{RESOLVING}»"
    for stated in (
        f"bounded at {DEFAULT_EVENT_CAPACITY} entries",
        "oldest",
        "restart",
        "no operation of this generation serves",
        "observation",
    ):
        assert stated in passage, f"«{RESOLVING}» no longer states: {stated}"
