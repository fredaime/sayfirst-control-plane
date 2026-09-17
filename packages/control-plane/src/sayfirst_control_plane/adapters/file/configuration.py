# SPDX-License-Identifier: Apache-2.0
"""The configuration file, judged by the walk the policy authority is judged by.

Article 8 protects the configuration in system mode "by effective access (mode
bits, access control lists, parent directories) and never by who owns the
file", which is the question `access/effective_access.py` already answers for
the policy authority. So this adapter holds no reading of its own: it hands the
configured name to that walk and answers with its verdicts. A second reading
here would be a second answer to one question, and the two would disagree the
first time a case only one of them covered arrived (article 2).

What it does *not* do is read the file. The reader of a deployment's own words
is `cli.load_settings`, and the path this is built from is the one that reader
was given — so nothing here can be a check of a file the daemon did not read,
which is the claim article 2 forbids rather than the protection article 8 asks
for.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...access.effective_access import protection, write_access
from ...ports.policy_store import (
    AccessVerdict,
    ProtectionExpectation,
    ProtectionVerdict,
)


@dataclass(frozen=True)
class FileConfiguration:
    """The file a deployment's own words were read from, and who can rewrite them."""

    path: Path

    def protection_at_start(self, expectation: ProtectionExpectation) -> ProtectionVerdict:
        """Whether every possible effective writer of this name is an administrator.

        Asked once, by the account the daemon runs as and before it listens.
        There is no descriptor bound across a pair of calls here, as there is
        on the authority: the configuration has already been read by the time
        this is asked — the start path holds the values, not the file — so
        there is no load after this verdict for a retargeted name to divert.
        """
        return protection(
            self.path,
            allowed_owner_uids=expectation.allowed_owner_uids,
            allowed_write_gids=expectation.allowed_write_gids,
        )

    def write_access_of(self, uid: int, gids: tuple[int, ...]) -> AccessVerdict:
        """What this principal could do to the configuration, through any name.

        **No descriptor is held across this walk, and the request path needs
        none.** Its sibling on the policy authority holds one and answers
        `changed_while_checked` when the name stops reaching the file it opened
        (`adapters/file/policy_store.py`), and it holds it for a stated reason:
        the authority's verdict is followed by a *load* of that file, so an
        answer about a file nobody is going to open is an answer about nothing.
        Here nobody is going to open anything. The configuration was read once,
        at start, and the words the daemon is running on are held in `Settings`;
        no step after this verdict reads the file, so there is no later read for
        a retargeted name to divert.

        A descriptor opened now would in fact bind the verdict to the wrong
        thing. What the file the daemon actually read *is*, this adapter cannot
        establish: the start kept no descriptor of it, so the only handle on it
        is the name. Opening the name again per request proves something about
        whatever the name reaches now, which is not the file the running
        configuration came from — so the claim would be wider than the evidence
        (article 2). The name is therefore the subject of this question, and
        `write_access` answers about the whole of it.

        What the absence does not excuse, and the caller is fail-closed on: the
        walk is not atomic. A name in motion during it is answered from
        whichever components the walk saw. The authority's per-decision check
        opens the name afresh and answers a name that moved during the walk as
        unknown; that buys an answer about the walk's own stability, not a
        binding to the file the start read, and it is the one answer this
        method does not make. The decision path treats every verdict that is
        not `not_writable`, `unknown` included, as a refusal.

        The identity crosses as the two numbers the question is about rather
        than as a `Principal`: the core keeps the principal it records the
        decision from, and a structure handed out here is a structure something
        could rewrite in place (article 3, input side). Two integers can carry
        nothing back.
        """
        return write_access(self.path, uid, tuple(gids))
