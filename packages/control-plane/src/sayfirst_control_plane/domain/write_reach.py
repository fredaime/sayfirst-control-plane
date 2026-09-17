# SPDX-License-Identifier: Apache-2.0
"""Whether write permission on a directory reaches the entry below it.

Four places in this daemon walk a path upwards and ask one question of every
directory on it: *if somebody could write this, could they replace what is
under it?* Article 6 asks it of the directory holding the local address, article
7 of the store when it grades a connection, and article 8 of the configuration
and of the policy authority, per connection and at start. The question is the
same in all four; the answer must be too, and it had three shapes before this
module existed — one that read the operating system's exemption before the
grants, one that read it after some of them, and one that did not read it at
all, so that a sticky ancestor made every principal on the host a writer.

The rule is the operating system's, not this project's. Write permission on a
directory is permission to create, remove and rename entries in it. The sticky
bit (`S_ISVTX`) removes the removing and the renaming: in a sticky directory
only an entry's own owner, the directory's owner and root may unlink or rename
what is in it. So a grant of write on a sticky directory does not reach an
entry the holder does not own — and it does not matter *how* the grant was
made, which is why the exemption is read before the mode's group bit, the
mode's other bit and an access control list rather than as an exception to any
one of them.

Two conditions bound it, and both are read here rather than assumed:

* Owning the directory defeats it. The owner of a sticky directory may unlink
  anything in it.
* Owning the entry defeats it. Its own owner may always remove it.

Creating a *new* name is not covered and does not need to be: every caller is
asking about an entry that already exists on the path it walked.
"""

from __future__ import annotations

import stat
from typing import Final

STICKY: Final[int] = stat.S_ISVTX


def write_reaches_the_entry_below(
    *,
    mode: int,
    is_directory: bool,
    writer_owns_the_directory: bool,
    writer_owns_the_entry: bool,
) -> bool:
    """Whether a grant of write on this component reaches the entry below it.

    `mode` is the component's permission bits as `stat` reported them, and
    `is_directory` is asked for separately because two of the callers hold a
    mode the file type was already stripped from. The two ownership flags say
    what the caller has established about the principal it is asking about —
    or, where a caller asks about every principal outside a set, what that set
    makes true of all of them.
    """
    if not is_directory:
        return True
    if not mode & STICKY:
        return True
    return writer_owns_the_directory or writer_owns_the_entry
