# SPDX-License-Identifier: Apache-2.0
"""The arguments digest, pinned so that two boundaries compute the same one.

Article 11 sends a digest rather than the arguments. The control plane pins that
digest as a grant condition and compares it exactly, so the canonicalisation is
part of the agreement and not an implementation detail: sorted keys, no
insignificant whitespace, and `TypeError` rather than a coercion for a value the
wire cannot carry — a silently stringified object would give two callers
different digests for the same call, or the same digest for different ones.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


def arguments_digest(arguments: Mapping[str, object]) -> str:
    """Digest the arguments of one intended effect.

    Raises `TypeError` for a value `json.dumps` cannot represent, which is the
    honest answer: the boundary cannot describe the call, so it must not claim
    to have described it.
    """
    canonical = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
