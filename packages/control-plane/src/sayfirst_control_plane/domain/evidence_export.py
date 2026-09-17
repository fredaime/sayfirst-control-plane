# SPDX-License-Identifier: Apache-2.0
"""Deterministic raw evidence-export manifests: three recipes, one writer, one reader each."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Final

from .evidence_chain import ChainVerdict, canonical_json, verdict_to_document

MANIFEST_V1: Final = "sayfirst-control-plane/evidence-export/v1"
MANIFEST_V2: Final = "sayfirst-control-plane/evidence-export/v2"
MANIFEST_V3: Final = "sayfirst-control-plane/evidence-export/v3"
MANIFEST_VERSIONS: Final = (MANIFEST_V1, MANIFEST_V2, MANIFEST_V3)
MANIFEST_VERSION: Final = MANIFEST_V3
"""v1 bound the requested range, `condition` and `up_to`, and the ordered entry
hashes. v2 bound the whole verdict, because the grade each connection ran at
sat outside the one number a verifier compared (article 7). v3 binds every
top-level member of the bundle except the hash itself: the policy attachments
and their availability states — an `absent` carries no bytes to hash — and the
recovery context move the digest too, or an export could weaken its own claim
while its digest stood (article 10). The older recipes stay readable, each by
its declared version; a writer writes the newest."""


def manifest_hash(
    *,
    scope: str,
    from_sequence: int,
    to_sequence: int | None,
    contract_version: str,
    verdict: ChainVerdict | Mapping[str, object],
    entry_hashes: Sequence[str],
) -> str:
    """The v2 recipe: the requested range, the whole verdict, the exact ordered entry hashes.

    The whole verdict, member by member, and not a reading of two of its
    members: what an independent verifier compares must change when anything
    the export claims changes. A `ChainVerdict` is rendered here the one way it
    is rendered anywhere, so a verifier recomputing this digest from the
    served `verification` object and a caller passing the value in reach the
    same answer.
    """
    rendered = verdict_to_document(verdict) if isinstance(verdict, ChainVerdict) else dict(verdict)
    document = {
        "version": MANIFEST_V2,
        "scope": scope,
        "from_sequence": from_sequence,
        "to_sequence": to_sequence,
        "contract_version": contract_version,
        "verdict": rendered,
        "entry_hashes": list(entry_hashes),
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


def manifest_digest(bundle: Mapping[str, object], *, version: str) -> str:
    """The digest of a served bundle under one of the three recipes, read from the bundle.

    This is the server's own implementation of every recipe, kept apart from
    the contract's and held equal to it by the published vector set (article
    13). `version` is the recipe to compute, never read from the bundle: a
    reader that let the bundle choose would recompute whatever it was told.
    """
    if version == MANIFEST_V3:
        return hashlib.sha256(
            canonical_json({key: value for key, value in bundle.items() if key != "manifest_hash"})
        ).hexdigest()
    entries = bundle.get("entries")
    verification = bundle.get("verification")
    if not isinstance(entries, list) or not isinstance(verification, Mapping):
        raise ValueError("a bundle carries a list of entries and a verification object")
    hashes = [str(entry["entry_hash"]) for entry in entries]
    if version == MANIFEST_V2:
        return manifest_hash(
            scope=str(bundle.get("scope")),
            from_sequence=int(bundle.get("from_sequence")),  # type: ignore[call-overload]
            to_sequence=bundle.get("to_sequence"),  # type: ignore[arg-type]
            contract_version=str(bundle.get("contract_version")),
            verdict=verification,
            entry_hashes=hashes,
        )
    if version == MANIFEST_V1:
        up_to = verification.get("up_to")
        document = {
            "version": MANIFEST_V1,
            "scope": bundle.get("scope"),
            "from_sequence": bundle.get("from_sequence"),
            "to_sequence": bundle.get("to_sequence"),
            "contract_version": bundle.get("contract_version"),
            "condition": str(verification.get("condition")),
            "up_to": up_to if isinstance(up_to, int) and not isinstance(up_to, bool) else None,
            "entry_hashes": hashes,
        }
        return hashlib.sha256(canonical_json(document)).hexdigest()
    raise ValueError(f"unknown manifest recipe {version!r}")
