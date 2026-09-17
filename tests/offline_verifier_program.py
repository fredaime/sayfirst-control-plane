# SPDX-License-Identifier: Apache-2.0
"""The program `tests/test_verifier_independence.py` runs in a clean environment.

It holds the contract wheel and nothing else of the project: it proves the
server and the conformance distributions absent, builds a chain under the
published recipes, verifies the export through re-derivation, and forges one
outcome to see the verdict move. It is a script, not a test, and pytest does
not collect it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys

from sayfirst_contract.evidence import (
    MANIFEST_V3,
    Rederivation,
    chained_document,
    manifest_hash,
    verify_chain,
    verify_export,
)

for absent in ("sayfirst_control_plane", "sayfirst_conformance"):
    try:
        __import__(absent)
    except ImportError:
        continue
    raise SystemExit(f"{absent} is installed; this proves nothing")

POLICY = (
    b'format = 1\n[revision]\nreason = "offline"\n'
    b'[[rule]]\nid = "scenario-0"\ncapability = "example.effect"\nscope = "local"\n'
    b'principals = ["user:alice"]\noutcome = "allow"\nreason = "the allow rule"\n'
)
VERSION = "sha256:" + hashlib.sha256(POLICY).hexdigest()
AT = "2026-09-05T10:00:00Z"
DAEMON = {"kind": "service", "id": "daemon", "via": []}
ALICE = {"kind": "user", "id": "alice", "via": []}


def record(kind: str, body: dict, connection: str = "connection-1") -> dict:
    return {
        "scope": "local",
        "kind": kind,
        "recorded_at": AT,
        "connection_id": connection,
        "principal": DAEMON if connection == "daemon" else ALICE,
        "body": body,
    }


records = (
    record("composition", {"providers": []}, "daemon"),
    record(
        "grade",
        {
            "grade": "observability",
            "basis": "caller_can_write",
            "evaluated_at": AT,
            "paths_inspected": 3,
        },
    ),
    record(
        "effect",
        {
            "capability": "example.effect",
            "decision_id": "decision-1",
            "outcome": "allow",
            "decided_at": AT,
            "policy_version": VERSION,
            "reason": "policy_allows",
            "rule_id": "scenario-0",
            "arguments_digest": None,
            "correlation": "gate-1",
            "correlation_source": "boundary_supplied",
            "principal_references": ["user:alice"],
            "evaluation_recipe": "sayfirst/policy-evaluation/v1",
            "decision_position": {"store_id": "store-a", "position": 1},
        },
    ),
    record(
        "recovery",
        {"event": "clean_stop", "epoch_id": "epoch-1", "from_sequence": 1, "through_sequence": 3},
        "daemon",
    ),
)
entries: list[dict] = []
for item in records:
    entries.append(chained_document(item, entries[-1] if entries else None))
verdict = verify_chain(entries, scope="local", from_sequence=1, to_sequence=4)
bundle: dict = {
    "contract_version": "1",
    "scope": "local",
    "from_sequence": 1,
    "to_sequence": 4,
    "entry_count": 4,
    "entries": entries,
    "verification": verdict.to_document(),
    "next_from": None,
    "manifest_version": MANIFEST_V3,
    "policy_versions": {
        VERSION: {"state": "present", "content": base64.b64encode(POLICY).decode()}
    },
    "recovery_context": [],
}
bundle["manifest_hash"] = manifest_hash(bundle, version=MANIFEST_V3)
result = verify_export(json.loads(json.dumps(bundle)))
assert result.overall is Rederivation.confirmed, result.to_document()
assert result.rederived_decision_ids == ("decision-1",)
assert result.confirmed_decision_ids == ("decision-1",)
forged = json.loads(json.dumps(bundle))
forged["entries"][2]["body"]["outcome"] = "deny"
assert verify_export(forged).overall is Rederivation.unverifiable
print("verified offline:", sum(1 for name in sys.modules if name.startswith("sayfirst_control")))
