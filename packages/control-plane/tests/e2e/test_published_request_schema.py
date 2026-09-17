# SPDX-License-Identifier: Apache-2.0
"""Article 13: the daemon accepts what its published request schema accepts.

"The open project's product boundary *is* the contract", so a request the
published `decision-ask-request` schema refuses is a request the daemon refuses;
and a request it accepts cannot produce a served document or a chain entry that
the published reader for that document refuses. A server that takes more than
its schema publishes is not implementable from the contract, and a document a
conforming verifier cannot read is not an export (article 10).

The schemas are the arbiter here, not a second spelling of them: each case
builds one body, asks the published schema what it thinks of it, and requires
the daemon to answer the same way.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from sayfirst_testing.schemas import document_is_valid

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def _ask(**members: object) -> dict[str, object]:
    return {"contract_generation": 1, "capability": "example.effect", **members}


#: Bodies the published request schema refuses, and what the daemon used to do
#: with each: coerce it, drop it, or write a chain for a scope nobody named.
REFUSED_BY_THE_SCHEMA: tuple[dict[str, object], ...] = (
    _ask(scope=42),
    _ask(scope=True),
    _ask(scope=None),
    _ask(scope=["local"]),
    _ask(scope="local", arguments_digest=12345),
    _ask(scope="local", arguments_digest={"x": 1}),
    _ask(scope="local", correlation=7),
    _ask(scope="local", capability="a" * 400),
    _ask(scope="local", correlation="c" * 400),
)


def _chain_files(session: Any) -> set[str]:
    root = Path(session.daemon.settings.socket_path).parent / "evidence"
    return {item.name for item in root.glob("*.jsonl")} if root.is_dir() else set()


@pytest.mark.parametrize("body", REFUSED_BY_THE_SCHEMA, ids=lambda item: json.dumps(item)[:60])
def test_a_request_the_published_schema_refuses_is_refused(composed, body) -> None:  # type: ignore[no-untyped-def]
    """Article 13: what the schema refuses, the daemon refuses, and by name."""
    assert not document_is_valid(body, "decision-ask-request"), body
    session = composed()
    before = _chain_files(session)

    status, problem = session.request("POST", "/decisions", body)

    assert (status, problem.get("code")) == (400, "request_malformed"), (body, problem)
    assert _chain_files(session) == before, body


def test_no_decision_the_daemon_serves_fails_its_own_published_schema(composed) -> None:  # type: ignore[no-untyped-def]
    """Articles 10 and 13: an answer and an entry a conforming reader can read.

    The bounds `_validate` did not carry — `capability`'s `maxLength` and
    `correlation`'s, both published — reached the answer and the chain, so an
    ordinary request produced an entry the published `evidence-entry` reader
    refuses.
    """
    session = composed()
    for body in (
        _ask(scope="local", capability="a" * 400),
        _ask(scope="local", correlation="c" * 400),
    ):
        status, document = session.request("POST", "/decisions", body)
        assert status == 400, (body, document)
        assert document_is_valid(document, "problem-document"), document

    status, document = session.request("POST", "/decisions", _ask(scope="local"))
    assert status == 200, document
    assert document_is_valid(document, "decision-result"), document

    deadline = time.monotonic() + 5.0
    path = Path(session.daemon.settings.socket_path).parent / "evidence" / "local.jsonl"
    entries: list[dict] = []
    while time.monotonic() < deadline and not entries:
        session.flush()
        time.sleep(0.01)
        if path.exists():
            entries = [json.loads(line) for line in path.read_text().splitlines() if line]
    assert entries
    unreadable = [entry for entry in entries if not document_is_valid(entry, "evidence-entry")]
    assert unreadable == []
