# SPDX-License-Identifier: Apache-2.0
"""Article 13: the generation is negotiated in band, on the shipped transport.

"Pinned in the contract package, echoed on every response, recorded by the
project's client at connection, refused with a distinct problem when
unsupported." The socket client is the project's client, so the rule is its
rule: a correctly owned peer that answers in a generation this client does not
speak is not an answer, and a profile pinned to one is never even opened.
"""

from __future__ import annotations

import io
import json
import os
from typing import Any

import pytest
from sayfirst_contract.client import Answered, CouldNotAsk
from sayfirst_contract.generation import CONTRACT_GENERATION, SUPPORTED_GENERATIONS
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.status import Status
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.transport.socket_client import (
    SocketClientProblem,
    SocketProfile,
    connect,
)
from sayfirst_testing.doubles import StaticPeerIdentity

_AT = "2026-09-04T00:00:00+00:00"
UNSUPPORTED = max(SUPPORTED_GENERATIONS) + 98


def _credential(uid: int) -> PeerCredential:
    return PeerCredential(uid=uid, gid=0, pid=1, captured_at=_AT)


def _whoami(generation: int) -> dict[str, object]:
    return {
        "contract_generation": generation,
        "connection_id": "connection-1",
        "socket_path": "/run/d.sock",
        "mode": "per_user",
        "peer": {"uid": os.geteuid(), "gid": os.getegid(), "pid": 1, "captured_at": _AT},
        "principal": None,
        "status": "unknown",
        "refresh_due_at": None,
        "group_lifetime_seconds": 60,
        "delegation": None,
    }


def _status(generation: int) -> dict[str, object]:
    return {
        "contract_generation": generation,
        "supported_generations": [generation],
        "integrity_grade": {
            "grade": "unverified",
            "basis": "access_not_established",
            "evaluated_at": "2026-09-04T00:00:00Z",
            "store": "none",
            "reevaluation_interval_seconds": 30,
        },
        "privacy_provider": "none",
        "principal": {"kind": "user", "uid": os.geteuid(), "name": None},
        "store": {"authority": "unknown", "kind": "none"},
    }


class _KeptStream(io.BytesIO):
    """A stream one reader may finish with while the connection lives on."""

    def close(self) -> None:
        pass


class ScriptedSocket:
    """A far end that answers with the documents a test scripted, in order."""

    def __init__(self, *answers: tuple[int, dict[str, object]]) -> None:
        stream = bytearray()
        for status, document in answers:
            body = json.dumps(document, sort_keys=True).encode()
            stream += (
                f"HTTP/1.1 {status} answer\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode()
            stream += body
        # One stream for the whole connection: a keep-alive reader reads the
        # answers in order, as it would from a socket.
        self.stream = _KeptStream(bytes(stream))
        self.written = bytearray()
        self.calls: list[str] = []

    def connect(self, address: str) -> None:
        self.calls.append("connect")

    def getsockopt(self, *_: object) -> bytes:
        return b""

    def sendall(self, data: bytes) -> None:
        self.calls.append("sendall")
        self.written.extend(data)

    send = sendall

    def close(self) -> None:
        self.calls.append("close")

    def settimeout(self, value: object) -> None:
        pass

    def makefile(self, *_: object, **__: object) -> _KeptStream:
        return self.stream


def _connect(far_end: ScriptedSocket, **profile: Any) -> Any:
    return connect(
        SocketProfile("/run/d.sock", **profile),
        peer_identity=StaticPeerIdentity(_credential(os.geteuid())),
        socket_factory=lambda: far_end,  # type: ignore[arg-type,return-value]
    )


def test_the_client_records_the_generation_of_the_connection() -> None:
    """Article 13: recorded by the project's client at connection."""
    far_end = ScriptedSocket((200, _whoami(CONTRACT_GENERATION)))
    connection = _connect(far_end)
    assert connection.negotiated_generation == CONTRACT_GENERATION
    result = connection.read_whoami()
    assert isinstance(result, Answered)
    assert result.contract_generation == CONTRACT_GENERATION


def test_an_answer_in_an_unsupported_generation_is_never_an_answer() -> None:
    """Article 13: refused with a distinct problem when unsupported."""
    far_end = ScriptedSocket((200, _whoami(UNSUPPORTED)))
    connection = _connect(far_end)
    result = connection.read_whoami()
    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED
    assert str(UNSUPPORTED) in result.problem.message


def test_a_profile_pinned_to_an_unsupported_generation_opens_nothing() -> None:
    """Article 13 and article 3: an unsupported pin fails closed, before the socket.

    What this case is for is the two assertions at the end: no address was
    opened and no byte was written, so a pin this package cannot speak reaches
    no far end at all.

    Which makes it a « could not ask », and the registry's class column does
    not say otherwise: the column classifies what a control plane PUBLISHED,
    and a refusal is a control plane's to give — the question reached it and
    it rejected it. Here nothing was dialled, so there is no control plane to
    have refused anything, whatever the code says when a daemon sends it
    (articles 1 and 2). The problem carries that fact itself and
    `classification` reads it; nothing here classes a code by hand.
    """
    far_end = ScriptedSocket((200, _whoami(CONTRACT_GENERATION)))
    with pytest.raises(SocketClientProblem) as refusal:
        _connect(far_end, contract_generation=UNSUPPORTED)
    assert refusal.value.problem.code is ProblemCode.GENERATION_UNSUPPORTED
    assert refusal.value.classification == "could_not_ask"
    assert far_end.calls == []
    assert bytes(far_end.written) == b""


def test_the_transport_answers_the_status_operation_the_protocol_names() -> None:
    """Article 13: the operation the negotiation gate reads exists on this transport."""
    far_end = ScriptedSocket((200, _status(CONTRACT_GENERATION)))
    connection = _connect(far_end)
    result = connection.read_status()
    assert isinstance(result, Answered)
    assert isinstance(result.value, Status)
    assert result.value.supported_generations == (CONTRACT_GENERATION,)


def test_a_far_end_that_changes_generation_mid_connection_is_refused() -> None:
    """Article 13: one connection, one generation, echoed on every response."""
    far_end = ScriptedSocket(
        (200, _whoami(CONTRACT_GENERATION)),
        (200, _whoami(CONTRACT_GENERATION + 1)),
    )
    connection = _connect(far_end)
    assert isinstance(connection.read_whoami(), Answered)
    second = connection.read_whoami()
    assert isinstance(second, CouldNotAsk)
    assert second.problem.code is ProblemCode.GENERATION_UNSUPPORTED


def test_a_problem_document_from_an_unsupported_generation_is_not_read() -> None:
    """Article 13: a stranger's refusal is not this generation's refusal."""
    far_end = ScriptedSocket(
        (
            403,
            {
                "contract_generation": UNSUPPORTED,
                "code": "peer_not_admitted",
                "message": "no",
                "retryable": False,
            },
        )
    )
    connection = _connect(far_end)
    result = connection.read_whoami()
    assert isinstance(result, CouldNotAsk)
    assert result.problem.code is ProblemCode.GENERATION_UNSUPPORTED
