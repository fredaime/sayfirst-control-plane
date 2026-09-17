# SPDX-License-Identifier: Apache-2.0
"""Contract client for HTTP connections over Unix sockets."""

from __future__ import annotations

import http.client
import json
import socket
import struct
import sys
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Final
from urllib.parse import quote, urlencode

from ...approvals import Approval, ApprovalResolution
from ...artifacts import load_json
from ...client import Answered, CouldNotAsk, Refused, Result
from ...decisions import Decision, DecisionAsk, read_decision
from ...generation import CONTRACT_GENERATION
from ...grants import Grant, GrantSignal
from ...policy import PolicyStatus
from ...problems import (
    Problem,
    ProblemCode,
    problem_class_of,
    problem_retryable,
    read_problem,
)
from ...replay import ScenarioNotApplicable
from ...status import Status
from ...whoami import WhoAmI
from .routes import DOCUMENT_MEDIA_TYPE, STREAM_MEDIA_TYPE


class _UnexpectedPeer(OSError):
    pass


class UnsupportedPlatform(ScenarioNotApplicable):
    """Peer identity cannot be verified on this operating system."""


def _peer_uid(peer: socket.socket) -> int:
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        size = struct.calcsize("3i")
        _, uid, _ = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        )
        return uid
    getpeereid = getattr(peer, "getpeereid", None)
    if getpeereid is not None:
        uid, _ = getpeereid()
        return int(uid)
    raise UnsupportedPlatform("peer identity is unsupported on this platform")


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, expected_uid: int, timeout: float) -> None:
        super().__init__("sayfirst", timeout=timeout)
        self.socket_path = socket_path
        self.expected_uid = expected_uid

    def connect(self) -> None:
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(self.timeout)
        try:
            peer.connect(str(self.socket_path))
            observed_uid = _peer_uid(peer)
            if observed_uid != self.expected_uid:
                raise _UnexpectedPeer(
                    f"server uid {observed_uid} differs from expected uid {self.expected_uid}"
                )
        except Exception:
            peer.close()
            raise
        self.sock = peer


#: The methods by which this client asks for something to be DONE rather than
#: read. A reply to one of these that never arrived may still have been the
#: reply to an act the far end took and recorded, which is what makes the
#: retryability of a lost write unknown rather than true (articles 1 and 3).
_WRITES: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _client_problem(
    code: ProblemCode,
    message: str,
    *,
    generation: int | None = CONTRACT_GENERATION,
    repeatable: bool = True,
) -> CouldNotAsk:
    """One of this client's own problems, retryable as the registry publishes it.

    `repeatable=False` weakens what is claimed rather than strengthening it:
    this occurrence carries a request that MAY have been received and acted on,
    so nothing here may say that sending it again is safe. `retryable` has a
    third value for exactly that, and an unknown is never read as the more
    permissive of the two (article 3). The class does not move with it: a
    problem this client mints for itself is a could-not-ask because no control
    plane answered, whatever the registry classes its code.
    """
    return CouldNotAsk(
        Problem(code, message, problem_retryable(code) if repeatable else None, generation)
    )


@dataclass(frozen=True)
class _Operation:
    method: str
    path: str

    def target(self, **parameters: str) -> str:
        return self.path.format(**parameters)


def _read_operations(binding: Mapping[str, object]) -> Mapping[str, _Operation]:
    paths = binding.get("paths")
    if not isinstance(paths, Mapping):
        raise ValueError("published binding lacks a paths object")
    operations: dict[str, _Operation] = {}
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, Mapping):
            raise ValueError("published binding contains an invalid path")
        for method, operation in path_item.items():
            if not isinstance(operation, Mapping) or not isinstance(
                operation.get("operationId"), str
            ):
                continue
            operations[operation["operationId"]] = _Operation(str(method).upper(), path)
    return operations


def _first_frame(response: http.client.HTTPResponse) -> bytes:
    """Read the data of the first frame of a stream and read no further.

    A replay observes the answer; it does not hold what the connection would go
    on carrying, so the frame that answers the request ends the read.
    """
    payload = b""
    while True:
        line = response.readline()
        if not line:
            break
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            if payload:
                return payload
            continue
        if stripped.startswith(b"data: "):
            payload = stripped.removeprefix(b"data: ")
    if payload:
        return payload
    raise http.client.HTTPException("the answered stream carried no frame")


def _next_frame(response: http.client.HTTPResponse) -> Mapping[str, object] | None:
    """Read one `data:` frame, or `None` once the stream has ended.

    The counterpart to `_first_frame`, which stops after the frame that answers
    the request because a replay only observes an answer. A holder needs the
    frames that come after it, and needs the end of the stream told apart from a
    quiet moment: `None` here means the peer has finished, which ends the grant
    (article 10), and is never "no news".

    Each frame the daemon writes is an `event:` line then a `data:` line then a
    blank line, terminated with `\\n` rather than `\\r\\n`. The `event:` name
    repeats what the payload's `kind` already says, so it is read past.
    """
    payload = b""
    while True:
        line = response.readline()
        if not line:
            return json.loads(payload) if payload else None
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            if payload:
                return json.loads(payload)
            continue
        if stripped.startswith(b"data: "):
            payload = stripped.removeprefix(b"data: ")


@dataclass
class GrantChannel:
    """The connection a decision was delivered on, kept open on purpose.

    Article 10 binds a grant to the channel that carried it, so holding the
    grant and holding the connection are one act. Giving this up is how a holder
    gives up its grant, and `close` is idempotent because a holder may well
    decide to abandon a grant it has already abandoned.

    `grant` is `None` for an answer that minted none — a deny, a suspend, or an
    allow the control plane chose not to cache. Such an answer still arrives on
    the stream the request selected, one frame and then the close.
    """

    grant: Grant | None
    _response: http.client.HTTPResponse
    _connection: http.client.HTTPConnection
    _closed: bool = field(default=False, init=False)

    def signals(self) -> Iterator[GrantSignal]:
        """Yield what has arrived, stopping at the end of the stream.

        A signal this generation cannot read raises out of here rather than
        being skipped: it may be the one that ends the grant, and treating it as
        noise would be the permissive reading of an unknown input (article 3).

        A peer that reset the connection is a different fact: it is gone, and a
        grant ends when its channel ends (article 10). A reset is therefore the
        end of the stream and not an error the holder must classify — which is
        also what a real daemon looks like when it stops.
        """
        while not self._closed:
            try:
                frame = _next_frame(self._response)
            except (ConnectionResetError, http.client.IncompleteRead):
                return
            if frame is None:
                return
            yield GrantSignal.from_document(frame)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._response.close()
        self._connection.close()


@cache
def _published_operations() -> Mapping[str, _Operation]:
    document = load_json("binding", "http-unix-socket", "openapi.json")
    if not isinstance(document, Mapping):
        raise ValueError("published binding must be an object")
    return _read_operations(document)


class SocketClient:
    """A contract client that verifies the listener before each HTTP request."""

    #: The selection a request makes when it wants the connection-bound answer.
    DECISION_ACCEPT = f"{STREAM_MEDIA_TYPE}, {DOCUMENT_MEDIA_TYPE}"
    #: The selection every other request makes.
    DOCUMENT_ACCEPT = DOCUMENT_MEDIA_TYPE

    def __init__(
        self,
        socket_path: Path,
        *,
        expected_uid: int,
        timeout: float = 5.0,
    ) -> None:
        self.socket_path = socket_path
        self.expected_uid = expected_uid
        self.timeout = timeout
        self._operations = _published_operations()

    def _operation(self, name: str) -> _Operation:
        try:
            return self._operations[name]
        except KeyError as exc:
            raise ValueError(f"published binding lacks operation {name!r}") from exc

    def _request(
        self,
        method: str,
        target: str,
        document: object | None = None,
        *,
        accept: str = DOCUMENT_ACCEPT,
    ) -> tuple[int, Mapping[str, object]] | CouldNotAsk:
        connection = _UnixConnection(self.socket_path, self.expected_uid, self.timeout)
        body = None if document is None else json.dumps(document)
        headers = {"Accept": accept}
        if body is not None:
            headers["Content-Type"] = DOCUMENT_MEDIA_TYPE
        sent = False
        try:
            connection.request(method, target, body=body, headers=headers)
            # From here on the far end MAY have the request, which is the whole
            # of what the retryability below turns on.
            sent = True
            response = connection.getresponse()
            # The binding publishes one selector for the two answers of a
            # decision, so which one arrived is read off the answer's own media
            # type rather than guessed from the request (article 13).
            payload = (
                _first_frame(response)
                if response.headers.get_content_type() == STREAM_MEDIA_TYPE
                else response.read()
            )
        except _UnexpectedPeer as exc:
            return _client_problem(ProblemCode.IMPOSTOR, str(exc))
        except UnsupportedPlatform:
            raise
        except OSError as exc:
            # A reply lost to a write may have been the reply to an act that WAS
            # taken and recorded; a request that never left this side took
            # nothing, and the registry's column stands as it is for that one.
            return _client_problem(
                ProblemCode.UNREACHABLE, str(exc), repeatable=not (sent and method in _WRITES)
            )
        except http.client.HTTPException as exc:
            return _client_problem(ProblemCode.ANSWER_UNREADABLE, str(exc))
        finally:
            connection.close()
        try:
            parsed = json.loads(payload)
            if not isinstance(parsed, dict):
                raise ValueError("response document is not an object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            # A body nested past what the parser accepts arrived and cannot be
            # read; `RecursionError` is a `RuntimeError`, so it needs naming
            # here to reach the answer the rest of this clause already gives.
            return _client_problem(ProblemCode.ANSWER_UNREADABLE, str(exc))
        return response.status, parsed

    def _read(
        self,
        method: str,
        target: str,
        document: object | None,
        reader: Callable[[Mapping[str, object]], object],
        *,
        accept: str = DOCUMENT_ACCEPT,
        accept_server_generation: bool = False,
    ) -> Result[object]:
        response = self._request(method, target, document, accept=accept)
        if isinstance(response, CouldNotAsk):
            return response
        status, payload = response
        return self._interpret(
            status,
            payload,
            reader,
            accept_server_generation=accept_server_generation,
        )

    def _interpret(
        self,
        status: int,
        payload: Mapping[str, object],
        reader: Callable[[Mapping[str, object]], object],
        *,
        accept_server_generation: bool = False,
    ) -> Result[object]:
        """Judge an answer already read off the wire.

        Split out of `_read` so that a caller which must KEEP its connection
        can reach the same judgement without going through a request that closes
        one. Behaviour is unchanged; `_read` is this function plus the request.
        """
        generation = payload.get("contract_generation")
        generation_is_readable = isinstance(generation, int) and not isinstance(generation, bool)
        if not generation_is_readable:
            return _client_problem(
                ProblemCode.GENERATION_UNSUPPORTED,
                f"response echoed contract generation {generation!r}, expected "
                f"{CONTRACT_GENERATION}",
                generation=None,
            )
        if status != 200:
            problem = read_problem(payload)
            # A far end that publishes `generation_unsupported` has ANSWERED
            # the question of the generation, so its answer stands instead of
            # this client's own complaint about the generation it echoed
            # (article 13). Precedence, not a class: which result it is comes
            # from the column below like every other published code.
            if (
                problem.code is not ProblemCode.GENERATION_UNSUPPORTED
                and generation != CONTRACT_GENERATION
            ):
                return _client_problem(
                    ProblemCode.GENERATION_UNSUPPORTED,
                    f"response echoed contract generation {generation!r}, expected "
                    f"{CONTRACT_GENERATION}",
                    generation=generation,
                )
            # The class is the registry's, read once for both clients of this
            # contract (article 1). A code this generation does not define is a
            # could-not-ask, never a denial (articles 2 and 3).
            if problem_class_of(problem) == "could_not_ask":
                return CouldNotAsk(problem)
            return Refused(problem)
        if not accept_server_generation and generation != CONTRACT_GENERATION:
            return _client_problem(
                ProblemCode.GENERATION_UNSUPPORTED,
                f"response echoed contract generation {generation!r}, expected "
                f"{CONTRACT_GENERATION}",
                generation=generation,
            )
        try:
            value = reader(payload)
        except (KeyError, TypeError, ValueError) as exc:
            return _client_problem(ProblemCode.ANSWER_UNREADABLE, str(exc))
        if isinstance(value, Answered | CouldNotAsk | Refused):
            return value
        return Answered(value, generation)

    def read_status(self) -> Result[Status]:
        operation = self._operation("read_status")
        return self._read(  # type: ignore[return-value]
            operation.method,
            operation.target(),
            None,
            Status.from_document,
            accept_server_generation=True,
        )

    def read_whoami(self) -> Result[WhoAmI]:
        operation = self._operation("read_whoami")
        return self._read(  # type: ignore[return-value]
            operation.method, operation.target(), None, WhoAmI.from_document
        )

    def ask_decision(self, ask: DecisionAsk) -> Result[Decision]:
        operation = self._operation("ask_decision")
        return self._read(
            operation.method,
            operation.target(),
            ask.to_document(CONTRACT_GENERATION),
            read_decision,
            accept=self.DECISION_ACCEPT,
        )  # type: ignore[return-value]

    def hold_decision(self, ask: DecisionAsk) -> tuple[Result[Decision], GrantChannel | None]:
        """Ask, and KEEP the connection the answer arrives on.

        `ask_decision` already selects the stream and already receives the grant
        — it lands in `Decision.extra["grant"]` — and then `_request` closes the
        connection in its `finally`. Article 10 ends a grant when its channel
        ends, so every grant this client has ever been served was killed by the
        client in the same call that obtained it. That is correct for a
        conformance replay, which observes an answer, and useless for a holder.

        Hence a separate method rather than a flag: the two have opposite
        obligations about the same connection, and a parameter that silently
        decided which would be the kind of thing a reader gets wrong once.

        The caller owns what comes back and must `close()` the channel. On any
        answer that cannot be read the connection is given up here, because
        there is nothing to hold.
        """
        operation = self._operation("ask_decision")
        connection = _UnixConnection(self.socket_path, self.expected_uid, self.timeout)
        sent = False
        try:
            connection.request(
                operation.method,
                operation.target(),
                body=json.dumps(ask.to_document(CONTRACT_GENERATION)),
                headers={
                    "Accept": self.DECISION_ACCEPT,
                    "Content-Type": DOCUMENT_MEDIA_TYPE,
                },
            )
            # From here on the far end MAY have the ask, and this operation is
            # always a write: a decision it answers is a decision it recorded.
            sent = True
            response = connection.getresponse()
            streamed = response.headers.get_content_type() == STREAM_MEDIA_TYPE
            frame = _next_frame(response) if streamed else json.loads(response.read())
        except _UnexpectedPeer as exc:
            connection.close()
            return _client_problem(ProblemCode.IMPOSTOR, str(exc)), None
        except UnsupportedPlatform:
            connection.close()
            raise
        except OSError as exc:
            connection.close()
            return (
                _client_problem(
                    ProblemCode.UNREACHABLE,
                    str(exc),
                    repeatable=not (sent and operation.method in _WRITES),
                ),
                None,
            )
        except (
            http.client.HTTPException,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            connection.close()
            return _client_problem(ProblemCode.ANSWER_UNREADABLE, str(exc)), None
        if not isinstance(frame, dict):
            connection.close()
            return (
                _client_problem(ProblemCode.ANSWER_UNREADABLE, "the stream carried no answer"),
                None,
            )
        result = self._interpret(response.status, frame, read_decision)
        if not result.is_ok or not streamed:
            connection.close()
            return result, None  # type: ignore[return-value]
        held = frame.get("grant")
        grant = Grant.from_document(held) if isinstance(held, Mapping) else None
        return result, GrantChannel(grant, response, connection)  # type: ignore[return-value]

    def read_approval(self, scope: str, approval_ref: str) -> Result[Approval]:
        operation = self._operation("read_approval")
        query = urlencode({"contract_generation": CONTRACT_GENERATION, "scope": scope})
        target = operation.target(approval_ref=quote(approval_ref, safe=""))
        return self._read(  # type: ignore[return-value]
            operation.method, f"{target}?{query}", None, Approval.from_document
        )

    def read_decision(self, scope: str, decision_ref: str) -> Result[Decision]:
        """Read a recorded decision in the requested scope."""
        operation = self._operation("read_decision")
        query = urlencode({"contract_generation": CONTRACT_GENERATION, "scope": scope})
        target = operation.target(decision_ref=quote(decision_ref, safe=""))
        return self._read(  # type: ignore[return-value]
            operation.method, f"{target}?{query}", None, read_decision
        )

    def read_policy_status(self) -> Result[PolicyStatus]:
        """Read the daemon's current policy status."""
        operation = self._operation("read_policy_status")
        query = urlencode({"contract_generation": CONTRACT_GENERATION})
        return self._read(  # type: ignore[return-value]
            operation.method, f"{operation.target()}?{query}", None, PolicyStatus.from_document
        )

    def read_evidence(
        self, scope: str, from_sequence: int, page_size: int = 100
    ) -> Result[Mapping[str, object]]:
        """Read a page of evidence without interpreting its members."""
        operation = self._operation("read_evidence")
        query = urlencode(
            [
                ("contract_generation", CONTRACT_GENERATION),
                ("from_sequence", from_sequence),
                ("page_size", page_size),
            ]
        )
        target = operation.target(scope=quote(scope, safe=""))
        return self._evidence_read(operation.method, f"{target}?{query}")

    def export_evidence(
        self, scope: str, from_sequence: int, to_sequence: int | None = None
    ) -> Result[Mapping[str, object]]:
        """Read one bounded export bundle; continue from its `next_from` if needed."""
        operation = self._operation("export_evidence")
        members = [
            ("contract_generation", CONTRACT_GENERATION),
            ("from_sequence", from_sequence),
        ]
        if to_sequence is not None:
            members.append(("to_sequence", to_sequence))
        query = urlencode(members)
        target = operation.target(scope=quote(scope, safe=""))
        return self._evidence_read(operation.method, f"{target}?{query}")

    def _evidence_read(self, method: str, target: str) -> Result[Mapping[str, object]]:
        response = self._request(method, target, None, accept=self.DOCUMENT_ACCEPT)
        if isinstance(response, CouldNotAsk):
            return response
        status, payload = response
        if status != 200:
            return self._interpret(status, payload, lambda d: d)  # type: ignore[return-value]
        version = payload.get("contract_version")
        if version != str(CONTRACT_GENERATION):
            return _client_problem(
                ProblemCode.GENERATION_UNSUPPORTED,
                f"response carries contract version {version!r}, expected "
                f"{str(CONTRACT_GENERATION)!r}",
            )
        return Answered(payload, CONTRACT_GENERATION)

    def resolve_approval(self, resolution: ApprovalResolution) -> Result[Approval]:
        operation = self._operation("resolve_approval")
        target = operation.target(approval_ref=quote(resolution.approval_ref, safe=""))
        return self._read(
            operation.method,
            target,
            resolution.to_document(CONTRACT_GENERATION),
            Approval.from_document,
        )  # type: ignore[return-value]


__all__ = ["SocketClient", "UnsupportedPlatform"]
