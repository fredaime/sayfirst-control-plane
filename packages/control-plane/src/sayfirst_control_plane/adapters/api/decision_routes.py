# SPDX-License-Identifier: Apache-2.0
"""Decision and grant-stream bodies on a connection accepted by the daemon."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from http import HTTPStatus
from threading import Lock

from sayfirst_contract.binding.http_unix_socket.routes import selects_stream
from sayfirst_contract.decisions import Decision
from sayfirst_contract.generation import CONTRACT_GENERATION
from sayfirst_contract.grants import (
    GrantEndReason as PublishedGrantEndReason,
)
from sayfirst_contract.grants import (
    GrantSignal as PublishedGrantSignal,
)
from sayfirst_contract.grants import (
    GrantSignalKind as PublishedGrantSignalKind,
)
from sayfirst_contract.policy import PolicyStatus as PublishedPolicyStatus
from sayfirst_contract.policy import ProjectionStatus as PublishedProjectionStatus
from sayfirst_contract.problems import Problem, ProblemCode, problem_retryable

from ...application.decisions import DecisionAnswer, DecisionProblem, DecisionService
from ...application.grants import GrantSignal, SignalKind
from ...domain.foreign import ForeignValueRefused
from ...domain.policy import DecisionQuestion
from ...ports.decision_store import ScopeRequired, core_owned_decision


def _instant(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class _SignalWriter:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self._lock = Lock()
        self._stream_started = False

    def _headers(
        self,
        status: int,
        content_type: str,
        *,
        content_length: int | None = None,
    ) -> bytes:
        """The head of a document answer, which never ends its connection.

        There is no `Connection: close` to write here and no parameter for
        one. The stream is the one answer that ends the connection it was
        delivered on, and `start_stream` writes its own head because it carries
        a header — `Cache-Control` — that no document answer carries. A
        parameter here that every caller passed `False` would be a branch
        nothing reaches.
        """
        phrase = HTTPStatus(status).phrase
        lines = [
            f"HTTP/1.1 {status} {phrase}",
            f"Content-Type: {content_type}",
        ]
        if content_length is not None:
            lines.append(f"Content-Length: {content_length}")
        return ("\r\n".join((*lines, "", ""))).encode("ascii")

    def start_stream(self) -> None:
        """Open the stream, which is the answer that ends its own connection.

        Article 10 binds a grant to the channel that carried it, so this
        connection is the grant and nothing else may be asked on it. The
        published `Connection: close` says so on the wire, and the write side
        is shut down when the stream ends.
        """
        with self._lock:
            if self._stream_started:
                return
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Connection: close\r\n\r\n"
            )
            self._stream_started = True

    def event(self, name: str, document: object) -> None:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        frame = b"event: " + name.encode() + b"\ndata: " + payload + b"\n\n"
        with self._lock:
            if not self._stream_started:
                raise RuntimeError("event stream headers have not been written")
            self.connection.sendall(frame)

    def document(self, document: object, *, status: int = 200) -> None:
        """One whole document, framed by its length, on a connection that stays.

        This used to publish `Connection: close` and shut the write side down,
        so every answer an adapter wrote — the two document reads included —
        ended its connection. A caller that read a decision and then its policy
        status paid a connect and a re-verification for the second, and rule C4
        forbids a client re-opening silently, so the cost was visible in every
        caller. Only a stream needs the close, and it is `start_stream` that
        takes it.
        """
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        with self._lock:
            self.connection.sendall(
                self._headers(
                    status,
                    "application/json",
                    content_length=len(payload),
                )
                + payload
            )

    def close(self) -> None:
        with self._lock:
            self.connection.shutdown(socket.SHUT_WR)

    def signal(self, signal: GrantSignal) -> None:
        document = PublishedGrantSignal(
            PublishedGrantSignalKind(signal.kind.value),
            signal.grant_id,
            signal.policy_version,
            _instant(signal.at),
            PublishedGrantEndReason(signal.reason.value) if signal.reason is not None else None,
            CONTRACT_GENERATION,
        ).to_document()
        self.event(signal.kind.value, document)
        if signal.kind is SignalKind.GRANT_ENDED:
            self.close()


class DecisionRoutes:
    """Serve the block's three binding operations on accepted connections."""

    def __init__(self, decisions: DecisionService) -> None:
        self.decisions = decisions

    def ask_decision(
        self,
        question: DecisionQuestion,
        connection: socket.socket,
        *,
        accept: str | None = None,
    ) -> DecisionAnswer | DecisionProblem:
        """Answer the media type the binding's published selector names for this request.

        The selector is the whole rule: whatever the answer turns out to be,
        an answered response is served as the media type the request selected.
        A grant is a further thing the stream can carry, never a condition on
        the media type, so a deny, a suspend, an absent rule and a full grant
        registry are all served as the stream when the stream was selected —
        one decision frame, then the close (articles 2, 10 and 13). A refusal
        is outside the selector: the binding publishes one media type for it.
        """
        signal_channel = selects_stream(accept)
        writer = _SignalWriter(connection)

        def deliver(answer: DecisionAnswer) -> None:
            writer.start_stream()
            writer.event("decision", answer.decision.to_document())

        answer = self.decisions.ask(
            question,
            grant_connection=signal_channel,
            signal_writer=writer.signal if signal_channel else None,
            deliver=deliver,
        )
        if isinstance(answer, DecisionProblem):
            writer.document(
                answer.problem.to_document(),
                status=self._problem_status(answer.problem),
            )
        elif answer.grant is None:
            if signal_channel:
                writer.start_stream()
                writer.event("decision", answer.decision.to_document())
                writer.close()
            else:
                writer.document(answer.decision.to_document())
        return answer

    def read_decision(
        self,
        scope: str,
        decision_ref: str,
        connection: socket.socket,
    ) -> Decision | Problem:
        writer = _SignalWriter(connection)
        try:
            answer = self.decisions.decisions.get(scope, decision_ref)
        except ScopeRequired:
            problem = self._problem(ProblemCode.SCOPE_REQUIRED, "scope is required")
            writer.document(problem.to_document(), status=400)
            return problem
        if answer is None:
            problem = self._problem(ProblemCode.DECISION_NOT_FOUND, "decision is not known")
            writer.document(problem.to_document(), status=404)
            return problem
        try:
            # The store is the authority for a decision already taken, but the
            # object it answered with is memory the store owns and this renders
            # it after reading it. One read, and the value rendered is the
            # core's own (article 3).
            decision = core_owned_decision(answer)
        except ForeignValueRefused:
            problem = self._problem(
                ProblemCode.INTERNAL, "the decision authority answered no decision"
            )
            writer.document(problem.to_document(), status=500)
            return problem
        document = decision.to_document()
        document.pop("approval_ref", None)
        document.pop("grant", None)
        writer.document(document)
        return decision

    def read_policy_status(self, connection: socket.socket):  # type: ignore[no-untyped-def]
        status = self.decisions.policy.status()
        writer = _SignalWriter(connection)
        writer.document(
            PublishedPolicyStatus(
                status.authority,
                status.policy_version,
                status.format,
                _instant(status.loaded_at),
                status.rule_count,
                PublishedProjectionStatus(
                    status.projection.kind,
                    status.projection.policy_version,
                    status.projection.in_step,
                ),
                CONTRACT_GENERATION,
                {},
            ).to_document()
        )
        return status

    @staticmethod
    def _problem(code: ProblemCode, message: str) -> Problem:
        return Problem(code, message, problem_retryable(code), CONTRACT_GENERATION)

    @staticmethod
    def _problem_status(problem: Problem) -> int:
        if problem.code in (
            ProblemCode.POLICY_UNAVAILABLE,
            ProblemCode.APPROVAL_PROVIDER_UNAVAILABLE,
            ProblemCode.DECISION_CONTENDED,
            ProblemCode.POLICY_ARCHIVE_UNAVAILABLE,
            ProblemCode.DECISION_STORE_UNAVAILABLE,
        ):
            return 503
        if problem.code in (
            ProblemCode.POLICY_WRITABLE_BY_PRINCIPAL,
            ProblemCode.CONFIGURATION_WRITABLE_BY_PRINCIPAL,
        ):
            return 403
        return 400
