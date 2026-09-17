# SPDX-License-Identifier: Apache-2.0 OR MIT-0
"""The standard-library HTTP-over-Unix-socket face of the contract fake.

All four reads the published binding declares are served here, at the targets
the binding names: a decision read back by reference, the policy status, a page
of evidence and an export. Two of them used to answer `operation_unknown`, so a
third party could not build the pair a published read exists for — ask, then
read back what was answered — against this fake at all, which is precisely the
barrier to third-party implementability that publishing the contract is meant
to remove (article 13).
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from sayfirst_contract.approvals import ApprovalResolution, Resolution
from sayfirst_contract.binding.http_unix_socket.addresses import (
    refuse_a_long_address,
    scenario_address,
)
from sayfirst_contract.binding.http_unix_socket.client import SocketClient
from sayfirst_contract.binding.http_unix_socket.routes import selects_stream
from sayfirst_contract.client import Answered, Result
from sayfirst_contract.decisions import Decision, DecisionAsk
from sayfirst_contract.generation import (
    CONTRACT_GENERATION,
    SUPPORTED_GENERATIONS,
    NegotiatedClient,
)
from sayfirst_contract.golden import Scenario
from sayfirst_contract.problems import Problem, ProblemCode, problem_retryable
from sayfirst_contract.whoami import Delegation, DelegationOutOfBounds

from .stub import Stub

_ASK_MEMBERS = {
    "contract_generation",
    "capability",
    "scope",
    "arguments_digest",
    "correlation",
    # Optional, and part of generation 1: a peer may declare for whom it acts
    # (rule D1). The fake accepts it because the contract defines it.
    "delegation",
}
_RESOLUTION_MEMBERS = {
    "contract_generation",
    "scope",
    "approval_ref",
    "resolution",
    "reason",
}
_CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$")
_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _problem(code: ProblemCode, message: str, *, member: str | None = None) -> Problem:
    return Problem(code, message, problem_retryable(code), CONTRACT_GENERATION, member)


def _generation_problem(document: object) -> Problem | None:
    if not isinstance(document, dict) or "contract_generation" not in document:
        return _problem(ProblemCode.GENERATION_MISSING, "contract_generation is required")
    generation = document["contract_generation"]
    if not isinstance(generation, int) or isinstance(generation, bool):
        return _problem(ProblemCode.GENERATION_UNREADABLE, "contract_generation is not an integer")
    if generation not in SUPPORTED_GENERATIONS:
        return _problem(ProblemCode.GENERATION_UNSUPPORTED, "contract_generation is not supported")
    return None


def _query_document(query: dict[str, list[str]]) -> dict[str, object]:
    document: dict[str, object] = {}
    if "contract_generation" in query:
        raw = query["contract_generation"][0]
        try:
            document["contract_generation"] = int(raw)
        except ValueError:
            document["contract_generation"] = raw
    if "scope" in query:
        document["scope"] = query["scope"][0]
    return document


def _status_for(problem: Problem) -> int:
    code = problem.code
    if code in {
        ProblemCode.GENERATION_MISSING,
        ProblemCode.GENERATION_UNREADABLE,
        ProblemCode.REQUEST_MALFORMED,
        ProblemCode.MEMBER_UNKNOWN,
        ProblemCode.SCOPE_REQUIRED,
        ProblemCode.SCOPE_INVALID,
        ProblemCode.EVIDENCE_RANGE_INVALID,
        ProblemCode.DELEGATION_INVALID,
    }:
        return 400
    if code in {
        ProblemCode.PRINCIPAL_REFUSED,
        ProblemCode.SCOPE_REFUSED,
        ProblemCode.PEER_NOT_ADMITTED,
        ProblemCode.PEER_UID_UNMAPPED,
    }:
        return 403
    if code in {ProblemCode.APPROVAL_UNKNOWN, ProblemCode.DECISION_NOT_FOUND}:
        # Read off the published binding's own responses for these two reads,
        # never decided here: a fake that answered a different status for a
        # code a conformance client pins is a disagreement about one request.
        return 404
    if code in {ProblemCode.GENERATION_UNSUPPORTED, ProblemCode.APPROVAL_RESOLVED}:
        return 409
    if code in {
        ProblemCode.POLICY_UNAVAILABLE,
        ProblemCode.EVIDENCE_STORE_UNAVAILABLE,
        ProblemCode.PEER_CREDENTIAL_UNAVAILABLE,
        ProblemCode.PRINCIPAL_GROUPS_UNAVAILABLE,
    }:
        return 503
    return 500


def _known_path(path: str) -> bool:
    return (
        path in {"/status", "/whoami", "/decisions", "/policy/status"}
        or re.fullmatch(r"/approvals/[^/]+(?:/resolution)?", path) is not None
        or re.fullmatch(r"/decisions/[^/]+", path) is not None
        or re.fullmatch(r"/scopes/[^/]+/evidence(?:/export)?", path) is not None
    )


def _unknown_operation_status(path: str) -> int:
    return 405 if _known_path(path) else 404


def _without_grant(result: Result[Decision]) -> Result[Decision]:
    if not isinstance(result, Answered) or result.value.extra.get("grant") is None:
        return result
    stripped = replace(result.value, extra={**result.value.extra, "grant": None})
    return Answered(stripped, result.contract_generation)


class _Handler(BaseHTTPRequestHandler):
    stub: Stub

    def _send(self, status: int, document: object) -> None:
        body = json.dumps(document, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_problem(self, problem: Problem, status: int | None = None) -> None:
        self._send(status or _status_for(problem), problem.to_document(CONTRACT_GENERATION))

    def _send_result(self, result: Result[Any]) -> None:
        if isinstance(result, Answered):
            value = result.value
            self._send(200, value if isinstance(value, dict) else value.to_document())
        else:
            self._send_problem(result.problem)

    def _send_stream(self, result: Result[Decision], ask: DecisionAsk) -> None:
        """Answer the stream the request selected, whatever the decision turns out to be.

        The published selector reads one header and names the 200 response it
        governs; the presence of a grant is not one of its conditions. A
        refusal publishes a document alone, so it leaves the stream unopened.
        """
        if not isinstance(result, Answered):
            self._send_result(result)
            return
        decision = result.value
        if decision.extra.get("grant") is None:
            self._send_frames([("decision", decision.to_document())])
            return
        self._send_grant_stream(decision, ask)

    def _send_frames(self, documents: list[tuple[str, object]]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for name, document in documents:
            payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            self.wfile.write(b"event: " + name.encode() + b"\ndata: " + payload + b"\n\n")
        self.close_connection = True

    def _send_grant_stream(self, decision: Decision, ask: DecisionAsk) -> None:
        issued_at = datetime.fromisoformat(decision.decided_at)
        lifetime = min(self.stub.scenario.given.grant_lifetime_seconds or 30, 30)
        principal = decision.extra["principal"]
        assert isinstance(principal, dict) and isinstance(principal["name"], str)
        grant = {
            "grant_id": "grant-1",
            "decision_ref": decision.decision_ref,
            "policy_version": decision.policy_version,
            "issued_at": decision.decided_at,
            "lifetime_seconds": lifetime,
            "expires_at": (issued_at + timedelta(seconds=lifetime)).isoformat(),
            "heartbeat_seconds": 5,
            "conditions": {
                "scope": decision.scope,
                "capability": decision.capability,
                "principal_reference": f"user:{principal['name']}",
                # A scenario may arrange a grant pinned to other arguments than
                # the ones the next ask carries (article 3).
                "arguments_digest": (
                    self.stub.scenario.given.grant_arguments_digest or ask.arguments_digest
                ),
            },
        }
        streamed = replace(decision, extra={**decision.extra, "grant": grant})
        documents = [("decision", streamed.to_document())]
        given = self.stub.scenario.raw["given"]
        if isinstance(given, dict) and "policy_changes_to" in given:
            documents.append(
                (
                    "grant_ended",
                    {
                        "contract_generation": CONTRACT_GENERATION,
                        "kind": "grant_ended",
                        "grant_id": grant["grant_id"],
                        "policy_version": "sha256:" + "f" * 64,
                        "at": decision.decided_at,
                        "reason": "policy_version_changed",
                    },
                )
            )
        self._send_frames(documents)

    def _body(self) -> object:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    def do_GET(self) -> None:
        target = urlsplit(self.path)
        if target.path == "/status":
            self._send_result(self.stub.read_status())
            return
        if target.path == "/whoami":
            self._send_result(self.stub.read_whoami())
            return
        evidence_match = re.fullmatch(
            r"/scopes/([^/]+)/evidence(?P<export>/export)?",
            target.path,
        )
        if evidence_match:
            self._read_evidence(target.query, evidence_match)
            return
        if target.path == "/policy/status":
            query = parse_qs(target.query, keep_blank_values=True)
            if problem := _generation_problem(_query_document(query)):
                self._send_problem(problem)
                return
            self._send_result(self.stub.read_policy_status())
            return
        decision_match = re.fullmatch(r"/decisions/([^/]+)", target.path)
        if decision_match:
            query = parse_qs(target.query, keep_blank_values=True)
            document = _query_document(query)
            if problem := _generation_problem(document):
                self._send_problem(problem)
                return
            if "scope" not in document or not document["scope"]:
                # Article 5: the writer's default never applies to a read, so a
                # read that names no scope is refused rather than served from
                # somewhere nobody asked about.
                self._send_problem(_problem(ProblemCode.SCOPE_REQUIRED, "scope is required"))
                return
            self._send_record(
                self.stub.read_decision(str(document["scope"]), unquote(decision_match.group(1)))
            )
            return
        match = re.fullmatch(r"/approvals/([^/]+)", target.path)
        if match:
            query = parse_qs(target.query, keep_blank_values=True)
            document = _query_document(query)
            if problem := _generation_problem(document):
                self._send_problem(problem)
                return
            if "scope" not in document or not document["scope"]:
                self._send_problem(_problem(ProblemCode.SCOPE_REQUIRED, "scope is required"))
                return
            self._send_result(
                self.stub.read_approval(str(document["scope"]), unquote(match.group(1)))
            )
            return
        self._send_problem(
            _problem(ProblemCode.OPERATION_UNKNOWN, "operation is not defined"),
            _unknown_operation_status(target.path),
        )

    def _send_record(self, result: Result[Decision]) -> None:
        """One decision answered as the `decision-record` this read publishes.

        A read back is not the answer that took the decision: the wait it
        opened and the grant it minted belong to that answer and to the
        connection that carried it (article 10). So the reference of a wait and
        the grant document come out, and the grant's identity goes in — which
        is the record the daemon's own route serves, member for member.
        """
        if not isinstance(result, Answered):
            self._send_problem(result.problem)
            return
        document = result.value.to_document()
        document.pop("approval_ref", None)
        grant = document.pop("grant", None)
        document["grant_id"] = grant["grant_id"] if isinstance(grant, dict) else None
        self._send(200, document)

    def _read_evidence(self, raw_query: str, match: re.Match[str]) -> None:
        query = parse_qs(raw_query, keep_blank_values=True)
        exporting = match.group("export") is not None
        allowed = {"contract_generation", "from_sequence"}
        allowed.add("to_sequence" if exporting else "page_size")
        if any(name not in allowed or len(values) != 1 for name, values in query.items()):
            self._send_problem(
                _problem(ProblemCode.EVIDENCE_RANGE_INVALID, "evidence query is invalid")
            )
            return
        document = _query_document(query)
        if problem := _generation_problem(document):
            self._send_problem(problem)
            return
        try:
            start = int(query["from_sequence"][0])
            optional_name = "to_sequence" if exporting else "page_size"
            optional = int(query[optional_name][0]) if optional_name in query else None
        except (KeyError, ValueError):
            self._send_problem(
                _problem(ProblemCode.EVIDENCE_RANGE_INVALID, "evidence range is invalid")
            )
            return
        invalid = start < 1 or (optional is not None and optional < 1)
        invalid = invalid or (not exporting and optional is not None and optional > 100)
        invalid = invalid or (exporting and optional is not None and optional < start)
        if invalid:
            self._send_problem(
                _problem(ProblemCode.EVIDENCE_RANGE_INVALID, "evidence range is invalid")
            )
            return
        scope = unquote(match.group(1))
        if _SCOPE.fullmatch(scope) is None:
            # The code the daemon answers for the same input, at the status the
            # published binding lists it on these two routes: a conformance
            # client pins the code, so a second one here is a disagreement
            # about one request (article 13).
            self._send_problem(_problem(ProblemCode.SCOPE_INVALID, "scope is malformed"))
            return
        if exporting:
            self._send_result(self.stub.export_evidence(scope, start, optional))
        else:
            self._send_result(self.stub.read_evidence(scope, start, optional or 100))

    def do_POST(self) -> None:
        target = urlsplit(self.path)
        resolution_match = re.fullmatch(r"/approvals/([^/]+)/resolution", target.path)
        if target.path != "/decisions" and resolution_match is None:
            self._send_problem(
                _problem(ProblemCode.OPERATION_UNKNOWN, "operation is not defined"),
                _unknown_operation_status(target.path),
            )
            return
        document = self._body()
        if problem := _generation_problem(document):
            self._send_problem(problem)
            return
        assert isinstance(document, dict)
        if target.query:
            member = next(iter(parse_qs(target.query, keep_blank_values=True)), "query")
            self._send_problem(
                _problem(
                    ProblemCode.MEMBER_UNKNOWN,
                    "request member is not defined",
                    member=member,
                )
            )
            return
        if target.path == "/decisions":
            if self._reject_unknown(document, _ASK_MEMBERS):
                return
            ask = self._read_ask(document)
            if isinstance(ask, Problem):
                self._send_problem(ask)
                return
            result = self.stub.ask_decision(ask)
            if selects_stream(self.headers.get("Accept")):
                self._send_stream(result, ask)
            else:
                # The request selected the plain document, so this connection
                # carries no signals and no grant can be delivered on it.
                self._send_result(_without_grant(result))
            return
        if resolution_match:
            if self._reject_unknown(document, _RESOLUTION_MEMBERS):
                return
            resolution = self._read_resolution(document, unquote(resolution_match.group(1)))
            if isinstance(resolution, Problem):
                self._send_problem(resolution)
                return
            self._send_result(self.stub.resolve_approval(resolution))
            return
        raise AssertionError("a recognized operation was not handled")

    def _reject_unknown(self, document: dict[str, object], allowed: set[str]) -> bool:
        unknown = next((member for member in document if member not in allowed), None)
        if unknown is None:
            return False
        self._send_problem(
            _problem(
                ProblemCode.MEMBER_UNKNOWN,
                "request member is not defined",
                member=unknown,
            )
        )
        return True

    def _read_ask(self, document: dict[str, object]) -> DecisionAsk | Problem:
        capability = document.get("capability")
        if (
            not isinstance(capability, str)
            or len(capability) > 128
            or _CAPABILITY.fullmatch(capability) is None
        ):
            return _problem(
                ProblemCode.REQUEST_MALFORMED, "capability is malformed", member="capability"
            )
        scope = document.get("scope", "local")
        if not isinstance(scope, str) or _SCOPE.fullmatch(scope) is None:
            return _problem(ProblemCode.REQUEST_MALFORMED, "scope is malformed", member="scope")
        digest = document.get("arguments_digest")
        if digest is not None and (
            not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            return _problem(
                ProblemCode.REQUEST_MALFORMED,
                "arguments_digest is malformed",
                member="arguments_digest",
            )
        correlation = document.get("correlation")
        if correlation is not None and (not isinstance(correlation, str) or len(correlation) > 128):
            return _problem(
                ProblemCode.REQUEST_MALFORMED,
                "correlation is malformed",
                member="correlation",
            )
        try:
            # Read for its bounds alone (rule D3). Nothing the peer declares
            # changes who it is, so nothing here reaches the decision.
            Delegation.from_request_member(document.get("delegation"))
        except DelegationOutOfBounds as error:
            return _problem(ProblemCode.DELEGATION_INVALID, str(error), member="delegation")
        return DecisionAsk(capability, scope, digest, correlation)

    def _read_resolution(
        self, document: dict[str, object], approval_ref: str
    ) -> ApprovalResolution | Problem:
        required = ("scope", "approval_ref", "resolution")
        if missing := next((member for member in required if member not in document), None):
            return _problem(
                ProblemCode.REQUEST_MALFORMED, "required member is missing", member=missing
            )
        if document["approval_ref"] != approval_ref:
            return _problem(
                ProblemCode.REQUEST_MALFORMED,
                "approval reference differs",
                member="approval_ref",
            )
        try:
            resolution = Resolution(document["resolution"])
        except (ValueError, TypeError):
            return _problem(
                ProblemCode.REQUEST_MALFORMED, "resolution is malformed", member="resolution"
            )
        scope = document["scope"]
        reason = document.get("reason")
        if not isinstance(scope, str) or _SCOPE.fullmatch(scope) is None:
            return _problem(ProblemCode.REQUEST_MALFORMED, "scope is malformed", member="scope")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 1024):
            return _problem(ProblemCode.REQUEST_MALFORMED, "reason is malformed", member="reason")
        return ApprovalResolution(scope, approval_ref, resolution, reason)

    def _answer_unknown_method(self) -> None:
        self._send_problem(
            _problem(ProblemCode.OPERATION_UNKNOWN, "operation is not defined"),
            _unknown_operation_status(urlsplit(self.path).path),
        )

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._answer_unknown_method
        raise AttributeError(name)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _Server(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True


@contextmanager
def serve(stub: Stub, socket_path: Path) -> Iterator[Path]:
    """Serve the fake at one new local socket until the context closes.

    An address that will not fit is refused here rather than at `bind`, where
    the kernel answers `AF_UNIX path too long` and names neither the limit nor
    the path. It is refused while it still fits, too: a fixture arranged at the
    kernel's exact limit works on the host it was measured on and on no host
    with a longer temporary root, which is the barrier to third-party
    implementability article 13 exists to remove.
    """
    refuse_a_long_address(socket_path)
    if socket_path.exists():
        raise FileExistsError(socket_path)
    handler = type("BoundHandler", (_Handler,), {"stub": stub})
    server = _Server(str(socket_path), handler)
    os.chmod(socket_path, 0o700)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield socket_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        socket_path.unlink(missing_ok=True)


class _SocketSession:
    def __init__(self, root: Path, scenario: Scenario) -> None:
        self._now = datetime(2026, 9, 4, tzinfo=UTC)
        stub = Stub(
            scenario.name,
            scenarios={scenario.name: scenario},
            clock=lambda: self._now,
        )
        self._stub = stub
        self._context = serve(stub, scenario_address(root, scenario.name))
        #: The address this session bound. A case that must ask over the socket
        #: rather than through the published client — a refusal the client
        #: cannot produce, because it always sends the member — needs it.
        self.socket_path = self._context.__enter__()
        self.client = NegotiatedClient(SocketClient(self.socket_path, expected_uid=os.geteuid()))

    def pass_deadline(self) -> None:
        self._now += timedelta(seconds=61)

    def change_policy(self, policy: Mapping[str, object]) -> None:
        self._stub.change_policy()

    def close(self) -> None:
        self._context.__exit__(None, None, None)


class SocketStubHarness:
    def __init__(self, root: Path) -> None:
        self.root = root

    def arrange(self, scenario: Scenario) -> _SocketSession:
        return _SocketSession(self.root, scenario)
