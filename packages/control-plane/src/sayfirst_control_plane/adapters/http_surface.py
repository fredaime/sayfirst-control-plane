# SPDX-License-Identifier: Apache-2.0
"""The whole served surface, spoken over the one local stream and nowhere else.

A refused connection is not dropped: its first request is answered with the
problem document that names the refusal, and the connection is then closed,
so a caller can always tell "the daemon said no" from "no answer exists"
(article 1, article 2).
"""

from __future__ import annotations

import json
import logging
import re
import select
import socket
import time
from contextlib import suppress
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Any, Final
from urllib.parse import parse_qsl, unquote, urlsplit

from sayfirst_contract.artifacts import domain_schema
from sayfirst_contract.binding.http_unix_socket.routes import (
    ACCEPT_HEADER,
    ROUTES,
    selects_stream,
)
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.generation import CONTRACT_GENERATION, SUPPORTED_GENERATIONS
from sayfirst_contract.problems import Problem, ProblemCode, problem_retryable
from sayfirst_contract.whoami import DelegationOutOfBounds

from ..application.evidence_emitter import EffectDecision, EvidenceConnection
from ..application.evidence_reads import (
    EvidenceRangeInvalid,
    EvidenceStoreUnavailable,
    ScopeInvalid,
)
from ..application.evidence_reads import ScopeRequired as EvidenceScopeRequired
from ..application.status import evidence_status
from ..application.status import status as read_status
from ..application.whoami import whoami
from ..domain.connection import ESTABLISHED, REFUSED, UNKNOWN, ConnectionIdentity
from ..domain.evidence import LOCAL_SCOPE
from ..domain.evidence_chain import Principal as ChainPrincipal
from ..domain.integrity_grade import CallerAccess
from ..domain.policy import DecisionQuestion
from ..domain.policy import Principal as PolicyPrincipal
from ..domain.published_schema import is_published_integer, refused_by
from .api.approval_routes import READ_REFUSALS, RESOLVE_REFUSALS

_EVIDENCE_REFUSALS: Final[tuple[type[Exception], ...]] = (
    EvidenceScopeRequired,
    ScopeInvalid,
    EvidenceRangeInvalid,
    EvidenceStoreUnavailable,
)
"""The four refusals the two evidence reads publish, each carrying its own code."""

LOG: Final[logging.Logger] = logging.getLogger("sayfirst_control_plane.daemon")
"""Where a defect of this daemon is recorded. Rule P1: "answered `internal` and
logged". Requests themselves are not logged — an access log of a governance
socket is a second, weaker copy of the evidence chain (article 11)."""

SERVED_OPERATIONS: Final[tuple[str, ...]] = (
    "read_status",
    "read_whoami",
    "ask_decision",
    "read_decision",
    "read_policy_status",
    "read_approval",
    "resolve_approval",
    "read_evidence",
    "export_evidence",
)
"""The published operations this daemon implements, by their binding names."""

COMPOSED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "read_decision",
        "read_policy_status",
        "read_approval",
        "resolve_approval",
        "read_evidence",
        "export_evidence",
    }
)
"""Served operations that answer out of what `bootstrap.compose` composed.

`ask_decision` is served either way — with a policy authority it decides, and
without one it answers the problem the binding publishes for an authority it
could not read. These six have no such answer to give: `read_decision`
publishes no code for "there is no decision authority here", and answering
`decision_not_found` would claim a store was consulted (article 2). The two
approval operations are the same: a deployment that composed no store holds no
wait either operation could be about, and `approval_unknown` would claim one
was looked for. A deployment that composed none therefore does not serve them
at all, and says `operation_unknown` — the one code this server spells for an
operation it does not answer."""

DEFERRED_OPERATIONS: Final[tuple[str, ...]] = ()
"""Every published operation is now answered by this server, so nothing is here.

The tuple stays, empty, because it is half of a partition the surface guard
checks: what is served and what is deferred together make up what the binding
publishes, and an operation dropped from both would be a gap nothing reports
(article 2).

What stood here was the approval pair and the four rules its serving needed.
All four are taken. A suspended approval is kept in memory by the daemon, which
is where its wait lives and dies with the process; a rule member bounds that
wait, so how long a person has is the administrator's to write and never this
server's to invent; the person of a resolution is the resolving connection's
verified principal, so the published request carries no member that could name
another; and the sweep that ends the grants expires the waits that ran out and
forgets what nothing can still need. Each was a rule rather than a wiring,
which is why the pair waited for them."""

_PATH_BY_OPERATION: Final[dict[str, str]] = {route.operation: route.path for route in ROUTES}
_METHOD_BY_OPERATION: Final[dict[str, str]] = {route.operation: route.method for route in ROUTES}

SERVED: Final[dict[tuple[str, str], str]] = {
    (_METHOD_BY_OPERATION[operation], _PATH_BY_OPERATION[operation]): operation
    for operation in SERVED_OPERATIONS
}
"""The one route table of this server, derived from the binding it serves.

A second spelling of a route is how a path drifts away from the document that
publishes it, so there is no second spelling: the paths below are read out of
the binding's own table (article 13).
"""

_TEMPLATE: Final[re.Pattern[str]] = re.compile(r"\{([a-z_]+)\}")


def _matcher(path: str) -> re.Pattern[str]:
    """One published path template, read as the pattern it already is.

    The binding writes a variable segment as `{name}`; nothing in this server
    spells the same path a second time, so the pattern is derived from the
    published template rather than typed beside it (article 13).
    """
    pieces: list[str] = []
    index = 0
    for found in _TEMPLATE.finditer(path):
        pieces.append(re.escape(path[index : found.start()]))
        pieces.append(f"(?P<{found.group(1)}>[^/]+)")
        index = found.end()
    pieces.append(re.escape(path[index:]))
    return re.compile("".join(pieces))


_MATCHERS: Final[tuple[tuple[str, re.Pattern[str], str], ...]] = tuple(
    (method, _matcher(path), operation) for (method, path), operation in SERVED.items()
)


def match_target(method: str, target: str) -> tuple[str, dict[str, str]] | None:
    """The operation a request line names, with the path variables it carried."""
    for spoken, pattern, operation in _MATCHERS:
        if spoken != method:
            continue
        found = pattern.fullmatch(target)
        if found is not None:
            return operation, {name: unquote(value) for name, value in found.groupdict().items()}
    return None


STATUS_TARGET: Final[str] = _PATH_BY_OPERATION["read_status"]
WHOAMI_TARGET: Final[str] = _PATH_BY_OPERATION["read_whoami"]
DECISIONS_TARGET: Final[str] = _PATH_BY_OPERATION["ask_decision"]
SPOKEN_VERSIONS: Final[tuple[str, ...]] = ("HTTP/1.0", "HTTP/1.1")
"""The versions this binding is written in; a request in another is not read."""

_NO_STATUS_LINE: Final[str] = "HTTP/0.9"
"""The one version an answer carries no status and no headers under."""

_MAX_REFUSAL_DETAIL: Final[int] = 120
"""How much of the base handler's message about a request travels back to it."""

_ASK_SCHEMA: Final[str] = "decision-ask-request"
"""The published schema an ask is judged by, read rather than restated."""

_ASK_MEMBERS: Final[frozenset[str]] = frozenset(domain_schema(_ASK_SCHEMA)["properties"])  # type: ignore[arg-type]
"""Every member generation one defines on a decision request, from the schema.

Article 13: a client never sends a request member its generation does not
define, so a member this generation does not carry is refused by the code the
route publishes for exactly that, rather than dropped in silence — and the list
of them is the published schema's own, so a member added to the contract cannot
be one this route quietly refuses."""

_RESOLVE_SCHEMA: Final[str] = "approval-resolve-request"
"""The published schema one person's act is judged by, read rather than restated."""

_RESOLVE_MEMBERS: Final[frozenset[str]] = frozenset(domain_schema(_RESOLVE_SCHEMA)["properties"])  # type: ignore[arg-type]
"""Every member generation one defines on a resolution, from the schema.

Read the same way the ask's members are, and refused the same way. One absence
in that list carries a rule of its own: the published request names no person,
because the person of a resolution is the connection's verified principal, so a
body that names one is refused as any member outside this generation is —
`member_unknown`, by name — rather than read and believed (articles 6 and 13).
"""

_KEEP_ALIVE_SECONDS: Final[float] = 30.0
_MAX_FRAMING_LINE: Final[int] = 65536
_FRAMING_BLOCK: Final[int] = 65536
_HEX_DIGITS: Final[bytes] = b"0123456789abcdefABCDEF"


def _statuses_the_binding_publishes() -> dict[str, int]:
    """The status each problem code carries, read out of the binding's own table.

    A second spelling is how the surface drifts from the document that
    publishes it, so there is no second spelling: this is the derivation
    `SERVED` already does for the paths, for the other thing the binding says
    about a problem (article 13). A code two routes published at two statuses
    would make the derivation a choice rather than a reading, so it is refused
    here rather than resolved silently.
    """
    published: dict[str, int] = {}
    for route in ROUTES:
        for status, codes in route.problems.items():
            for code in codes:
                if published.setdefault(code, status) != status:
                    raise ValueError(f"{code} is published at {published[code]} and at {status}")
    return published


_STATUS_OFF_THE_ROUTES: Final[dict[str, int]] = {
    # A request that names no route is answered by no route, so no route
    # publishes the code for it. It is the one status this server spells
    # itself, and it is named apart so that stays visible.
    "operation_unknown": 404,
}
_STATUS_BY_CODE: Final[dict[str, int]] = {
    **_statuses_the_binding_publishes(),
    **_STATUS_OFF_THE_ROUTES,
}
_REFUSAL_MESSAGES: Final[dict[str, str]] = {
    # One fact each (article 2), and a could-not-ask is never written as a
    # denial (article 1).
    "peer_not_admitted": "the peer's credential is not on this daemon's admission list",
    "peer_uid_unmapped": (
        "the kernel reported the overflow id: a user id from another user namespace "
        "with no mapping here"
    ),
    "peer_credential_unavailable": (
        "the operating system delivered no credential for this connection"
    ),
    "principal_groups_unavailable": "the account directory could not be consulted in time",
}


GRANT_WATCH_SECONDS: Final[float] = 0.2
"""How often a connection held open for a grant is checked while it holds one.

It is not a latency budget: the peer going away wakes the watch at once, and
this is only how long a grant that ended for another reason — a policy version
change, the daemon stopping — waits before its connection is let go. Article 10
puts no latency figure in the constitution; this one is small enough that a
boundary sees the close within a fifth of a second and large enough that a
thousand held connections cost five thousand wake-ups a second between them."""


def connection_timeout(status: object, settings: object) -> float:
    """How long a connection may stay silent before the daemon closes it.

    A refused connection is closed after its problem document, or after
    `resolution_timeout_seconds` if no request ever arrives (rule A5). That
    bound applies to every refusal, whichever check produced it.
    """
    if status == REFUSED:
        return float(settings.resolution_timeout_seconds)  # type: ignore[attr-defined]
    return _KEEP_ALIVE_SECONDS


def _one(query: list[tuple[str, str]], name: str) -> str | None:
    """The single value a query member carried, or `None` when it carried none.

    A member written twice is not a member with two values here: the last one
    wins nowhere, because a reader that picks one of two is a reader two ends
    can disagree about (article 13).
    """
    values = [value for member, value in query if member == name]
    return values[0] if len(values) == 1 else None


def _generation_refusal(query: list[tuple[str, str]]) -> tuple[str, str] | None:
    """The generation this request declared, refused by name when it is not one.

    Article 13 negotiates the generation in band, and these operations publish
    the three codes for it. A read carries it as a query member, because a read
    carries no body to put it in.
    """
    raw = _one(query, "contract_generation")
    if raw is None:
        return ("generation_missing", "contract_generation is required")
    try:
        generation = int(raw)
    except ValueError:
        return ("generation_unreadable", "contract_generation is not an integer")
    if generation not in SUPPORTED_GENERATIONS:
        return ("generation_unsupported", "contract_generation is not supported")
    return None


def _problem(code: str, message: str) -> Problem:
    """One problem, with the retryability its own registry publishes.

    Whether a problem may be retried is a fact of the contract, answered in
    one place for every side of it: the client reads it there, the stub reads
    it there, and this daemon — the only server implementing the binding —
    reads it there too. A copy here would be a second answer to a question the
    contract already answers, and the two would part company at the first block
    that edits the registry (article 13: one contract, both sides).
    """
    published = ProblemCode(code)
    return Problem(published, message, problem_retryable(published), CONTRACT_GENERATION)


class RequestHandler(BaseHTTPRequestHandler):
    """Every request runs on a connection whose identity was bound at accept."""

    protocol_version = "HTTP/1.1"
    server_version = "sayfirst"
    sys_version = ""

    def __init__(
        self, request: Any, client_address: Any, server: Any, *, identity: ConnectionIdentity | None
    ) -> None:
        self.identity = identity
        self.answered = False
        self.defect: BaseException | None = None
        self.grant_connection: Any = None
        """The grant this connection issued, if it issued one (article 10)."""
        self._sweep_defect_logged = False
        """Whether the sweep on this held connection has already reported a defect."""
        self.timeout = connection_timeout(
            None if identity is None else identity.status, server.daemon.settings
        )
        super().__init__(request, client_address, server)

    @property
    def daemon(self) -> Any:
        return self.server.daemon  # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        if self.identity is None:
            return
        try:
            self.daemon.on_connection(self.identity)
            # Admission and the unmapped-id check run here, so the bound is
            # applied again now that the connection's state is settled (rule A5).
            self.timeout = connection_timeout(self.identity.status, self.daemon.settings)
            self.connection.settimeout(self.timeout)
        except Exception as error:  # a defect is answered, never dropped
            # An exception raised here leaves `handle()` unentered, so the
            # connection closes with nothing written — the bare EOF a client
            # reads as "unreachable". It is held until the first request, which
            # is answered `internal` like any other defect (rule P1).
            self.defect = error

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            if self.grant_connection is not None:
                # A connection that closes releases what it held: the grant it
                # issued had this connection for its channel, and article 10
                # gives a boundary that has lost it nothing to hold. Held here
                # as well as at the end of the watch, because a defect between
                # the answer and the watch must not leak the registry slot.
                self.grant_connection.peer_closed()
            if self.identity is not None:
                self.daemon.on_close(self.identity)

    # -- writing --------------------------------------------------------------

    def _send(self, status: int, document: object) -> None:
        body = json.dumps(document, sort_keys=True).encode()
        if self.request_version == _NO_STATUS_LINE:
            # HTTP/0.9 has no status line and no headers, so an answer written
            # under it carries neither: the caller reads a bare body it cannot
            # tell from a truncated one. The binding publishes a status for
            # every answer, so every answer this daemon writes carries one.
            self.request_version = ""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.answered = True

    def _send_problem(self, code: str, message: str) -> None:
        self._send(
            _STATUS_BY_CODE.get(code, 500),
            _problem(code, message).to_document(CONTRACT_GENERATION),
        )

    def _consume_body(self) -> bytes | None:
        """The bytes the request framed, or `None` once it has been answered.

        Every route consumes the body its request framed, whether it reads it
        or not: bytes left in the stream are read as the next request line, so
        the caller's following request is answered as an operation nobody named
        and its connection is broken. Article 13's stated purpose is
        third-party implementability, and `protocol_version` is HTTP/1.1, so a
        conforming caller may frame a request in a way this daemon does not
        read — which is refused by name, never answered with a fact about a
        body nobody read (article 2).
        """
        encoding = self.headers.get("Transfer-Encoding")
        if encoding is not None:
            return self._refuse_framing(encoding)
        declared = self.headers.get("Content-Length")
        if declared is None:
            return b""
        try:
            length = int(declared)
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            self._send_problem("request_malformed", f"Content-Length {declared!r} is not a length")
            return None
        return self.rfile.read(length)

    def _refuse_framing(self, encoding: str) -> None:
        """Refuse a framing this daemon does not read, and say which one it was.

        The framing is skipped where it can be — a chunked body is a length,
        the bytes, and the next length — so the connection keeps its contract
        and the caller's next request is still a request. Nothing of the body
        is read: a body this daemon did not frame is not a body it has, and
        `request_malformed` is what the registry publishes for a request the
        server will not read (article 2, article 3).
        """
        framed = (
            self.headers.get("Content-Length") is None
            and encoding.strip().lower() == "chunked"
            and self._skip_chunked()
        )
        self.close_connection = not framed
        self._send_problem(
            "request_malformed",
            "this daemon reads a body framed by Content-Length; "
            f"Transfer-Encoding: {encoding} is not read",
        )
        return None

    def _skip_chunked(self) -> bool:
        """Read past a chunked body without reading it; whether the stream is framed."""
        while True:
            line = self.rfile.readline(_MAX_FRAMING_LINE + 1)
            if not line or len(line) > _MAX_FRAMING_LINE:
                return False
            digits = line.split(b";", 1)[0].strip()
            # Hexadecimal digits and nothing else: `int(b"0x8", 16)` and
            # `int(b"+8", 16)` are numbers to Python and are not chunk sizes,
            # and a length read differently by two ends is how a stream is
            # smuggled a second request.
            if not digits or any(digit not in _HEX_DIGITS for digit in digits):
                return False
            size = int(digits, 16)
            if size == 0:
                break
            while size:
                block = self.rfile.read(min(size, _FRAMING_BLOCK))
                if not block:
                    return False
                size -= len(block)
            if self.rfile.read(2) != b"\r\n":
                return False
        while True:  # the trailer section, ended by an empty line
            line = self.rfile.readline(_MAX_FRAMING_LINE + 1)
            if not line or len(line) > _MAX_FRAMING_LINE:
                return False
            if line in (b"\r\n", b"\n"):
                return True

    def _document(self, raw: bytes) -> object:
        try:
            return json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    # -- the surface ----------------------------------------------------------

    def _guard(self) -> bool:
        """Whether this request may be served at all on this connection."""
        if self.defect is not None:
            self.close_connection = True
            self._answer_internal_error(self.defect)
            return False
        if self.identity is None:
            # Unreachable from a client: the transport binds an identity to
            # every connection before a byte of it is read (rule P1).
            self.close_connection = True
            self._send_problem("internal", "the connection carries no identity")
            return False
        # Counted first: a lookup this request owes must be made inside this
        # request, and an outage recorded at accept belongs to no request at
        # all, so the first request after it is the next request (rule G5).
        self.identity.begin_request()
        refusal = self.daemon.refresh_if_due(self.identity)
        if self.identity.status == REFUSED:
            self.close_connection = True
            code = refusal or self.identity.refusal or "peer_not_admitted"
            self._send_problem(code, _REFUSAL_MESSAGES.get(code, "this peer is not served"))
            return False
        return True

    def do_GET(self) -> None:
        if not self._guard():
            return
        assert self.identity is not None
        if self._consume_body() is None:
            return
        split = urlsplit(self.path)
        matched = match_target("GET", split.path)
        if matched is None:
            self._send_problem("operation_unknown", "operation is not defined")
            return
        operation, parameters = matched
        if operation == "read_whoami":
            result = whoami(
                self.identity,
                generation=CONTRACT_GENERATION,
                group_lifetime_seconds=self.daemon.settings.group_lifetime_seconds,
            )
            self._send(200, result.to_document())
            return
        if operation == "read_status":
            self._answer_status()
            return
        services = self.daemon.services
        if services is None:
            # Nothing was composed for this operation, so this daemon does not
            # serve it; it is not an operation that looked and found nothing.
            self._send_problem("operation_unknown", "operation is not defined")
            return
        query = parse_qsl(split.query, keep_blank_values=True)
        refusal = _generation_refusal(query)
        if refusal is not None:
            self._send_problem(*refusal)
            return
        if operation == "read_policy_status":
            services.decision_routes.read_policy_status(self.connection)
            self._answered_on_the_connection(streamed=False)
            return
        if operation == "read_decision":
            services.decision_routes.read_decision(
                _one(query, "scope") or "",
                parameters["decision_ref"],
                self.connection,
            )
            self._answered_on_the_connection(streamed=False)
            return
        if operation == "read_approval":
            self._answer_approval(services, _one(query, "scope") or "", parameters["approval_ref"])
            return
        self._answer_evidence(services, operation, parameters["scope"], query)

    def _answer_approval(self, services: Any, scope: str, approval_ref: str) -> None:
        """One approval as of now, or the refusal its own route publishes.

        Answered through this handler rather than written on the connection.
        `adapters/api` writes an answer itself where the answer may be a
        document or a stream — the decision routes own that pair — and these
        two are documents always, so they take the path the evidence reads and
        the status read take: one document, the status the binding publishes
        for each refusal, and a connection left open for the next request. A
        person who reads a wait and then ends it does both on one connection.
        """
        routes = services.approval_routes
        if not routes.served:
            self._send_problem("operation_unknown", "operation is not defined")
            return
        try:
            document = routes.read(scope, approval_ref)
        except READ_REFUSALS as refused:
            self._send_problem(refused.code, str(refused))
            return
        self._send(200, document)

    def _answer_status(self) -> None:
        """This daemon's own status, answered from what it actually composed."""
        assert self.identity is not None
        if self.identity.principal is None:
            # The status result names a principal, and this connection has
            # none resolved. `read_status` publishes this problem at 503
            # for exactly that; inventing a kind and a name for a directory
            # that could not be consulted would be a claim with nothing
            # behind it (article 2, article 3, rule G5). `whoami` is served
            # on an `unknown` connection, and is where the state is read.
            self._send_problem(
                "principal_groups_unavailable",
                "the account directory could not be consulted",
            )
            return
        document = read_status(
            self.identity.principal,
            generation=CONTRACT_GENERATION,
            supported_generations=tuple(SUPPORTED_GENERATIONS),
        ).to_document()
        services = self.daemon.services
        if services is not None:
            # Composed, the members that were "not established here" are read
            # off the emitter that does hold them, for this caller's own
            # connection (articles 2 and 7).
            document.update(
                evidence_status(
                    services.emitter,
                    scope=LOCAL_SCOPE,
                    connection=self._evidence_connection(),
                    principal=self._chain_principal(),
                )
            )
            document["store"] = {
                "authority": "authoritative",
                "kind": services.emitter.store_location.kind,
            }
            document["decision_store"] = services.decision_store_status()
        self._send(200, document)

    def _answer_evidence(
        self, services: Any, operation: str, scope: str, query: list[tuple[str, str]]
    ) -> None:
        """One of the two evidence reads, with the refusals the binding publishes."""
        routes = services.evidence_routes
        read = routes.read if operation == "read_evidence" else routes.export
        try:
            document = read(
                scope,
                query,
                connection=self._evidence_connection(),
                principal=self._chain_principal(),
            )
        except _EVIDENCE_REFUSALS as refused:
            self._send_problem(refused.code, str(refused))
            return
        self._send(200, document)

    def _answered_on_the_connection(self, *, streamed: bool) -> None:
        """An adapter wrote the whole answer itself; this connection is finished — or not.

        `adapters/api` owns the two answers that may be a document or a stream,
        so it writes them on the connection rather than through this handler.
        Recording that here is what keeps `_answer_internal_error` from writing
        a second answer after the first.

        Only a STREAM ends the connection, and it ends it because the adapter
        shut its write side down: article 10 binds a grant to the channel that
        carried it. A document answer — a decision read, a policy status, an
        ask the request did not select the stream for — leaves a connection
        that is still good for the next request, and closing it made every
        caller pay a connect and a re-verification for its second read while
        rule C4 forbade it re-opening silently.
        """
        self.answered = True
        self.close_connection = streamed

    def _evidence_connection(self) -> EvidenceConnection:
        """This connection, as the evidence pipeline grades it."""
        assert self.identity is not None
        return EvidenceConnection(self.identity.connection_id, self._caller_access())

    def _caller_access(self) -> CallerAccess:
        assert self.identity is not None
        principal = self.identity.principal
        peer = self.identity.peer
        uid = principal.uid if principal is not None else (peer.uid if peer is not None else -1)
        gids = set()
        if principal is not None:
            gids.add(principal.gid)
            gids.update(principal.unnamed_group_ids)
        elif peer is not None:
            gids.add(peer.gid)
        return CallerAccess(uid, frozenset(gids))

    def _chain_principal(self) -> ChainPrincipal:
        assert self.identity is not None
        principal = self.identity.principal
        if principal is None:
            return ChainPrincipal("unknown", str(self.identity.connection_id))
        return ChainPrincipal(principal.kind, principal.name or str(principal.uid))

    def _deciding_principal(self) -> PolicyPrincipal:
        """The identity a policy is evaluated against, built from this connection."""
        assert self.identity is not None
        principal = self.identity.principal
        assert principal is not None
        return PolicyPrincipal(
            kind=principal.kind,
            uid=principal.uid,
            user_name=principal.name or str(principal.uid),
            gids=(principal.gid, *principal.unnamed_group_ids),
            group_names=tuple(principal.groups or ()),
        )

    def do_POST(self) -> None:
        if not self._guard():
            return
        assert self.identity is not None
        raw = self._consume_body()
        if raw is None:
            return
        target = urlsplit(self.path).path
        matched = match_target("POST", target)
        if matched is None:
            self._send_problem("operation_unknown", "operation is not defined")
            return
        operation, parameters = matched
        if operation == "resolve_approval":
            self._resolve_approval(parameters["approval_ref"], raw)
            return
        assert operation == "ask_decision", "this binding defines two requests it is sent"
        document = self._document(raw)
        if not isinstance(document, dict):
            self._send_problem("request_malformed", "the request is not an object")
            return
        if not self._body_declares_a_generation_this_server_speaks(document):
            return
        try:
            self.daemon.read_delegation(document)
        except DelegationOutOfBounds as error:
            self._send_problem("delegation_invalid", str(error))
            return
        if self.identity.status == UNKNOWN or self.identity.principal is None:
            self._send_problem(
                "principal_groups_unavailable",
                "the account directory could not be consulted",
            )
            return
        assert self.identity.status == ESTABLISHED
        if not self._request_is_of_this_generation(document):
            return
        scope = document.get("scope", "local")
        assert isinstance(scope, str), "the published schema has held the type"
        self.daemon.touch(self.identity, scope)
        services = self.daemon.services
        if services is None:
            # This deployment composed no policy authority, so no decision was
            # taken and none is claimed (article 3: fail-closed; article 2: an
            # unknown is not a negative fact).
            self._send_problem("policy_unavailable", "no policy authority is configured")
            return
        self._decide(services, document, scope)

    def _body_declares_a_generation_this_server_speaks(self, document: dict[str, object]) -> bool:
        """The three codes article 13 negotiates a generation with, on a request body.

        One reading for every operation that carries a body: the two this
        binding defines publish the same three codes at the same statuses, and
        a second spelling of the negotiation is how two routes of one server
        come to disagree about `1.0` (article 13).
        """
        generation = document.get("contract_generation")
        if generation is None:
            self._send_problem("generation_missing", "contract_generation is required")
            return False
        if not is_published_integer(generation):
            # What an `integer` is, asked of the module that holds the published
            # schema rather than of Python. `1.0` is one JSON number with a zero
            # fractional part, the schema checker accepts it, and a guard here
            # that demanded a Python `int` refused it as unreadable — a server
            # refusing what its own contract publishes (article 13).
            self._send_problem("generation_unreadable", "contract_generation is not an integer")
            return False
        if generation not in SUPPORTED_GENERATIONS:
            self._send_problem("generation_unsupported", "contract_generation is not supported")
            return False
        return True

    def _resolve_approval(self, approval_ref: str, raw: bytes) -> None:
        """One person's act on one wait, the person taken from this connection.

        The order of the checks is the order of the facts. Whether this
        deployment serves the operation at all comes first: a refusal about the
        request would claim an authority was consulted (article 2). Then the
        generation, because a request of another generation is not read at all.
        Then the principal, because the person of a resolution *is* the
        connection's principal, and an act nobody can be attributed to is not
        one this core records (articles 3, 6 and 12). Then the body, against
        the schema its own route publishes — which is where a body naming a
        person is refused as a member this generation does not define.

        No scope is touched. A read and a resolution write nothing to a scope's
        chain — the durable record of a resolution is the resumed decision the
        next ask appends — and touching one writes a connection record for a
        chain this request will not otherwise enter (articles 5 and 10).
        """
        assert self.identity is not None
        services = self.daemon.services
        routes = None if services is None else services.approval_routes
        if routes is None or not routes.served:
            self._send_problem("operation_unknown", "operation is not defined")
            return
        document = self._document(raw)
        if not isinstance(document, dict):
            self._send_problem("request_malformed", "the request is not an object")
            return
        if not self._body_declares_a_generation_this_server_speaks(document):
            return
        if self.identity.status == UNKNOWN or self.identity.principal is None:
            self._send_problem(
                "principal_groups_unavailable",
                "the account directory could not be consulted",
            )
            return
        assert self.identity.status == ESTABLISHED
        if not self._request_is_of_this_generation(
            document, schema=_RESOLVE_SCHEMA, members=_RESOLVE_MEMBERS
        ):
            return
        try:
            answer = routes.resolve(
                approval_ref, document, person=self._deciding_principal().reference
            )
        except RESOLVE_REFUSALS as refused:
            self._send_problem(refused.code, str(refused))
            return
        self._send(200, answer)

    def _request_is_of_this_generation(
        self,
        document: dict[str, object],
        *,
        schema: str = _ASK_SCHEMA,
        members: frozenset[str] = _ASK_MEMBERS,
    ) -> bool:
        """Hold a request to the schema its route publishes, before anything acts on it.

        A member this generation does not define is refused by name, as it
        always was. A member it *does* define, carried at the wrong type, used
        to be coerced or dropped without a word: `str(scope)` turned a JSON
        `null` into the scope literally named `None`, which passes the scope
        pattern and gets an evidence chain of its own — a caller's records
        partitioned into a scope it never named (article 5) — and a digest that
        was not a string was dropped, so the caller was handed an `allow`
        pinned to nothing and told nothing (article 3).

        A server that accepts what its published request schema refuses is not
        implementable from the contract (article 13), so the schema is the
        judge, read from the published file rather than spelled again here.
        This runs before the scope is touched, because touching a scope writes
        to its chain.
        """
        unknown = sorted(set(document) - members)
        if unknown:
            self._send_problem("member_unknown", f"{unknown[0]} is not a request member")
            return False
        complaint = refused_by(document, schema)
        if complaint is not None:
            self._send_problem("request_malformed", complaint)
            return False
        return True

    def _decide(self, services: Any, document: dict[str, object], scope: str) -> None:
        """One ask, decided by the composed authority and recorded as it is answered."""
        assert self.identity is not None
        capability = document.get("capability")
        assert isinstance(capability, str), "the published schema has held the type"
        digest = document.get("arguments_digest")
        correlation = document.get("correlation")
        question = DecisionQuestion(
            DecisionAsk(
                capability=capability,
                scope=scope,
                arguments_digest=digest if isinstance(digest, str) else None,
                correlation=correlation if isinstance(correlation, str) else None,
            ),
            self._deciding_principal(),
        )
        accept = self.headers.get(ACCEPT_HEADER)
        answer = services.decision_routes.ask_decision(question, self.connection, accept=accept)
        # Read before anything else can fail: from here on this connection
        # holds whatever the answer opened on it, and `finish` releases it.
        self.grant_connection = getattr(answer, "connection", None)
        # The route opens a stream when the request selected one and the answer
        # is a decision; a refusal is published in one media type, so it is a
        # document whatever the request selected (article 13). Both halves are
        # read where they are: the selector from the published function the
        # route itself reads it from, and the kind of answer from the answer
        # the route just returned. A grant is NOT the condition — a deny served
        # on a selected stream opens one and mints none.
        self._answered_on_the_connection(
            streamed=selects_stream(accept) and getattr(answer, "decision", None) is not None
        )
        self._record_effect(services, scope, answer)
        self._hold_the_issuing_connection(services)

    def _record_effect(self, services: Any, scope: str, answer: object) -> None:
        """Write the decision to the scope's chain, at this connection's own grade.

        A refusal is not written: no decision was taken, and article 2 keeps a
        could-not-ask off the chain of things that happened. The write is
        asynchronous by design — article 10 keeps the evidence authority off
        the hot path — so a store that is refusing appends declares a gap
        rather than holding the answer back.
        """
        decision = getattr(answer, "decision", None)
        if decision is None:
            return
        extra = decision.extra
        references = extra.get("principal_references")
        services.emitter.emit_effect(
            scope=scope,
            connection=self._evidence_connection(),
            principal=self._chain_principal(),
            capability=decision.capability,
            decision=EffectDecision(
                decision_id=decision.decision_ref,
                outcome=decision.outcome,
                decided_at=datetime.fromisoformat(decision.decided_at),
                policy_version=decision.policy_version,
                # The copied facts of M1, read off the record the service
                # answered with: the same values the authority holds.
                reason=decision.reason,
                rule_id=extra.get("rule_id"),
                arguments_digest=extra.get("arguments_digest"),
                correlation=decision.correlation,
                principal_references=tuple(references) if isinstance(references, list) else (),
                evaluation_recipe=extra.get("evaluation_recipe"),
                position=getattr(answer, "position", None),
            ),
        )

    def _hold_the_issuing_connection(self, services: Any) -> None:
        """Keep the connection a grant was delivered on for as long as it holds it.

        Article 10 makes the issuing connection part of what a grant is: the
        control plane "signals a change of version to every connected boundary
        over the connection that issued the grant", and a boundary that has
        lost that connection "treats its grants as expired". This daemon closed
        the connection under its own grant the instant it had answered, so
        every grant it issued was dead on arrival and the published
        `grant_ended` reason `connection_lost` had no code anywhere that could
        produce it. Closing released nothing either, so sixty-four ordinary
        asks spent the per-principal bound and the sixty-fifth got no grant.

        The connection is watched rather than slept on. The peer going away is
        the loss article 10 names, and it wakes this at once. Anything the peer
        writes ends the hold too: the stream answer published `Connection:
        close`, so this binding defines no second operation on it, and reading
        one would be answering an operation into the middle of a stream.

        The hold is bounded by the grant's own lifetime, so a boundary that
        neither reads nor closes cannot hold a thread of this daemon for
        longer than the grant it was given, and the grant ends as `expired`
        rather than as a connection somebody lost.

        End of file on the read side is the boundary going away. A peer that
        closed and a peer that shut only its write side down are one event
        here, and no peek tells them apart, because a half-closed peer has left
        nothing to peek at. That is why the binding publishes `x-stream-hold`
        on the operation that serves this stream: a boundary holding it keeps
        its write side open for as long as it holds the grant, so
        `connection_lost` is true of everything this can see (article 13).

        This is also the boundary article 10's "connection that asks nothing
        more" names. It is parked here, and the wake below is the daemon's own
        attention on it, so the wake is where the policy reload age and the
        grant registry are consulted: no scan, no thread and no clock of this
        handler's own, and nothing consulted that a decision request does not
        consult. A version change therefore reaches this boundary within the
        reload interval whether or not anything else asks, and the heartbeat
        the grant document promised it is written on this connection.
        """
        held = self.grant_connection
        if held is None:
            return
        deadline = time.monotonic() + held.grant.lifetime_seconds
        try:
            while held.live:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    held.reached_its_lifetime()
                    return
                readable, _, _ = select.select(
                    [self.connection], [], [], min(GRANT_WATCH_SECONDS, remaining)
                )
                if readable:
                    if self._peer_wrote_rather_than_closed():
                        held.peer_wrote()
                    return
                self._sweep_while_holding(services)
        except OSError:
            # The connection itself failed, which is the loss, and `finish`
            # records it as one.
            return

    def _sweep_while_holding(self, services: Any) -> None:
        """One consultation of the reload age and the grant registry, on a held wake.

        A defect here must not take the hold down with it: the connection is
        this boundary's only channel, and dropping it would report a daemon
        that failed to notice a version change as a boundary that went away
        (article 2). So it is answered the way every other defect of this
        daemon is — logged, once per held connection, and never as a record on
        the chain — and the hold continues. Logging once is the bound: the wake
        repeats several times a second, and a defect that repeated with it
        would bury the line that named it.
        """
        try:
            services.decisions.sweep()
        except Exception:  # a defect of this daemon, never of the boundary
            if not self._sweep_defect_logged:
                self._sweep_defect_logged = True
                LOG.exception("the policy reload and grant sweep failed on a held connection")

    def _peer_wrote_rather_than_closed(self) -> bool:
        """Whether the readable connection carries bytes, or is at end of file.

        `select` says only that a read would not block, and a peer that closed
        and a peer that wrote both make it say so. They are not the same record
        (article 2): one boundary has gone away, and the other is still there
        and it is this daemon that is about to close on it. One peek tells them
        apart and consumes nothing; a peek that fails is the connection itself
        failing, which is the loss.
        """
        try:
            return bool(self.connection.recv(1, socket.MSG_PEEK))
        except OSError:
            return False

    def _answer_unknown_operation(self) -> None:
        """Any method this binding does not define, answered as one of its own.

        A refused connection answers its first request with the problem
        document that names the refusal, whichever method that request named:
        an answer that only five verbs receive leaves the sixth reading the
        base handler's bare 501 page, which a caller cannot tell apart from
        "could not ask" (article 1, article 2). Beyond the refusal, an
        operation the binding does not define is `operation_unknown`.
        """
        if not self._guard():
            return
        if self._consume_body() is None:  # whatever it framed, so the stream stays framed
            return
        self._send_problem("operation_unknown", "operation is not defined")

    def handle_one_request(self) -> None:
        """One request, and a defect in answering it answered as a defect.

        Nothing above this caught an exception from a handler: `handle_error`
        was `pass` and `log_message` was `pass`, so the connection closed with
        zero bytes written and no record anywhere. Rule P1 already says what a
        programming error is answered with — `internal`, "and logged".
        """
        try:
            super().handle_one_request()
        except OSError:
            # The connection itself failed, so there is nobody left to answer
            # and nothing to claim about it here.
            raise
        except Exception as error:  # a defect is answered, never dropped
            self.close_connection = True
            self._answer_internal_error(error)

    def _answer_internal_error(self, error: BaseException) -> None:
        """A defect of this daemon, recorded as one and answered as one.

        A bare EOF is what a daemon that died looks like:
        `VerifiedConnection._request` reads zero bytes as `unreachable`,
        retryable, so the project's own client told its caller "the daemon
        could not be reached, try again" about a deterministic defect on a
        socket that answered every other request. The evidence held for that
        claim is an exception this daemon caught and discarded, and
        "unreachable" is a stronger claim than that evidence (article 2).
        `internal` at 500 is what all five routes already publish for it.
        """
        connection = None if self.identity is None else self.identity.connection_id
        LOG.error(
            "the daemon failed to answer a request on connection %s", connection, exc_info=error
        )
        if self.answered:
            # A response was already begun, so a second one would be read as
            # the tail of the first; the connection ends instead.
            return
        with suppress(OSError):
            self._send_problem("internal", "the daemon failed to answer this request")

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """The base handler's HTML page, answered as a problem this binding publishes.

        `BaseHTTPRequestHandler.send_error` runs before any `do_*` method and
        before `_guard`: an over-long request line, a version it cannot read,
        too many headers or a request line it cannot parse are answered with an
        HTML page at 414, 505, 431 or 400. No route of the binding publishes
        those statuses and none of those bodies is a problem document, so a
        caller of the contract can read none of them, and a refused peer whose
        first request is malformed used to receive one before its refusal was
        ever consulted. It is the same defect `_answer_unknown_operation` closed
        one door along (article 2, article 13).

        The request was never read, so `request_malformed` — the code the
        registry publishes for a request this server will not read — is the
        fact, at the 400 the binding publishes for it.
        """
        del explain
        self.close_connection = True
        detail = message or f"the request was not read ({code})"
        self._send_problem("request_malformed", detail[:_MAX_REFUSAL_DETAIL])

    def parse_request(self) -> bool:
        """The binding is HTTP/1.1 over this socket; a request in another version is not one.

        An `HTTP/0.9` request line is accepted by the base handler and reaches
        `do_GET`, and an answer under it carries no status and no headers at
        all. The binding publishes statuses, so a request that cannot receive
        one is refused by name rather than answered by half (article 13).
        """
        if not super().parse_request():
            return False
        if self.request_version not in SPOKEN_VERSIONS:
            self.close_connection = True
            self._send_problem(
                "request_malformed",
                f"this daemon reads HTTP/1.1; {self.request_version or 'no version'} is not read",
            )
            return False
        return True

    def __getattr__(self, name: str) -> Any:
        # `BaseHTTPRequestHandler` dispatches on `do_<METHOD>` and answers 501
        # in HTML when it finds none. Every method reaches the guard instead.
        if name.startswith("do_"):
            return self._answer_unknown_operation
        raise AttributeError(name)

    def log_message(self, format: str, *args: object) -> None:
        """No access log: what happened on a connection is the evidence chain.

        A defect is not an access record and does not come through here; it is
        recorded by `_answer_internal_error`, which is the one thing rule P1
        asks to be logged.
        """
