# SPDX-License-Identifier: Apache-2.0
"""The client's side of the boundary: it verifies the server before it speaks.

Article 6: a client verifies the server's peer credential at connect and
refuses a server that is not the daemon's principal. It does that with the
same code the daemon uses, which is why this lives in the distribution both
sides may depend on.

The client never sends a credential of its own — no header, no cookie, no
body member names who it is. Who it is, the boundary says.

The generation is negotiated in band (article 13): pinned in the contract
package, recorded on the connection when it is opened, compared with what the
far end echoes on every response, and refused with the published problem when
it is one this client does not speak.
"""

from __future__ import annotations

import http.client
import json
import os
import pwd
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import quote, urlencode

from ..approvals import Approval, ApprovalResolution
from ..client import Answered, CouldNotAsk, Refused, Result
from ..decisions import Decision, read_decision
from ..generation import CONTRACT_GENERATION, SUPPORTED_GENERATIONS, negotiate_generation
from ..policy import PolicyStatus
from ..problems import (
    Problem,
    ProblemCode,
    problem_class_of,
    problem_retryable,
    read_problem,
)
from ..status import Status
from ..whoami import Delegation, WhoAmI
from .peer import PeerCredential, PeerIdentity, PeerIdentityUnsupported, select_peer_identity

PER_USER: Final[str] = "per_user"
SYSTEM: Final[str] = "system"
MODES: Final[tuple[str, ...]] = (PER_USER, SYSTEM)
PLACEHOLDER_HOST: Final[str] = "sayfirst"
STATUS_TARGET: Final[str] = "/status"
WHOAMI_TARGET: Final[str] = "/whoami"
DECISIONS_TARGET: Final[str] = "/decisions"
APPROVALS_TARGET: Final[str] = "/approvals"
#: What the binding appends to one approval's address for the act that ends it.
#: Spelled here as the other targets are, and held against the published
#: document by `test_the_transports_approval_targets_are_the_published_paths`.
RESOLUTION_SUFFIX: Final[str] = "/resolution"
#: The methods by which this transport asks for something to be DONE rather
#: than read. A reply to one of these that never arrived may still have been
#: the reply to an act the far end took and recorded, which is what makes the
#: retryability of a lost write unknown rather than true (articles 1 and 3).
_WRITES: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: What a reader of a 200 raises when the body is not a document of this
#: generation. One tuple for every reader this transport calls, because a
#: reader that INDEXES its argument and a reader that asks it for a member
#: report the same fact by different exception types — a JSON array reaches
#: one as a `TypeError` and the other as an `AttributeError` — and a number
#: too large to be an integer arrives as an `OverflowError`, outside
#: `ValueError` entirely. Every one of them is « the answer is unreadable »,
#: and none of them is an exception a caller can be asked to classify
#: (articles 1 and 2).
_UNREADABLE: Final = (AttributeError, KeyError, TypeError, ValueError, OverflowError)


class ProfileMisuse(ValueError):
    """A profile that cannot say what it must verify is not a profile."""


class SocketClientProblem(Exception):
    """A refusal or an absent answer, carrying the problem that names it."""

    def __init__(self, problem: Problem) -> None:
        super().__init__(problem.message)
        self.problem = problem

    @property
    def classification(self) -> str:
        """Which of the two results this is, asked of the value and not of the code.

        Every problem this transport raises out of here it made for itself —
        an address it could not open, an answer it could not read, a profile
        pinned to a generation it does not speak — so no control plane
        answered and the honest reading is « could not ask » (articles 1
        and 2). `problem_class_of` is what says so, rather than a rule written
        again here, so a published problem that ever reaches this exception is
        classed by the registry's column instead.
        """
        return problem_class_of(self.problem)


def _problem(
    code: ProblemCode,
    message: str,
    *,
    generation: int | None = CONTRACT_GENERATION,
    repeatable: bool = True,
) -> Problem:
    """One of this client's own problems, retryable as the registry publishes it.

    A caller reads `retryable` to decide whether asking again could produce an
    answer; a credential the operating system did not deliver this time may be
    delivered on the next connection (rule P6), and saying otherwise here
    would make the client's rendering of the same code differ from the
    daemon's (article 13: one contract, both sides).

    `generation` is the one the problem is reported on: this package's own
    before a connection is open, and a connection's negotiated one after —
    never a claim that a generation was agreed where none was.

    `repeatable=False` is the one thing that overrides the column, and it
    weakens rather than strengthens what is claimed: this occurrence of the
    code carries a request that MAY have been received and acted on, so nothing
    here may say that sending it again is safe. `retryable` has a third value
    for exactly that, and an unknown is never read as the more permissive of
    the two (article 3). The class of the problem does not move with it — that
    is the registry's column, read through `problem_class_of`, and every
    problem minted here is a could-not-ask because no control plane answered.
    """
    return Problem(code, message, problem_retryable(code) if repeatable else None, generation)


@dataclass(frozen=True)
class SocketProfile:
    """Where the daemon is, in which mode, and whose principal it must be.

    A system profile without `daemon_user` is a usage error and never a
    default to root: a default would let a profile written for one host
    verify the wrong thing on another (rule C1).
    """

    socket_path: str
    mode: str = PER_USER
    daemon_user: str | None = None
    scope: str = "local"
    contract_generation: int = CONTRACT_GENERATION

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ProfileMisuse(f"mode must be one of {', '.join(MODES)}")
        if self.mode == SYSTEM and not self.daemon_user:
            raise ProfileMisuse("a system profile names the account the daemon runs as")
        if self.mode == PER_USER and self.daemon_user:
            raise ProfileMisuse("a per-user profile has one principal and names no account")


def expected_principal_uid(
    profile: SocketProfile, *, account_uid: Callable[[str], int | None] | None = None
) -> int:
    """The uid the process listening at the address must have (rule C1)."""
    if profile.mode == PER_USER:
        return os.geteuid()
    lookup = account_uid or _account_uid
    uid = lookup(profile.daemon_user or "")
    if uid is None:
        raise SocketClientProblem(
            _problem(
                ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL,
                f"this host has no account named {profile.daemon_user!r}",
            )
        )
    return uid


def _account_uid(name: str) -> int | None:
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def declared_delegation(environ: Mapping[str, str] | None = None) -> Delegation | None:
    """What a privilege tool says about who invoked it, declared and never proven.

    Absence is "nothing declared", never "no delegation" (rule D4).
    """
    values = os.environ if environ is None else environ
    name = values.get("SUDO_USER") or values.get("DOAS_USER")
    raw_uid = values.get("SUDO_UID")
    if not name and not raw_uid:
        return None
    uid = int(raw_uid) if raw_uid and raw_uid.isdigit() else None
    return Delegation.declared(
        [{"kind": "user", "name": name or None, "uid": uid, "via": "privilege_tool"}]
    )


class LocalHttpConnection(http.client.HTTPConnection):
    """HTTP over one verified local stream, with no network to fall back to.

    The stock class dials its host and port when its socket is gone. This one
    has `auto_open` off, so a dropped keep-alive is refused rather than
    silently re-opened, and its `connect` opens the same local address and
    verifies the far end again — there is no "verified once per profile"
    (rule C4), and there is no path from here to a network (article 6).
    """

    auto_open = 0

    def __init__(self, opener: Callable[[], tuple[socket.socket, PeerCredential, int]]) -> None:
        super().__init__(PLACEHOLDER_HOST)
        self._opener = opener
        self.last_credential: PeerCredential | None = None
        self.last_expected_uid: int | None = None

    def connect(self) -> None:
        self.sock, self.last_credential, self.last_expected_uid = self._opener()


@dataclass
class VerifiedConnection:
    """A connection whose far end was verified before a byte was written."""

    profile: SocketProfile
    server_credential: PeerCredential
    expected_uid: int
    http: LocalHttpConnection
    negotiated_generation: int = CONTRACT_GENERATION
    extra: Mapping[str, object] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return self.server_credential.uid == self.expected_uid

    def _echoed_generation(self, document: object) -> Problem | None:
        """The published refusal when a response does not speak this connection's generation.

        Article 13: the generation is echoed on every response and recorded by
        this client at connection. A far end that answers in a generation this
        client does not speak has not answered the question that was asked, so
        the answer is an unknown and never a verdict (article 2).
        """
        if not isinstance(document, Mapping):
            return None
        echoed = document.get("contract_generation")
        if not isinstance(echoed, int) or isinstance(echoed, bool):
            return None
        problem = negotiate_generation(SUPPORTED_GENERATIONS, echoed)
        if problem is not None:
            return problem
        if echoed != self.negotiated_generation:
            return _problem(
                ProblemCode.GENERATION_UNSUPPORTED,
                f"this connection was opened on contract generation "
                f"{self.negotiated_generation} and the answer echoes {echoed}",
                generation=echoed,
            )
        return None

    def reconnect(self) -> None:
        """Open the address again and verify the far end again (rule C4).

        The expectation is resolved again too: an account remapped between two
        connections must not be verified against the uid it had at the first
        (rule C1). What this reports having verified is what it verified.
        """
        self.http.close()
        self.http.connect()
        assert self.http.last_credential is not None
        assert self.http.last_expected_uid is not None
        self.server_credential = self.http.last_credential
        self.expected_uid = self.http.last_expected_uid

    def _request(self, method: str, target: str, document: object | None = None):  # type: ignore[no-untyped-def]
        body = None if document is None else json.dumps(document, sort_keys=True)
        headers = {"Host": PLACEHOLDER_HOST}
        if body is not None:
            headers["Content-Type"] = "application/json"
        # Two guards, because there are two facts and one of them is about
        # whether the plane was reached at all. Everything up to and including
        # the read of the body is obtaining an answer; parsing what was obtained
        # is reading one. A clause that covered both would report « the answer
        # is not a document of this generation » for a request that failed
        # before a byte of it was written, which is the reasoning this method is
        # otherwise careful about.
        sent = False
        try:
            self.http.request(method, target, body=body, headers=headers)
            # From here on the far end MAY have the request, which is the whole
            # of what the retryability below turns on.
            sent = True
            response = self.http.getresponse()
            arrived = response.read()
        except (OSError, ValueError, RecursionError, http.client.HTTPException) as error:
            # No answer about the effect exists. A reply lost to a write may
            # have been the reply to an act that WAS taken and recorded, so
            # nothing here may claim that asking again is safe; a request that
            # never left this side took nothing, and the registry's column
            # stands as it is written for that one.
            raise SocketClientProblem(
                _problem(
                    ProblemCode.UNREACHABLE,
                    str(error),
                    repeatable=not (sent and method in _WRITES),
                )
            ) from error
        try:
            payload = json.loads(arrived or b"{}")
        except RecursionError as error:
            # A reply nested past what the parser accepts ARRIVED, so the
            # control plane was reached: it is an answer this client cannot
            # read, which is a different fact from one it could not obtain
            # (articles 1 and 2).
            raise SocketClientProblem(
                _problem(
                    ProblemCode.ANSWER_UNREADABLE,
                    f"the answer is nested deeper than this client parses: {error}",
                    generation=self.negotiated_generation,
                )
            ) from error
        except ValueError as error:
            # The plane WAS reached and what arrived is not a document of this
            # generation. It was filed as « unreachable » while the two clients
            # of this contract disagreed about classes, so that `ask` did not
            # move under a fix round; the registry's class column settles it and
            # both codes are could-not-asks, so the classification does not move
            # and the code becomes honest. `json.JSONDecodeError` and
            # `UnicodeDecodeError` are both `ValueError`, which is what makes
            # this one clause cover a body that is not JSON and one that is not
            # even text.
            raise SocketClientProblem(
                _problem(
                    ProblemCode.ANSWER_UNREADABLE,
                    f"the answer is not a document of this generation: {error}",
                    generation=self.negotiated_generation,
                )
            ) from error
        return response.status, payload

    def _unreadable(self, detail: object) -> CouldNotAsk:
        return CouldNotAsk(
            _problem(
                ProblemCode.ANSWER_UNREADABLE,
                f"the answer is not a document of this generation: {detail}",
                generation=self.negotiated_generation,
            )
        )

    def _classify(self, status: int, document: object) -> Result[Any]:
        """The problem the far end published, or « unreadable » when it published none.

        A non-200 is an answer too, and a body this generation cannot read as a
        problem document — anything that is not an object, or an object without
        the `code` the document requires — names no problem at all. It is then
        an unknown carrying the status it arrived with, never an exception the
        caller has to classify for itself (articles 1 and 2), and never a
        problem invented from the status, which the answer did not claim.
        """
        if not isinstance(document, Mapping):
            return self._unreadable(f"the body at status {status} is not an object")
        if not isinstance(document.get("code"), str):
            return self._unreadable(f"the body at status {status} carries no problem code")
        return _classified(document)

    def read_status(self) -> Result[Status]:
        """What the daemon says about itself, and which generations it speaks.

        It is the operation the negotiation gate reads (article 13), so this
        transport answers it like every other client of the contract.
        """
        status, document = self._request("GET", STATUS_TARGET)
        if (refusal := self._echoed_generation(document)) is not None:
            return CouldNotAsk(refusal)
        if status != 200:
            return self._classify(status, document)
        try:
            value = Status.from_document(document)
        except _UNREADABLE as error:
            return self._unreadable(error)
        return Answered(value, value.contract_generation)

    def read_whoami(self) -> Result[WhoAmI]:
        """What the daemon says this connection is."""
        status, document = self._request("GET", WHOAMI_TARGET)
        if (refusal := self._echoed_generation(document)) is not None:
            return CouldNotAsk(refusal)
        if status != 200:
            return self._classify(status, document)
        try:
            value = WhoAmI.from_document(document)
        except _UNREADABLE as error:
            return self._unreadable(error)
        return Answered(value, value.contract_generation)

    def ask_decision(self, ask: object, delegation: Delegation | None = None) -> Result[Any]:
        """Submit a question; block 2.3 gives the answer its shape."""
        from ..decisions import read_decision

        document = ask.to_document(self.negotiated_generation)  # type: ignore[attr-defined]
        if delegation is not None:
            document["delegation"] = delegation.to_document()
        status, answer = self._request("POST", DECISIONS_TARGET, document)
        if (refusal := self._echoed_generation(answer)) is not None:
            return CouldNotAsk(refusal)
        if status == 200:
            # Article 1: the same reading as `read_status` and `read_whoami`,
            # on the one operation that decides an effect. An answer this
            # generation cannot read is an unknown with the published problem,
            # never an exception the caller has to classify for itself and
            # never a verdict.
            try:
                return read_decision(answer)
            except _UNREADABLE as error:
                return self._unreadable(error)
        return self._classify(status, answer)

    def read_decision(self, scope: str, decision_ref: str) -> Result[Decision]:
        """Read a recorded decision in the requested scope.

        The daemon leaves the connection open after this answer, as it does
        after every document it writes, so a caller may read a decision and
        then its policy status without paying a second connect and a second
        verification for the pair. That is the daemon's behaviour and not a
        promise this transport makes: a far end that DOES close is reported as
        could-not-ask on the next request, and the caller's own `reconnect()`
        verifies the address again before it speaks (rule C4).
        """
        query = urlencode([("contract_generation", self.negotiated_generation), ("scope", scope)])
        target = f"{DECISIONS_TARGET}/{quote(decision_ref, safe='')}?{query}"
        return self._document_read(target, read_decision)

    def read_policy_status(self) -> Result[PolicyStatus]:
        """Read the daemon's current policy status.

        Left open by the daemon after the answer, like `read_decision`, and
        under the same qualification: what this transport owes is the same
        either way, and a far end that closes needs the caller's `reconnect()`
        (rule C4).
        """
        query = urlencode([("contract_generation", self.negotiated_generation)])
        return self._document_read(f"/policy/status?{query}", PolicyStatus.from_document)

    def read_approval(self, scope: str, approval_ref: str) -> Result[Approval]:
        """Where one suspension stands, as of the instant the daemon answers it.

        The daemon leaves the connection open here too — which is what lets a
        person read a wait and then end it without reconnecting. Only a stream
        ends a connection now, and this read opens none; the qualification on
        `read_decision` applies here word for word.
        """
        query = urlencode([("contract_generation", self.negotiated_generation), ("scope", scope)])
        target = f"{APPROVALS_TARGET}/{quote(approval_ref, safe='')}?{query}"
        return self._document_read(target, Approval.from_document)

    def resolve_approval(self, resolution: ApprovalResolution) -> Result[Approval]:
        """End one wait, and answer the record the act left behind.

        The person is the connection's verified principal; no member of the
        body says who acted, and a body that named one would be refused as any
        member this generation does not define (article 12). The answer is the
        published `approval-result`, read by the reader `read_approval` uses,
        so a caller reads one shape whether it asked or acted. The connection
        is left open by the daemon here too.

        Put exactly once, and never put again by this transport: an act the far
        end received and did not answer may have been recorded, so asking again
        is the caller's decision to weigh and not this client's to take
        (rule C4, articles 1 and 2).

        How a refusal of this act is classed is the registry's answer and not
        this method's. A wait already over and an approval this daemon does not
        keep are both published codes, and the registry's class column classes
        both as refusals — the question reached the daemon and the daemon
        rejected it — so both clients of this contract now make the same thing
        of the same document (article 1).
        """
        target = f"{APPROVALS_TARGET}/{quote(resolution.approval_ref, safe='')}{RESOLUTION_SUFFIX}"
        return self._document_put(
            target,
            resolution.to_document(self.negotiated_generation),
            Approval.from_document,
        )

    def read_evidence(
        self, scope: str, from_sequence: int, page_size: int = 100
    ) -> Result[Mapping[str, object]]:
        """Read a page of evidence without interpreting its members."""
        query = urlencode(
            [
                ("contract_generation", self.negotiated_generation),
                ("from_sequence", from_sequence),
                ("page_size", page_size),
            ]
        )
        return self._evidence_read(f"/scopes/{quote(scope, safe='')}/evidence?{query}")

    def export_evidence(
        self, scope: str, from_sequence: int, to_sequence: int | None = None
    ) -> Result[Mapping[str, object]]:
        """One bounded export bundle from `from_sequence`, at most through `to_sequence`.

        The daemon bounds a bundle by entry count and by size and may stop
        before the end asked for; the bundle says where with `next_from`. A
        caller that wants the rest asks again from there — this method makes
        one request and claims nothing about what lies beyond the bundle.
        """
        members = [
            ("contract_generation", self.negotiated_generation),
            ("from_sequence", from_sequence),
        ]
        if to_sequence is not None:
            members.append(("to_sequence", to_sequence))
        query = urlencode(members)
        return self._evidence_read(f"/scopes/{quote(scope, safe='')}/evidence/export?{query}")

    def _document_read[T](
        self, target: str, reader: Callable[[Mapping[str, object]], T | Result[T]]
    ) -> Result[T]:
        status, document = self._request("GET", target)
        return self._document_answer(status, document, reader)

    def _document_put[T](
        self,
        target: str,
        document: object,
        reader: Callable[[Mapping[str, object]], T | Result[T]],
    ) -> Result[T]:
        """POST one document, and judge the answer by the reads' own front guard.

        The same three checks in the same order — the echoed generation, then
        the status, then whether the body is an object at all — because a POST
        that answers a document is answered under the same rules as a read of
        one, and two front guards would be two answers to one question
        (article 13). What is different is the request, and only the request:
        it is written once on the connection this object holds, and
        `LocalHttpConnection` re-opens no address, so a far end that took the
        request and hung up is an unknown rather than a second request
        (rule C4).
        """
        status, answer = self._request("POST", target, document)
        return self._document_answer(status, answer, reader)

    def _document_answer[T](
        self,
        status: int,
        document: object,
        reader: Callable[[Mapping[str, object]], T | Result[T]],
    ) -> Result[T]:
        """The one front guard of the four document operations: the two decision reads
        and the two approval operations. The status, whoami and ask paths, and the
        evidence reads, keep checks of their own (a later change folds them here)."""
        if (refusal := self._echoed_generation(document)) is not None:
            return CouldNotAsk(refusal)
        if status != 200:
            return self._classify(status, document)
        if not isinstance(document, Mapping):
            # The guard `_evidence_read` already had: a reader handed a body
            # that is not an object raises out of this transport instead of
            # answering the published problem, on the one read a governed
            # caller takes a verdict from.
            return self._unreadable(f"the body at status {status} is not an object")
        try:
            value = reader(document)
        except _UNREADABLE as error:
            return self._unreadable(error)
        if isinstance(value, Answered | Refused | CouldNotAsk):
            return value
        return Answered(value, self.negotiated_generation)

    def _evidence_read(self, target: str) -> Result[Mapping[str, object]]:
        status, document = self._request("GET", target)
        if status != 200:
            if (refusal := self._echoed_generation(document)) is not None:
                return CouldNotAsk(refusal)
            return self._classify(status, document)
        if not isinstance(document, Mapping):
            # A body that is not an object carries no version to disagree
            # about, so it is unreadable rather than a generation this client
            # refuses: the version was never there to be read (article 2).
            return self._unreadable(f"the body at status {status} is not an object")
        version = document.get("contract_version")
        if version != str(self.negotiated_generation):
            return CouldNotAsk(
                _problem(
                    ProblemCode.GENERATION_UNSUPPORTED,
                    f"this connection was opened on contract version "
                    f"{str(self.negotiated_generation)!r} and the answer carries {version!r}",
                    generation=self.negotiated_generation,
                )
            )
        return Answered(document, self.negotiated_generation)

    def close(self) -> None:
        self.http.close()


def _classified(document: Mapping[str, object]) -> Result[Any]:
    """The published problem, classed as the registry classes it (article 1).

    A document arrived, so a control plane answered, and the class column is
    the whole of the answer to which result this is.
    """
    problem = read_problem(document)
    if problem_class_of(problem) == "refused":
        return Refused(problem)
    return CouldNotAsk(problem)


def connect(
    profile: SocketProfile,
    *,
    peer_identity: PeerIdentity | None = None,
    platform: str | None = None,
    socket_factory: Callable[[], socket.socket] | None = None,
    account_uid: Callable[[str], int | None] | None = None,
) -> VerifiedConnection:
    """Open the connection, verify the far end, and only then hand it over.

    Nothing is written until the credential has been read and compared: an
    impostor at the address receives zero bytes (rules C2, C4, C5).

    The generation the profile pins is the generation this connection is
    recorded on (article 13). A profile pinned to one this package does not
    speak opens nothing at all: there is no generation to negotiate on, so
    there is no connection to open (article 3).
    """
    import sys

    pinned = negotiate_generation(SUPPORTED_GENERATIONS, profile.contract_generation)
    if pinned is not None:
        raise SocketClientProblem(pinned)

    try:
        adapter = peer_identity or select_peer_identity(platform or sys.platform)
    except PeerIdentityUnsupported as error:
        raise SocketClientProblem(
            _problem(ProblemCode.PEER_IDENTITY_UNSUPPORTED, str(error))
        ) from error

    def open_verified() -> tuple[socket.socket, PeerCredential, int]:
        # Resolved on every open, never once per profile: the account a system
        # profile names may be remapped between two connections (rules C1, C4).
        expected = expected_principal_uid(profile, account_uid=account_uid)
        stream = (socket_factory or _default_socket)()
        try:
            stream.connect(profile.socket_path)
        except OSError as error:
            stream.close()
            raise SocketClientProblem(_problem(ProblemCode.UNREACHABLE, str(error))) from error
        try:
            credential = adapter.establish(stream)
        except Exception as error:
            stream.close()
            raise SocketClientProblem(
                _problem(ProblemCode.PEER_CREDENTIAL_UNAVAILABLE, str(error))
            ) from error
        if credential.uid != expected:
            stream.close()
            raise SocketClientProblem(
                _problem(
                    ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL,
                    f"the process listening there runs as uid {credential.uid}, "
                    f"expected {expected}",
                )
            )
        return stream, credential, expected

    connection = LocalHttpConnection(open_verified)
    connection.connect()
    assert connection.last_credential is not None
    assert connection.last_expected_uid is not None
    return VerifiedConnection(
        profile,
        connection.last_credential,
        connection.last_expected_uid,
        connection,
        negotiated_generation=profile.contract_generation,
    )


def _default_socket() -> socket.socket:
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


def whoami(connection: VerifiedConnection) -> Result[WhoAmI]:
    """The operation the article names, on an already-verified connection."""
    return connection.read_whoami()
