# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import http.client
import json
import os
import socket
from collections.abc import Mapping
from pathlib import Path

import pytest
from sayfirst_contract.client import CouldNotAsk, Refused
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_contract.generation import negotiate_generation
from sayfirst_contract.golden import schema_examples
from sayfirst_contract.problems import ProblemCode, problem_retryable
from sayfirst_contract.transport.peer import PeerCredential
from sayfirst_contract.transport.socket_client import (
    PLACEHOLDER_HOST,
    ProfileMisuse,
    SocketClientProblem,
    SocketProfile,
    VerifiedConnection,
    connect,
    declared_delegation,
    expected_principal_uid,
)
from sayfirst_testing.doubles import StaticPeerIdentity
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms
from sayfirst_testing.privileges import requires_unprivileged

_AT = "2026-09-04T00:00:00+00:00"
WHOAMI_ANSWER = {
    "contract_generation": 1,
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


def _credential(uid: int) -> PeerCredential:
    return PeerCredential(uid=uid, gid=0, pid=1, captured_at=_AT)


class RecordingSocket:
    """A socket that remembers the order in which it was used."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.written = bytearray()

    def connect(self, address: str) -> None:
        self.calls.append("connect")

    def getsockopt(self, *_: object) -> bytes:
        self.calls.append("getsockopt")
        return b""

    def sendall(self, data: bytes) -> None:
        self.calls.append("sendall")
        self.written.extend(data)

    send = sendall

    def close(self) -> None:
        self.calls.append("close")

    def makefile(self, *_: object, **__: object):  # type: ignore[no-untyped-def]
        import io
        import json as _json

        body = _json.dumps(WHOAMI_ANSWER, sort_keys=True).encode()
        head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        return io.BytesIO(head + body)

    def settimeout(self, value: object) -> None:
        pass


def test_a_system_profile_names_its_daemon_user() -> None:
    """Article 6, rule C1: never a default to root, on any host."""
    with pytest.raises(ProfileMisuse):
        SocketProfile("/run/d.sock", mode="system")
    with pytest.raises(ProfileMisuse):
        SocketProfile("/run/d.sock", mode="system", daemon_user="")
    with pytest.raises(ProfileMisuse):
        SocketProfile("/run/d.sock", mode="loopback")
    assert SocketProfile("/run/d.sock", mode="system", daemon_user="daemon").daemon_user == "daemon"
    assert expected_principal_uid(SocketProfile("/run/d.sock")) == os.geteuid()
    assert (
        expected_principal_uid(
            SocketProfile("/run/d.sock", mode="system", daemon_user="daemon"),
            account_uid=lambda _: 4242,
        )
        == 4242
    )


def test_the_client_sends_nothing_before_it_has_verified_the_server() -> None:
    """Article 6, rule C2: the request is never sent to an impostor."""
    recorder = RecordingSocket()
    profile = SocketProfile("/run/d.sock")
    with pytest.raises(SocketClientProblem) as refusal:
        connect(
            profile,
            peer_identity=StaticPeerIdentity(_credential(os.geteuid() + 1)),
            socket_factory=lambda: recorder,  # type: ignore[arg-type,return-value]
        )
    assert refusal.value.problem.code is ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL
    assert recorder.calls == ["connect", "close"]
    assert bytes(recorder.written) == b""
    assert refusal.value.classification == "could_not_ask"


def test_the_client_opens_nothing_on_a_platform_with_no_adapter() -> None:
    """Article 6, rule C5: no fallback to an unverified connection."""
    recorder = RecordingSocket()
    with pytest.raises(SocketClientProblem) as refusal:
        connect(
            SocketProfile("/run/d.sock"),
            platform="win32",
            socket_factory=lambda: recorder,  # type: ignore[arg-type,return-value]
        )
    assert refusal.value.problem.code is ProblemCode.PEER_IDENTITY_UNSUPPORTED
    assert recorder.calls == []


@requires_platforms(*OS_REAL_PLATFORMS)
@requires_unprivileged()
def test_an_impostor_bound_at_the_path_is_refused_by_the_client(tmp_path: Path) -> None:
    """Article 6, rule C2: the impostor receives zero bytes.

    Not runnable as root: the impostor binds the address as the tester, and the
    profile expects the daemon to be root, so a root tester *is* the account
    the client is checking for and there is no impostor left to refuse.
    """
    address = tmp_path / "daemon.sock"
    impostor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    accepted = None
    try:
        impostor.bind(str(address))
        impostor.listen(1)
        impostor.settimeout(5)
        profile = SocketProfile(str(address), mode="system", daemon_user="root")
        with pytest.raises(SocketClientProblem) as refusal:
            connect(profile)
        assert refusal.value.problem.code is ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL
        assert str(os.geteuid()) in refusal.value.problem.message
        accepted, _ = impostor.accept()
        accepted.setblocking(False)
        try:
            received = accepted.recv(4096)
        except BlockingIOError:
            received = b""
        assert received == b""
    finally:
        if accepted is not None:
            accepted.close()
        impostor.close()
        address.unlink(missing_ok=True)


def test_a_foreign_credential_on_a_per_user_profile_is_refused() -> None:
    """Article 6, rule C2, scripted: the same refusal without a second account."""
    recorder = RecordingSocket()
    with pytest.raises(SocketClientProblem) as refusal:
        connect(
            SocketProfile("/run/d.sock"),
            peer_identity=StaticPeerIdentity(_credential(os.geteuid() + 7)),
            socket_factory=lambda: recorder,  # type: ignore[arg-type,return-value]
        )
    assert refusal.value.problem.code is ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL
    assert bytes(recorder.written) == b""


def test_the_client_never_sends_a_credential() -> None:
    """Article 6, rule C6: who it is, the boundary says."""
    recorder = RecordingSocket()
    connection = connect(
        SocketProfile("/run/d.sock"),
        peer_identity=StaticPeerIdentity(_credential(os.geteuid())),
        socket_factory=lambda: recorder,  # type: ignore[arg-type,return-value]
    )
    assert connection.verified
    from sayfirst_contract.client import Answered

    result = connection.read_whoami()
    assert isinstance(result, Answered)
    assert result.value.connection_id == "connection-1"
    _assert_no_credential(bytes(recorder.written))

    from sayfirst_contract.decisions import DecisionAsk

    asking = RecordingSocket()
    submission = connect(
        SocketProfile("/run/d.sock"),
        peer_identity=StaticPeerIdentity(_credential(os.geteuid())),
        socket_factory=lambda: asking,  # type: ignore[arg-type,return-value]
    )
    submission.ask_decision(
        DecisionAsk("example.effect"),
        delegation=declared_delegation({"SUDO_USER": "alice", "SUDO_UID": "1001"}),
    )
    _assert_no_credential(bytes(asking.written), allowed=("delegation", '"uid": 1001'))


def _assert_no_credential(written: bytes, allowed: tuple[str, ...] = ()) -> None:
    """The bytes on the wire name no caller: who it is, the boundary says."""
    rendered = written.decode(errors="replace")
    assert rendered, "the client wrote nothing at all"
    lowered = rendered.lower()
    head, _, body = rendered.partition("\r\n\r\n")
    for line in head.splitlines()[1:]:
        name = line.split(":", 1)[0].strip().lower()
        assert name not in {"authorization", "cookie", "proxy-authorization"}, line
        assert not name.startswith("x-"), line
    for forbidden in ("token", "credential", "password", "secret"):
        assert forbidden not in lowered, forbidden
    for forbidden in ('"principal"', '"caller"', '"requested_by"'):
        assert forbidden not in lowered, forbidden
    if '"uid"' in body and not any(item in body for item in allowed):
        raise AssertionError("the request body names a user id")
    assert f"host: {PLACEHOLDER_HOST}".lower() in lowered


def test_a_refusal_and_an_absent_answer_reach_the_caller_apart() -> None:
    """Article 1: the client's two lanes come from the published classification."""
    from sayfirst_contract.transport.socket_client import _classified

    refused = _classified(
        {
            "contract_generation": 1,
            "code": "peer_not_admitted",
            "message": "no",
            "retryable": False,
        }
    )
    unknown = _classified(
        {
            "contract_generation": 1,
            "code": "principal_groups_unavailable",
            "message": "later",
            "retryable": True,
        }
    )
    future = _classified(
        {
            "contract_generation": 1,
            "code": "zz-synthetic-code",
            "message": "?",
            "retryable": None,
        }
    )
    assert isinstance(refused, Refused)
    assert isinstance(unknown, CouldNotAsk)
    assert isinstance(future, CouldNotAsk)
    assert unknown.reported_outcome == "unknown"


def test_a_privilege_tool_is_declared_and_nothing_else_is() -> None:
    """Article 6, rule D4: absence is nothing declared, never no delegation."""
    assert declared_delegation({}) is None
    assert declared_delegation({"USER": "alice"}) is None
    delegation = declared_delegation({"SUDO_USER": "alice", "SUDO_UID": "1001"})
    assert delegation is not None
    assert delegation.status == "declared"
    assert delegation.chain[0].name == "alice"
    assert delegation.chain[0].uid == 1001
    assert delegation.chain[0].via == "privilege_tool"
    assert declared_delegation({"DOAS_USER": "bob"}).chain[0].name == "bob"  # type: ignore[union-attr]


def test_a_client_problem_carries_the_retryability_the_registry_publishes() -> None:
    """Rule P6: the credential the OS did not deliver is refused, retryable, on both sides."""
    from sayfirst_contract.problems import problem_retryable

    recorder = RecordingSocket()
    with pytest.raises(SocketClientProblem) as absent:
        connect(
            SocketProfile("/run/d.sock"),
            peer_identity=StaticPeerIdentity(unavailable=True),
            socket_factory=lambda: recorder,  # type: ignore[arg-type,return-value]
        )
    assert absent.value.problem.code is ProblemCode.PEER_CREDENTIAL_UNAVAILABLE
    assert absent.value.problem.retryable is True
    assert absent.value.classification == "could_not_ask"

    with pytest.raises(SocketClientProblem) as impostor:
        connect(
            SocketProfile("/run/d.sock"),
            peer_identity=StaticPeerIdentity(_credential(os.geteuid() + 1)),
            socket_factory=lambda: RecordingSocket(),  # type: ignore[arg-type,return-value]
        )
    with pytest.raises(SocketClientProblem) as unsupported:
        connect(
            SocketProfile("/run/d.sock"),
            platform="win32",
            socket_factory=lambda: RecordingSocket(),  # type: ignore[arg-type,return-value]
        )
    for raised in (absent, impostor, unsupported):
        problem = raised.value.problem
        assert isinstance(problem.code, ProblemCode)
        assert problem.retryable == problem_retryable(problem.code), problem.code


def test_a_two_hundred_this_generation_cannot_read_is_could_not_ask() -> None:
    """Articles 1 and 2: an unreadable answer is an unknown, never a traceback.

    `read_status` and `read_whoami` wrap their read in `_unreadable`, so a 200
    whose body is missing a member of this generation's shape becomes the
    published `answer_unreadable` problem. `ask_decision` called `read_decision`
    bare, so the same answer on the one operation that decides an effect left
    the exception to the caller: `sayfirst ask --json` exited 1 on a `KeyError`
    with a traceback, on the path this module's own docstring says never turns
    could not ask into anything else.
    """
    from sayfirst_contract.decisions import DecisionAsk
    from sayfirst_contract.transport.socket_client import VerifiedConnection

    class Answer:
        status = 200

        def read(self) -> bytes:
            # A well-formed document of this generation, missing `decision_ref`.
            return b'{"contract_generation": 1, "outcome": "allow"}'

    class Truncating:
        def request(self, *args: object, **members: object) -> None:
            pass

        def getresponse(self) -> Answer:
            return Answer()

        def close(self) -> None:
            pass

    uid = os.geteuid()
    connection = VerifiedConnection(
        SocketProfile("/run/d.sock"),
        _credential(uid),
        uid,
        Truncating(),  # type: ignore[arg-type]
    )

    result = connection.ask_decision(DecisionAsk("example.effect"))

    assert isinstance(result, CouldNotAsk), result
    assert result.problem.code is ProblemCode.ANSWER_UNREADABLE, result.problem
    assert result.reported_outcome == "unknown"


def _verified(http_connection: object) -> VerifiedConnection:
    """A connection already past the credential check, speaking to a scripted far end."""
    uid = os.geteuid()
    return VerifiedConnection(
        SocketProfile("/run/d.sock"),
        _credential(uid),
        uid,
        http_connection,  # type: ignore[arg-type]
    )


def _connection_answering(status: int, body: bytes) -> VerifiedConnection:
    """A far end that answers those exact bytes, whatever they are."""

    class Answer:
        def __init__(self) -> None:
            self.status = status

        def read(self) -> bytes:
            return body

    class Http:
        def request(self, *args: object, **members: object) -> None:
            pass

        def getresponse(self) -> Answer:
            return Answer()

        def close(self) -> None:
            pass

    return _verified(Http())


def _connection_dropping_after_the_request() -> VerifiedConnection:
    """A far end that read the request whole and then hung up without answering."""

    class Http:
        def request(self, *args: object, **members: object) -> None:
            pass

        def getresponse(self) -> object:
            raise http.client.RemoteDisconnected("remote end closed connection without response")

        def close(self) -> None:
            pass

    return _verified(Http())


def _connection_that_cannot_write_its_request(error: Exception) -> VerifiedConnection:
    """A far end that never receives the request, because writing it failed."""

    class Http:
        def request(self, *args: object, **members: object) -> None:
            raise error

        def getresponse(self) -> object:  # pragma: no cover - never reached
            raise AssertionError("the request was never written")

        def close(self) -> None:
            pass

    return _verified(Http())


def _ask() -> DecisionAsk:
    return DecisionAsk(capability="example.effect", scope="local")


def test_a_request_that_could_not_be_written_is_not_an_answer_that_could_not_be_read() -> None:
    """No answer exists to be unreadable: nothing was obtained (articles 1 and 2).

    A `ValueError` raised while the request is being written — a method or a
    header this client would have to have built wrongly — sat in the same clause
    as the parse of the answer, and so was reported as « the answer is not a
    document of this generation » for an answer that never arrived. The two are
    separate guards now, and this holds the seam: the code is the one for a
    control plane that could not be reached, with the retryability the registry
    publishes, because a request that never left this side took nothing.
    """
    connection = _connection_that_cannot_write_its_request(ValueError("method is not valid"))
    with pytest.raises(SocketClientProblem) as raised:
        connection.read_status()
    assert raised.value.problem.code is ProblemCode.UNREACHABLE
    assert raised.value.problem.retryable is problem_retryable(ProblemCode.UNREACHABLE)
    assert raised.value.classification == "could_not_ask"


def test_a_two_hundred_that_is_not_json_is_an_unreadable_answer_not_an_unreachable_plane() -> None:
    """The control plane WAS reached; what arrived cannot be read (articles 1 and 2).

    It was left as `unreachable` on purpose while the two clients of this
    contract disagreed about classes, so that `ask`'s observable behaviour did
    not move under a fix round. The registry's class column settles it:
    `answer_unreadable` is a could-not-ask, exactly as `unreachable` is, so the
    code and the message move and the classification does not.
    """
    connection = _connection_answering(200, b"<!doctype html>")
    with pytest.raises(SocketClientProblem) as raised:
        connection.read_status()
    assert raised.value.problem.code is ProblemCode.ANSWER_UNREADABLE
    assert raised.value.classification == "could_not_ask"


#: The document each of the two 200-readers reads, by the name the published
#: examples give it.
_READ_DOCUMENTS: dict[str, str] = {
    "read_status": "status-result",
    "read_whoami": "whoami-result",
}


def _a_number_too_large_for_an_integer(reader: str) -> bytes:
    """The reader's own document, with one integer member too large to be one.

    `1e400` is valid JSON that parses to a float infinity, so the `int(...)` an
    integer member goes through raises `OverflowError`. The document is
    otherwise exactly this generation's shape, so the reader reaches that
    member rather than failing earlier for another reason.
    """
    sentinel = "a-number-too-large"
    document = dict(schema_examples()[_READ_DOCUMENTS[reader]])
    if reader == "read_status":
        grade = document["integrity_grade"]
        assert isinstance(grade, Mapping)
        document["integrity_grade"] = {**grade, "reevaluation_interval_seconds": sentinel}
    else:
        document["group_lifetime_seconds"] = sentinel
    return json.dumps(document).replace(f'"{sentinel}"', "1e400").encode()


@pytest.mark.parametrize("reader", sorted(_READ_DOCUMENTS))
@pytest.mark.parametrize("body", ["an array", "a number too large for an integer"])
def test_a_two_hundred_the_readers_cannot_read_is_the_published_problem(
    reader: str, body: str
) -> None:
    """Both readers answer the published problem for a body they cannot read.

    What this holds is the answer, and not a history: the array never escaped.
    Both readers INDEX their argument, so a JSON array reaches them as a
    `TypeError`, which the clause each of them already named — so that input is
    pinned here as the behaviour it has, never as a raise that was repaired.

    The second input is the one the widened clause is for. `1e400` parses to a
    float infinity and the `int(...)` of an integer member raises
    `OverflowError`, an `ArithmeticError` outside `ValueError` entirely and so
    outside the clause as it stood: it reached the caller as an exception to
    classify for itself, on a read that had already been answered (articles 1
    and 2). It is the one member of the widened tuple these two readers reach;
    `AttributeError` belongs to the readers that ask their argument for a
    member instead of indexing it, and is defensive on this path.
    """
    payload = (
        b'["not", "an", "object"]'
        if body == "an array"
        else _a_number_too_large_for_an_integer(reader)
    )
    answer = getattr(_connection_answering(200, payload), reader)()
    assert isinstance(answer, CouldNotAsk), answer
    assert answer.problem.code is ProblemCode.ANSWER_UNREADABLE, answer.problem
    assert answer.reported_outcome == "unknown"


def test_a_lost_reply_to_a_write_does_not_claim_asking_again_is_safe() -> None:
    """The decision may have been taken and recorded. `retryable` has a third value.

    Nothing here knows whether the far end acted on the request before it went
    away, so nothing here may say that sending it again is safe. Unknown is what
    `null` means, and it is never the more permissive of the two (article 3).
    """
    connection = _connection_dropping_after_the_request()
    with pytest.raises(SocketClientProblem) as raised:
        connection.ask_decision(_ask())
    assert raised.value.problem.code is ProblemCode.UNREACHABLE
    assert raised.value.problem.retryable is None
    assert raised.value.classification == "could_not_ask"


def test_a_lost_reply_to_a_read_still_takes_the_registrys_retryability() -> None:
    """A read that was lost decided nothing, so the column stands as it is written."""
    connection = _connection_dropping_after_the_request()
    with pytest.raises(SocketClientProblem) as raised:
        connection.read_status()
    assert raised.value.problem.code is ProblemCode.UNREACHABLE
    assert raised.value.problem.retryable is problem_retryable(ProblemCode.UNREACHABLE)


def test_a_generation_refusal_takes_its_retryability_from_the_registry() -> None:
    """The refusal wrote its flag by hand, and agreed with the published column by luck."""
    problem = negotiate_generation((1,), 7)
    assert problem is not None
    assert problem.retryable is problem_retryable(ProblemCode.GENERATION_UNSUPPORTED)
