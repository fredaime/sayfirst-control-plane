# SPDX-License-Identifier: Apache-2.0
"""The published media-type selector, read from the binding and served."""

from __future__ import annotations

import json
import os
import socket
from datetime import UTC, datetime

import pytest
from sayfirst_contract.artifacts import load_json
from sayfirst_contract.decisions import DecisionAsk
from sayfirst_control_plane.adapters.api.decision_routes import DecisionRoutes
from sayfirst_control_plane.adapters.file.policy_store import FilePolicyStore
from sayfirst_control_plane.adapters.memory.decision_store import MemoryDecisionStore
from sayfirst_control_plane.adapters.memory.policy_projection import MemoryPolicyProjection
from sayfirst_control_plane.application.decisions import (
    DecisionAnswer,
    DecisionProblem,
    DecisionService,
    GrantSettings,
)
from sayfirst_control_plane.application.grants import GrantConnections
from sayfirst_control_plane.application.policy import PolicyService
from sayfirst_control_plane.domain.policy import DecisionQuestion, Principal
from sayfirst_control_plane.ports.policy_store import (
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)

DIGEST = "sha256:" + "1" * 64


class _Protected(FilePolicyStore):
    """Protection is proven elsewhere; this scenario isolates the answer media type."""

    def protection_at_start(self, expectation):  # type: ignore[no-untyped-def]
        return ProtectionVerdict(ProtectionState.PROTECTED)


def _selector() -> dict[str, object]:
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    assert isinstance(binding, dict)
    return binding["paths"]["/decisions"]["post"]["x-media-type-selector"]


def _policy(outcome: str | None) -> bytes:
    if outcome is None:
        return b'format = 1\n[revision]\nreason = "no rule applies"\n'
    lifetime = "grant_lifetime_seconds = 30\n" if outcome == "allow" else ""
    return (
        "format = 1\n"
        "[revision]\n"
        'reason = "selector scenario"\n'
        "[[rule]]\n"
        'id = "mail"\n'
        'capability = "mail.send"\n'
        'principals = ["user:build"]\n'
        f'outcome = "{outcome}"\n'
        'reason = "host rule"\n'
        f"{lifetime}"
        f'arguments_digest = "{DIGEST}"\n'
    ).encode()


def _routes(
    tmp_path,  # type: ignore[no-untyped-def]
    outcome: str | None,
    *,
    max_connections: int = 1024,
    remove_authority: bool = False,
) -> DecisionRoutes:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_bytes(_policy(outcome))
    os.chmod(policy_path, 0o600)
    clock = lambda: datetime(2026, 9, 4, tzinfo=UTC)  # noqa: E731
    authority = _Protected(policy_path, clock=clock)
    policy = PolicyService(authority, (MemoryPolicyProjection(),), clock=clock)
    policy.start(ProtectionExpectation.per_user(os.getuid()))
    if remove_authority:
        policy_path.unlink()
    return DecisionRoutes(
        DecisionService(
            policy,
            authority,
            MemoryDecisionStore(),
            GrantConnections(max_connections=max_connections, clock=clock),
            settings=GrantSettings(default_lifetime_seconds=30),
            clock=clock,
        )
    )


def _ask(routes: DecisionRoutes, accept: str | None) -> tuple[object, bytes, bytes]:
    question = DecisionQuestion(
        DecisionAsk("mail.send", arguments_digest=DIGEST),
        Principal("process", os.getuid(), "build", tuple(os.getgroups()), ("users",)),
    )
    server, client = socket.socketpair(socket.AF_UNIX)
    client.settimeout(2)
    try:
        answer = routes.ask_decision(question, server, accept=accept)
        # Neither answer ends at the end of the connection: a live grant holds
        # its stream open, and a document answer leaves the connection for the
        # next request. So a stream is read to the end of its first frame and a
        # document to the length it declares.
        data = b""
        while not _complete(data):
            part = client.recv(65536)
            if not part:
                break
            data += part
    finally:
        server.close()
        client.close()
    head, body = data.split(b"\r\n\r\n", 1)
    return answer, head, body


def _complete(data: bytes) -> bool:
    """Whether these bytes already carry the whole of one answer, of either shape.

    A different question from the unit tree's `read_one_document`, which is why
    this is not that: it has to answer for a stream as well as for a document,
    so a head that declares no length is the ordinary case here and a failure
    there. It is also out of that reader's reach — pytest puts a test file's
    own directory on the import path and nothing above it, so `tests/unit` is
    importable from `tests/unit` and not from here. So the head is read for the
    headers it carries rather than for a length that may not be there.
    """
    head, separator, body = data.partition(b"\r\n\r\n")
    if not separator:
        return False
    declared = {
        name.strip().lower(): value.strip()
        for name, _, value in (line.partition(b":") for line in head.split(b"\r\n")[1:])
    }
    length = declared.get(b"content-length")
    return b"\n\n" in body if length is None else len(body) >= int(length)


def _content_type(head: bytes) -> str:
    for line in head.decode().split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-type":
            return value.strip()
    raise AssertionError(f"no content type in {head!r}")


# Every answer the ask operation can give with a 200: the allow that mints a
# grant, and each answer that mints none.
ANSWERS = (
    ("allow", "allow", {}),
    ("deny", "deny", {}),
    ("suspend", "suspend", {}),
    ("policy_absent", None, {}),
    ("full_registry", "allow", {"max_connections": 0}),
)


@pytest.mark.parametrize(("name", "outcome", "options"), ANSWERS)
def test_every_answer_is_served_in_the_media_type_the_binding_selects(
    tmp_path,  # type: ignore[no-untyped-def]
    name: str,
    outcome: str | None,
    options: dict[str, object],
) -> None:
    """Article 13: the published selector, not the presence of a grant, picks the answer.

    A third-party boundary that implements `x-media-type-selector` and reads the
    stream must not break on a deny, a suspend, an absent rule or a full grant
    registry; article 2 forbids publishing a rule stronger than what is served.
    """
    selector = _selector()
    selected = str(selector["selects"])
    otherwise = str(selector["otherwise"])

    answer, head, body = _ask(_routes(tmp_path, outcome, **options), selected)  # type: ignore[arg-type]
    assert isinstance(answer, DecisionAnswer), name
    assert head.startswith(b"HTTP/1.1 200 OK\r\n"), name
    assert _content_type(head) == selected, name
    assert body.startswith(b"event: decision\ndata: {"), name
    document = json.loads(body.split(b"\ndata: ", 1)[1].split(b"\n\n", 1)[0])
    assert document["outcome"] == (outcome or "deny")
    assert (document["grant"] is not None) == (name == "allow")

    plain, plain_head, plain_body = _ask(_routes(tmp_path, outcome, **options), otherwise)  # type: ignore[arg-type]
    assert isinstance(plain, DecisionAnswer), name
    assert _content_type(plain_head) == otherwise, name
    assert json.loads(plain_body)["outcome"] == (outcome or "deny")


def test_the_selector_governs_the_answered_response_and_says_so(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """Articles 2 and 13: a refusal is published in one media type, and the selector says so."""
    selector = _selector()
    assert selector["response"] == "200"
    answer, head, body = _ask(
        _routes(tmp_path, "allow", remove_authority=True), str(selector["selects"])
    )
    assert isinstance(answer, DecisionProblem)
    assert head.startswith(b"HTTP/1.1 503 Service Unavailable\r\n")
    assert _content_type(head) == str(selector["otherwise"])
    assert json.loads(body)["code"] == "policy_unavailable"
