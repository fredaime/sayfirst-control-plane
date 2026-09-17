# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path

import pytest
from sayfirst_contract.artifacts import (
    BINDING_ARTIFACTS,
    DOMAIN_ARTIFACTS,
    DOMAIN_SCHEMAS,
    artifact,
    domain_schema,
    load_json,
)
from sayfirst_contract.binding.http_unix_socket.routes import (
    ACCEPT_HEADER,
    DOCUMENT_MEDIA_TYPE,
    STREAM_MEDIA_TYPE,
    selects_stream,
)
from sayfirst_contract.client import ControlPlaneClient, CouldNotAsk
from sayfirst_contract.decisions import read_decision
from sayfirst_contract.generation import CONTRACT_GENERATION

SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "build_contract.py"
SPEC = importlib.util.spec_from_file_location("build_contract", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def test_the_binding_is_derived_from_the_domain_contract() -> None:
    """Article 13: generation reproduces the committed binding byte for byte."""
    assert (
        BUILD.canonical(BUILD.generate_openapi())
        == artifact("binding", "http-unix-socket", "openapi.json").read_bytes()
    )


def test_every_artefact_is_in_canonical_form() -> None:
    """Article 13: every artefact has one deterministic byte representation."""
    for relative in (*DOMAIN_ARTIFACTS, *BINDING_ARTIFACTS, "digests.json"):
        raw = artifact(*relative.split("/")).read_bytes()
        assert raw == BUILD.canonical(json.loads(raw))


def _digest_failures(root: Path) -> tuple[str, ...]:
    digests = json.loads((root / "digests.json").read_text(encoding="utf-8"))["artifacts"]
    return tuple(
        relative
        for relative, expected in digests.items()
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected
    )


def test_every_artefact_matches_its_digest() -> None:
    """Article 13: the byte pin covers every domain and binding artefact."""
    root = Path(str(artifact()))
    assert _digest_failures(root) == ()


def test_the_digest_guard_catches_a_reformatted_artefact(tmp_path: Path) -> None:
    """Article 13: harmless-looking byte changes are still review-visible."""
    source = Path(str(artifact()))
    import shutil

    target = tmp_path / "contracts"
    shutil.copytree(source, target)
    schema = target / "domain" / "schemas" / "decision-result.schema.json"
    schema.write_text(json.dumps(json.loads(schema.read_text()), indent=4) + "\n")
    assert "domain/schemas/decision-result.schema.json" in _digest_failures(target)


def _schema_from_binding(name: str, embedded: dict[str, object]) -> dict[str, object]:
    restored = copy.deepcopy(embedded)

    def refs(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    key == "$ref"
                    and isinstance(item, str)
                    and item.startswith("#/components/schemas/")
                ):
                    value[key] = item.removeprefix("#/components/schemas/") + ".schema.json"
                else:
                    refs(item)
        elif isinstance(value, list):
            for item in value:
                refs(item)

    refs(restored)
    source = domain_schema(name)
    restored["$schema"] = source["$schema"]
    restored["x-spdx-license-identifier"] = source["x-spdx-license-identifier"]
    return restored


def _binding_vocabulary_failures(binding: dict[str, object]) -> tuple[str, ...]:
    failures = []
    schemas = binding["components"]["schemas"]
    for name in DOMAIN_SCHEMAS:
        if _schema_from_binding(name, schemas[name]) != domain_schema(name):
            failures.append(f"schema:{name}")
    registry = load_json("domain", "problem-codes.json")["codes"]
    operations = set()
    parameter_names = set()
    header_names = set()

    def enum_outside_schema(value: object) -> bool:
        if isinstance(value, dict):
            return "enum" in value or any(enum_outside_schema(item) for item in value.values())
        if isinstance(value, list):
            return any(enum_outside_schema(item) for item in value)
        return False

    if enum_outside_schema({"info": binding["info"], "paths": binding["paths"]}):
        failures.append("enum-outside-domain")
    for path_item in binding["paths"].values():
        for operation in path_item.values():
            operations.add(operation["operationId"])
            for item in operation.get("parameters", []):
                # A header is the transport's own vocabulary, which this binding
                # names; a path or query member is domain vocabulary and is not.
                if item["in"] == "header":
                    header_names.add(item["name"])
                else:
                    parameter_names.add(item["name"])
            for response in operation["responses"].values():
                for code in response.get("x-problem-codes", []):
                    if code not in registry or registry[code]["origin"] != "server":
                        failures.append(f"problem:{code}")
    protocol_operations = {
        name
        for name, value in inspect.getmembers(ControlPlaneClient, inspect.isfunction)
        if not name.startswith("_")
    }
    if operations != protocol_operations:
        failures.append("operations")
    if not parameter_names <= {
        "contract_generation",
        "scope",
        "approval_ref",
        "decision_ref",
        "from_sequence",
        "to_sequence",
        "page_size",
    }:
        failures.append("parameters")
    if not header_names <= {ACCEPT_HEADER}:
        failures.append("headers")
    return tuple(failures)


def test_the_binding_adds_no_vocabulary() -> None:
    """Articles 4 and 13: the binding maps only published domain words."""
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    assert _binding_vocabulary_failures(binding) == ()


def test_the_binding_publishes_decision_reads_policy_status_and_grant_streams() -> None:
    """Articles 6 and 13: block 2.3 operations are in the generated binding."""
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    assert "/decisions/{decision_ref}" in binding["paths"]
    assert "/policy/status" in binding["paths"]
    decision_post = binding["paths"]["/decisions"]["post"]
    content = decision_post["responses"]["200"]["content"]
    assert {"application/json", "text/event-stream"} <= set(content)


def test_the_vocabulary_guard_catches_a_binding_with_an_extra_code() -> None:
    """Article 13: the binding guard catches a planted code."""
    binding = copy.deepcopy(load_json("binding", "http-unix-socket", "openapi.json"))
    operation = next(iter(next(iter(binding["paths"].values())).values()))
    next(iter(operation["responses"].values()))["x-problem-codes"] = ["route_not_found"]
    assert "problem:route_not_found" in _binding_vocabulary_failures(binding)


def test_the_scenario_documentation_is_derived_from_the_file() -> None:
    """Article 13: scenario prose is generated from the authoritative file."""
    assert BUILD.write_or_check(check=True, docs=True) == ()


def test_the_docs_option_selects_the_generated_scenario_prose() -> None:
    """Article 13: explicit prose generation includes the README output."""
    assert BUILD.README not in BUILD.outputs(docs=False)
    assert BUILD.README in BUILD.outputs(docs=True)


def test_the_binding_publishes_the_selector_between_its_two_answer_media_types() -> None:
    """Article 13: how a server chooses between two published answers is published."""
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    operation = binding["paths"]["/decisions"]["post"]
    selector = operation["x-media-type-selector"]
    content = operation["responses"]["200"]["content"]
    assert selector["header"] == ACCEPT_HEADER
    assert set(content) == {selector["selects"], selector["otherwise"]}
    assert selector["selects"] == STREAM_MEDIA_TYPE
    assert selector["otherwise"] == DOCUMENT_MEDIA_TYPE
    # The rule reads one header and names the response it governs, and holds
    # no further condition: a reader implements it from these members alone.
    assert set(selector) == {"header", "selects", "otherwise", "response"}
    assert selector["response"] == "200"
    assert set(operation["responses"]) - {"200"}
    header = next(item for item in operation["parameters"] if item["name"] == ACCEPT_HEADER)
    assert header["in"] == "header" and header["required"] is False
    for path_item in binding["paths"].values():
        for other in path_item.values():
            published = set(other["responses"]["200"]["content"])
            assert ("x-media-type-selector" in other) == (len(published) > 1), other["operationId"]


def test_the_binding_says_what_a_boundary_holding_the_stream_must_not_do() -> None:
    """Article 13: the recorded reason is true because the binding says it is.

    A grant's issuing connection is part of what the grant is (article 10), so
    the daemon watches the read side of the stream for the boundary going away.
    A socket's read side cannot tell a peer that closed from a peer that shut
    only its write side down: both are end of file, and both are recorded
    `connection_lost`. The mechanism has no way to be finer, so the binding is
    what makes the record true — a boundary that holds this stream keeps its
    write side open for as long as it holds the grant, and one that does not
    has said, in the only word the transport has, that it is gone (article 2).
    """
    binding = load_json("binding", "http-unix-socket", "openapi.json")
    operation = binding["paths"]["/decisions"]["post"]
    hold = operation["x-stream-hold"]
    assert set(hold) == {
        "description",
        "half-close",
        "reason-at-end-of-file",
        "response",
        "selects",
    }
    assert hold["half-close"] == "forbidden"
    assert hold["reason-at-end-of-file"] == "connection_lost"
    assert hold["response"] == "200"
    assert hold["selects"] == STREAM_MEDIA_TYPE
    assert hold["selects"] in operation["responses"]["200"]["content"]
    # Published where a stream is published and nowhere else: an operation that
    # answers one media type holds no connection and has nothing to require.
    for path_item in binding["paths"].values():
        for other in path_item.values():
            streams = STREAM_MEDIA_TYPE in other["responses"]["200"]["content"]
            assert ("x-stream-hold" in other) == streams, other["operationId"]


@pytest.mark.parametrize(
    ("accept", "stream"),
    [
        (None, False),
        ("", False),
        ("application/json", False),
        ("*/*", False),
        ("text/event-stream", True),
        ("Text/Event-Stream", True),
        ("application/json, text/event-stream", True),
        ("text/event-stream;q=0.5", True),
        ("text/event-stream; q=0", False),
        ("text/event-stream;q=nonsense", False),
        ("text/event-streaming", False),
    ],
)
def test_the_published_selector_reads_one_header_and_defaults_to_the_document(
    accept: str | None, stream: bool
) -> None:
    """Articles 10 and 13: only an explicit acceptance selects the connection-bound answer."""
    assert selects_stream(accept) is stream


def test_the_could_not_asks_of_the_decide_route_are_read_as_could_not_asks() -> None:
    """Articles 1 and 2: a « could not ask » is never read as a denial, by either reader.

    The distinction this holds is the product's first one: an effect that has
    not started does not start, and the caller is not told a policy or a person
    refused it. `policy_unavailable` has a golden scenario saying so
    (`policy_unavailable_is_could_not_ask`); the other codes the decide route
    publishes at 503 have none, because a scenario for any of them would need a
    `given` member the published reader does not define and a server able to
    produce the failure on demand — a race, for one of them. So the class is
    held here for every one of them, through the published client and the
    whoami reader both.

    Every code this route publishes at 503 is walked, not a chosen few: the
    status says the daemon could not answer, the registry's class column says
    « could not ask » for each, and a code added at 503 with the other class
    arrives here as a failure rather than as a difference nobody notices.
    """
    from sayfirst_contract.binding.http_unix_socket.client import SocketClient
    from sayfirst_contract.problems import ProblemCode
    from sayfirst_contract.whoami import classify

    binding = load_json(*BINDING_ARTIFACTS[0].split("/"))
    published: set[str] = set()
    for path_item in binding["paths"].values():  # type: ignore[union-attr]
        for operation in path_item.values():
            if operation["operationId"] != "ask_decision":
                continue
            published.update(operation["responses"]["503"]["x-problem-codes"])
    published_at_503 = tuple(sorted(published))
    assert {
        "policy_unavailable",
        "approval_provider_unavailable",
        "decision_contended",
        "decision_store_unavailable",
        "policy_archive_unavailable",
        "peer_credential_unavailable",
        "principal_groups_unavailable",
    } <= published
    # The reader, not a connection: nothing is asked of a daemon here, and the
    # client is constructed over a path it never reaches.
    reader = SocketClient(Path("/nonexistent/daemon.sock"), expected_uid=0)
    for code in published_at_503:
        answer = reader._interpret(
            503,
            {
                "contract_generation": CONTRACT_GENERATION,
                "code": code,
                "message": "the daemon could not answer",
                "retryable": True,
            },
            read_decision,
        )
        assert isinstance(answer, CouldNotAsk), f"{code} is not read as a could-not-ask"
        assert answer.problem.code is ProblemCode(code)
        assert answer.problem.retryable is True
        assert classify(code) == "could_not_ask"
