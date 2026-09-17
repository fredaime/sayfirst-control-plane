# SPDX-License-Identifier: Apache-2.0
"""Generate and byte-check the one binding, its digests, and scenario prose."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from sayfirst_contract.artifacts import (  # noqa: E402
    BINDING_ARTIFACTS,
    DOMAIN_ARTIFACTS,
    DOMAIN_DOCUMENTS,
    DOMAIN_SCHEMAS,
)
from sayfirst_contract.binding.http_unix_socket.routes import (  # noqa: E402
    ACCEPT_HEADER,
    DOCUMENT_MEDIA_TYPE,
    ROUTES,
    STREAM_MEDIA_TYPE,
    Route,
)

SOURCE_ROOT = PACKAGE_ROOT / "src" / "sayfirst_contract"
CONTRACT_ROOT = SOURCE_ROOT / "_contracts"
README = PACKAGE_ROOT / "README.md"
SCENARIO_START = "<!-- BEGIN GENERATED SCENARIOS -->"
SCENARIO_END = "<!-- END GENERATED SCENARIOS -->"


def canonical(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _load(relative: str) -> object:
    return json.loads((CONTRACT_ROOT / relative).read_text(encoding="utf-8"))


def _rewrite_refs(value: object) -> object:
    if isinstance(value, dict):
        rewritten = {}
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str) and item.endswith(".schema.json"):
                rewritten[key] = f"#/components/schemas/{item.removesuffix('.schema.json')}"
            else:
                rewritten[key] = _rewrite_refs(item)
        return rewritten
    if isinstance(value, list):
        return [_rewrite_refs(item) for item in value]
    return value


def _schema(name: str) -> dict[str, object]:
    document = _load(f"domain/schemas/{name}.schema.json")
    assert isinstance(document, dict)
    document.pop("$schema", None)
    document.pop("x-spdx-license-identifier", None)
    return _rewrite_refs(document)  # type: ignore[return-value]


# Where a parameter's shape is already published, it is read out of the schema
# that publishes it rather than spelled a second time (article 13). The evidence
# range parameters name no document member, so they carry their own shape.
_PARAMETER_SCHEMAS = {
    "approval_ref": "approval-resolve-request",
    "decision_ref": "decision-record",
    "scope": "approval-resolve-request",
    "contract_generation": "decision-ask-request",
}


def _parameter(name: str, where: str, *, required: bool = True) -> dict[str, object]:
    schema_name = _PARAMETER_SCHEMAS.get(name)
    if schema_name is None:
        schema: dict[str, object] = {"minimum": 1, "type": "integer"}
        if name == "page_size":
            schema["maximum"] = 100
    else:
        source_schema = _load(f"domain/schemas/{schema_name}.schema.json")
        assert isinstance(source_schema, dict)
        schema = source_schema["properties"][name]
    return {
        "in": where,
        "name": name,
        "required": required,
        "schema": schema,
    }


def _operation(route: Route) -> dict[str, object]:
    content = {DOCUMENT_MEDIA_TYPE: {"schema": {"$ref": f"#/components/schemas/{route.response}"}}}
    if route.stream:
        content[STREAM_MEDIA_TYPE] = {
            "schema": {"oneOf": [{"$ref": f"#/components/schemas/{name}"} for name in route.stream]}
        }
    operation: dict[str, object] = {
        "operationId": route.operation,
        "responses": {
            "200": {
                "content": content,
                "description": "Answered",
            }
        },
    }
    if route.stream:
        # Two answer media types need a published rule for choosing between
        # them, or a client and a server can each pick one and both believe
        # they conform (article 13). The rule names the response it governs:
        # a refusal publishes one media type, so nothing chooses there.
        operation["x-media-type-selector"] = {
            "header": ACCEPT_HEADER,
            "otherwise": DOCUMENT_MEDIA_TYPE,
            "response": "200",
            "selects": STREAM_MEDIA_TYPE,
        }
        # A grant's issuing connection is part of what the grant is (article
        # 10), so the daemon watches the read side of this stream for the
        # boundary going away. A socket's read side cannot tell a peer that
        # closed from a peer that shut only its write side down — both are end
        # of file — so no mechanism can make the record finer, and the binding
        # is what makes it true (article 13). Published where the stream is.
        operation["x-stream-hold"] = {
            "description": (
                "A boundary that holds this stream keeps the connection's write side open "
                "for as long as it holds the grant. The control plane watches the read "
                "side for the loss article 10 names, where a peer that closed and a peer "
                "that shut its write side down are one event."
            ),
            "half-close": "forbidden",
            "reason-at-end-of-file": "connection_lost",
            "response": "200",
            "selects": STREAM_MEDIA_TYPE,
        }
    if route.request is not None:
        operation["requestBody"] = {
            "content": {
                "application/json": {"schema": {"$ref": f"#/components/schemas/{route.request}"}}
            },
            "required": True,
        }
    parameters: list[dict[str, object]] = []
    if route.stream:
        parameters.append(
            {
                "in": "header",
                "name": ACCEPT_HEADER,
                "required": False,
                "schema": {"maxLength": 256, "type": "string"},
            }
        )
    for reference in ("approval_ref", "decision_ref"):
        if "{" + reference + "}" in route.path:
            parameters.append(_parameter(reference, "path"))
    if "{scope}" in route.path:
        parameters.append(_parameter("scope", "path"))
    if route.operation in {
        "read_approval",
        "read_decision",
        "read_policy_status",
        "read_evidence",
        "export_evidence",
    }:
        parameters.append(_parameter("contract_generation", "query"))
    if route.operation in {"read_approval", "read_decision"}:
        parameters.append(_parameter("scope", "query"))
    if route.operation == "read_evidence":
        parameters.extend(
            (
                _parameter("from_sequence", "query"),
                _parameter("page_size", "query", required=False),
            )
        )
    if route.operation == "export_evidence":
        parameters.extend(
            (
                _parameter("from_sequence", "query"),
                _parameter("to_sequence", "query", required=False),
            )
        )
    if parameters:
        operation["parameters"] = parameters
    responses = operation["responses"]
    assert isinstance(responses, dict)
    for status_code, codes in route.problems.items():
        responses[str(status_code)] = {
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/problem-document"}}
            },
            "description": "Refused",
            "x-problem-codes": sorted(codes),
        }
    return operation


def generate_openapi() -> dict[str, object]:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    marker = _load("domain/generation.json")
    assert isinstance(marker, dict)
    paths: dict[str, object] = {}
    for route in ROUTES:
        paths.setdefault(route.path, {})[route.method.lower()] = _operation(route)  # type: ignore[index]
    return {
        "components": {"schemas": {name: _schema(name) for name in DOMAIN_SCHEMAS}},
        "info": {
            "title": project["name"],
            "version": project["version"],
            "x-contract-generation": marker["contract_generation"],
        },
        "openapi": "3.1.0",
        "paths": paths,
        "servers": [
            {
                "description": (
                    "The host is a placeholder and is ignored by the daemon; the surface is "
                    "reached over the one Unix domain socket, whose path the deployment "
                    "configures (see docs/deployment.md)."
                ),
                "url": "http://sayfirst",
                "x-socket-path-default": "/run/sayfirst/daemon.sock",
            }
        ],
        "x-spdx-license-identifier": "Apache-2.0",
        "x-transport": "http-unix-socket",
    }


def generate_digests(binding_bytes: bytes) -> dict[str, object]:
    artifacts = {}
    for relative in (*DOMAIN_ARTIFACTS, *DOMAIN_DOCUMENTS):
        artifacts[relative] = hashlib.sha256((CONTRACT_ROOT / relative).read_bytes()).hexdigest()
    assert BINDING_ARTIFACTS == ("binding/http-unix-socket/openapi.json",)
    artifacts[BINDING_ARTIFACTS[0]] = hashlib.sha256(binding_bytes).hexdigest()
    return {
        "artifacts": artifacts,
        "x-contract-generation": _load("domain/generation.json")["contract_generation"],  # type: ignore[index]
        "x-spdx-license-identifier": "Apache-2.0",
    }


def generate_scenario_docs() -> str:
    document = _load("domain/golden-scenarios.json")
    assert isinstance(document, dict)
    lines = [SCENARIO_START, "", "| Scenario | Binds | Article | Expected |", "|---|---|---:|---|"]
    for name, scenario in document["scenarios"].items():
        expected = ", ".join(f"`{key}={value}`" for key, value in scenario["expect"].items())
        if "then" in scenario:
            after_the_act = scenario["then"]["expect"]
            expected += f", `state={after_the_act['state']}`"
            # A scenario that scripts a re-ask asserts what the re-ask answers,
            # and the prose says so: a reader of this table must be able to see
            # which fixture reaches a published reason (article 13).
            for key, value in (after_the_act.get("after_resolution") or {}).items():
                expected += f", `after_resolution.{key}={value}`"
        lines.append(f"| `{name}` | {scenario['binds']} | {scenario['article']} | {expected} |")
    lines.extend(("", SCENARIO_END))
    return "\n".join(lines)


def _replace_docs(current: str, generated: str) -> str:
    before, separator, remainder = current.partition(SCENARIO_START)
    if not separator:
        raise ValueError("README lacks generated scenario markers")
    _, separator, after = remainder.partition(SCENARIO_END)
    if not separator:
        raise ValueError("README lacks closing scenario marker")
    return before + generated + after


def outputs(*, docs: bool) -> Mapping[Path, bytes]:
    binding = canonical(generate_openapi())
    generated = {
        CONTRACT_ROOT / BINDING_ARTIFACTS[0]: binding,
        CONTRACT_ROOT / "digests.json": canonical(generate_digests(binding)),
    }
    if docs:
        generated[README] = _replace_docs(
            README.read_text(encoding="utf-8"), generate_scenario_docs()
        ).encode()
    return generated


def write_or_check(*, check: bool, docs: bool) -> tuple[str, ...]:
    differences = []
    for target, content in outputs(docs=docs).items():
        if check:
            if not target.exists() or target.read_bytes() != content:
                differences.append(str(target.relative_to(PACKAGE_ROOT)))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    return tuple(differences)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--docs", action="store_true", help="include generated scenario prose")
    arguments = parser.parse_args()
    differences = write_or_check(check=arguments.check, docs=arguments.docs or arguments.check)
    if differences:
        for difference in differences:
            print(f"generated artefact differs: {difference}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
