<!-- SPDX-License-Identifier: Apache-2.0 -->
---
kind: spec
status: draft
date: 2026-09-04
block: "2.1"
title: The contract distribution (article 13)
branch: skeleton/spec-21
---

# Block 2.1 — The contract distribution

> **Note, 2026-09-05.** This document writes the command of articles 6, 7 and 11
> as `sayfirst whoami` and `sayfirst status`, which is what the name was when the
> design was approved on 2026-09-04. On 2026-09-05 the operator settled a
> collision between two repositories: `sayfirst` — the distribution
> `sayfirst-cli`, the import package `sayfirst_cli` and the console script
> `sayfirst` — belongs to the product command-line interface, and the operator
> surface that inspects this repository's daemon is `sayfirstd` in all three
> forms. Nothing else in this design changes: no schema, no operation name, no
> module path, and no distribution of the contract family is renamed. The
> sentences above are left as they were written, because a design note records
> the decision of its own date and rewriting it would erase the history this
> note exists to keep.

## Purpose

This block designs the **contract distribution** that this repository publishes beside the server: a wheel named `sayfirst-contract` carrying the **domain contract** of article 13 — JSON schemas, the golden scenarios, the problem-code registry, the attribute registry and the contract generation marker — and, published beside it in the same wheel, the domain contract's **one transport binding**: the OpenAPI document for HTTP served over the Unix domain socket of article 6. The domain contract names no transport; the binding is derived from it by a script, adds no vocabulary to it, and is pinned byte for byte. The block also fixes **generation 1** of the contract: the exact request shapes, response shapes, outcome vocabulary, problem codes and scenarios the walking skeleton needs to ask one decision about one capability in one scope over the socket, to suspend it for one person's review, and to replay the same scenarios against the server and against the scriptable stub. It implements article 13 in full, and holds articles 1 (three closed outcomes, "could not ask"), 2 (three-valued status surfaces), 4 (no technology in the domain contract), 5 (`scope` on every record), 11 (no payload member by default), 12 (one-person review only, no fourth outcome), 14 (the client depends on this distribution, never on the server) and 15 (licence, SPDX, dependency list) at the contract surface. Every later block of the skeleton (2.2–2.6) depends on it and nothing in it depends on them.

Two decisions of 2026-09-04 shape generation 1: the skeleton ships `PrivacyRedactor` v1 and `ApprovalProvider` v1 from the start, so the contract carries the `suspend` outcome and the one-person approval family in generation 1 rather than adding them later (a new request member is a new generation, article 13); and policy authority is a file with a rebuildable database projection, so the decision result carries the file's `policy_version` and nothing about where it was read from.

## Interfaces

### I.1 Distributions and packages

| Distribution (wheel) | Import package | Contents | Runtime dependencies |
|---|---|---|---|
| `sayfirst-contract` | `sayfirst_contract` | the domain contract artefacts, the binding document, the Python types, the client protocol, the scenario loader, the scenario replayer | **none** (`dependencies = []`) |
| `sayfirst-contract-stub` | `sayfirst_contract_stub` | the scriptable, non-authoritative fake of the control plane: an in-process client and an HTTP-over-socket server for it | `sayfirst-contract==<same version>` |

The stub is reachable through the extra `sayfirst-contract[stub]`, which resolves to `sayfirst-contract-stub==<same version>`, and through nothing else. The approved contract-boundary decision D2 applies as decided: an extra cannot gate a module inside its own wheel, so the stub is its own distribution and the extra is the door to it. A server that depends on `sayfirst-contract` never inherits a fake of itself; a client that wants one asks for it by name.

Both wheels come from this repository and are versioned together. Versioning: the distributions carry one semantic version (`0.1.0` at the skeleton); the **contract generation** (I.3) is a separate integer and is the only thing a client negotiates. A distribution version says nothing a client may act on.

Build metadata, identical for both distributions:

- `requires-python = ">=3.12,<3.15"` — a closed range, the one CI runs.
- `[build-system] requires = ["hatchling==1.32.0"]`, `build-backend = "hatchling.build"`. The backend is pinned because it is part of what the wheel is (byte-pinning, I.9).
- `license = "Apache-2.0"` in `[project]`; every file carries an SPDX line (article 15).
- The wheel of `sayfirst-contract` includes the artefact tree as **package data**: `[tool.hatch.build.targets.wheel] packages = ["src/sayfirst_contract"]` — hatchling includes non-Python files under the package by default; the test of G.2 proves the artefacts load from an installed wheel, not from the source tree.

Repository layout (all new; the repository holds no code before this block):

```text
pyproject.toml                          # uv workspace root (I.10)
packages/
  contract/
    pyproject.toml                      # sayfirst-contract
    README.md
    src/sayfirst_contract/
      __init__.py
      _contracts/                       # the published artefacts, package data
        domain/
          generation.json               # I.3  the generation marker
          problem-codes.json            # I.6  the problem-code registry
          attributes.json               # I.7  the attribute registry
          golden-scenarios.json         # I.8  the golden scenarios
          schemas/
            decision-ask-request.schema.json
            decision-result.schema.json
            approval-result.schema.json
            approval-resolve-request.schema.json
            status-result.schema.json
            problem-document.schema.json
        binding/
          http-unix-socket/
            openapi.json                # I.9  generated, byte-pinned
        digests.json                    # I.9  sha256 of every artefact above
      artifacts.py                      # importlib.resources access to _contracts/
      generation.py                     # CONTRACT_GENERATION and the marker
      values.py                         # Unknown, read_enum
      decisions.py                      # Outcome, Reason, DecisionAsk, Decision
      approvals.py                      # ApprovalState, Resolution, ApprovalResolution, Approval
      status.py                         # IntegrityGrade, Principal, Status
      problems.py                       # ProblemCode, Problem
      client.py                         # Answered / Refused / CouldNotAsk, ControlPlaneClient
      golden.py                         # Scenario, load_scenarios
      replay.py                         # NEW — the scenario replayer (harness protocol, report)
      binding/
        __init__.py
        http_unix_socket/
          __init__.py
          routes.py                     # the route table: the binding's only own input
    scripts/
      build_contract.py                 # generates openapi.json and digests.json; --check
    tests/                              # this block's tests (G)
  contract-stub/
    pyproject.toml                      # sayfirst-contract-stub
    src/sayfirst_contract_stub/
      __init__.py
      stub.py                           # Stub: in-process ControlPlaneClient scripted by scenario name
      stub_http.py                      # serves the binding over a Unix socket with http.server
    tests/
```

The socket **client** (the counterpart of `stub_http.py`) is *not* delivered by this block: it needs the server's socket and the peer-credential rule of article 6, which arrive with the transport block. Its module path is reserved here as `sayfirst_contract/binding/http_unix_socket/client.py` and its contract is fixed by B.16–B.18 so that the transport block implements, not designs, it.

### I.2 Artefact access

Every artefact is read through `importlib.resources`, never through a path relative to `__file__`:

```python
# sayfirst_contract/artifacts.py
from importlib.resources import files
from importlib.resources.abc import Traversable

def artifact(*parts: str) -> Traversable:
    """A published artefact, by its path under `_contracts/` (e.g. artifact("domain", "generation.json"))."""
    return files(__package__).joinpath("_contracts", *parts)

def load_json(*parts: str) -> object:
    return json.loads(artifact(*parts).read_text(encoding="utf-8"))

def domain_schema(name: str) -> dict[str, object]:
    """One of DOMAIN_SCHEMAS by its short name (e.g. "decision-result")."""

DOMAIN_SCHEMAS: Final[tuple[str, ...]] = (
    "decision-ask-request", "decision-result",
    "approval-resolve-request", "approval-result",
    "status-result", "problem-document",
)
DOMAIN_ARTIFACTS: Final[tuple[str, ...]] = (
    "domain/generation.json", "domain/problem-codes.json", "domain/attributes.json",
    "domain/golden-scenarios.json",
    *(f"domain/schemas/{name}.schema.json" for name in DOMAIN_SCHEMAS),
)
BINDING_ARTIFACTS: Final[tuple[str, ...]] = ("binding/http-unix-socket/openapi.json",)
```

`DOMAIN_ARTIFACTS` and `BINDING_ARTIFACTS` are the two lists every guard of G iterates over; a file present under `_contracts/` and absent from both lists fails `test_every_artefact_is_listed` (G.1).

### I.3 The generation marker

`_contracts/domain/generation.json`:

```json
{
  "contract_generation": 1,
  "deprecated_generations": []
}
```

- `contract_generation` — integer ≥ 1. The generation this package pins. It is the **only** version a client negotiates.
- `deprecated_generations` — array of `{"contract_generation": <int>, "deprecated_since": "<YYYY-MM-DD>", "deprecated_in_release": "<semver>"}`. Generation 1 has none. When generation 2 is published, generation 1 enters this list with the date and release its deprecation was announced in; a server built from that package accepts both until the window of article 8 (at least two minor releases or six months, whichever is longer) has expired, and the release notes say so (`GOVERNANCE.md`, Releases).

`generation.py`:

```python
CONTRACT_GENERATION: Final[int] = 1
SUPPORTED_GENERATIONS: Final[tuple[int, ...]] = (1,)   # the pinned one plus every deprecated one still in its window

@dataclass(frozen=True)
class GenerationMarker:
    contract_generation: int
    deprecated_generations: tuple[DeprecatedGeneration, ...]

def load_generation_marker() -> GenerationMarker: ...
```

`test_the_pinned_generation_matches_the_marker` (G.3) holds `CONTRACT_GENERATION == load_generation_marker().contract_generation` and `SUPPORTED_GENERATIONS == (marker.contract_generation, *deprecated within window)`, so the integer is written in the artefact and asserted in code, never written twice by hand.

The member name **`contract_generation`** appears in every request document (sent by the client) and every response document (echoed by the server), and nowhere else. There is no minor version: article 13 defines what may change within a generation (additive response members) and says everything else is a new generation, which leaves nothing for a minor number to say.

### I.4 The domain schemas (generation 1)

All six schemas are JSON Schema 2020-12 documents (`"$schema": "https://json-schema.org/draft/2020-12/schema"` — the dialect identifier, exempted by name from the transport-term guard, G.5). They carry `title`, `description`, `"x-contract-generation": 1`, and `"additionalProperties": false` on **request** schemas (a server rejects an undefined request member, B.6) and `"additionalProperties": true` on **response** schemas (a client tolerates an undefined response member, B.7). They carry no `$id`; every `$ref` is a relative file reference to a sibling schema (`"problem-document.schema.json"`), rewritten in-document by the binding generator. Common bounds: `scope` is a string, 1–128 characters, pattern `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; `capability` is a string, 1–128 characters, pattern `^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$` (a capability names a kind of effect, dotted, lower-case — the bound is this project's own rule, restated without reference to any store); every `*_ref` is a string of 1–128 characters; every free-text `reason` or `message` is bounded at 1024 characters; every timestamp is RFC 3339 with an explicit offset (`"format": "date-time"`). Digests are `sha256:` followed by 64 lower-case hexadecimal characters.

**`decision-ask-request`** — what a governed program sends before an effect (article 1). Request: `additionalProperties: false`.

| member | type | required | meaning |
|---|---|---|---|
| `contract_generation` | integer | yes | the client's pinned generation (I.3) |
| `capability` | string | yes | the kind of effect (constitution, preface) |
| `scope` | string | no; absent reads as `"local"` | article 5: a writer that names none writes to `"local"` |
| `arguments_digest` | string (`sha256:…`) | no | a digest of the effect's arguments computed at the boundary; never the arguments (article 11) |
| `correlation` | string ≤128 | no | an opaque token the client chooses to tie its own records to the evidence; the control plane copies it and never interprets it |

There is no `requested_at` (the control plane's clock is the authority, article 3), no principal member (identity is the socket's peer credential, article 6: a member naming the caller would be a claim the server must not believe), and no `program` member (article 11 lists the identity of an effect as capability, scope, principal, decision, timing; a program's self-declared name is at most an observation and is left to a later generation if an open use asks for it).

**`decision-result`** — the answer (articles 1, 2, 3). Response: `additionalProperties: true`.

| member | type | required | meaning |
|---|---|---|---|
| `contract_generation` | integer | yes | echoed (B.3) |
| `authority` | `"authoritative"` (const) | yes | article 3: a decision is an authority record |
| `decision_ref` | string | yes | the record's reference; append-only at the store |
| `scope` | string | yes | the scope the decision was recorded in (`"local"` when the ask named none) |
| `capability` | string | yes | as asked |
| `outcome` | enum `allow`, `deny`, `suspend` | yes | article 1, closed at three |
| `reason` | enum (below) | yes | why the policy resolved as it did |
| `policy_version` | string \| null | yes | the content version of the policy file the decision was taken under (decision of 2026-09-04: the file is the authority); `null` when no policy applied (`reason` = `policy_absent`) |
| `approval_ref` | string \| null | yes | the approval opened for a `suspend`; `null` otherwise |
| `decided_at` | date-time | yes | the control plane's clock |
| `correlation` | string \| null | yes | copied from the ask |

`reason` enum, generation 1, closed: `policy_allows` (outcome `allow`), `policy_denies` (`deny`), `policy_absent` (`deny` — article 1: an absent policy is never a permission), `policy_requires_review` (`suspend`), `capability_unknown` (`deny` — a capability the catalog does not hold is refused as a decision with evidence, not as a problem without one). The pairing outcome↔reason is a domain rule (B.9) and a schema `oneOf` is **not** used to encode it — a client reads the two members independently and an unknown `reason` reads as unknown while the `outcome` still governs (B.8).

**`approval-resolve-request`** — one person approves or rejects a suspended effect (article 12). Request: `additionalProperties: false`.

| member | type | required | meaning |
|---|---|---|---|
| `contract_generation` | integer | yes | |
| `scope` | string | yes | article 5: this is a write against a named record; the default does not apply to naming an existing record |
| `approval_ref` | string | yes | |
| `resolution` | enum `approve`, `reject` | yes | the two resolutions a person can give |
| `reason` | string ≤1024 | no | the person's stated reason; recorded, never interpreted |

The resolver is the socket's principal; there is no `resolved_by` member in the request.

**`approval-result`** — an approval as the control plane holds it (articles 3, 12). Response: `additionalProperties: true`.

| member | type | required | meaning |
|---|---|---|---|
| `contract_generation` | integer | yes | |
| `authority` | `"authoritative"` (const) | yes | |
| `approval_ref` | string | yes | |
| `decision_ref` | string | yes | the suspended decision it references (article 3: a resolution is a new record referencing the decision, never an edit) |
| `scope` | string | yes | |
| `capability` | string | yes | |
| `state` | enum `pending`, `approved`, `rejected`, `expired`, `unknown` | yes | article 2: a status surface carries an explicit unknown value in its schema. A conforming server never emits `unknown` about its own record (B.10); the value exists so that the schema, the client and the documentation share one word for "the control plane could not say" |
| `requested_at` | date-time | yes | |
| `deadline` | date-time | yes | the instant after which the approval is `expired` without anyone acting |
| `resolved_at` | date-time \| null | yes | |
| `resolution_reason` | string \| null | yes | |

> **Note, 2026-09-16.** `person` — string, not required — joined this response
> additively within generation 1: it names who acted, on a wait somebody
> approved or rejected, and is absent where nobody acted. The published schema
> is the authority for the member list; the table above records the design of
> 2026-09-04 and is not rewritten by a later addition.

**`status-result`** — the status surface (articles 2, 6, 7, 11, 13); read by `sayfirst status` and `sayfirst whoami`, and by the client at connection to record the generation. Response: `additionalProperties: true`.

| member | type | required | meaning |
|---|---|---|---|
| `contract_generation` | integer | yes | the server's pinned generation |
| `supported_generations` | array of integer, ≥1 item, contains `contract_generation` | yes | every generation the server accepts (article 13: every one whose deprecation window has not expired) |
| `integrity_grade` | enum `observability`, `evidence`, `unverified` | yes | article 7, for the caller's connection; `unverified` is the value that claims nothing |
| `privacy_provider` | string; `none` and `unknown` are reserved values | yes | article 11: the active provider by name; `none` when the no-op default is active, `unknown` when the daemon cannot tell; a client never renders `none` as protection |
| `principal` | object `{ "kind": string, "uid": integer, "name": string \| null }` | yes | the principal as the socket saw it (article 6). `kind` is an open registry whose documented values are `user`, `service`, `workload`, `process`; `name` is `null` when the user id has no name on the host — an unmapped id from another namespace is refused before any document is produced |
| `store` | object `{ "authority": "authoritative" \| "projection" \| "observation" \| "unknown", "kind": string }` | yes | article 3 stated on the status surface: what the daemon's policy source is. The skeleton always answers `{"authority": "authoritative", "kind": "file"}`; a configured database projection appears, later, as an additional member, never as this one |

`status-result` is the document that will grow: the delegation record of article 6, the re-evaluation interval of article 7, the composed plugins of article 8 are **response members** and enter this schema within generation 1, additively, by the blocks that produce them (B.7). Nothing in `status-result` is a request; there is no `status-request`.

**`problem-document`** — every refusal (articles 2, 13). Response: `additionalProperties: true`.

| member | type | required | meaning |
|---|---|---|---|
| `contract_generation` | integer | yes | the generation the server answered under (B.3) |
| `code` | string | yes | a code of the registry (I.6) |
| `message` | string ≤1024 | yes | for a human; never parsed |
| `retryable` | boolean \| null | yes | `null` means the server does not know (article 2), and a client treats `null` as "not known to be safe to retry" |
| `member` | string \| null | no | for `request_malformed` and `member_unknown`: the offending member's name |

### I.5 Outcomes and the reading rule

`decisions.py`:

```python
class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    SUSPEND = "suspend"
```

Exactly three members; `test_the_outcome_vocabulary_is_closed_at_three` (G.4) asserts `len(Outcome) == 3` and that the schema enum equals `{o.value for o in Outcome}`. There is **no** `UNKNOWN` member: the constitution closes the enumeration at three, and the reading of a value outside it is a client rule (article 13), implemented once in `values.py`:

```python
@dataclass(frozen=True)
class Unknown:
    """A value this generation does not define, kept verbatim and never interpreted."""
    raw: str

def read_enum(cls: type[E], raw: object) -> E | Unknown: ...
```

`read_enum(Outcome, "allow")` is `Outcome.ALLOW`; `read_enum(Outcome, "zz-synthetic-outcome-4e1f")` is `Unknown(raw="zz-synthetic-outcome-4e1f")`; a non-string is `Unknown(raw=repr(value))`. The client's decision reader (B.8) turns an `Unknown` outcome into a `CouldNotAsk` result whose reported outcome is the word `unknown`, and every other enum (`reason`, `state`, `integrity_grade`) reads as `Unknown` without stopping anything.

### I.6 The problem-code registry

`_contracts/domain/problem-codes.json`:

```json
{
  "x-contract-generation": 1,
  "codes": {
    "generation_missing":     {"origin": "server", "retryable": false, "article": "13", "meaning": "the request carries no contract_generation"},
    "generation_unreadable":  {"origin": "server", "retryable": false, "article": "13", "meaning": "contract_generation is not an integer"},
    "generation_unsupported": {"origin": "server", "retryable": false, "article": "13", "meaning": "contract_generation is not one the server accepts; supported_generations of the status surface says which are"},
    "request_malformed":      {"origin": "server", "retryable": false, "article": "13", "meaning": "the request does not validate against its schema; `member` names the first offending member"},
    "member_unknown":         {"origin": "server", "retryable": false, "article": "13", "meaning": "the request carries a member this generation does not define; `member` names it"},
    "operation_unknown":      {"origin": "server", "retryable": false, "article": "13", "meaning": "the request names no operation this generation defines"},
    "scope_required":         {"origin": "server", "retryable": false, "article": "5",  "meaning": "a read named no scope; the default never applies to a read"},
    "scope_refused":          {"origin": "server", "retryable": false, "article": "5",  "meaning": "the principal may not write this scope (system mode)"},
    "principal_refused":      {"origin": "server", "retryable": false, "article": "6",  "meaning": "the peer credential is not an identity the daemon admits (an unmapped user id), or the principal could write the daemon's configuration (article 8)"},
    "approval_unknown":       {"origin": "server", "retryable": false, "article": "12", "meaning": "no approval with this reference in this scope"},
    "approval_resolved":      {"origin": "server", "retryable": false, "article": "12", "meaning": "the approval is already approved, rejected or expired; a resolution is a new record and a record is never edited"},
    "policy_unavailable":     {"origin": "server", "retryable": true,  "article": "3",  "meaning": "the policy authority could not be read; no decision is taken and none is recorded as taken"},
    "evidence_not_recorded":  {"origin": "server", "retryable": true,  "article": "10", "meaning": "the evidence of the decision could not be written; the decision is not given"},
    "internal":               {"origin": "server", "retryable": null,  "article": "2",  "meaning": "the server failed for a reason it cannot classify"},
    "unreachable":            {"origin": "client", "retryable": true,  "article": "1",  "meaning": "the control plane could not be reached"},
    "impostor":               {"origin": "client", "retryable": false, "article": "6",  "meaning": "the peer is not the daemon's principal"},
    "answer_unreadable":      {"origin": "client", "retryable": null,  "article": "13", "meaning": "the response is not a document of this generation"},
    "outcome_unknown":        {"origin": "client", "retryable": false, "article": "13", "meaning": "the server answered an outcome this generation does not define; the effect does not start and the outcome is reported as unknown, never as a denial"}
  }
}
```

- `origin` ∈ {`server`, `client`}: a `server` code is what a server puts in a `problem-document`; a `client` code is what the project's client produces on its own side when no document could be had, and **a conforming server never emits it** (the test value of G.6 proves the stub does not). The registry is one file because article 13 names one registry and the exit-code table of the client (a later block) is derived from it.
- `retryable` ∈ {`true`, `false`, `null`}: three-valued (article 2).
- `article` is the article the code holds; `meaning` is prose for the derived documentation and is not parsed.
- Codes are `^[a-z][a-z0-9_]*$`, and none names a transport (G.5): the two codes the binding needs for a route or method it does not serve are covered by `operation_unknown` (B.13), so the binding adds no code of its own.

`problems.py`:

```python
class ProblemCode(StrEnum):
    GENERATION_MISSING = "generation_missing"
    # … one member per registry code, in registry order …
    OUTCOME_UNKNOWN = "outcome_unknown"

@dataclass(frozen=True)
class Problem:
    code: ProblemCode | Unknown
    message: str
    retryable: bool | None
    contract_generation: int | None      # None when the document carried none (client-origin problems carry the client's)
    member: str | None = None

def read_problem(document: Mapping[str, object]) -> Problem: ...
```

`test_the_problem_code_enum_matches_the_registry` (G.4) holds the enum and the file to one list, with an anti-vacuity floor of 15 codes.

### I.7 The attribute registry

`_contracts/domain/attributes.json` — the names the instrumentation library and the evidence export use for the identity of an effect (article 11); it is the registry article 13 names and the instrumentation library (another repository) reads it from this wheel.

```json
{
  "x-contract-generation": 1,
  "prefix": "sayfirst",
  "attributes": {
    "scope":               {"type": "string", "values": "open",  "article": "5"},
    "capability":          {"type": "string", "values": "open",  "article": "1"},
    "principal.kind":      {"type": "string", "values": "open",  "article": "6", "documented_values": ["user", "service", "workload", "process"]},
    "decision.ref":        {"type": "string", "values": "open",  "article": "1"},
    "decision.outcome":    {"type": "string", "values": ["allow", "deny", "suspend", "unknown"], "article": "1"},
    "decision.reason":     {"type": "string", "values": ["policy_allows", "policy_denies", "policy_absent", "policy_requires_review", "capability_unknown", "unknown"], "article": "1"},
    "policy.version":      {"type": "string", "values": "open",  "article": "3"},
    "approval.ref":        {"type": "string", "values": "open",  "article": "12"},
    "approval.state":      {"type": "string", "values": ["pending", "approved", "rejected", "expired", "unknown"], "article": "12"},
    "contract.generation": {"type": "int",    "values": "open",  "article": "13"},
    "integrity.grade":     {"type": "string", "values": ["observability", "evidence", "unverified"], "article": "7"},
    "privacy.provider":    {"type": "string", "values": "open",  "article": "11", "reserved_values": ["none", "unknown"]},
    "authority":           {"type": "string", "values": ["authoritative", "projection", "observation", "unknown"], "article": "3"},
    "evidence.ref":        {"type": "string", "values": "open",  "article": "10"},
    "arguments.digest":    {"type": "string", "values": "open",  "article": "11"},
    "correlation":         {"type": "string", "values": "open",  "article": "13"}
  }
}
```

- The full attribute name is `f"{prefix}.{key}"`; the prefix is written **once**, in this file, and `test_every_attribute_is_in_this_project_namespace` (G.7) derives the expected prefix from the distribution name (`importlib.metadata.distribution("sayfirst-contract").name` with the `-contract` suffix removed) rather than writing it a second time. Keys are `^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`.
- Where an attribute mirrors a schema enum, the registry's `values` list equals the schema enum plus `"unknown"` (the value the *reader* records when the wire carried something it does not define, B.8); `test_attribute_values_agree_with_the_schemas` (G.4) holds the equality.
- No attribute carries a payload: there is no argument, content or return value attribute, and there is no `carries_payload` member because there is nothing to mark — `test_no_registered_attribute_carries_a_payload` (G.8) is the guard article 11 names, formulated on the registry.

### I.8 The golden scenarios

`_contracts/domain/golden-scenarios.json`. The file is the arbiter between a client and a server (article 13); it is authoritative, and the documentation of the scenarios is derived from it (G.10), never written beside it.

```json
{
  "x-contract-generation": 1,
  "scenarios": {
    "allow": {
      "binds": "both", "article": "1",
      "given": {"policy": {"example.effect": "auto"}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"outcome": "allow", "reason": "policy_allows"}
    },
    "deny": {
      "binds": "both", "article": "1",
      "given": {"policy": {"example.effect": "deny"}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"outcome": "deny", "reason": "policy_denies"}
    },
    "missing_policy": {
      "binds": "both", "article": "1",
      "given": {"policy": {}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"outcome": "deny", "reason": "policy_absent"}
    },
    "review_approve": {
      "binds": "both", "article": "12",
      "given": {"policy": {"example.effect": "review"}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"outcome": "suspend", "reason": "policy_requires_review"},
      "then":  {"resolve": "approve", "expect": {"state": "approved"}}
    },
    "review_reject": {
      "binds": "both", "article": "12",
      "given": {"policy": {"example.effect": "review"}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"outcome": "suspend", "reason": "policy_requires_review"},
      "then":  {"resolve": "reject", "expect": {"state": "rejected"}}
    },
    "review_expire": {
      "binds": "both", "article": "12",
      "given": {"policy": {"example.effect": "review"}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"outcome": "suspend", "reason": "policy_requires_review"},
      "then":  {"resolve": "expire", "expect": {"state": "expired"}}
    },
    "unreachable": {
      "binds": "client", "article": "1",
      "given": {"server": "unreachable"},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"result": "could_not_ask", "problem": "unreachable"}
    },
    "unknown_outcome": {
      "binds": "client", "article": "13",
      "given": {"server": {"answers": {"outcome": "zz-synthetic-outcome-4e1f", "reason": "policy_allows"}}},
      "ask":   {"capability": "example.effect", "scope": "local"},
      "expect": {"result": "could_not_ask", "problem": "outcome_unknown", "reported_outcome": "unknown"}
    }
  }
}
```

Scenario object, every member exact:

| member | required | meaning |
|---|---|---|
| `binds` | **yes** | `client`, `server` or `both`. `server` and `both` bind the server's acceptance suite; `client` and `both` bind the client's. A scenario without `binds` is a contract defect and fails `test_every_scenario_declares_what_it_binds` (G.9) — never a default. |
| `article` | yes | the article the scenario holds, as a string |
| `given` | yes | the world before the ask. `policy`: an object mapping capability → regime ∈ {`auto`, `review`, `deny`}; a capability absent from the map has no policy; every capability named in `ask` is registered in the catalog by the harness (an unknown capability is a different scenario, deferred, N.4). `server` (client-bound scenarios only): the literal `"unreachable"`, or `{"answers": <partial decision-result>}` — the harness's fake server answers that document, completed with the members `given` does not set. |
| `ask` | yes | a `decision-ask-request` **without** `contract_generation`; the replayer inserts `CONTRACT_GENERATION` |
| `expect` | yes | for `server`/`both`: `{"outcome", "reason"}`, compared member by member against the decision. For `client`: `{"result": "could_not_ask", "problem": <client-origin code>}` plus `"reported_outcome": "unknown"` when the scenario is about an outcome. |
| `then` | no | a second step: `{"resolve": "approve" \| "reject" \| "expire", "expect": {"state": <ApprovalState>}}`. `approve`/`reject` is a `resolve_approval` by the harness's principal on the `approval_ref` the decision returned; `expire` is the harness moving its clock past `deadline` and nobody acting. `then.expect.state` is compared against `read_approval` after the step. |

The names `review_*` follow the recommendation of O.1, pending the operator's decision, that the review regime is called `review`; see O.1. The value `zz-synthetic-outcome-4e1f` is manifestly synthetic and names no feature of any product, present or planned; `test_the_unknown_test_value_is_manifestly_synthetic` (G.6) holds that every string a scenario uses as an unknown value starts with `zz-synthetic-`.

Two of the scenarios describe **client** behaviour no conforming server produces — `unreachable` and `unknown_outcome` — which is why `binds` exists: without it the server's acceptance suite (article 13) is red on two scenarios it must be unable to satisfy.

`golden.py`:

```python
class Binds(StrEnum):
    CLIENT = "client"; SERVER = "server"; BOTH = "both"

@dataclass(frozen=True)
class Scenario:
    name: str
    binds: Binds
    article: str
    given: Given                 # Given(policy: Mapping[str, Regime] | None, server: Literal["unreachable"] | Answers | None)
    ask: DecisionAsk
    expect: Expect               # Expect(outcome, reason) | ClientExpect(result, problem, reported_outcome)
    then: Then | None            # Then(resolve: Literal["approve","reject","expire"], expect_state: ApprovalState)

    def binds_server(self) -> bool: return self.binds in (Binds.SERVER, Binds.BOTH)
    def binds_client(self) -> bool: return self.binds in (Binds.CLIENT, Binds.BOTH)

def load_scenarios(path: Path | None = None) -> Mapping[str, Scenario]:
    """The shipped file when path is None; the loader refuses a scenario without `binds` (ContractDefect)."""
```

`Regime` (`auto`, `review`, `deny`) is a **scenario** vocabulary in this block: it is what `given.policy` says. It becomes the domain's `Regime` in the domain block; the two are held equal by a test that block brings, and this block writes the three words in `golden.py` only.

### I.9 The binding, its generation and the byte pin

`_contracts/binding/http-unix-socket/openapi.json` is an OpenAPI 3.1 document. It is **generated**, never edited: `packages/contract/scripts/build_contract.py` derives it from the domain contract and from one binding-owned input, the route table `binding/http_unix_socket/routes.py`:

```python
@dataclass(frozen=True)
class Route:
    operation: str            # a domain operation name (I.11): "read_status", "ask_decision", "read_approval", "resolve_approval"
    method: str               # "GET" | "POST"
    path: str                 # "/status", "/decisions", "/approvals/{approval_ref}", "/approvals/{approval_ref}/resolution"
    request: str | None       # a DOMAIN_SCHEMAS name or None
    response: str             # a DOMAIN_SCHEMAS name
    problems: Mapping[int, tuple[str, ...]]   # HTTP status → registry codes served with it

ROUTES: Final[tuple[Route, ...]] = (
    Route("read_status",      "GET",  "/status",                             None,                       "status-result",   {403: ("principal_refused",), 500: ("internal",)}),
    Route("ask_decision",     "POST", "/decisions",                          "decision-ask-request",     "decision-result", {400: ("request_malformed", "member_unknown", "generation_missing", "generation_unreadable"), 403: ("principal_refused", "scope_refused"), 409: ("generation_unsupported",), 503: ("policy_unavailable", "evidence_not_recorded"), 500: ("internal",)}),
    Route("read_approval",    "GET",  "/approvals/{approval_ref}",           None,                       "approval-result", {400: ("scope_required", "generation_missing", "generation_unreadable"), 403: ("principal_refused",), 404: ("approval_unknown",), 409: ("generation_unsupported",), 500: ("internal",)}),
    Route("resolve_approval", "POST", "/approvals/{approval_ref}/resolution", "approval-resolve-request", "approval-result", {400: ("request_malformed", "member_unknown", "generation_missing", "generation_unreadable"), 403: ("principal_refused", "scope_refused"), 404: ("approval_unknown",), 409: ("generation_unsupported", "approval_resolved"), 503: ("evidence_not_recorded",), 500: ("internal",)}),
)
```

The route table is the only place where a path, a method or a status code is written; it is binding vocabulary (article 4: the binding "names its transport, and nothing else"). For `read_approval` the generation and the scope travel as query members `contract_generation` (required, B.4 applies) and `scope` (required, B.12 applies) — the same names as the request members they stand for; `approval_ref` is a path member. `read_status` takes no parameter at all: it is how a client learns which generations the server supports, so it cannot be gated by one. Every unmatched path or method is answered `404` or `405` with a `problem-document` whose code is `operation_unknown` (B.13). Every response body of every route, refusals included, is a document of the domain contract with `Content-Type: application/json`.

Generation algorithm of `build_contract.py` (`test_the_binding_is_derived_from_the_domain_contract`, G.11, re-runs it in memory and asserts byte equality with the committed file):

1. `info`: `title` = the distribution name, `version` = the distribution version, `x-contract-generation` = the marker's integer; `servers` = `[]` (there is no URL: the socket path is a deployment fact, not a contract fact); `x-transport` = `"http-unix-socket"`.
2. `components/schemas`: every schema of `DOMAIN_SCHEMAS`, embedded verbatim with `$schema` and `x-spdx-license-identifier` removed and every relative `$ref` rewritten to `#/components/schemas/<name>`. Nothing is added, renamed or reordered.
3. `paths`: one entry per `Route`, `operationId` = `Route.operation`, request body referencing `Route.request`, `200` referencing `Route.response`, each status of `Route.problems` referencing `problem-document` with `x-problem-codes` = the tuple, sorted.
4. Serialisation: `json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"`, UTF-8, LF. The same canonical form is required of every hand-authored domain artefact (`test_every_artefact_is_in_canonical_form`, G.11) so that a reformat is a byte change and a byte change is a review.
5. `_contracts/digests.json`: `{"x-contract-generation": 1, "artifacts": {"<path under _contracts/>": "<sha256 hex>"}}` for every entry of `DOMAIN_ARTIFACTS` and `BINDING_ARTIFACTS`, in sorted order, in the same canonical form.

`build_contract.py --check` regenerates steps 1–5 in memory and exits non-zero on any difference, naming the artefact; CI runs it, and G.11 runs the same comparison as a test so a fork without the script's CI step is held too. The generation of the domain artefacts themselves is by hand — they are the authority — and the pin catches the hand: a schema edited without regenerating fails on `digests.json`, a binding edited by hand fails on regeneration.

Two properties the pin exists for, each with its own guard:

- **The domain contract names no transport** (article 13 guard; G.5): every key and every string value in every `DOMAIN_ARTIFACTS` file, and every docstring of `decisions.py`, `approvals.py`, `status.py`, `problems.py`, `golden.py`, `replay.py`, is free of the terms `http`, `https`, `url`, `uri`, `header`, `socket`, `tcp`, `port`, `path`, `route`, `endpoint`, `method`, `get`, `post`, `status code`, `grpc`, `websocket`, `json-rpc`, matched as whole words, case-insensitive; the `$schema` dialect identifier is the one exempted value. In consequence the prose of the artefacts says "peer credential" where article 6 says socket (the `principal` description of `status-result`: "the principal as the peer credential established it"), and "reached" where a reader would say connected. This list is public because it names transports, not private products (article 4's warning concerns a deny-list of private words). The test has an anti-vacuity floor: at least 10 artefacts scanned and at least 200 strings inspected.
- **The binding adds no vocabulary** (article 13; G.12): (a) `components/schemas` of the committed binding, after reversing the `$ref` rewrite and restoring the two stripped members, equals the domain schemas exactly; (b) every code in every `x-problem-codes` is a `server`-origin code of the registry; (c) the set of `operationId`s equals the set of operation names of `ControlPlaneClient` (I.11); (d) every parameter name in `paths` is one of `contract_generation`, `scope`, `approval_ref`, and no `enum` keyword appears outside `components/schemas`. Paths, methods, status codes and the OpenAPI structural keywords are the transport's words and are permitted, nowhere else than in `paths` and `info`.

### I.10 The workspace and the clean-environment build

The repository root gains `pyproject.toml`:

```toml
[project]
name = "sayfirst-workspace"
version = "0.0.0"
requires-python = ">=3.12,<3.15"

[tool.uv.workspace]
members = ["packages/*"]

[tool.uv.sources]
"sayfirst-contract" = { workspace = true }
"sayfirst-contract-stub" = { workspace = true }

[dependency-groups]
dev = ["pytest==8.4.1", "jsonschema==4.25.1"]
```

`jsonschema` (MIT) validates documents against the domain schemas in tests and only in tests. `test_every_dependency_carries_a_licence_from_the_closed_list` (G.13) reads the installed metadata of every distribution in the resolved environment, dev group included, against the closed list of article 15; a test library under a licence outside the list (weak copyleft included) does not enter, even as a dev dependency, without the request for comments article 15 requires. The two pins above are the versions resolved on 2026-09-04; the implementer pins what `uv lock` resolves and commits `uv.lock`.

The server distribution `sayfirst-control-plane` joins `members` when its block lands; nothing in this block's `pyproject.toml` names it. Root `pyproject.toml` is not itself a published distribution (`[tool.uv] package = false`).

`test_the_contract_artifacts_load_from_an_installed_wheel` (G.2, the guard article 13 names) does, in the foreground: `uv build packages/contract --wheel --out-dir <tmp>`; `uv venv <tmp>/venv`; `uv pip install --python <tmp>/venv <wheel>` with `--no-deps`; then runs, in that interpreter with the repository **not** on `sys.path` (`cwd` = `<tmp>`, `-I`), a script that imports `sayfirst_contract`, loads every entry of `DOMAIN_ARTIFACTS` and `BINDING_ARTIFACTS` through `artifacts.artifact`, verifies every digest of `digests.json`, and prints the marker's integer; the test asserts the integer equals `CONTRACT_GENERATION`. The same test then installs the stub wheel with `--no-deps` on top and imports `sayfirst_contract_stub`. The build backend is pinned, so the wheel's bytes are the wheel's bytes.

### I.11 The Python client surface

`client.py`:

```python
T = TypeVar("T")

@dataclass(frozen=True)
class Answered(Generic[T]):
    value: T                              # Decision | Approval | Status
    contract_generation: int              # what the server echoed

@dataclass(frozen=True)
class Refused:
    problem: Problem                      # the server answered a problem-document (server-origin code)

@dataclass(frozen=True)
class CouldNotAsk:
    problem: Problem                      # no answer of this generation could be had (client-origin code)
    reported_outcome: Literal["unknown"] = "unknown"

Result = Answered[T] | Refused | CouldNotAsk

class ControlPlaneClient(Protocol):
    def read_status(self) -> Result[Status]: ...
    def ask_decision(self, ask: DecisionAsk) -> Result[Decision]: ...
    def read_approval(self, scope: str, approval_ref: str) -> Result[Approval]: ...
    def resolve_approval(self, resolution: ApprovalResolution) -> Result[Approval]: ...
```

The four operation names are the domain's operation vocabulary; the binding's `operationId`s equal them (G.12 c). The three result kinds are `Answered`, `Refused` and `CouldNotAsk`, because article 1 closes the outcomes at three and holds "could not ask" apart from both of them: `CouldNotAsk` is the constitution's own phrase (article 1) and the third kind is what the client renders with its own exit code, distinct from `deny` (article 1 guard; the exit-code table is the client block's). A `Decision` whose outcome was not of this generation is never an `Answered`: the reader returns `CouldNotAsk(problem=Problem(code=ProblemCode.OUTCOME_UNKNOWN, …))` (B.8).

Data classes (all frozen, all with a `from_document(document) -> Self` reader that tolerates unknown members and keeps them in `extra: Mapping[str, object]`, and request classes with a `to_document(contract_generation: int) -> dict` writer that emits **only** the members of I.4 and omits `None`):

```python
# decisions.py
@dataclass(frozen=True)
class DecisionAsk:
    capability: str
    scope: str = "local"
    arguments_digest: str | None = None
    correlation: str | None = None

@dataclass(frozen=True)
class Decision:
    decision_ref: str
    scope: str
    capability: str
    outcome: Outcome                      # never Unknown: an unknown outcome is not a Decision (B.8)
    reason: Reason | Unknown
    policy_version: str | None
    approval_ref: str | None
    decided_at: str
    correlation: str | None
    contract_generation: int
    extra: Mapping[str, object]

# approvals.py
class ApprovalState(StrEnum): PENDING = "pending"; APPROVED = "approved"; REJECTED = "rejected"; EXPIRED = "expired"; UNKNOWN = "unknown"
class Resolution(StrEnum): APPROVE = "approve"; REJECT = "reject"

@dataclass(frozen=True)
class ApprovalResolution:
    scope: str
    approval_ref: str
    resolution: Resolution
    reason: str | None = None

@dataclass(frozen=True)
class Approval:
    approval_ref: str; decision_ref: str; scope: str; capability: str
    state: ApprovalState | Unknown
    requested_at: str; deadline: str
    resolved_at: str | None; resolution_reason: str | None
    contract_generation: int; extra: Mapping[str, object]

def wait_until_resolved(client: ControlPlaneClient, scope: str, approval_ref: str, *,
                        pause: Callable[[], None], max_polls: int) -> Result[Approval]:
    """Polls read_approval until state leaves `pending` or max_polls is spent; an Unknown state is never
    returned as permission — the caller receives the Approval with its Unknown state and starts nothing (B.17)."""

# status.py
class IntegrityGrade(StrEnum): OBSERVABILITY = "observability"; EVIDENCE = "evidence"; UNVERIFIED = "unverified"
class Authority(StrEnum): AUTHORITATIVE = "authoritative"; PROJECTION = "projection"; OBSERVATION = "observation"; UNKNOWN = "unknown"

@dataclass(frozen=True)
class Principal:
    kind: str; uid: int; name: str | None

@dataclass(frozen=True)
class Status:
    contract_generation: int
    supported_generations: tuple[int, ...]
    integrity_grade: IntegrityGrade | Unknown
    privacy_provider: str
    principal: Principal
    store_authority: Authority | Unknown
    store_kind: str
    extra: Mapping[str, object]
```

`ApprovalState.UNKNOWN` and `Authority.UNKNOWN` exist because the schema carries the value (article 2); `Outcome` has none because article 1 closes it and the reader handles the rest (I.5). `IntegrityGrade` needs none: `unverified` is its value that claims nothing.

### I.12 The replayer (new)

`replay.py` is new in this block: the server must replay the scenarios "as its own acceptance suite" (article 13) and must not depend on the client (article 14), so the replayer lives in the one distribution both may depend on.

```python
class Side(StrEnum): CLIENT = "client"; SERVER = "server"

class Session(Protocol):
    client: ControlPlaneClient
    def pass_deadline(self) -> None: ...   # move the world's clock past every open approval's deadline
    def close(self) -> None: ...

class Harness(Protocol):
    def arrange(self, scenario: Scenario) -> Session:
        """Build the world of `scenario.given` and return a session bound to it.
        A server harness configures the policy authority from given.policy and registers every capability the ask names;
        a client harness starts a fake server per given.server; a stub harness scripts the stub with the scenario's name."""

class Verdict(StrEnum): PROVEN = "proven"; FAILED = "failed"; NOT_APPLICABLE = "not-applicable"

@dataclass(frozen=True)
class Observed:                            # what the side actually did, in scenario terms
    outcome: str | None; reason: str | None; result: str | None; problem: str | None
    reported_outcome: str | None; state: str | None

@dataclass(frozen=True)
class ScenarioReport:
    name: str; verdict: Verdict; expected: Mapping[str, object]; observed: Observed | None; detail: str

@dataclass(frozen=True)
class Report:
    side: Side
    scenarios: tuple[ScenarioReport, ...]
    def failures(self) -> tuple[ScenarioReport, ...]: ...
    def bound(self) -> tuple[ScenarioReport, ...]: ...      # everything but NOT_APPLICABLE

def replay(scenarios: Mapping[str, Scenario], harness: Harness, side: Side) -> Report: ...
def compare(a: Report, b: Report) -> tuple[str, ...]:
    """The names of scenarios bound by both reports whose Observed differ — the two sides disagree, one has a defect (article 13)."""
```

`replay` runs, for `side`, exactly the scenarios that bind that side (`Scenario.binds_server()` / `binds_client()`), reports the others as `NOT_APPLICABLE` (present in the report, never counted as proven — an absence is not a pass, article 2), and for each bound scenario: `arrange`; `ask_decision(scenario.ask)`; map the `Result` to an `Observed` (`Answered` → outcome/reason; `Refused` → result `refused` + problem code; `CouldNotAsk` → result `could_not_ask` + problem code + reported outcome); if `then` is present and the decision was `suspend`: `resolve_approval` or `pass_deadline`, then `read_approval`, into `Observed.state`; compare with `expect` (and `then.expect`) member by member; `close`. A raised exception inside a scenario is a `FAILED` verdict with the exception's type in `detail`, never a crash of the whole replay.

The shipped members are `PROVEN`, `FAILED` and `NOT_APPLICABLE`: the replayer block widened "not bound to this side" into "this side was not asked", so that a declared absence and a scenario the environment cannot run render as the same non-claim rather than as a pass, and a separate `bound_to_side` flag keeps the one fact the name used to carry. The names in this section are the names the code carries.

The end-to-end step of the skeleton is `compare(replay(S, server_harness, SERVER), replay(S, stub_harness, SERVER))` being empty **and** both reports having no failure. This block delivers the replayer, the stub harness and `test_the_stub_replays_every_scenario_that_binds_the_server` (G.14); the server harness and `test_the_server_replays_exactly_the_scenarios_that_bind_it` are the api block's (D.3).

### I.13 The stub

`sayfirst_contract_stub.stub`:

```python
class Stub(ControlPlaneClient):
    def __init__(self, scenario: str, *, scenarios: Mapping[str, Scenario] | None = None,
                 clock: Callable[[], datetime] | None = None) -> None: ...
    # Scripted by scenario name against the shipped file (or the injected one).
    # ask_decision answers the scenario's `expect`; a `suspend` opens one pending approval whose deadline is
    # now + 60 s on the injected clock; resolve_approval records the first resolution and refuses the second
    # with approval_resolved; read_approval after the deadline answers expired; read_status answers
    # generation 1, supported (1,), integrity_grade "unverified", privacy_provider "none",
    # principal {kind "user", uid os.getuid(), name pwd name}, store {"authority": "authoritative", "kind": "file"}.
    # A scenario bound to the client only (`given.server` set) is refused at construction with ValueError:
    # the stub is a server and a server cannot be unreachable to itself.
```

The stub answers **only** outcomes of this generation: `test_the_stub_answers_only_outcomes_of_this_generation` (G.6) drives every server-bound scenario through it and asserts every `outcome` ∈ `Outcome` and every problem code has `origin: server`. The client's tolerance of an unknown outcome is exercised by the **client harness** of `unknown_outcome`, whose fake server is not the stub.

`sayfirst_contract_stub.stub_http`: `serve(stub: Stub, socket_path: Path) -> ContextManager[Path]` — an `http.server` bound to an `AF_UNIX` socket with mode `0700`, answering the routes of `ROUTES` from the stub, enforcing B.1–B.6 exactly as a server must (a stub that accepted an undefined request member would teach a client to send one). It is the only place in the two distributions where a socket is opened, and it is a dependency of nothing but tests.

## Behaviour

Each rule names the article it holds and the test (section Guards) that proves it. "Server" means any implementation that claims the binding — the control plane and the stub alike; "client" means the project's client and any reader built on `sayfirst_contract`.

**Generation negotiation (article 13)**

- **B.1** The package pins one generation: `CONTRACT_GENERATION` equals `generation.json`'s `contract_generation`; `SUPPORTED_GENERATIONS` equals the pinned generation plus every deprecated generation whose window has not expired at the package's build date. — G.3.
- **B.2** Every request document a client sends carries `contract_generation` = `CONTRACT_GENERATION`; the `to_document` writers refuse to emit a document without it. — G.15.
- **B.3** Every response document a server produces carries `contract_generation`: for a request whose generation the server accepts, the request's generation; for a `problem-document` refusing the generation itself (B.4), the server's pinned generation. A server never produces a document without it. — G.6 (stub), G.16 (schemas: the member is `required` in every response schema).
- **B.4** A server refuses, with a distinct problem and before any other validation: a request without `contract_generation` (`generation_missing`), one whose value is not an integer (`generation_unreadable`), one whose integer is not in its `supported_generations` (`generation_unsupported`). The order is fixed so that a client learns the generation problem first. No decision is taken and no evidence of a decision is recorded for such a request. — G.17.
- **B.5** At connection the client reads `status-result`, records `contract_generation` and `supported_generations`, and if `CONTRACT_GENERATION ∉ supported_generations` produces `CouldNotAsk(problem.code = generation_unsupported)` for every subsequent operation on that connection without sending it; the record it keeps is the client block's concern, the refusal is this contract's. — G.18 (the stub harness with a `supported_generations` the client is not in).
- **B.6** A server refuses a request carrying a member its generation does not define (`member_unknown`, `member` = the name), and a request that fails its schema (`request_malformed`, `member` = the first offending member); request schemas carry `additionalProperties: false`. — G.16, G.17.
- **B.7** A server may add a response member within a generation; a client keeps unknown response members in `extra` and never fails on one; response schemas carry `additionalProperties: true`. A block that adds a response member adds it to the schema, regenerates the binding and the digests, and bumps nothing. — G.16, G.19.
- **B.8** A client reads an enum value its generation does not define as `Unknown(raw)`. For `outcome` the client produces `CouldNotAsk(problem.code = outcome_unknown, reported_outcome = "unknown")`: the effect does not start (article 1), the outcome is reported as `unknown` and never as `deny` (article 2). For every other enum (`reason`, `state`, `integrity_grade`, `store.authority`) the `Unknown` is carried in the value and nothing stops. — G.19, G.20.
- **B.9** A conforming server pairs outcome and reason exactly: `allow` ↔ `policy_allows`; `deny` ↔ `policy_denies` | `policy_absent` | `capability_unknown`; `suspend` ↔ `policy_requires_review`; and answers `approval_ref` non-null if and only if the outcome is `suspend`. — G.6 (stub), and the server's replay (D.3).
- **B.10** A conforming server never emits `unknown` for `approval.state`, never emits a client-origin problem code, and never emits an outcome outside `Outcome`. — G.6.
- **B.11** Deprecation: publishing generation *n+1* moves generation *n* into `deprecated_generations` with the date and release; a server built from that package keeps accepting generation *n* for at least two minor releases or six months, whichever is longer (article 8 by article 13's reference), and `SUPPORTED_GENERATIONS` lists it until then. Generation 1 has no deprecated predecessor; the rule is stated so that the guard `test_a_deprecated_generation_is_still_supported_inside_its_window` (G.3) exists from the first generation with a fixture marker, not from the second. — G.3.

**Scope and identity (articles 5, 6)**

- **B.12** A `decision-ask-request` without `scope` is recorded in scope `"local"`, and the `decision-result` says `"scope": "local"` explicitly. `read_approval` without `scope` is refused with `scope_required`; `approval-resolve-request` requires `scope` by schema. — G.16, G.17, G.21.
- **B.13** The binding answers a path or method it does not serve with a `problem-document` of code `operation_unknown`; the problem-code registry holds no other code for this, and the binding declares no code the registry lacks. — G.12, G.22.
- **B.14** No request document carries a principal: the server takes the principal from the socket's peer credential and reports it on `status-result.principal` (`sayfirst whoami`). A request member naming a caller is `member_unknown`. — G.16 (no such member in any request schema), G.17.

**Outcomes and approvals (articles 1, 2, 12)**

- **B.15** The outcome vocabulary is `allow`, `deny`, `suspend` and nothing else, in the schema, in `Outcome`, in the attribute registry (plus the reader's `unknown`) and in every scenario. A fourth value in any of the four fails the domain's own tests. — G.4.
- **B.16** `resolve_approval` is one person's act: a `resolution` of `approve` or `reject`, recorded as a new record referencing the approval and the decision (article 3), never as an edit; a second resolution is refused with `approval_resolved`, and a resolution after `deadline` is refused with `approval_resolved` because the approval is `expired`. There is no signature count, no designation and no round in generation 1. — G.6 (stub), G.16 (schemas carry no such member), D.3 (server).
- **B.17** A client that receives `suspend` does not start the effect; it polls `read_approval` with `scope` and `approval_ref` until `state` leaves `pending`, and treats an `Unknown` state as "still not permitted": nothing starts on an unknown value (article 3: no relaxation makes an unknown input more permissive). — G.20.

**The scenarios as arbiter (article 13)**

- **B.18** Every scenario declares `binds`; the loader refuses a file with a scenario lacking it (`ContractDefect`), and the replayer for a side runs exactly the scenarios bound to that side, reporting the others as `not_bound`. — G.9, G.14.
- **B.19** The stub passes every scenario with `binds ∈ {server, both}` through `replay(…, Side.SERVER)`, and no scenario with `binds = client` is constructible on it. — G.14, G.6.
- **B.20** The stub over its socket (`stub_http`) and the stub in process answer the same `Observed` for every server-bound scenario: `compare` of the two reports is empty. — G.23.
- **B.21** The documentation of the scenarios (`packages/contract/README.md`, section "Scenarios") is generated from the file by `build_contract.py --docs` and checked by `--check`; a hand edit to the section is a byte difference and fails. — G.10.

**Publication (articles 13, 14, 15)**

- **B.22** `sayfirst-contract` has no runtime dependency and imports nothing outside the standard library and itself; `sayfirst-contract-stub` depends on `sayfirst-contract` alone. Neither imports the server distribution or any web framework or database layer. — G.24, G.13.
- **B.23** Every artefact loads from an installed wheel in a clean environment, and every digest verifies there. — G.2.
- **B.24** Every domain artefact is free of transport terms (I.9) and every binding artefact adds no vocabulary (I.9). — G.5, G.12.
- **B.25** Every authored file carries `SPDX-License-Identifier: Apache-2.0` in the form its format allows (article 15): a comment line in Python and TOML, an HTML comment in Markdown, and in JSON — which has no comment — a top-level member `"x-spdx-license-identifier": "Apache-2.0"`, which the binding generator strips from embedded schemas with `$schema` (I.9 step 2) and writes on the generated documents themselves. The golden scenarios and the stub are fixtures offered under both licences (article 15): `golden-scenarios.json` carries `"x-spdx-license-identifier": "Apache-2.0 OR MIT-0"` and the stub's Python files carry that expression. — G.25.

## What generation 1 carries, and why each shape is what it is

Every module and artefact below is authored in this repository against the interfaces above. This section states the **rule** that fixes each shape and the article the rule comes from; a shape is what it is because an article requires it, never because something else already had it.

Where any file entered an open repository from a closed one, it entered by copy under article 14, whose provenance review is a **private** record: the public artefact is the note on the copying commit — the copyright holder and the licence, nothing more — so no public document of this repository carries an inventory of what a copy brought, what it left behind, or what it was called before.

| Module or artefact | The rule that fixes its shape | Article |
|---|---|---|
| `decisions.py` | the outcome vocabulary is **closed at three** (`allow`, `deny`, `suspend`); a fourth member cannot be added to the enum, and a value outside the three is read as unknown by `values.py` rather than admitted — `Outcome`, `Reason`, `DecisionAsk`, `Decision`, with `DecisionAsk` carrying exactly the five members of I.4 | 1, 13 |
| `problems.py` | one registry (I.6) is the single source of the code enum, and each code carries the `origin` that says which side produces it and the article it serves; a code exists only where a document of this generation can carry it, so a code for a capability generation 1 has no request for is not defined | 3, 13 |
| `client.py` | three result kinds — `Answered`, `Refused`, `CouldNotAsk` — because article 1 holds "could not ask" apart from a denial and article 2 forbids reporting one as the other; the surface is the four operations of I.11 and no more, because article 5 keeps this software to what governs one execution on one host, and article 6 keeps application-level authentication off it | 1, 2, 5, 6 |
| `golden.py` + `_contracts/domain/golden-scenarios.json` | the scenarios are the **arbiter** between a client and a server, so each declares the side it `binds` and the article it holds, and a scenario a side cannot satisfy is reported `not_bound` rather than passed — an absence is never a pass | 2, 9, 13 |
| `_contracts/domain/attributes.json` | a **closed** registry, every key in this project's own namespace derived from the distribution name, and no key that could carry a payload — article 11's default is that nothing of an effect's content is emitted, so `arguments.digest` is the one `arguments.*` key and it is a digest by type | 0, 11 |
| `_contracts/domain/schemas/*.json` | request schemas close (`additionalProperties: false`) and response schemas open, because article 13 lets a server add response members within a generation and forbids a client to send a member its generation does not define; every response schema requires `contract_generation`; no request schema names a principal, because article 6 puts identity in the peer credential and not in a document | 6, 13 |
| `_contracts/domain/problem-codes.json` | the registry is authoritative and the enum is derived from it, so the two cannot drift; `retryable` and `origin` are members of the registry rather than knowledge held in a client | 3, 13 |
| `binding/http_unix_socket/routes.py`, `scripts/build_contract.py`, `_contracts/digests.json` | the binding is **derived from** the domain contract and adds no vocabulary to it, so the route table plus the domain contract generate it and a byte pin holds the published document equal to what they generate; a served surface is never the source of the contract | 4, 13 |
| `values.py` | article 13's reading rule — an unknown enum value reads as unknown — lives in exactly one place, so no reader can implement it differently | 13 |
| `generation.py`, `_contracts/domain/generation.json` | the generation is pinned in the contract package and negotiated in band, and a deprecated generation stays supported for the window of article 8, so the marker carries the window and not a policy a server invents | 8, 13 |
| `status.py`, `status-result.schema.json` | every status surface is at least three-valued with an unknown or unverified member, because article 2 forbids a two-valued claim about something the software cannot know; it carries the integrity grade, the privacy provider, the principal and the store authority | 2, 3, 6, 7, 11 |
| `replay.py` | both sides replay the same scenarios, so the replayer lives in the one distribution both may depend on and depends on neither | 13, 14 |
| `stub.py`, `stub_http.py` | the fake is a **separate distribution** behind an extra, so installing the contract never installs a fake and installing the client never installs a server | 14 |
| the root `pyproject.toml` workspace and every test of the Guards section | a guard that the constitution names arrives with the walking skeleton, and a guard that scans a set carries an anti-vacuity floor | 9, 13 |

**What generation 1 deliberately does not carry.** Anything the walking skeleton cannot ask, answer and prove is not in generation 1, and the reason is an article rather than a schedule:

- **No transport word in the domain contract** and no framework in the contract's dependency list (articles 4, 13, 14). The contract builds and tests with no web framework in the environment.
- **No organisational concern** — no member that exists because there are many hosts or many organisations (articles 1, 5). Article 5's word is `scope`, defaulting to `"local"`, and it is on every record.
- **No payload member** anywhere by default; where an effect's arguments must be identified, they are identified by digest (article 11).
- **No second approver, no round and no designation** in the approval family: article 12 admits one person's review and no fourth outcome, so a shape that would express a second is not published.
- **No application-level authentication member** and no principal in any request: article 6 establishes identity from the peer credential of the socket (N.1, D.3).
- **No catalog request** (N.4) and **no evidence verdict document** (N.7): each would be a new request member and therefore a new generation (article 13), and neither is needed to ask one decision and prove it.

A capability that a later generation needs is added as a **new generation**, announced through the marker and the deprecation window of article 8; it is never smuggled into generation 1 as a member nothing reads, because article 9 forbids a shape that proves nothing and article 2 forbids publishing one as if it worked.

## Guards

Tests live in `packages/contract/tests/` (contract, architecture), `packages/contract-stub/tests/` (stub) and `tests/` (whatever this repository holds as a whole, rather than any one package). Each test names the article it holds in its docstring's first line. Every guard that scans a set has an anti-vacuity floor (the set has at least N members, stated in the test), so an empty scan cannot pass. Negative tests plant the defect in a copy in a temporary directory and assert the guard fails there — they exist so that a guard which passes by checking nothing is caught (article 9's discipline applied to the contract's guards).

| # | Test | Article | Holds |
|---|---|---|---|
| G.1 | `test_every_artefact_is_listed` | 13 | every file under `_contracts/` is in `DOMAIN_ARTIFACTS`, `BINDING_ARTIFACTS` or is `digests.json`; floor 10 |
| G.2 | `test_the_contract_artifacts_load_from_an_installed_wheel` | 13 (guard), 14 | I.10: builds both wheels, installs `--no-deps` in a fresh venv, loads every artefact with the repository off `sys.path`, verifies digests, imports the stub; runs in the foreground |
| G.3 | `test_the_pinned_generation_matches_the_marker`, `test_a_deprecated_generation_is_still_supported_inside_its_window`, `test_a_generation_past_its_window_is_not_supported` | 13, 8 | B.1, B.11 — the two window tests use a fixture marker with a deprecated generation and a fixed clock on both sides of two minor releases / six months |
| G.4 | `test_the_outcome_vocabulary_is_closed_at_three`, `test_the_problem_code_enum_matches_the_registry`, `test_every_schema_enum_matches_its_python_enum`, `test_attribute_values_agree_with_the_schemas` | 1, 13 | B.15, I.5–I.7: schema enums == Python enums (`Outcome`, `Reason`, `ApprovalState`, `Resolution`, `IntegrityGrade`, `Authority`); registry == `ProblemCode` (floor 15); attribute values == schema enum + `unknown` |
| G.5 | `test_the_domain_contract_names_no_transport`, negative `test_the_transport_guard_catches_a_planted_term` | 13 (guard), 4 | I.9 word list on every domain artefact and the docstrings of the domain modules; floor 10 files / 200 strings; the negative plants `"path"` as a key in a copy |
| G.6 | `test_the_stub_answers_only_outcomes_of_this_generation`, `test_the_stub_pairs_outcome_and_reason`, `test_the_unknown_test_value_is_manifestly_synthetic` | 1, 13 | B.9, B.10: every server-bound scenario through `Stub`; every unknown value in the scenario file starts with `zz-synthetic-` |
| G.7 | `test_every_attribute_is_in_this_project_namespace` | 0, 14 | I.7: prefix derived from the distribution name, written once; floor 12 attributes |
| G.8 | `test_no_registered_attribute_carries_a_payload` | 11 | no attribute key contains `argument`, `arguments.value`, `content`, `payload`, `return`, `result.value`, `prompt`, `input`, `output` as a segment; `arguments.digest` is the one `arguments.*` key allowed and is a digest by type |
| G.9 | `test_every_scenario_declares_what_it_binds`, negative `test_the_binds_guard_catches_a_scenario_without_binds` | 13 | B.18: the loader raises `ContractDefect` naming the scenario |
| G.10 | `test_the_scenario_documentation_is_derived_from_the_file`, `test_every_scenario_names_the_article_it_holds` | 13 (guard) | B.21; every `article` is a string of an existing article number (0–18) |
| G.11 | `test_the_binding_is_derived_from_the_domain_contract`, `test_every_artefact_is_in_canonical_form`, `test_every_artefact_matches_its_digest`, negative `test_the_digest_guard_catches_a_reformatted_artefact` | 13 | I.9 steps 1–5, byte for byte; the negative re-indents a copy of one schema with 4 spaces |
| G.12 | `test_the_binding_adds_no_vocabulary`, negative `test_the_vocabulary_guard_catches_a_binding_with_an_extra_code` | 13, 4 | I.9 (a)–(d); every `$ref` stays in-document; the negative adds `x-problem-codes: ["route_not_found"]` to a copy |
| G.13 | `test_every_dependency_carries_a_licence_from_the_closed_list` | 15 | from `importlib.metadata` of every installed distribution in the dev environment: `License-Expression` or a `License ::` classifier in the closed list; a distribution with neither fails naming it; floor 2 |
| G.14 | `test_the_stub_replays_every_scenario_that_binds_the_server`, `test_the_replayer_runs_exactly_the_scenarios_bound_to_a_side`, `test_a_scenario_that_raises_is_a_failed_verdict_not_a_crash` | 13 (guard) | B.18, B.19: `replay(shipped, StubHarness(), SERVER)` has no failure and reports `unreachable`, `unknown_outcome` as `not_bound`; `Side.CLIENT` on a harness that records calls proves the complement; an exploding harness yields `FAILED` |
| G.15 | `test_a_request_writer_emits_only_defined_members`, `test_a_request_writer_never_omits_the_generation` | 13 | B.2: `DecisionAsk.to_document` / `ApprovalResolution.to_document` keys ⊆ schema `properties`, `contract_generation` present, `None` omitted; validated with `jsonschema` against the request schema |
| G.16 | `test_request_schemas_close_and_response_schemas_open`, `test_every_response_schema_requires_the_generation`, `test_no_request_schema_names_a_principal`, `test_a_status_field_has_at_least_three_values`, `test_the_default_ask_emits_no_payload_member` | 13, 2, 6, 11 | I.4: `additionalProperties` false/true by kind; `contract_generation` in every response `required`; no request property named `principal`, `user`, `uid`, `caller`, `requested_by`, `on_behalf`; every enum-typed property of a response schema whose name ends in `state`, `grade` or `authority` has ≥3 values, one of them `unknown` or `unverified`, and `privacy_provider` carries `"x-reserved-values": ["none", "unknown"]`; the property names of `decision-ask-request` are exactly the five of I.4 |
| G.17 | `test_the_stub_refuses_the_generation_before_anything_else`, `test_the_stub_refuses_an_undefined_request_member`, `test_a_read_without_a_scope_is_refused`, `test_a_generation_refusal_records_no_decision` | 13, 5 | B.4, B.6, B.12: over `stub_http`, a body with an unknown member **and** no generation is refused `generation_missing`; with generation and unknown member → `member_unknown` naming it; `GET /approvals/{ref}` without `scope` → `scope_required`; after a `generation_unsupported` refusal the stub holds no decision |
| G.18 | `test_the_client_refuses_a_server_that_does_not_support_its_generation` | 13 | B.5: a fake status with `supported_generations: [99]` → every operation is `CouldNotAsk(generation_unsupported)` and the fake records no further request |
| G.19 | `test_a_reader_keeps_unknown_response_members`, `test_an_unknown_enum_value_reads_as_unknown` | 13 | B.7, B.8: `Decision.from_document` with an extra member keeps it in `extra`; `reason: "zz-synthetic-reason"` → `Unknown` on a still-`Answered` decision |
| G.20 | `test_an_unknown_outcome_is_could_not_ask_and_reported_unknown`, `test_an_unknown_approval_state_never_permits`, `test_could_not_ask_is_never_rendered_as_deny` | 1, 2, 3, 13 | B.8, B.17: the reader on the `unknown_outcome` document yields `CouldNotAsk` with `reported_outcome == "unknown"` and `problem.code == OUTCOME_UNKNOWN`; the replayer's `Observed.outcome` for it is `None`, never `"deny"`; a polling helper (`approvals.wait_until_resolved`, delivered here with a bounded step count and an injected sleep) does not return "permitted" on `Unknown` |
| G.21 | `test_an_ask_without_scope_is_recorded_in_local` | 5 | B.12 on the stub in process and over the socket |
| G.22 | `test_an_unknown_route_answers_operation_unknown` | 13, 4 | B.13 over `stub_http`: `GET /nowhere` and `DELETE /decisions` both answer a `problem-document` with `operation_unknown` and the stub's generation |
| G.23 | `test_the_stub_over_the_socket_answers_as_the_stub_in_process` | 13 | B.20: `compare` of the two server-side reports is empty; this is the first execution of the skeleton's end-to-end parity step, with the stub standing on both sides until the server exists |
| G.24 | `test_the_contract_distribution_imports_nothing_of_the_server`, `test_the_stub_depends_on_the_contract_alone`, `test_the_contract_distribution_has_no_runtime_dependency` | 14 | B.22: AST walk of every module of both packages — imports are stdlib or the two packages; `pyproject.toml` `dependencies` is `[]` for the contract and exactly the contract for the stub; the server package name `sayfirst_control_plane` appears in no import (the test carries the name so that the guard exists before the package does) |
| G.25 | `test_every_authored_file_carries_an_spdx_identifier` | 15 | B.25: every `*.py`, `*.md`, `*.toml` under `packages/` and the root `pyproject.toml` carries the identifier in its first three lines; every `*.json` under `_contracts/` carries the top-level member, with `Apache-2.0` or `Apache-2.0 OR MIT-0` as its value; floor 20 files |
| G.26 | `test_no_tracked_file_carries_a_non_public_provenance_shape`, negative `test_the_public_vocabulary_guard_catches_each_prohibited_shape` | 14, 0 | repository scope: every **tracked** file, by its path and by its content, is free of an internal design path, an attribution of a named artefact to a source this repository does not hold, a reference to a planning document it does not publish, a section-sign citation, a scheduled roadmap, an enum member it does not define, a cited source path it does not hold and a commit identifier in prose; floor 40 files; the negative plants a synthetic example of each class |

The guards the constitution names that this block **brings**: article 13's three (clean-environment wheel, G.2; scenario set authoritative and documentation derived, G.10; domain contract free of transport terms, G.5) and the client half of "the server replaying the scenarios it publishes" (G.14, G.23 — the server half is D.3); article 1's "the domain enumerates the three outcomes" (G.4); article 2's "a two-valued status fails contract tests" (G.16); article 11's "the default configuration emits no payload member" at the contract surface (G.16, G.8); article 14's import guard for these two distributions (G.24); article 15's licence and SPDX checks for this workspace (G.13, G.25); and article 14's public-vocabulary check over everything this repository publishes (G.26), which article 0 makes load-bearing the moment the repository becomes public.

## Non-goals

- **N.1 The socket client** (the socket client module reserved under `binding/http_unix_socket/`, peer-credential check of the server, article 6): the transport block; B.5, B.8 and B.17 fix what it must do, and the fake-server harness of this block exercises the reader without it.
- **N.2 The server's replay of the scenarios** and `test_the_server_replays_exactly_the_scenarios_that_bind_it`: the api block (D.3). Article 13 says this guard "arrives with the walking skeleton"; this block makes it a one-line call.
- **N.3 Every control the walking skeleton does not exercise** — among them grants, multi-signature and designation (articles 6, 10, 12) — is outside generation 1. Article 9 forbids a shape that proves nothing, so no such control is carried in a hollowed form: a scenario no side runs would report `proven` for something never run. Adding one is a new request member and therefore a new generation (article 13).
- **N.4 Catalog operations over the contract** (register/read a capability, articles 3, 4): generation 1 has no catalog request. The skeleton's server registers its one capability from its configuration (D.2), and `capability_unknown` is a deny reason so that the unknown-capability path is already a decision with evidence. Adding catalog requests is a generation-2 change and is the first candidate for it.
- **N.5 The exit-code table and the profile record of the client** (article 1's "distinct exit codes", article 13's "recorded by the project's client at connection"): the client block, derived from `problem-codes.json` `origin`.
- **N.6 Policy file format** (decision of 2026-09-04): the domain/policy block; the contract sees only `policy_version` and the scenario vocabulary `auto`/`review`/`deny`.
- **N.7 Evidence export schema and verdict** (articles 7, 10): the evidence block; when it publishes a verdict document it enters this distribution as a new response schema and a new read operation — which is a generation-2 request (O.4).
- **N.8 Anything on the other side of article 14's direction of dependency**, and every organisational concern article 1 puts out of scope (fleets of hosts, multi-organisation tenancy, central identity): this contract is depended upon, and depends on none of it.
- **N.9 Telemetry export** of the attributes (article 17): the instrumentation repository reads the registry; nothing here sends anything anywhere.

## Dependencies on other blocks

This block depends on no other block. What the others take from it, by name:

- **D.1 Domain block (2.2)**: `Outcome`, `Reason`, `ApprovalState`, `Resolution` are the contract's; the domain defines its own `Regime` (`auto`, `review`, `deny`) and holds it equal to `golden.py`'s scenario regimes by a test (`test_the_domain_regime_matches_the_scenario_vocabulary`); the domain's `Outcome` may be the contract's enum imported, since the server depends on the contract (article 14 allows that direction).
- **D.2 Ports and policy blocks (2.3, 2.4)**: `PolicyStore` v1 answers, for `(scope, capability)`, one of the three regimes or absent, and exposes `policy_version`; the server harness of D.3 writes `given.policy` into the file authority. The server's capability registration from configuration is what makes `capability_unknown` reachable.
- **D.3 Transport and api blocks (2.5)**: implement `ROUTES` exactly (paths, methods, statuses, codes), serve documents that validate against the six schemas, echo the generation per B.3, apply B.4/B.6/B.12/B.13/B.14, and bring `ServerHarness(Harness)` plus `test_the_server_replays_exactly_the_scenarios_that_bind_it` = `replay(load_scenarios(), ServerHarness(), Side.SERVER)` with no failure and the client-only scenarios `not_bound`, and `test_the_server_serves_the_published_binding` (served operations, paths, methods and problem statuses equal the committed `openapi.json` after canonicalisation; a served response member absent from the schema is a defect, a schema member the server never emits is not). The socket client of N.1 implements `ControlPlaneClient` and produces `impostor`, `unreachable`, `answer_unreadable` per the registry.
- **D.4 Client block (2.6)**: depends on `sayfirst-contract` and, in tests, `[stub]`; derives exit codes from `problem-codes.json`; records `contract_generation` and `supported_generations` at connection (B.5); renders `CouldNotAsk` and `deny` distinctly.
- **D.5 Plugin block (`PrivacyRedactor` v1, `ApprovalProvider` v1)**: fills `status-result.privacy_provider` by the active provider's name (`none` for the no-op); resolves `review_*` scenarios through `ApprovalProvider` v1 whose only outputs are `approve`/`reject` bound to the request it received — the contract's `approval-resolve-request` is the *person's* act, and the provider sits behind the server; nothing of the provider is a contract member.

## Open questions

Only those that change the implementation; each with a recommendation. Nobody answers during this task; the implementer applies the recommendation unless the operator has ruled otherwise by then.

- **O.1 `review` or `hitl` for the review regime and the `review_*` scenario names.** The name is not yet decided; this spec uses `review` throughout (`policy_requires_review`, `review_approve`, `review_reject`, `review_expire`, scenario regime `review`). *Recommendation:* `review` — an acronym of a machine-learning literature is a vocabulary article 4 keeps out, and the change costs nothing before generation 1 and a generation after. If the operator rules `hitl`, the rename is mechanical (five identifiers, one word in `golden.py`) and must happen before the first release, never after.
- **O.2 Integer or string for `contract_generation`.** This spec: integer, no minor. *Recommendation:* keep the integer; the article's rules leave a minor number nothing to express, and an integer cannot be "1.0" on one side and "1" on the other.
- **O.3 Whether the approval family belongs to generation 1 or waits for the approval slice.** *Recommendation:* generation 1, as specified. A request added later is a new generation (article 13); a skeleton that suspends (decision of 2026-09-04) but negotiates generation 2 to resolve would be born deprecating its own first generation.
- **O.4 Where the OpenAPI truth lies once the server exists — the generated document (this spec) or the surface a web framework renders at run time.** *Recommendation:* the generated document stays the truth and the served surface is held equal to it (D.3); it is what article 13 says ("derived from the domain contract"), it lets the contract be built and tested without a web framework in the environment (article 14), and a framework's rendering of a schema is not a contract.
- **O.5 `principal` on the status surface: `{kind, uid, name}` now, or defer the member to the identity block.** *Recommendation:* now, as specified — it is a response member, so the identity block can extend it (delegation) without a generation; deferring it would leave `sayfirst whoami` (article 6 guard) without a contract surface.
- **O.6 The stub as a workspace member of this repository versus a package of the client repository.** *Recommendation:* here — the stub is a fake of *this* server against *this* contract, article 13 publishes both wheels from the control plane's repository, and the client repository consumes it through the extra.

## Provenance and authority

This document is a design of this repository, and its authority is the constitution it cites. Every rule above names the article that makes it a rule, so a reader can judge the design against `CONSTITUTION.md` in this tree and needs nothing else to do it: the articles read while writing were 0–18 in full, with 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14 and 15 re-read against each interface, together with `GOVERNANCE.md`, `CONTRIBUTING.md` and `SECURITY.md`.

Where a shape entered an open repository from a closed one, article 14 governs it: the copy carries the note on its own commit — the copyright holder and the licence, nothing more — and the provenance review that authorised it is a **private** record. A public document therefore records no closed source, no closed path, no closed identifier and no section of a closed document, because a reference is a name published, and article 14's reason is that "a dependency pointing the wrong way is a leak that cannot be unpublished".

Nothing outside this repository was executed or modified while this document was written.
