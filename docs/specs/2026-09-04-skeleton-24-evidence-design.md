<!-- SPDX-License-Identifier: Apache-2.0 -->
---
kind: spec
status: draft
date: 2026-09-04
block: 24
title: Walking skeleton, block 2.4 — evidence, integrity grade and minimisation
articles: [7, 10, 11, 5]
---

# Block 2.4 — evidence, integrity grade and minimisation

> **Note, 2026-09-05.** Where this document writes `sayfirst status`, that is what the
> command was when the design was approved on 2026-09-04. On 2026-09-05 the
> operator settled a collision between two repositories: `sayfirst` — the
> distribution `sayfirst-cli`, the import package `sayfirst_cli` and the console
> script `sayfirst` — belongs to the product command-line interface, and the
> operator surface that inspects this repository's daemon is `sayfirstd` in all
> three forms. Nothing else in this design changes. The sentences below are left
> as they were written, because a design note records the decision of its own
> date.

## Purpose

This block gives the walking skeleton its evidence: the record of one decision
about one effect, chained per scope with sequence numbers, a verifier that
issues a verdict, a raw export, and the **integrity grade** that says how much
the record is worth. It implements article 10 (the chain, its verdict and its
raw export in the open core; asynchronous bounded emission with declared gaps),
article 11 (a record carries the identity of an effect and no payload unless a
capability opted in; the privacy port with its no-op default, named in
status and never rendered as protection), article 7 (the grade, computed per
connection from effective access to the store's path, re-evaluated at a
documented interval, recorded as evidence, rendered in status and in every
verdict) and article 5 (one chain per scope; a reader names its scope or is
refused). It also defines the first plugin interface the skeleton ships,
`PrivacyRedactor` version 1, whose discovery, activation and composition are
block 2.5's. Everything here is written for the per-user daemon and the memory
and file stores of the skeleton; the evidence grade, which needs a proof of
store exclusivity, is deferred and the deferral is stated (Non-goals).

Vocabulary: a **record** is what a writer submits; an **entry** is a record
the store has placed in a chain (sequence, link and hash added); the **chain**
of a scope is its entries in sequence order; the **emitter** is the
asynchronous pipeline between writers and the store; a **verdict** is what the
verifier says about a range of one chain.

## Interfaces

All names below are public vocabulary. Python names are given as the
implementer will write them in the server distribution
`sayfirst_control_plane`; JSON member names are those of the domain
contract (block 2.1). Integer versions are the interface versions of
article 8; the skeleton ships version 1 of each.

### Ports (internal, version 1)

#### `EvidenceStore` v1 — `ports/evidence_store.py`

The store is an **authority** (article 3): it accepts appends, owns the chain
invariant of every scope, and publishes no update, delete, purge, truncate or
rewrite verb of any name.

```python
class EvidenceStore(Protocol):
    def append(self, record: EvidenceRecord) -> EvidenceEntry: ...
    def read_range(self, scope: str, *, from_sequence: int,
                   to_sequence: int | None = None) -> Sequence[EvidenceEntry]: ...
    def latest_sequence(self, scope: str) -> int | None: ...
    def location(self) -> StoreLocation: ...
```

- `append` places the record at the next sequence of its scope (the first
  entry of a scope has sequence `FIRST_SEQUENCE = 1`), links it to the
  scope's previous entry, computes its hash with `chained()` (below) and
  returns the entry persisted. Two concurrent appends to one scope obtain
  consecutive sequences with no gap and no duplicate. A record whose `scope`
  is empty is refused (`ValueError`); the default `"local"` is applied by the
  emitter for a writer that names none, never by the store.
- `read_range` returns the entries of `scope` with `from_sequence <= sequence
  <= to_sequence`, ascending; `to_sequence` `None` means the head. It refuses
  (`ValueError`) `from_sequence < 1`, `to_sequence < from_sequence`, and an
  empty or missing scope — the port carries no default scope for a read
  (article 5). A range past the head is an empty sequence, not a refusal.
  Entries of another scope are never returned.
- `latest_sequence` is the highest sequence held for the scope, `None` when
  the scope has recorded nothing — never `0`.
- `location` reports what the grade evaluator inspects (below).

```python
@dataclass(frozen=True)
class StoreLocation:
    kind: str                     # "memory" | "file"
    root: Path | None             # the directory holding the store, None for memory
    def scope_path(self, scope: str) -> Path | None: ...  # the scope's file, None for memory
    retention: str                # documented default, a sentence (article 11)
```

Two open implementations ship in this change (article 4):

- `adapters/memory/evidence_store.py` — `InMemoryEvidenceStore`: a dict of
  scope → list of entries under one lock. `location()` is
  `StoreLocation(kind="memory", root=None, retention="held in the daemon's
  memory for the life of the process; nothing survives a restart")`.
- `adapters/file/evidence_store.py` —
  `FileEvidenceStore(root: Path, *, clock: Clock | None = None)` (**new**): one append-only file per scope, `<root>/<scope>.jsonl`, one entry
  per line as canonical JSON (below), opened with `O_APPEND`, written under an
  exclusive advisory lock on the file (`fcntl.flock`), flushed and `fsync`ed
  per append; reads take a shared lock. The previous hash and sequence are
  read from the file's last complete line, so an append reads a bounded tail,
  never the whole file. A scope that does not match the scope pattern of the
  domain contract (Dependencies, 2.1) is refused before any path is formed.
  A damaged tail is a **declared condition with a recovery**, never a scope
  that refuses every further append (Behaviour 8a, 8b); the `clock` dates the
  gap entry the recovery leaves.
  `location()` is `StoreLocation(kind="file", root=root, retention="kept until
  an operator removes the file; there is no purge command in this version and
  a partial removal is an undeclared gap the verifier refuses")`.

The contract suite `tests/contract/evidence_store_contract.py`
(`EvidenceStoreContract`) runs against both adapters (Guards).

#### `PathAccess` v1 — `ports/path_access.py` (**new**)

The one operating-system-facing port of the grade. It reports facts; the
grade is decided in the domain.

```python
@dataclass(frozen=True)
class PathFacts:
    path: Path
    exists: bool
    owner_uid: int | None
    owner_gid: int | None
    mode: int | None              # permission bits, 0o7777 masked
    acl_present: bool | None      # None when the platform cannot tell

class PathAccess(Protocol):
    def inspect(self, path: Path) -> PathFacts: ...
```

Open implementation: `adapters/posix/path_access.py` — `PosixPathAccess`,
`os.lstat` plus a check for a `system.posix_acl_access` extended attribute on
Linux; on macOS `acl_present` is read from `st_flags`/`listxattr` where
available and `None` otherwise. A path that does not exist yields
`exists=False` and `None` for every other member.

#### `Clock` v1

Consumed, not defined here (Dependencies): `now() -> datetime`, aware, UTC.

### Plugin interface (version 1)

#### `PrivacyRedactor` v1 — `plugins/interfaces.py` (**new**)

> Revised 2026-09-07. This design put the interface in a module of its own,
> beside a second `PrivacyRedactor` that the plugin block had declared in
> `plugins/interfaces.py` over a mapping; both claimed version 1. The one
> interface is now declared once, in `plugins/interfaces.py`, with the shape
> below, and the version constant is the contract distribution's
> `PRIVACY_REDACTOR_VERSION` rather than a second one here.

```python
PRIVACY_REDACTOR_INTERFACE_VERSION = 1

@dataclass(frozen=True)
class Redaction:
    content: bytes
    status: str          # "applied" | "not_applicable" | "failed"
    provider: str        # the provider's name, as status will render it

class PrivacyRedactor(Protocol):
    interface_version: int   # == 1
    name: str                # "none" for the no-op; a provider's own name otherwise
    def redact(self, *, scope: str, capability: str, content: bytes) -> Redaction: ...
```

The redactor sees **only captured payload** (Behaviour 14–18): the identity of
an effect — capability, scope, principal, decision, timing — is never passed
to it and never redacted. A redactor that raises is treated as
`status="failed"`.

Open implementation shipped with the interface (article 11 names it):
`plugins/privacy/none.py` — `NoRedaction`, `name = "none"`, returns the
content unchanged with `status="not_applicable"`. It is the default provider
of the port. No document, log line, status field or docstring describes it as
redaction, masking, protection or privacy; its docstring says "records
captured content as it was given".

The conformance suite for providers is
`tests/contract/privacy_redactor_contract.py` (`PrivacyRedactorContract`):
`interface_version == 1`; `name` is a non-empty string; `redact` returns a
`Redaction` whose `provider == name`; `status` is one of the three values; an
empty input yields an empty output. Block 2.5 publishes it in
`sayfirst.testing`.

### Data shapes

#### `EvidenceRecord` and `EvidenceEntry` — `domain/evidence_chain.py`

The envelope is common to every kind of entry; the body depends on the kind.

```python
FIRST_SEQUENCE = 1
PREIMAGE_VERSION = "<distribution-name>/evidence/v1"   # see Behaviour 5
ENTRY_KINDS = ("effect", "grade", "gap", "composition")

@dataclass(frozen=True)
class Principal:            # the shape block 2.2 renders its principal to
    kind: str               # open registry: "user" | "service" | "workload" | "process" | …
    id: str                 # opaque, stable for the host: e.g. a user name
    via: tuple["Principal", ...] = ()   # delegation chain, outermost first (article 6)

@dataclass(frozen=True)
class EvidenceRecord:
    scope: str
    kind: str                       # one of ENTRY_KINDS
    recorded_at: datetime           # aware UTC; the emitter's clock
    connection_id: str              # block 2.2's id, or DAEMON_CONNECTION
    principal: Principal
    body: Mapping[str, object]      # kind-specific, JSON-serialisable (below)

@dataclass(frozen=True)
class EvidenceEntry(EvidenceRecord):
    sequence: int                   # >= FIRST_SEQUENCE
    previous_hash: str | None       # None at sequence FIRST_SEQUENCE only
    entry_hash: str                 # 64 lowercase hex characters
    preimage_version: str           # the tag the hash was computed under

DAEMON_CONNECTION = "daemon"        # records the daemon writes on its own behalf
```

Bodies, by kind (every member listed is required unless marked optional;
no other member is permitted — an unknown member refuses the record):

| kind | body members |
|---|---|
| `effect` | `capability: str`; `decision_id: str` (block 2.3's identifier); `outcome: "allow" \| "deny" \| "suspend"`; `decided_at: str` (RFC 3339 UTC, the decision's instant); `policy_version: str` (the version the decision was taken under, block 2.3); `capture` (**optional**, present only when a capture rule applied — Behaviour 14) |
| `grade` | `grade: "observability" \| "evidence" \| "unverified"`; `basis: "caller_can_write" \| "caller_cannot_write" \| "access_not_established"`; `evaluated_at: str`; `paths_inspected: int` |
| `gap` | `reason: "dropped" \| "purged"`; `count: int` (≥ 1); `first_at: str`; `last_at: str`; `kinds: {kind: int}` (how many of each kind were lost) |
| `composition` | `providers: [{ "interface": str, "version": int, "provider": str }]` (block 2.5 writes it at start, article 8) |

The `capture` member of an `effect` body:

```json
{"captured": true, "provider": "none", "bytes": 312, "truncated": false, "content": "…"}
{"captured": false, "provider": "none", "withheld": "redaction_failed"}
```

`content` is the captured payload after the redactor ran, UTF-8 text (bytes
that are not UTF-8 are base64 and `encoding: "base64"` is added). The domain
contract's schema marks `capture` as captured payload, in a `description` that
says so and in the member's name; a reader that wants payload-free entries
drops the member and nothing else changes.

#### Grade — `domain/integrity_grade.py` (**new**)

```python
class Grade(str, Enum):
    unverified = "unverified"       # rank 0
    observability = "observability" # rank 1
    evidence = "evidence"           # rank 2 — never produced in this version

GRADE_RANK = {Grade.unverified: 0, Grade.observability: 1, Grade.evidence: 2}

@dataclass(frozen=True)
class CallerAccess:                 # what block 2.2 knows of the connection's peer
    uid: int
    gids: frozenset[int]            # primary and supplementary groups at accept()

@dataclass(frozen=True)
class GradeEvaluation:
    grade: Grade
    basis: str                      # as in the grade body
    evaluated_at: datetime
    paths_inspected: int

def evaluate_grade(caller: CallerAccess, facts: Sequence[PathFacts], *, at: datetime) -> GradeEvaluation: ...
def weakest(grades: Iterable[Grade]) -> Grade: ...
```

#### Verdict — `domain/evidence_chain.py`

```python
class ChainCondition(str, Enum):
    intact = "intact"
    broken_at = "broken_at"          # an entry's hash or link does not hold
    gap_at = "gap_at"                # a sequence is missing and no gap entry declares it
    unverifiable = "unverifiable"    # the verifier could not run: no entry, or an unknown preimage version

@dataclass(frozen=True)
class ConnectionGrade:
    connection_id: str
    grade: Grade                     # weakest in effect over the covered entries; unverified when no grade record

@dataclass(frozen=True)
class ChainVerdict:
    scope: str
    condition: ChainCondition
    from_sequence: int               # what was asked
    to_sequence: int | None          # last sequence covered, None when nothing was
    up_to: int | None                # last sequence found intact; None unless condition is intact
    sequence: int | None             # the failing sequence for broken_at / gap_at
    expected: str | None             # broken_at only: the recomputed hash
    found: str | None                # broken_at only: the stored hash
    version: str | None              # the unknown preimage version, when that is the reason
    covers_an_entry: bool
    declared_gaps: tuple[DeclaredGap, ...]   # (sequence, reason, count) of every gap entry in range
    grades: tuple[ConnectionGrade, ...]      # one per connection covered, sorted by connection_id

def verify(entries: Sequence[EvidenceEntry], *, scope: str, from_sequence: int,
           grades_before: Mapping[str, Grade]) -> ChainVerdict: ...
```

The verdict is never a bare boolean and never a percentage. `grades` is a
**required** member of the verdict's schema, and the schema enumerates the
three grade values (article 7) although this version emits two.

#### Export bundle — `domain/evidence_export.py`

```python
MANIFEST_VERSION = "<distribution-name>/evidence-export/v2"

def manifest_hash(*, scope: str, from_sequence: int, to_sequence: int | None,
                  contract_version: str, verdict: ChainVerdict,
                  entry_hashes: Sequence[str]) -> str: ...
```

The bundle (JSON, the domain contract's `evidence-export-result`):

```
contract_version, scope, from_sequence, to_sequence, entry_count,
entries[]      — every entry of the range, complete, as stored
verification   — the verdict, rendered
manifest_hash  — sha256 over MANIFEST_VERSION, scope, the range, contract_version,
                 the whole verdict as it is rendered into `verification`, and the
                 entry hashes (not the entries)
next_from      — the next position when the bundle was bounded (Behaviour 25), else null
```

The bundle is deterministic: no clock, no identifier, no requesting principal
inside it. Nothing about an export is stored — no register, no export id
(Non-goals).

`manifest_hash` binds the **whole** verdict, and the version says v2 because it
once did not. v1 read `condition` and `up_to` out of the verdict and bound
those two members alone, which left the strongest claim an export makes — the
grade each connection ran at over the period the export covers (article 7) —
outside the one number a verifier is told to compare. A claim could weaken or
strengthen, and the digest a verifier checks stayed the same. The verdict is
therefore rendered here by `verdict_to_document`, the one rendering used
everywhere, so that a verifier recomputing the digest from the served
`verification` object and a caller passing the verdict in reach the same
answer. The bump is breaking for anyone holding a v1 digest of the same range:
the recipe is not shipped with the contract, so this paragraph is where it is
written, and a v1 digest must be recomputed rather than compared.

#### Verification page — `evidence-page-result`

```
contract_version, scope, from_sequence, to_sequence, entries[], verification, next_from
```

Same members as the bundle minus `entry_count` and `manifest_hash`; `entries`
is bounded by `PAGE_BOUND = 100`; `next_from` is the **next position**
computed from `latest_sequence`, never from the entries returned, so a hole at
a page boundary cannot pass for the end of the chain.

#### Status members — `status-result`

`sayfirst status` carries, beside whatever other blocks add:

```json
"integrity_grade": {"grade": "unverified", "basis": "access_not_established",
                    "evaluated_at": "2026-09-04T10:00:00Z", "store": "memory",
                    "reevaluation_interval_seconds": 30},
"privacy_provider": "none"
```

`integrity_grade.grade` has the three values in its schema; `privacy_provider`
is a string: a provider's `name`, `"none"` when the no-op is the active
provider, `"unknown"` when the registry cannot be consulted (the value the
transport renders when the daemon did not answer the member). Rendering rules:
Behaviour 27–29.

### Problem codes

Registered in the domain contract's problem-code catalogue (block 2.1):

| code | when | HTTP status in the transport binding |
|---|---|---|
| `scope_required` | a read names no scope (article 5) | 400 |
| `scope_invalid` | a read names a scope that does not match the contract's scope pattern (article 5) | 400 |
| `evidence_range_invalid` | `from_sequence < 1`, `to_sequence < from_sequence`, or a page size over `PAGE_BOUND` | 400 |
| `evidence_store_unavailable` | the store could not be read when a page, a verdict or an export was asked for | 503 |

Neither read answers `scope_refused`. That code is registered as "the
principal may not write this scope" (403); these two are reads whose caller's
permissions are never consulted, so answering it would be a claim about
something never evaluated (articles 2, 13). A malformed scope is a malformed
request and says so.

A non-intact verdict is a **result**, not a problem: the response is 200 and
the verdict says `broken_at` or `gap_at`. The command-line client maps a
`broken_at` or `gap_at` verdict to its verify-failed exit code and an
`unverifiable` one to its "could not observe" exit code — never to the denied
one (article 2). No problem code is defined for a refused capture, a failed
redaction or a dropped record: each of those is evidence, not a refusal
(Behaviour 9, 17).

### Transport binding (HTTP over the socket, article 13)

Two reads, both served by `adapters/api/evidence_routes.py`:

- `GET /scopes/{scope}/evidence?from_sequence=&page_size=` → `evidence-page-result`, 200.
- `GET /scopes/{scope}/evidence/export?from_sequence=&to_sequence=` → `evidence-export-result`, 200.

A repeated query key is refused with `evidence_range_invalid`. There is no
write route: evidence enters through the emitter only. The route shape follows
block 2.2's conventions for the socket's HTTP surface; if 2.2 names paths
differently, its naming wins and this section is updated.

## Behaviour

Each rule names the article it implements and the guard that holds it
(Guards section, by number).

### The record (article 11)

1. An `effect` record carries the identity of an effect — `capability`,
   `scope`, `principal`, `decision_id` with its `outcome` and
   `policy_version`, `decided_at` and `recorded_at` — and nothing else. The
   emitter's `emit_effect(...)` accepts an optional `payload: bytes | None`
   from the decision service (block 2.3); when no capture rule names the
   capability, the payload is discarded before the record is built and the
   record has **no `capture` member** — not a null one, not an empty one.
   [G1]
2. The `principal` member is the principal block 2.2 attributed to the
   connection at `accept()`, rendered to `Principal`; a delegation is
   recorded in `via`, outermost first, never collapsed into the delegating
   human's identity (article 6). A process id never appears in a record. [G2]
3. Every record carries `scope`; a writer that names none is given `"local"`
   by the emitter; the store never applies a default. Every port method that
   carries a record carries `scope` (article 5). [G3, G4]

### The chain (articles 10, 5)

4. One chain per scope. Sequences start at `FIRST_SEQUENCE = 1` per scope
   and are gapless at the store: `append` allocates the next sequence under
   the scope's lock. A chain may not follow another scope's entry
   (`chained()` refuses a predecessor of another scope). [G5, G6]
5. The hash of an entry is `sha256` over the **preimage**: the concatenation
   of length-prefixed components — `str(len(raw)).encode() + b":" + raw`,
   with `b"-:"` for an absent component — in this fixed order:
   `PREIMAGE_VERSION`, `scope`, `str(sequence)`, `kind`, `recorded_at` as
   `YYYY-MM-DDTHH:MM:SSZ` (UTC, second precision, a naive instant refused),
   `connection_id`, canonical JSON of `principal`, canonical JSON of `body`,
   `previous_hash` or absent. Canonical JSON is
   `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`;
   a value that is not JSON-serialisable refuses the record (no `default=`).
   The hex digest is lowercase. The recipe is pinned by a fixture of expected
   bytes and hashes at `tests/fixtures/evidence/preimage-v1.json`; changing
   any byte of it is a new preimage version, never an edit of this one. [G7]
6. `PREIMAGE_VERSION` is `"<name>/evidence/v1"` where `<name>` is this
   project's server distribution name as `pyproject.toml` declares it; the
   tag's first segment names this project and its second is `evidence`. A
   fixture holds the tag as a literal; a rename of the distribution before the
   first release re-pins the fixture, and after it is a new preimage version.
   `chained()` takes no version argument: a writer cannot choose the recipe
   (anti-downgrade). [G8]
7. An entry does not verify its own hash at construction; the verifier
   judges. `chained(record, previous: EvidenceEntry | None)` refuses a skipped
   sequence, a genesis that names a predecessor, a later entry that names
   none, and a hash that is not 64 lowercase hex characters. [G9]
8. The store publishes no verb that updates, deletes, removes, replaces,
   redacts, purges, rewrites, edits, drops or truncates — checked over
   `dir()` of each adapter including private names (article 3: decisions
   and their evidence are append-only). [G10]
8a. A file whose last line is **torn** — a process died mid-append, leaving
    bytes after the last newline — is recovered rather than refused. The bytes
    that never became an entry are dropped (no append completed for them,
    nothing links to them, no reader has seen them, so this removes no record:
    article 3), and the loss is declared as a `gap` entry with
    `reason="torn"`, `count: 1` and **no** `kinds`, because a record that never
    completed has no kind to claim (article 2). Refusing instead would let one
    interrupted write stop a scope's evidence for good. [G39]
8b. A last line that does **not recompute** — a flipped byte, an edit — does
    not stop the recorder either: the next entry names the stored predecessor
    as it stands (`chained_after_break`), the verifier reports `broken_at` at
    the damaged entry, and recording continues. `chained` itself still refuses
    a predecessor it cannot verify, which is the rule for a writer building a
    chain; continuing over a break is a distinct, named operation of the store.
    Refusing every append after one damaged byte is a denial of evidence, not
    a protection. [G39]

### Emission and declared gaps (article 10)

9. Evidence is emitted **asynchronously**: `EvidenceEmitter.emit(record)`
   enqueues and returns without waiting for the store; one daemon thread
   drains the queue in order into `EvidenceStore.append`. The queue is
   bounded — `EVIDENCE_QUEUE_CAPACITY`, default 4096 records, configurable —
   and a full queue **drops** the incoming record: `emit` never blocks a
   decision and never raises to the caller. This diverges from a synchronous
   recorder that refuses the command when it cannot write; the constitution
   chooses the declared gap over the refused command, and the decision
   service (2.3) does not wait for evidence. [G11]
10. A dropped record is counted, per scope, in a **pending gap**: `count`,
    `first_at`, `last_at`, `kinds`. The pending gap is not a queue item: the
    draining thread, before appending the next record of a scope, appends
    that scope's pending gap as a `gap` entry with `reason="dropped"` and
    resets it. The gap entry therefore sits in the chain exactly where the
    loss happened: after the last record accepted before the drop, before the
    first accepted after it. `EvidenceEmitter.flush(scope, timeout)` appends
    the pending gap even when no record follows; the daemon flushes every
    scope before issuing a verdict (Behaviour 21) and at shutdown. A pending
    gap the daemon could not append before exit is lost with the process; the
    memory store loses everything then anyway and says so in `retention`. [G12]
11. `reason="purged"` is defined in the schema for a retention purge
    (article 11: "a purge leaves a declared gap"); no code path of this
    version emits it, because neither store purges (retention sentences
    above). A future purge appends a `purged` gap entry naming the count
    removed before removing anything; it adds no generation (article 13: an
    added enum value reads as unknown to an older client).
12. The `grade` record of a connection and the `effect` record it precedes
    (Behaviour 19) are enqueued as one unit: both or neither; a drop of the
    unit counts two in the pending gap, with both kinds.
13. Order within a scope is emission order; the single draining thread keeps
    it. Records of different scopes never wait on each other's chain lock
    (each `append` locks its scope only).
13a. A store that **refuses an append** is a declared condition, not a silent
    one. The records of the refused unit join the scope's pending gap, so the
    loss is declared as soon as the store accepts anything again; the retry is
    **bounded** — the first retry after `RETRY_INITIAL_SECONDS`, doubling to
    `RETRY_MAX_SECONDS` — so a store that is down for the daemon's life costs
    one wakeup every few seconds rather than a core, and a flush request that
    timed out is discarded rather than left standing as a reason to retry.
    `close` makes one last attempt per scope and then ends the worker, so a
    refusing store cannot hold the daemon open; it returns `False`, which is
    what says the pending gaps were not written. [G37]
13b. While the store is refusing, `emit` and `emit_effect` return `False`: the
    boolean means "accepted **and** the pipeline is recording", never merely
    "enqueued" (article 2). The record is still queued, so it is written if the
    store recovers. `status` carries `evidence_emission` — `delivering`,
    `undelivered_records`, `scopes_undelivered` — because while the store
    refuses, the declared gaps are held in the emitter where no reader of the
    chain can see them, and an unrecorded record is never silently
    unrecorded (article 10). The client renders three values: delivering, not
    delivering with the count and scopes, and unknown when the daemon did not
    report it. [G38]

### Capture, opt-in and marked (article 11)

14. A capture rule is per capability: `CaptureRule(capability: str,
    max_bytes: int)` with `max_bytes` in `[1, CAPTURE_HARD_CEILING]`,
    `CAPTURE_HARD_CEILING = 65536`. The set of rules is `CapturePolicy`,
    **empty by default**; the configuration file (block 2.5 owns its
    ownership rules) is the only way to add a rule. No rule ever applies to
    a capability it does not name; there is no wildcard. [G1, G13]
15. When a rule names the capability and the decision service passed a
    payload, the emitter truncates it to `max_bytes` (marking
    `truncated: true`), passes the truncated bytes to the active
    `PrivacyRedactor`, and records the redactor's output in `capture.content`
    with `captured: true`, `provider` = the redaction's `provider`, `bytes` =
    the length recorded. [G13]
16. `provider` is recorded as the redactor named it — `"none"` for the no-op
    — and nowhere does the record, the schema, a log line or a rendering
    say "redacted", "masked" or "protected" for `status="not_applicable"`;
    the command-line client renders a capture whose provider is `none` as
    `captured as given (no redaction)`. [G14]
17. A redactor that returns `status="failed"` or raises withholds the
    capture: the record carries `{"captured": false, "provider": …,
    "withheld": "redaction_failed"}` and no `content`; the effect record is
    still emitted (evidence of the decision does not depend on the capture).
    Fail closed on payload, never on evidence. [G15]
18. The redactor is never invoked for a record without a capture rule; the
    identity members are never passed to it. [G16]

### The integrity grade (article 7)

19. The grade is a property of a **connection** and is evaluated per
    (connection, scope). The first record a connection contributes to a
    scope's chain is preceded by a `grade` record for that connection
    (Behaviour 12); every later change of the connection's grade for that
    scope is recorded as another `grade` record before the record that
    follows the change. The daemon's own records (`DAEMON_CONNECTION`) obey
    the same rule with the daemon's own credentials. [G17]
20. `evaluate_grade` decides from **effective access**, never from
    ownership as protection. The inspected paths are, in order from `/`:
    every ancestor directory of the store root, the root itself, and the
    scope's file when it exists. Given the caller's `uid` and `gids` and
    their `PathFacts`:
    - if `caller.uid == 0`: `observability`, basis `caller_can_write`;
    - if the store's `location()` has no root (the memory store), or any
      inspected path has `acl_present` `True` or `None`: `unverified`,
      basis `access_not_established`;
    - otherwise the caller's permission on a path is read from the mode bits
      of the class the caller falls in (owner when `caller.uid ==
      owner_uid`, else group when `owner_gid in caller.gids`, else others).
      A path is **reachable** when the caller has the search bit on every
      ancestor directory. The caller **can write** a path when it is
      reachable and either the caller owns it (an owner can change the bits)
      or the caller's class has the write bit — except that a directory
      carrying the sticky bit lets the caller replace an entry only when the
      caller owns the directory or owns that entry. If the caller can write
      the scope's file, or can write any directory on the path (which lets
      the store be replaced): `observability`, basis `caller_can_write`;
    - otherwise: `unverified`, basis `caller_cannot_write` — the caller
      cannot write the store, but the grade above `observability` needs a
      proof of exclusivity this version does not compute (Non-goals), and
      `unverified` claims nothing. The `basis` member keeps the two
      `unverified` cases distinguishable (article 2: "did not look" and
      "looked and found nothing" differ).
    `paths_inspected` counts the facts consulted. `evidence` is never
    returned. The rule is a pure function of `CallerAccess` and `PathFacts`,
    so its table is unit-tested with facts built by hand. [G18, G19]
21. The grade of a (connection, scope) is re-evaluated when the last
    evaluation is older than `GRADE_REEVALUATION_INTERVAL_SECONDS` (default
    30, configurable in `[1, 300]`) at the moment a record is emitted, and
    always **before a verdict is issued** to that connection. The interval is
    the latency of detection of a permission change, and the documentation
    of the configuration key says so in those words. A change of grade is
    recorded (Behaviour 19) before the record or verdict that follows it. A
    permission change during a connection that removes the caller's write
    access lowers the grade from `observability` to `unverified` in the
    evidence recorded after the next re-evaluation; a change that grants it
    raises the grade to `observability`. [G20, G21]
22. The verifier reads the grades the chain recorded and adds nothing: for
    each connection with a covered entry, `ConnectionGrade.grade` is the
    weakest (`GRADE_RANK`) of the grades in effect over its covered entries,
    where the grade in effect at an entry is the connection's latest `grade`
    record at or before that entry in the chain — `grades_before` supplies
    the state at `from_sequence - 1`, computed by the application from the
    chain's earlier grade records. A connection with a covered entry and no
    grade record at or before it is `unverified`. [G22, G23]

### The verifier (article 10)

23. `verify(entries, scope=, from_sequence=, to_sequence=, grades_before=)` refuses
    (`InvalidEvidence`) entries of another scope or out of sequence order,
    then checks, in this order and stopping at the first failure: the range
    begins where it was asked to (else `gap_at` at `from_sequence`); each
    sequence follows its predecessor by one (else `gap_at` at the missing
    sequence); each entry hashes its own content under the preimage version
    it declares (an unknown version is `broken_at` with `version` set and
    `expected` `None` — never a fallback to another recipe); each link names
    its predecessor's hash (else `broken_at` at the entry). Intact ⇒
    `up_to` = last sequence. A `gap` entry is not a gap: sequences stay
    contiguous around it and it is listed in `declared_gaps`. An **undeclared
    gap** — a missing sequence — is a refusal (`gap_at`). [G24, G25, G26]
24. An empty range is `unverifiable` with `covers_an_entry: false`,
    `up_to: None`, `grades: ()`; it states nothing about any entry, and the
    client renders "no entry to verify", never "intact" (article 2). [G27]
25. A verdict covers the range returned, never the whole chain; the
    asked-for `from_sequence` **and** the asked-for `to_sequence` are passed,
    so a deletion at either end of the range reads `gap_at` rather than a
    shorter clean chain. `to_sequence` is the end the store's head claimed to
    hold: when a reader passes it and the entries stop short of it, the hole
    is at `last returned + 1`, and when the store answers a claimed range with
    nothing at all the hole is at `from_sequence`. A reader that names no end
    asserts none, and a short answer is verified as it stands. `next_from`
    still comes from the head and never from the entries returned — that rule
    keeps a short page from being mistaken for the end of a chain, and it is
    not licence to step over a hole, because the page that steps over it has
    already declared it. A page is bounded by `PAGE_BOUND`; an export is bounded by
    `EXPORT_BOUND = 10000` entries and sets `next_from` when the range asked
    for exceeds it: an export range over the bound is bounded and says so,
    while a `page_size` over `PAGE_BOUND` is refused
    (`evidence_range_invalid`), never clamped. [G28, G36]
26. An unreadable store is `evidence_store_unavailable`, never an empty page
    or an `unverifiable` verdict: a missing answer is not a clean chain. [G29]

### Status (articles 7, 11, 2)

27. `status` carries `integrity_grade` for the calling connection, evaluated
    at the moment of the call against the store root (and the scope's file
    when the caller names a scope), with its `basis`, `evaluated_at`, `store`
    (the store's kind) and `reevaluation_interval_seconds`. When the evaluation cannot
    run (the `PathAccess` adapter raised), the member is `{"grade":
    "unverified", "basis": "access_not_established", …}` — never a default
    of `observability`. [G30, G31]
28. `status` carries `privacy_provider`: the active provider's `name`,
    `"none"` for the no-op, `"unknown"` when the composition cannot be
    consulted. The client renders `privacy provider: none (captured content is
    recorded as given)` for `none`, `privacy provider: unknown (could not
    consult the composition)` for `unknown`, and `privacy provider: <name>`
    otherwise; a provider's name is rendered verbatim, and the rendering
    template itself contains none of the words "protected", "redacted" or
    "masked". [G32, G33]
29. The client renders the grade with its meaning: `integrity grade:
    observability (the caller can write the store; the chain detects
    accidental corruption only)`, `integrity grade: unverified
    (access not established)` or `(the caller cannot write the store;
    exclusivity is not evaluated in this version)`. No rendering of any grade
    says "proof", "tamper-proof" or "tamper detection". [G31, G34]

### Reads (article 5)

30. A page or export read that names no scope is refused with
    `scope_required` before the store is consulted; the default `"local"`
    never applies to a read. [G4, G35]

## What this block carries, and why each shape is what it is

Every module and artefact below is authored in this repository against the
interfaces above. This section states the **rule** that fixes each shape and the
article the rule comes from; a shape is what it is because an article requires
it, never because something else already had it.

Where any file entered an open repository from a closed one, it entered by copy
under article 14, whose provenance review is a **private** record: the public
artefact is the note on the copying commit — the copyright holder and the
licence, nothing more — so no public document of this repository carries an
inventory of what a copy brought, what it left behind, or what it was called
before.

| Module or artefact | The rule that fixes its shape | Article |
|---|---|---|
| `domain/evidence_chain.py` | the hashed preimage is **length-prefixed over a fixed component order** with a distinct absent marker, so no two different records can share a preimage and no component can be moved without changing it; the version tag is derived from this project's own distribution name and `chained()` takes no version of a caller's choosing, so a chain cannot be written under a recipe this repository does not define; an entry never verifies its own hash at construction, so verification stays the verifier's job | 10, 3 |
| `domain/evidence_chain.py` (`verify`) | the ordered checks are range start, contiguity, own hash, then link, because a gap must be reported as a gap rather than as a broken hash; an undeclared gap is refused and a declared `gap` entry is not a gap; an unknown preimage version is `broken_at` with no expectation rather than a fallback; an empty range is `unverifiable` and says it covers no entry | 10, 2 |
| `domain/evidence_export.py` | the export is **raw**: a range of entries, the verdict over them, the declared gaps, and a hash computed over stored digests rather than over entry content, so an export proves the range it names and asserts nothing about what the records mean | 10, 2 |
| `domain/integrity_grade.py` | the grade is a **pure function** of the caller's effective access and the facts of the store's path, so it can be tested by hand-built facts and cannot drift with the host; `evidence` is never returned in this version because no exclusivity proof exists to support it, and `unverified` is the answer whenever access cannot be established | 7, 2 |
| `domain/scope.py` | article 5's word is `scope`, defaulting to `"local"`, and it is on every record and every read; a scope that does not match the published pattern is refused before any path is formed | 5 |
| `ports/evidence_store.py` | the store publishes `append`, `read_range`, `latest_sequence` and `location()` and **no update or delete verb of any name**, private names included, because article 3 makes the chain an authority and an authority that can be edited is not one | 3, 10 |
| `ports/path_access.py`, `adapters/posix/path_access.py` | the grade is computed from facts a port supplies, so a host that cannot answer (an unreadable access control list, a raising adapter) yields "access not established" instead of a guess | 7, 2 |
| `plugins/interfaces.py`, `plugins/privacy/none.py` | the default is a **no-op that says so**: it is named `none`, its documentation says it records captured content as it was given, and no rendering or schema description of it uses the words "protected", "redacted" or "masked" — article 11's default is that nothing of an effect's content is emitted, so the plugin exists to be opted into, never to imply a protection that is absent | 11, 2, 8 |
| `application/evidence_emitter.py` | emission is **asynchronous and bounded**, and the pipeline declares its gaps: a record the queue cannot hold becomes a `gap` entry at the place of the loss, counted and named by kind, so a store under pressure never produces a clean record by losing part of one | 10, 2 |
| `application/evidence_reads.py` | the next page is computed from the **head of the chain**, never from the entries returned, so a short page is not mistaken for the end of a chain; a read that names no scope is refused before the store is consulted; an unreadable store is a problem document, never an empty page | 10, 5, 2 |
| `adapters/memory/evidence_store.py` | one chain per scope under a per-scope lock, so concurrent appends are consecutive with no gap and no duplicate, and one scope's appends never move another's sequence | 5, 10 |
| `adapters/file/evidence_store.py` | append-only lines, one file per scope, flushed to disk before the append is reported, with the predecessor read from a bounded tail rather than the whole file; a damaged tail is declared and recovered from rather than turned into a scope that refuses every further append, because a recorder stopped by one byte records nothing; the retention property of the store is documented rather than enforced by a purge that does not exist | 3, 10, 11 |
| `adapters/api/evidence_routes.py` | two read routes and no write route, because the chain is written by the emitter and read by a caller; a duplicate key in a request document is refused rather than resolved | 3, 13 |
| the domain-contract schemas `evidence-entry`, `evidence-verdict`, `evidence-page-result`, `evidence-export-result`, the two `status-result` members and the three problem codes | written new against the shapes above for block 2.1's registry; every status surface carries at least three values with an unknown or unverified member, and a problem code is used only with the meaning its registry entry gives it | 2, 13 |
| `tests/fixtures/evidence/preimage-v1.json` | the recipe is pinned by **this project's own vectors**: the fixture carries the preimage bytes and the digest, and a mutation of any component changes them, so a silent change of recipe cannot pass | 10, 9 |
| `testing/evidence_store_contract.py`, `testing/privacy_redactor_contract.py` | a port's contract is a suite an implementer can run, so every adapter of that port is held to the same behaviour; publication under article 8's namespace is block 2.5's | 8, 9 |
| the client's `status` and `evidence` renderings | the grade is rendered with its meaning and no rendering of any grade says "proof", "tamper-proof" or "tamper detection", because article 2 forbids a claim stronger than the evidence held for it | 2, 7 |
| the guards of the Guards section | a guard the constitution names arrives with the walking skeleton, and a guard that scans a set carries an anti-vacuity floor so an empty scan cannot pass | 9 |

## Guards

Tests are named as they will exist; each names its article. Negative tests
are marked (−).

Article 11 — minimisation:

- G1 `tests/contract/test_minimisation.py::test_the_default_configuration_emits_no_payload_member` — with an empty `CapturePolicy`, an `effect` record built from a decision that carried a 4 KiB payload has no `capture` key in its body and the serialised entry contains none of the payload's bytes.
- G13 `tests/unit/test_capture.py::test_a_capture_rule_bounds_and_marks_what_it_captures` — a rule of 16 bytes on the capability; the body's `capture` has `captured: true`, `bytes: 16`, `truncated: true`, `provider: "none"`.
- G13 (−) `test_a_capture_rule_never_applies_to_a_capability_it_does_not_name`.
- G13 (−) `test_a_rule_above_the_hard_ceiling_is_refused`.
- G14 (−) `tests/architecture/test_privacy_words.py::test_no_open_rendering_calls_the_no_op_protection` — greps the client's renderings and the schema descriptions for "protected", "redacted", "masked" beside `none`; and `test_no_sealing_call_survives_in_the_open_adapters` (AST: no call named `seal`, `encrypt`, `pseudonymise` in `adapters/`).
- G15 `tests/unit/test_capture.py::test_a_failed_redaction_withholds_the_capture_and_keeps_the_record`; (−) `test_a_raising_redactor_is_a_failed_redaction`.
- G16 (−) `test_the_redactor_never_sees_a_record_without_a_rule` — a spy redactor is not called.
- G32 `tests/unit/test_status.py::test_status_renders_the_active_privacy_provider_by_name`; `test_status_names_none_when_the_no_op_is_active`; `test_status_names_unknown_when_the_composition_cannot_be_consulted`.
- `tests/contract/test_privacy_redactor_none.py` — the no-op passes `PrivacyRedactorContract`.

Article 10 — chain, emission, gaps, verifier, export:

- G5 `tests/contract/evidence_store_contract.py::test_the_first_entry_takes_the_first_place_and_names_no_predecessor`, `test_each_append_takes_the_next_place_and_names_the_one_before`, `test_a_long_chain_leaves_no_hole`, `test_two_concurrent_appends_are_consecutive_with_no_gap_and_no_duplicate` (both adapters).
- G6 (−) `tests/unit/test_evidence_chain.py::test_a_chain_may_not_follow_another_scopes_entry`.
- G7 `tests/unit/test_evidence_preimage_pinned.py::test_the_preimage_recipe_is_pinned_by_a_fixture` — the fixture's entries hash to the fixture's bytes and digests; `test_every_component_is_load_bearing`; `test_an_absent_previous_hash_is_not_an_empty_one`; `test_length_prefixing_leaves_no_two_field_lists_colliding`; (−) `test_a_non_serialisable_body_refuses`.
- G8 `test_the_version_tag_names_this_project` — `PREIMAGE_VERSION.split("/") == [<pyproject name>, "evidence", "v1"]`; (−) `test_chained_accepts_no_version_of_the_callers_choosing` (`TypeError`).
- G9 `test_an_entry_does_not_verify_its_own_hash_at_construction`; (−) `test_a_skipped_sequence_is_refused`, `test_a_genesis_naming_a_predecessor_is_refused`, `test_a_later_entry_naming_no_predecessor_is_refused`, `test_a_hash_that_is_not_a_lowercase_digest_is_refused`.
- G10 (−) `tests/architecture/test_evidence_chain_guards.py::test_the_store_publishes_no_update_or_delete_verb_of_any_name` (both adapters, private names included).
- G11 `tests/unit/test_evidence_emitter.py::test_emit_returns_before_the_store_has_appended` (a stalling store double); `test_emit_never_raises_when_the_queue_is_full`.
- G12 `tests/unit/test_evidence_emitter.py::test_a_dropped_record_becomes_a_declared_gap_where_the_loss_happened` — a small capacity, a stalled store, more emissions than the queue holds, then release and `flush`: the chain reads the accepted entries, then one `gap` entry whose `count` is the number of records dropped and whose `kinds` names them, then the entries accepted after release; `test_flush_appends_a_pending_gap_with_no_record_following`; `test_a_grade_and_effect_pair_is_dropped_whole_and_counted_twice` (Behaviour 12).
- G39 `tests/contract/test_evidence_store.py::test_an_append_after_a_torn_last_line_records_and_declares_the_loss`; `test_the_torn_recovery_never_removes_a_complete_entry`; `test_an_append_after_a_tampered_last_line_keeps_recording`; (−) `tests/unit/test_evidence_chain.py::test_a_torn_gap_that_names_a_kind_is_refused`; (−) `test_a_dropped_gap_still_accounts_for_every_record_it_names`; (−) `test_a_continuation_after_a_break_may_not_cross_a_scope`; (−) `test_a_predecessor_that_does_not_recompute_is_refused`.
- G37 (−) `tests/unit/test_evidence_emitter.py::test_a_pending_gap_a_failing_store_refuses_does_not_spin_the_drain_thread` — a store that refuses every append is retried at most twenty times in a second, not a hundred thousand; (−) `test_a_flush_that_timed_out_leaves_no_standing_request`; (−) `test_close_terminates_the_worker_even_when_the_store_refuses`; `test_a_store_that_recovers_writes_the_gap_it_refused`.
- G38 (−) `tests/unit/test_evidence_emitter.py::test_emit_does_not_report_success_while_the_store_is_refusing`; `test_a_refusing_store_is_declared_in_the_emission_status`; `tests/unit/test_status.py::test_status_declares_a_pipeline_that_is_not_delivering`; `test_status_renders_a_pipeline_that_is_not_delivering`; (−) `test_status_without_an_emission_member_says_it_is_unknown`; `packages/contract/tests/test_evidence_contract.py::test_the_status_schema_carries_the_emission_state`.
- G12 **the exporter's test named by article 10**: `tests/unit/test_evidence_export.py::test_the_export_carries_the_gap_marker_recorded_under_backpressure` — the same setup read through `export()`: the bundle's entries contain the `gap` entry at its sequence, the verdict is `intact` and `declared_gaps` names that sequence with `reason == "dropped"` and the count, and `manifest_hash` changes when the gap entry is removed from the input.
- G24 **the verifier's refusal named by article 10**: (−) `tests/unit/test_evidence_chain.py::test_the_verifier_refuses_a_chain_with_an_undeclared_gap` — entries 1, 2, 4 → `gap_at`, `sequence == 3`, `up_to is None`; and `test_a_declared_gap_is_not_a_gap` — entries 1, 2, gap(3), 4 → `intact`, `declared_gaps` names 3.
- G25 (−) `test_an_unknown_preimage_version_is_a_refusal_never_a_fallback` — `broken_at`, `version` named, `expected is None`.
- G26 `test_a_rewritten_entry_is_broken_at_its_own_sequence`; `test_a_recomputed_hash_breaks_the_link_at_the_next_sequence`; `test_a_deletion_at_the_head_of_the_asked_range_is_a_gap`; (−) `test_a_mixed_scope_range_refuses`.
- G27 `test_an_empty_range_is_unverifiable_and_covers_no_entry`.
- G36 (−) `tests/unit/test_evidence_chain.py::test_a_missing_tail_of_the_asked_range_is_a_gap`; (−) `test_an_asked_range_the_store_answers_with_nothing_is_a_gap_not_an_absence`; `test_a_range_asked_without_an_end_still_verifies_what_it_covers`; (−) `tests/unit/test_evidence_reads.py::test_a_page_whose_tail_was_removed_is_never_intact`; (−) `test_no_page_of_a_holed_chain_reads_intact_over_the_hole` — paging a chain whose sequence 3 was removed never renders a page `intact` over the hole; (−) `test_an_export_whose_tail_was_removed_is_never_intact`.
- G28 `tests/unit/test_evidence_reads.py::test_next_from_is_computed_from_the_head_not_from_the_page`; `test_an_export_over_the_bound_is_bounded_and_says_so`; (−) `test_a_page_size_over_the_bound_is_refused`.
- G29 (−) `test_an_unreadable_store_is_a_problem_never_an_empty_page`.
- `tests/unit/test_evidence_export.py::test_the_manifest_hashes_entry_hashes_not_entries`; `test_the_bundle_is_deterministic`; `test_a_bundle_over_a_range_beginning_after_the_asked_start_carries_gap_at`.

Article 7 — grade:

- G17 `tests/unit/test_evidence_emitter.py::test_a_connections_first_record_in_a_scope_is_preceded_by_its_grade`; `test_the_daemons_own_records_are_graded_too`.
- G18 `tests/unit/test_integrity_grade.py::test_a_caller_that_can_write_the_store_is_at_observability`; `test_a_writable_parent_directory_is_write_access` (replace path); `test_root_is_at_observability`; `test_an_owner_of_a_path_element_counts_as_able_to_write` (ownership is never protection); `test_a_sticky_directory_writable_by_others_does_not_let_a_stranger_replace_the_store`; (−) `test_an_unreachable_writable_path_is_not_write_access` (no search bit on an ancestor).
- G19 `test_an_acl_the_adapter_cannot_read_is_access_not_established`; `test_the_memory_store_is_unverified_and_says_so`; `test_a_caller_that_cannot_write_is_unverified_with_its_basis`; (−) `test_evidence_grade_is_never_produced_in_this_version`.
- G20 **named by article 7**: `tests/integration/test_grade_reevaluation.py::test_a_permission_change_during_a_connection_lowers_the_grade_after_the_next_reevaluation` — file store in a temporary directory whose mode is `0o711`, store root `0o777`, `PosixPathAccess` for the temporary tree and a double answering root-owned `0o755` without ACL for the ancestors above it (so the host's own `/tmp` bits do not decide the test); the caller is a synthetic `CallerAccess` whose uid owns nothing in the tree (observability: others may write the root); `chmod 0o755` the root, advance the injected clock past the interval; the next emitted record is preceded by a `grade` entry `unverified`/`caller_cannot_write`, and the verdict over the whole chain carries `unverified` for that connection while a verdict over the earlier range alone carries `observability`.
- G20 `test_a_permission_change_that_grants_write_raises_the_grade_to_observability`.
- G21 `test_the_grade_is_reevaluated_before_a_verdict`; `test_the_interval_is_documented_as_the_latency_of_detection` (the configuration key's help text contains "latency of detection").
- G22 **named by article 7**: `tests/unit/test_evidence_chain.py::test_a_verdict_carries_the_weakest_grade_of_the_period` — a connection graded `observability` then `unverified` within the range → `unverified`.
- G23 **named by article 7**: `test_a_connection_whose_grade_record_is_missing_renders_unverified` — an `effect` entry with no preceding `grade` entry for its connection and none in `grades_before`.
- `tests/contract/test_verdict_schema.py::test_the_verdict_schema_requires_grades_with_three_values` (schema-level, article 7).
- G30 `tests/unit/test_status.py::test_status_names_the_grade`; G31 **named by article 2**: `test_status_renders_unverified_when_access_cannot_be_established` — a `PathAccess` double that raises; (−) `test_status_never_defaults_the_grade`.
- G34 (−) `tests/architecture/test_privacy_words.py::test_no_grade_rendering_claims_proof_or_tamper_detection`.

Article 5 — scope:

- G3 `tests/architecture/test_scope_guards.py::test_every_port_carrying_a_record_carries_a_scope` (enumerates `EvidenceStore` and the emitter's record types).
- G4 (−) `tests/contract/evidence_store_contract.py::test_a_read_without_a_scope_is_refused`; `test_another_scopes_entries_are_never_read_here`; `test_one_scopes_appends_never_move_anothers_sequence`; `test_each_scopes_chain_verifies_on_its_own`.
- G35 (−) `tests/unit/test_evidence_reads.py::test_a_read_that_names_no_scope_is_scope_required_before_the_store_is_consulted`; (−) `test_a_scope_outside_the_contract_is_refused_before_the_store_is_consulted` — `scope_invalid`, never the permission code; `packages/contract/tests/test_evidence_contract.py::test_a_malformed_scope_on_a_read_is_its_own_code_not_a_permission_refusal`.
- G2 `tests/unit/test_evidence_chain.py::test_a_delegation_is_recorded_in_via_and_never_collapsed` (article 6); (−) `test_a_record_carries_no_process_id`.

Article 2 — three values:

- G33 `tests/contract/test_status_schema.py::test_a_status_field_has_at_least_three_values` — `integrity_grade.grade` and `privacy_provider`'s documented values (`none`, `unknown`, a name); `test_the_verdict_condition_has_an_unknown_value` (`unverifiable`).

Article 15: every new file carries `SPDX-License-Identifier: Apache-2.0`;
the existing header guard covers them.

## Non-goals

- **Evidence grade.** Not produced in this version: it needs a proof of
  exclusivity from the store adapter (every mutation path enumerated, none
  reachable by an admitted principal), which the file adapter does not compute
  and the memory adapter cannot. Article 7 allows it by ranking `unverified`
  below the two others and making it the answer "when access cannot be
  established": every connection that would qualify for evidence grade
  renders `unverified` with basis `caller_cannot_write`, which claims nothing.
  The schema already carries the third value so its arrival adds no
  generation (article 13).
- **ACL evaluation.** An access control list on any inspected path yields
  `unverified` (Behaviour 20); reading ACLs is deferred under the same
  clause of article 7.
- **Purge and retention commands.** Retention is a documented property of
  each store (Interfaces); no purge exists; `reason="purged"` is defined and
  unused. Article 11 requires the declared gap when a purge exists, not the
  purge.
- **Compliance packages, disclosure registers (export listing, export
  identifiers, export orders), regulatory workflows, narratives.** Article 10
  places them outside the open core.
- **What followed the decision.** An `effect` body records the decision
  (`event` is not a member in v1); records of an effect's start and end are
  the walking skeleton's later blocks (preface: "one decision"); adding them
  is additive within the generation.
- **Indexing grade records.** `grades_before` is computed by reading the
  chain from `FIRST_SEQUENCE`; article 10 makes no latency figure
  constitutional, and the skeleton's stores are small.
- **Cross-scope verdicts.** A verifier "may cover several scopes, each on its
  own chain" (article 10); this version verifies one scope per call.
- **Discovery, activation, composition** of the `PrivacyRedactor` and the
  publication of `sayfirst.testing` — block 2.5 (article 8).
- **Trace attributes** (`sayfirst.privacy.provider`, `sayfirst.scope`
  in the attribute registry) — the attribute registry belongs to the domain
  contract (article 13, block 2.1); this block names the values those two
  attributes carry when the registry is written, and emits no trace itself.

## Dependencies on other blocks

- **Block 2.1 (contract).** Schemas `evidence-entry`, `evidence-verdict`,
  `evidence-page-result`, `evidence-export-result` and the two `status-result`
  members, written from the shapes above; the three problem codes; the
  `scope` pattern (recommended `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, which the
  file adapter needs to form a path — if 2.1 chooses another, the file adapter
  encodes the scope with a reversible, filesystem-safe encoding and this spec
  says which); the contract generation marker `contract_version` echoed in
  every page and bundle; the information contract module and its declaration
  API, in which `evidence_entries` is declared an authority with the no-verb
  guard (G10) as its proof; the `Clock` port if 2.1 ships it (else 2.2).
- **Block 2.2 (socket, identity, connection).** A connection identifier
  unique for the daemon's life and never equal to `"daemon"`; the peer's
  `uid` and `gids` as captured at `accept()` (`CallerAccess`); the principal
  rendered to `Principal` (kind from the open registry, id, delegation chain);
  the HTTP surface over the socket to mount `evidence_routes` on, and the
  `status` read to add the two members to; the connection's lifetime events
  so the emitter drops its per-connection grade state at close.
- **Block 2.3 (policy, decision).** The decision identifier, its
  `outcome` (`allow`/`deny`/`suspend`), `policy_version` and `decided_at`;
  the call `emitter.emit_effect(scope=, connection=, principal=, capability=,
  decision=, payload=None)` placed after the decision is appended to the
  `DecisionStore` — the decision store remains the authority for decisions,
  the chain references them by id and never edits them (article 3).
- **Block 2.5 (plugins).** Activation of the `PrivacyRedactor` named in
  the configuration, the `composition` record at start, the configuration
  keys `evidence.queue_capacity`, `evidence.grade_reevaluation_seconds`,
  `evidence.store` (`memory` | `file`), `evidence.file.root`,
  `evidence.capture[]` (capability, max_bytes), and the publication of the two
  contract suites in `sayfirst.testing`.
- **Implementation order.** 2.4 is implemented on the contract branch of 2.1
  and needs 2.2's connection and 2.3's decision to emit a real `effect`
  record; until they land, `emit_effect` is exercised by tests with
  hand-built values, which the shapes above make possible.

## Open questions

1. **Sequence at the store or at the source?** This spec allocates
   sequences at `append` (gapless per scope) and declares losses with a
   `gap` entry; the alternative allocates at emission so a drop leaves a
   numbered hole the marker names. Recommendation: **at the store**, as
   written — one invariant owner (article 3), a verifier with no lookahead,
   and the same declared-gap semantics.
2. **`unverified` for a caller that cannot write.** In this version a caller
   with *less* access renders the *lower* grade (Behaviour 20, fourth case),
   which reads oddly until evidence grade exists. Alternative: render
   `observability` for every caller with an established access. Rejected:
   `observability` is defined by article 7 as "the governed program can write
   or replace the store", which would be false. Recommendation: **keep
   `unverified` with basis `caller_cannot_write`** and say so in the status
   rendering (Behaviour 29).
3. **Grade records per (connection, scope) or per connection?** Per
   (connection, scope) as written: a verdict names one scope and must find the
   grade in that chain. Recommendation: **as written**; the cost is one extra
   `grade` entry per scope a connection writes.
4. **Should `status` accept a scope?** Optional as written (Behaviour 27);
   without one the scope file is not inspected and `paths_inspected` is
   smaller. Recommendation: **optional**, and the client passes its
   configured scope when it has one.

## Provenance and authority

This document is a design of this repository, and its authority is the
constitution it cites. Every rule above names the article that makes it a rule,
so a reader can judge the design against `CONSTITUTION.md` in this tree and
needs nothing else to do it: the articles read while writing were 0–18 in full,
with 2, 3, 5, 6, 7, 8, 10, 11, 13 and 14 re-read against each interface,
together with `GOVERNANCE.md`, `CONTRIBUTING.md` and `SECURITY.md`.

Where a shape entered an open repository from a closed one, article 14 governs
it: the copy carries the note on its own commit — the copyright holder and the
licence, nothing more — and the provenance review that authorised it is a
**private** record. A public document therefore records no closed source, no
closed path, no closed identifier, no object name of a closed history and no
section of a closed document, because a reference is a name published, and
article 14's reason is that "a dependency pointing the wrong way is a leak that
cannot be unpublished".

Sibling specs (2.1, 2.2, 2.3) were not yet published when this was written; the
Dependencies section names what this block needs from them in terms both sides
can meet.

Nothing outside this repository was executed or modified while this document was
written.
