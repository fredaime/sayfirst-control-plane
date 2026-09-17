<!-- SPDX-License-Identifier: Apache-2.0 -->
---
kind: spec
status: draft
date: 2026-09-05
revision: 3
block: "2.7"
title: Walking skeleton, block 2.7 — the durable decision lifecycle
articles: [1, 2, 3, 5, 7, 8, 10, 11, 13, 14]
---

# Block 2.7 — the durable decision lifecycle

## Purpose

A daemon must explain a decision after restarting, and an independent reader
must be able to check its recorded answer against the policy bytes it names.
On the rebased `origin/main`, production still composes `MemoryDecisionStore`;
the effect entry lacks the reason, rule, digest and correlation; a policy hash
does not recover its bytes. This block supplies a durable decision authority,
policy archive, enriched evidence, explicit recovery accounting and a complete
offline verifier in the contract wheel (articles 1, 3, 7, 10, 11, 13, 14).
Its mandatory lifecycle gate covers a named decision through answer, connection
termination, restart, durable read, export and retrospective re-derivation.
A separate crash gate proves durable readability and declared missing evidence;
it does not pretend to re-derive a decision absent from the export.

This revision is based on main after its two merged fix series, with the
specification branch rebased first. The issuing-connection fix and composition
after privilege drop are
already on main: they are regression obligations, not preceding work. Main's
manifest recipe is already v2, binds the whole verdict, and verifies
prefixes before carrying grades. This design extends those protections.
Main also owns copies of foreign adapter values before deciding, hashing or
rendering; all new storage and archive inputs preserve that discipline.
The operator surface is `sayfirstd`, not the retired client package name.

The runtime sweeps remain outside this block: nothing on this base schedules
`GrantConnections.tick` or `PolicyService.reload_if_due`. Heartbeat and automatic
reload observations are separately reported `not-applicable` until production
scheduling lands. They cannot turn the durable lifecycle gate red or supply
fabricated evidence of liveness. The gate binds on what this block actually
makes observable (articles 2, 10).

## Interfaces

### Distribution and dependency boundaries

| Distribution / package | Additions |
|---|---|
| `sayfirst-control-plane` / `sayfirst_control_plane` | adapters/file/decision_store.py, ports/policy_archive.py, adapters/file/policy_archive.py, adapters/file/recovery_store.py, application/reconciliation.py; changes to decisions, policy, emitter, reads, grade inspection, status and bootstrap |
| `sayfirst-contract` / `sayfirst_contract` | `evidence.py` (complete offline verifier), `retrospective_policy.py` (pure historical evaluator), normative recipe documents and vectors, response schemas, optional lifecycle replay extension |
| `sayfirst-conformance` / `sayfirst_conformance` | `lifecycle.py`, the connection-holding consumer and `lifecycle` subcommand; it calls the contract verifier |
| `sayfirst-testing` / `sayfirst_testing` | file-decision and archive conformance suites, recovery fault-injection support |

`verify_export(bundle) -> ExportVerdict` works with the contract wheel alone.
The promise that survives is the **complete offline verifier**; the promise
that yields is **“the contract distribution installs no evaluator.”** The
contract keeps `dependencies = []`; standard-library parsing and validation
implement the published rules, with schema differential tests. Conformance
depends on contract, never the reverse; neither imports server code.

The server retains its own live evaluator, `domain/policy.py`, and never imports
or delegates to `sayfirst_contract.retrospective_policy`. There are **two
implementations and one fixture arbiter**, `policy-evaluation-v1.json`. Both
pass it independently. Packaging the historical evaluator with the contract
does not collapse the implementations or remove their arbiter.

Article 14 is satisfied because no server implementation is imported. Article 1
forbids a boundary deciding locally; it does not forbid retrospective checking.
Nevertheless, an importable evaluator in the wheel every boundary installs is
the shortest path to a second control plane without evidence. Mitigation is
part of delivery: the module is named `retrospective_policy`, its only public
entry is `rederive_recorded_decision`, it is not re-exported from the package
root, its documentation says “historical audit only; never authorize an effect,”
and G29 fails if a boundary or the CLI imports it, directly or transitively.
It consumes recorded inputs and archived bytes, returns an outcome triple or
an audit failure, performs no I/O, reaches no daemon, holds no state, and cannot
mint a Decision, approval or Grant. G29 also holds the live server path apart.

### Server ports and on-disk structures

`DecisionStore` remains internal port v1, with `append(decision) -> None`,
`get(scope, decision_ref) -> Decision | None`, and added `location() ->
StoreLocation`. Successful append means the durable protocol C2 completed.
`DecisionAppendIndeterminate` distinguishes uncertain persistence from a known
pre-write refusal. These are adapter/service facts, not decision outcomes.
An internal `scan(scope)` yields storage envelopes for reconciliation; it is
not a public read operation. Both memory and file adapters retain explicit-scope
reads and duplicate rejection. Production with a policy always uses the file
adapter; policy-less composition takes no decisions.

`FileDecisionStore(root)` stores canonical JSON lines at
`<root>/decisions/<scope>.jsonl`. The file is authoritative, the in-memory
`(scope, decision_ref) -> offset` index a rebuildable projection. The **storage
envelope**, not the wire decision, fixes the recovery format:

```json
{"storage_version": 1, "scope": "local", "store_id": "<opaque-id>",
 "position": 1, "recording_epoch": "<opaque-id>",
 "decision": {"decision_ref": "<id>", "scope": "local", "outcome": "allow"}}
```

The example's `decision` is abbreviated: the real member is the complete
published `decision-record`. `position` is a strictly increasing positive
integer per store; `store_id` is created once per scope. IDs are opaque random
identifiers, never clocks. Positions and IDs are not recycled after recovery.
A per-scope header establishes the store ID before the first append. There is
one writer process per root (a held root lock refuses a second writer), an
in-process append mutex and an exclusive `flock` per scope file. Different
scopes can append concurrently. New files and directories are synced as C2
specifies. No operation updates or deletes a committed decision.

`PolicyStore` v1's `LoadedPolicy` gains `content: bytes`, the exact bytes read
and hashed by the file authority. It remains a side-effect-free reader.

```python
class ArchiveState(str, Enum):
    present = "present"
    absent = "absent"
    damaged = "damaged"

@dataclass(frozen=True)
class ArchivedPolicy:
    version: str
    state: ArchiveState
    content: bytes | None  # present only

class PolicyArchive(Protocol):
    VERSION = 1
    def keep(self, version: str, content: bytes) -> ArchivedPolicy: ...
    def read(self, version: str) -> ArchivedPolicy: ...
    def location(self) -> StoreLocation: ...
```

`FilePolicyArchive(root)` ships with the port (article 4). One immutable file
`<root>/policy/<hex>.toml` holds bytes whose version is
`sha256:` plus the 64 lowercase hex characters of SHA-256 over the exact file.
`keep` rejects mismatched input with `ValueError`, returns an existing present
file without rewriting it, and never overwrites a damaged file. `read` returns
`absent` only for missing bytes, `damaged` for a digest mismatch, and raises
`OSError` for unreadable storage. The application snapshots values into
core-owned immutable bytes before comparing, archiving and exporting them.

`<root>/recovery/<scope>.jsonl` is an append-only coordination journal, also
scoped and authoritative for baseline and epoch bookkeeping. It holds
version-1 records of `baseline`, `epoch_open`, `epoch_clean`, and
`epoch_reconciled`. Each record has `scope` and a monotonically increasing
journal position. Its exact bodies are specified in C3 and S7. This journal
records the limits of evidence coverage; it is not an alternative decision
store and never reconstructs decisions. Header, record, duplicate and torn-tail
rules are the same as for decision storage. No pending event payload is stored
here: non-decision loss after an unclean stop is explicitly **unknown**.

All three stores and the chains use `evidence.path`; no new configuration key.
The daemon creates `decisions/`, `policy/`, `recovery/` at `0700`, files at
`0600`, as its dropped account. Existing paths must satisfy the effective-access
and replacement-path checks already on main, including ACLs, all parents,
actual child files, held descriptors and the paths naming them. A common parent
alone is no proof of equal protection. The grade examines all four structures;
an inaccessible inspection yields `unverified` (article 7).

The unscoped archive needs its **own** article-5 exception, not an extension of
entry 1 whose restoration concerns policy authority reads. Implementation adds
an entry for `PolicyArchive.keep/read`, `ArchivedPolicy` and the content files,
and matching scope-register entries. Its restoration is concrete: when policy
versions become scope-addressed, new decisions use scoped archives; legacy
whole-file blobs are retained under this exception until every referring
legacy decision and chain segment has been explicitly retired with declared
loss, then removed with the exception. It cannot silently survive that
migration. Review this condition when that generation opens; inability to keep
a path back requires article 16's amendment process, not an indefinite waiver.

Default retention is **indefinite, no automatic expiry**, for decisions, policy
versions, coordination journals and evidence. No purge command is added. Backup
and restore must include all four consistently. A version must outlive every
retained decision/effect naming it. Manual removal is not a supported purge;
missing bytes are disclosed on reads, in reconciliation and in export. A future
purge must declare its affected records/versions before removal (article 11).
A shared root couples deletion, exhaustion and restore failures; it is not an
independent integrity witness.

### Decision and evidence shapes

New writers add the following response members to `decision-record` and
`decision-result`; all existing members retain their meanings:

| Member | Type / meaning |
|---|---|
| `principal_references` | sorted unique strings; M3 defines the exact intersection and bounds |
| `evaluation_recipe` | `sayfirst/policy-evaluation/v1` for this implementation |
| `correlation_source` | `boundary_supplied` when correlation is non-null, otherwise `absent` |

New `effect-body` writers copy `reason`, `rule_id`, `arguments_digest`,
`correlation`, `principal_references`, `evaluation_recipe` and
`correlation_source`, in addition to the existing capability, decision ID,
outcome, time, policy version and optional marked capture. They also carry
`decision_position: {store_id, position}` from the envelope. Every newly written
evidence body, including grade and composition, carries `recording_epoch`.
These members are within the body, so the existing preimage recipe hashes them;
adding an unhashed envelope field is not an equivalent implementation.

`effect-body`, `gap-body`, `grade-body` and `composition-body` are published
with `additionalProperties: false`, so every member named here is a change to
the shipped `evidence-entry` schema and to `build_contract.py --check`, not a
member a writer may add beside a closed object. Ship two definitions: the
new-writer schema, which admits and requires the new members, and the
historical-reader schema, which stays closed over the generation-one members and
admits an old body. Both are generated artefacts of block 2.1's build and both
are exercised by the published-schema differential test. Adding a response
member is additive within generation one (article 13); a third party validating
new entries against a frozen closed copy of the old schema is the tolerance
article 13 puts on the client, and the deployment documentation says so.

The decision ID is compared to `decision_ref`; envelope scope is compared to
scope. Nullable values remain nullable and are never synthesized for an absent
historical member. Reason is the published closed enum; rule ID is nullable;
digest is nullable `^sha256:[0-9a-f]{64}$`; correlation remains nullable with its
published maximum of 128 characters. No request member changes.

New `gap-body` writers add `decision_ids` and `decision_positions` for losses of
known decisions; both lists contain the same decisions, sorted by position,
with exact one-to-one pairing. `decision_positions` items are `{store_id,
position}`. At most `gap_id_bound = 8192` decisions occur per marker; larger
losses produce multiple markers, **never an id-less fallback**. `count` and
`kinds.effect` count those decisions. New decision-loss gap writers retain the original producer epoch in
`recording_epoch`, and their positions are accounted by identity independently
of the epoch sequence interval. New reason `unflushed` means a committed
decision lacks a surviving effect entry after recovery; it says nothing about
reply delivery or whether the emitter accepted it before death. `dropped`
markers use the same identities for decision losses.

Existing torn gaps describe physical incomplete records. When the bytes cannot
identify a decision they do not claim one. Add optional
`accounting: physical_record | decision | event` to gaps; new torn gaps are
`physical_record`, known-decision gaps are `decision`, other counted losses are
`event`. Physical and decision counts can describe the same failure and MUST
NOT be summed as disjoint losses. Historical markers without this member have
unknown accounting. C4 defines deduplication and the torn-plus-unflushed case.

Add evidence kind `recovery` with `recording_epoch` and one of these bodies:

- `event: baseline`, `store_id`, `first_decision_position: 1`,
  `first_covered_sequence`, `legacy_effects_without_authority` (integer),
  `established_at` (display instant).
- `event: clean_stop`, `epoch_id`, `from_sequence`, `through_sequence`.
- `event: unclean_stop`, `epoch_id`, `from_sequence`, `through_sequence`,
  `lost_event_count: null`, `possibly_lost_kinds` containing at least `effect`,
  `grade`, `composition`, `gap`, and `coverage: unknown`.

Baseline and closure markers use the synchronous recovery writer, not the
asynchronous emitter. A baseline marker uses `recording_epoch: baseline:<store_id>`;
this singleton metadata epoch is complete when its marker is durably written
and requires no separate closure. Its journal baseline contains that same value.
Other synchronous recovery markers use `recording_epoch: recovery:<epoch_id>`;
these are complete metadata epochs, not reopened producer epochs. Their body
`epoch_id` names the producer epoch being closed/reconciled. `from_sequence` and
`through_sequence` cover its recovered producer records before recovery markers
are appended; neither cursor is derived from wall time.
A recovery entry is hashed like every other kind; its principal is the daemon's
and its connection is `DAEMON_CONNECTION`. Record its grade first, or its grade
is `unverified`. It does not borrow the asking connection's grade. The unknown
loss marker deliberately uses a new body, not `gap.count = 0` or a made-up count.

### Export and offline verdict

New exports add `manifest_version`, `policy_versions` and `recovery_context`.
The policy map has one key for every distinct policy version named by an effect
entry in the included range, with exactly `{state: present, content: <base64>}`,
`{state: absent}` or `{state: damaged}`. Base64 uses RFC 4648 without newlines.
Missing required keys are verification failures, never a successful empty map.

`MANIFEST_VERSION` becomes `sayfirst-control-plane/evidence-export/v3`.
Its hash is lowercase SHA-256 over `canonical_json` of **all top-level bundle
members except `manifest_hash`**, including the exact entry documents, whole
`verification`, availability states, content, recovery context, counts, covered
range, continuation and version fields. This is an explicit new recipe;
v1 and v2 remain supported with their original preimages, selected by a declared
version. Historical bundles without `manifest_version` are tried against both
old recipes and report the one that matches, or a mismatch if neither does.
Historical absence of new fields is not malformed new evidence.

The map's content hashes catch substitution, but cannot bind an `absent` or
`damaged` assertion or a removed attachment. Excluding the map would repeat the
claim-binding defect fixed by main's v2. v3 covers these claims. A recomputable
manifest is still neither a signature nor an external witness: a writer able
to replace the complete bundle can recompute it.

`recovery_context` carries exact recovery entries outside the requested range
needed to determine closure of epochs represented within it, plus a contiguous
chain suffix from the last included entry through those markers. This suffix
is supporting context, never additional re-derived decision coverage. It must
link to the included range's last hash and verify completely. If absent, too
large for the bound, or unverifiable, the affected epoch coverage is `unknown`;
no asserted journal state substitutes for verifiable chain context. Empty
context is valid. V1 specifies the equally conservative prefix-grade rule.

Exports keep main's existing `next_from` pagination and 10,000-entry maximum,
and add a **32 MiB bound on the canonical serialized whole response**, including
base64 and supporting context. Choose the largest contiguous prefix within both
bounds, with complete policy attachments for its included effects. Never split
an attachment or silently omit a version to fit. `next_from` is the first
excluded sequence; the consumer follows it, checking adjacency and hashes,
until the requested range ends. Recovery context may be omitted with coverage
unknown to fit the bound; included policy attachments may not. A policy file
remains bounded by the existing 1 MiB file-reader limit. M3's maximum effect
encoding fits within 8 MiB, so at least one normal entry plus its policy fits.
An oversized/corrupt stored entry yields `evidence_store_unavailable` with a
bounded diagnostic rather than a non-progressing empty page. The exporter
snapshots the range head; continuation never claims to include later appends.

```python
class Rederivation(str, Enum):
    confirmed = "confirmed"
    differs = "differs"
    unverifiable = "unverifiable"

@dataclass(frozen=True)
class EntryRederivation:
    sequence: int
    decision_id: str
    evaluation_recipe: str | None  # recorded, never inferred from policy bytes
    verdict: Rederivation
    cause: str | None
    expected: tuple[str, str, str | None] | None  # computed triple, differs only

@dataclass(frozen=True)
class ExportVerdict:
    scope: str | None  # None for a malformed bundle with no valid scope
    chain: ChainVerdict | None
    manifest_version: str | None
    manifest_hash_recomputes: bool | None
    policy_versions: Mapping[str, ArchiveState]
    evaluation_recipes: tuple[str, ...]  # distinct recorded identifiers encountered
    rederivations: tuple[EntryRederivation, ...]  # included effects only
    rederived_decision_ids: tuple[str, ...]  # actually evaluated: confirmed OR differs
    confirmed_decision_ids: tuple[str, ...]
    declared_missing_decision_ids: tuple[str, ...]
    coverage: str  # complete | incomplete | unknown, definition H2
    from_sequence: int | None
    to_sequence: int | None
    next_from: int | None
    issues: tuple[str, ...]
    overall: Rederivation  # precedence and non-vacuity: H3
```

Entry causes are `policy_absent`, `policy_damaged`, `policy_unparseable`,
`members_absent`, `evaluation_recipe_unsupported`, `reason_outside_recipe`,
`entry_untrusted`.
Top-level issues also include `bundle_invalid`, `manifest_mismatch`,
`manifest_recipe_unsupported`, `policy_map_incomplete`, `chain_damaged`,
`recovery_context_unverified`, `coverage_incomplete`, `coverage_unknown`,
`no_decisions`. There is no `no_evaluator` state: the contract includes it.
Unknown future recipes are reported unsupported, never evaluated with current
semantics. Structural invalidity returns an unverifiable verdict with populated
issues and nullable unestablished fields, not a boolean or fabricated scope.

### Status and problem codes

`status-result` gains this shape (one example scope; status names each scoped
result in `reconciliations`, without merging their counts):

```json
"decision_store": {
  "store": "file",
  "reconciliations": [{
    "scope": "local", "checked_at": "2026-09-05T10:00:00Z",
    "through_sequence": 42, "through_decision_position": 9,
    "state": "agrees",
    "baseline": {"state": "established", "store_id": "opaque",
                 "first_covered_sequence": 31,
                 "legacy_effects_without_authority": 7},
    "effects_without_decision": 0, "contradictory_decisions": 0,
    "unflushed_declared": 1, "unknown_event_coverage": true,
    "policy_versions_absent": 0, "policy_versions_damaged": 0
  }]
}
```

`store` is `file | memory | unknown`; reconciliation state is
`agrees | disagrees | contradicts | not_run`; baseline state is
`established | unknown | not_established`. When unavailable, time, cursors and
counts are null, never zero. A per-scope journal records the baseline once;
a restart or a successful new decision never resets it. `contradicts` takes
precedence over `disagrees`; unknown coverage is independently visible, so
`agrees` does not mean complete evidence. S7 defines the historical entitlement.
The client renders scope, observation time and covered cursors, baseline and
legacy count, discrepancies, and unknown coverage in plain language. It does
not describe missing authority as proof that a decision never existed.

| Problem code | HTTP / retryable | Meaning |
|---|---|---|
| `decision_store_unavailable` | 503 / true | No usable answer; a pre-write failure establishes no committed decision, an uncertain write may have committed (C2). Never claim both cases mean “no decision taken.” |
| `policy_archive_unavailable` | 503 / true | Before decision append: policy bytes could not be durably kept or are damaged. No decision is committed. |

Both render “could not ask,” never `deny`, and release no usable grant. An
indeterminate append is allowed to have a surviving effect or a declared gap
on recovery; a known pre-write refusal writes no effect. A retry is a new
question with a new decision ID, not an exactly-once promise. Existing
`decision_not_found` means consulted authority does not hold this ID. For a
corrupt/unreadable scope, reads return `decision_store_unavailable`, not absence.

Start refusals `decision_store_unusable`, `policy_archive_unusable`,
`recovery_store_unusable` name storage/protection failures after privilege drop
and before listening. Historical discrepancies alone do not refuse startup;
new decisions require a usable current store for their scope. A malformed
complete line or duplicate storage identity makes that scope unusable, visible
in status; healthy scopes may still serve. If global journal/protection
invariants cannot be established, startup refuses.

No new route, request member or scope permission code is added. Added response
members and readable unknown enum values remain generation one. Historical
reader schemas accept old bodies without the new members; separate new-writer
schemas require them. Both are shipped and exercised: absence reaches
`members_absent`, not a premature `bundle_invalid`. No claim is made that a
future new route automatically fits generation one; settle its generation
under articles 13 and 16 when proposed.

### Replay extension

Keep the existing four-member `Session`/`Harness` protocol working. Do not add
required methods to it. Add optional `LifecycleSession` with integer `VERSION =
1`, discovered by an explicit extension lookup; missing or unsupported extension
raises `ScenarioNotApplicable` for lifecycle scenarios and leaves old scripted
ones runnable. It provides `hold`, `signals`, `close_connection`,
`restart_daemon`, `read_decision`, and `export`; exact steps follow:

| Step | Members / operation |
|---|---|
| `hold` | Retain the stream that delivered the decision; refuse if the ask selected no stream |
| `observe_signal` | `expect: {kind, reason?}`, `within_seconds`; compare actually read frames |
| `change_policy` | `policy: {capability: regime}`; harness changes the authority file |
| `close_connection` | Close the held socket and observe its end |
| `restart_daemon` | `graceful: bool`; stop/start the same process deployment and root |
| `read_decision` | `expect: {outcome, reason, rule_id, grant_present}`; use the ask's own ID on a new connection |
| `export_and_verify` | `expect: {chain, overall, decision_rederived, unflushed_names_the_decision?}`; collect pages and call contract-only verifier |
| `use_grant` | `expect: {grant_use}`; published holder rule uses observed EOF/frames and a monotonic clock |

Unknown steps or members are contract defects. A scenario with steps cannot
supply `given.connection_live` or `given.grant_lifetime_seconds`.
`ScenarioReport` gains a machine-derived `liveness:
scripted | observed | not_applicable` and per-step status/reason. `RunVerdict`
is a closed three-value `StrEnum` (`proven | failed | unknown`) and stays
closed: article 2's three-valued rule owns those values and a fourth would be a
new whole-run claim. The run-level carrier is `Report`, the frozen dataclass
that computes `Report.verdict`; it gains the observed, scripted and
not-applicable counts beside its existing `failures`/`bound`/`proven` readers,
and `failure_reason` names an unexecuted observed scenario as such. An
unexecuted observed scenario is not
reported observed merely because it contains steps. The generated README table
labels its intended mode, while run reports state what actually ran. Public
conformance claims include these counts and named fixtures (article 13).

## Behaviour

### R — durable decisions (articles 1, 3, 5, 7)

**R1.** Production composes the file authority wherever policy can decide.
Memory remains for tests and policy-less composition. [G1, G10]

**R2.** No answer precedes durable archive and decision append. Follow C1–C2;
append exceptions do not establish absence. [G2, G11, G39]

**R3.** A record is append-only; `get` returns the decision as stored and never
rebuilds it from evidence. Duplicate references are refused. The storage
envelope owns recovery positions; its projection is rebuildable. [G1, G3]

**R4.** Quarantine a torn final suffix, sync its removal before another append,
and report the byte count. Never discard a malformed complete line or choose
between duplicate IDs. A torn append was not successfully acknowledged under
the stated process-failure model; storage corruption outside that model cannot
establish that no historical answer was delivered. [G4, G39]

**R5.** All reads explicitly name scope; validate scope before forming a path.
No default scope on read. [G1]

**R6.** Grade inspection includes all decision, archive and recovery files and
replacement paths. Ownership alone is insufficient. Protect and compose after
the privilege drop using the already-merged rules. [G5, G6]

### A — archive and disclosure (articles 2, 3, 5, 7, 10, 11)

**A1.** Archive the exact loaded policy before committing any decision. A start
version is archived before listen; a reload version is archived before it first
decides. Archive failure refuses the question, never uses a projection. [G7, G12]

**A2.** Version bytes are immutable and digest-checked on every read/keep.
Existing damage is reported, never overwritten; a new policy version may still
be used. Archive lookup never substitutes the current policy. [G8, G9]

**A3.** Indefinite retention is the default. Removal/damage of a referenced
version makes retrospective verification unavailable; it does not change the
historical decision or validate it against new bytes. Reconciliation reports
missing versions explicitly. Any future supported purge declares loss. [G9, G13]

**A4.** The archive records historical authoritative inputs, not a writable
policy authority. Its content-addressed copy is not promoted to the source of
live policy. Admin restoration of byte-identical content is distinct from a
store API overwriting a damaged file. [G7, G9]

**A5.** Inspect actual files as well as their parent. Rewriting bytes under an
unchanged digest produces `damaged`, not a different successfully re-derived
answer; the direct archive attack is loss of verifiability. Whole-store
replacement remains subject to article 7's limits. [G6, G28]

**A6.** This revision deliberately retains main's read entitlement: **every
principal admitted by the socket may read/export any explicitly named scope**;
there is no read authorization check. Consequently `export_evidence` on one
scope discloses the administrator's **whole policy file**, including comments,
revision reasons, rules and principal names for other scopes, for every included
version. Scope partitions selection; it is not a confidentiality boundary among
socket-admitted principals. This is an explicit deployment constraint, not an
inference from the policy exception. A system daemon must admit only readers
entitled to that complete history. Be exact about the operator's remedies:
**generation one has no configuration that suppresses the policy attachments**,
because omitting them is a response-member removal (article 13) and refusing
them per caller is the read-authorization model this block does not add. The
only remedies are compositional — run per-user rather than in system mode, or
restrict the admission group to principals entitled to the whole history — and
declining to deploy this version. Do not offer the operator a switch that does
not exist (article 2). No policy projection/redaction can preserve the original
whole-file hash. Publish this entitlement in the operation docs,
`docs/deployment.md` and the repository security change before release. [G13, G42]

This choice avoids silently inventing read permissions or a new 403 meaning in
this block. It accepts disclosure to the existing admission set; it is not a
claim that scopes provide confidentiality. `OSError` during an authorized read
is `evidence_store_unavailable`, never `absent`. [G13]

### M — minimisation and provenance (article 11)

**M1.** Copying decision facts into the chain places them under its integrity
mechanism and makes raw export useful (articles 7, 10); article 3 leaves the
decision file authoritative. Article 11 is the minimisation constraint, not a
reason to omit the facts needed to explain the question and answer. `reason`
and `rule_id` describe the evaluator's answer; references record daemon-resolved
identity inputs; digest and correlation are boundary declarations. [G14, G24]

The published correlation schema accepts **any string up to 128 characters**,
so a short payload fits. The daemon cannot prove it is an identifier; marking
`correlation_source: boundary_supplied` tells an export reader who chose those
bytes. Boundary guidance requires an opaque identifier, `null` when unused,
and forbids content in it. Digests reveal equality and may allow guesses from a
small input space; hashing is not a privacy guarantee. A no-payload-member test
proves the structural default, not that arbitrary supplied strings contain no
content. [G14, G15]

**M2.** Default evidence omits arguments, return values and payload; explicit
capture remains opt-in per capability, bounded, redacted and marked. Process ID
is not a decisional input. Rule text is not repeated in each effect, but is
necessarily disclosed in the policy attachments (A6). No claim is made that a
correlation value necessarily carries none of the boundary's record. [G14]

**M3.** Compute `principal_references = refs(caller) ∩ refs(relevant_rules)`.
First select **all** rules matching the requested scope and capability,
including competing rules and those whose digest does not match; then take their
named references. Do not retain groups used only in another scope/capability or
only the winning rule's references. This preserves every membership test the
retrospective evaluation needs. Sort lexicographically, deduplicate, never
truncate. Principal names match the current parser: exactly one colon separator,
`user` or `group`, nonempty name up to 256 Unicode characters, no C0/C1 controls;
ordinary whitespace remains accepted. [G16]

Remove the proposed global 64-reference policy restriction: it would turn a
recording bound into startup refusal for an otherwise valid deployment. The
existing 1 MiB policy file bound supplies the size model. Even the shortest
quoted reference plus TOML separators consumes more than eight bytes, so
`maxItems: 131072` is a conservative schema bound on distinct recorded
references; it imposes no new limit on accepted file policy. JSON escaping of
these names plus fixed metadata fits the 8 MiB effect bound used by export.
Test the bound against worst-case escaping and full-sized accepted policies;
never claim exact re-derivation after truncation. A custom adapter must obey the
same serialized-policy limit when supplying `LoadedPolicy.content`. [G16, G42]

**M4.** Redaction remains for marked capture, not decisional identity. The five
facts are preserved for comparison, with correlation explicitly marked as
boundary-supplied. This is the council's provenance-marking choice, not a
proof of content exclusion or an exemption allowing intentional payload capture
through metadata. [G15]

### C — durable commit and recovery protocol at every boundary (articles 1, 2, 3, 7, 10)

**C1. Failure model and preparation.** The restart promise covers daemon process
exit, including SIGKILL, on a functioning local filesystem honoring completed
file and directory syncs. It is not a demonstrated host-power-loss, disk-loss or
malicious-daemon guarantee. Fault-injection tests establish the protocol edges;
a SIGKILL test alone does not establish storage hardware behavior.
Validate and load a core-owned policy snapshot, evaluate on the live server,
reserve a connection-bound grant ID if applicable, and prepare the immutable
record. Reservation is not issuance and is never usable before delivery.
Archive through a unique same-directory temporary file: write fully, file
`fsync`, publish atomically without overwriting a final file, directory `fsync`.
A crash before publication can leave an orphan temporary; remove it at recovery
without interpreting it as a version. A crash after publication may leave an
unused archived version, which is harmless and retained. [G7, G39]

**C2. Commit, emission and response.** Under the scope lock, allocate the next
position and write the complete decision envelope plus newline with short-write
handling; `fsync` the descriptor and, for a new file/header, its directory before
success. Only then publish the index entry. The durable decision commit is this
completed sync; the effect's `decision_position` is now fixed. Offer the effect
to the bounded asynchronous emitter after commit. If it drops, declare the
known ID/position; if it dies first, recovery declares it. Evidence durability
is not a prerequisite for response delivery. Activate the reserved grant only
on the still-open issuing connection, then deliver the response. If activation
or delivery fails, cancel/remove the reservation; the decision remains committed.
If the response was partially written, receipt is unknown; a successful socket
write establishes neither peer receipt nor effect execution. [G2, G11, G39]

An error before any append bytes are written is a known refusal. Any short
write, sync error or exception after write begins is **indeterminate** until
recovery examines storage. Return no usable answer, cancel the reservation,
and fence further writes to that scope until its tail is recovered and synced.
A complete valid line found after an indeterminate result is retained, synced
and indexed: it may represent a committed decision the caller never received.
Do not “roll it back” or assert no decision occurred. A torn suffix is handled
by R4. Neither a persisted `grant_id` nor an effect entry establishes delivery;
`grant_id` records a **prepared grant identifier**, never evidence that the
boundary received or used it. There is no fourth decision outcome and no
exactly-once delivery claim. [G39]

**C3. Cover non-decision loss without pretending to inventory it.** Before the
asynchronous emitter can accept any event in a scope during this process, durably append
`epoch_open` to that scope's recovery journal. It names `epoch_id`, `store_id`
(if established), and `from_sequence` (the next chain sequence). It precedes
even grade and composition emission. The local scope is opened before startup
composition; additional scopes are opened before their first event. Scope
locks serialize opening, event admission and shutdown; an epoch never closes
while a producer can still enqueue into it.

On graceful shutdown stop admission, drain/declare all queues, sync the chain,
append and sync a `recovery/clean_stop` record on each opened scope, then append
and sync `epoch_clean` with the marker sequence/hash to the journal. A failed
flush or uncertain sync leaves the epoch open. An open epoch after restart
means **unknown event coverage**, even if every durable decision has an effect.
Append a `recovery/unclean_stop` marker spanning that epoch's chain positions
with unknown count and possibly lost kinds. This explicitly covers a vanished
grade downgrade, composition or other event the decision inventory cannot see.
No daemon-connection grade can fill that absence. A counted dropped grade or
composition event also makes the affected epoch incomplete, and a dropped grade
makes every affected connection unverified for the epoch even after clean stop.
When the dropped marker cannot identify those connections, lower all connections
represented in that epoch. [G40]

For every connection represented in an unclean epoch, verification reports
`unverified` over that epoch; a surviving stronger grade cannot establish that
no downgrade was lost. A range wholly inside the epoch needs its closure marker
as verified recovery context; without closure it reports unknown coverage and
unverified grades. New-epoch grades do not retroactively strengthen old epochs.
This conservative loss of coverage is the chosen cost of keeping non-decision
evidence asynchronous instead of introducing a synchronous event journal.

**C4. Recovery ordering and idempotence.** After chain torn-tail recovery,
compare the durable decision positions with surviving effect positions and
exact known-decision loss positions. For each unaccounted decision, append a
bounded `unflushed` marker with its exact ID/position; no wall-clock comparison
participates. Existing `dropped`/`unflushed` markers prevent another declaration.
If a torn tail identifies no decision, its physical marker and the decision's
unflushed marker describe physical damage and logical absence separately; they
are never summed. If the recovered physical marker does name exact decision
positions, exclude those positions from subsequent decision-loss markers.
Historical id-less gaps do not exempt any new decision positions. [G22, G40]

Sync each recovery marker before journaling `epoch_reconciled`, which names its
marker sequence/hash. If recovery itself crashes, scan complete markers first;
already accounted positions and the existing epoch marker are reused, not
appended again. A complete clean marker with no `epoch_clean` journal record
can be reconciled as clean only after verifying the marker and preceding chain;
its writers were quiesced before it was written. A journal clean/reconciled
record whose chain marker is absent or mismatches is a discrepancy and unknown
coverage, never a reason to omit recovery. Wall-clock reversal, multiple crashes,
more than 8192 decisions, id-less old gaps and a crash between marker sync and
journal sync must all converge without silently excluding a later decision.
Malformed complete chain records remain damage; recovery never launders them
into a clean prefix. [G39, G40]

### S — restart and reconciliation baseline (articles 1, 2, 3, 7, 10)

**S1.** Decision records survive and their index rebuilds. Reads name the
original record, including suspension and prepared grant ID. [G17]

**S2.** Complete evidence survives; append follows its recovered head. Grade and
recovery records precede the new composition where required. Composition is
emitted on local for every start, never claimed to be the first record ahead of
recovery. [G17, G22]

**S3.** Archived bytes survive; missing/damaged files remain missing/damaged.
The current policy is reread from its authority, and its projections rebuild;
they never become the authority for historical or live answers. [G18]

**S4.** Connections, cached groups and grant registry end with the process.
Reconnection establishes fresh peer identity and grade. [G17, G20]

**S5.** No grant survives restart. Graceful stop sends `grant_ended` with
`daemon_stopping` while the original socket is held, then closes; a crash can
send nothing, and the holder expires on connection loss. The already-merged
issuing-connection fix is a regression guard G19, without a fabricated heartbeat.
After restart the registry is empty and a boundary asks anew. The retained
`grant_id` proves preparation only (C2). [G19, G20]

**S6.** A restart never resolves a suspension. Approval persistence and the
currently unserved approval operations remain their own design; no approved,
rejected or expired result is inferred from startup. [G21]

**S7. Baseline.** Reconcile the union of scopes in chain files, decision files
and recovery journals, including a scope whose decision file was wholly removed.
On first adoption only, before any new decision/event admission, recover the
legacy chain, create/sync the decision header and journal, then commit a
`baseline` journal record containing `store_id`, `first_decision_position: 1`,
`first_covered_sequence` (the next chain sequence, which will hold its baseline
marker), and the count of earlier effect entries without decision authority.
Append/sync the identical `recovery/baseline` chain marker before serving.
A crash between the two resumes that same baseline; it does not choose a new
sequence or count. A chain baseline with missing journal/header is visible
historical damage/unknown baseline, never permission to initialize afresh.
Post-block fields in surviving records likewise prevent automatic first-adoption
classification. Conflicting baseline copies are `contradicts`. [G24, G41]

Post-baseline `effects_without_decision` counts only effect entries at/after
`first_covered_sequence` that have no authoritative decision. Pre-baseline
history is separately rendered as `legacy_effects_without_authority` and has
**unknown durable-decision coverage**, not confirmed history and not permanent
post-baseline disagreement. No decisions are invented for it. That is the only
entitlement a deployment predating the store gains. Baseline is immutable;
missing metadata, truncation, new decisions or a later restart cannot advance
it to conceal discrepancies. If all independent copies are replaced together,
the store has no external witness: article 7 still limits the claim.

**S8. Compare contents, not just IDs.** For each shared ID compare all copied
facts: scope, capability, outcome, decided time, policy version, reason, rule,
digest, correlation and its source, principal references, evaluation recipe and
storage position. Compare principal representations where shared by the
existing serialization, without claiming that a display name independently
proves identity. Missing historical fields are unknown, not unequal to null.
A demonstrably different shared value makes `contradicts`, with count and named
fields in bounded diagnostics (never copied field contents). The decision file
wins for `read_decision`; the chain owns the assertion of what was recorded on
that connection. Repair neither from the other. The offline verifier only has
the chain; it does **not** cross-check the decision authority. The gate compares
its read decision to the matching exported effect explicitly. [G24, G41]

Missing post-baseline authority makes `disagrees`; absence alone does not prove
why it is missing. Start and serve when current stores remain usable. A wholly
missing established decision file is unavailable for new decisions in that
scope until restored; it cannot be silently recreated as an empty authority.
Other healthy scopes can operate. Status retains the time and cursors of the
last reconciliation and its historical discrepancies, not a moving health flag.

**S9.** Reconcile before listen in this order: protection after drop and root
writer lock; policy first load/archive; open journals and decision indexes;
recover chain tails; establish/resume baseline where eligible; reconcile facts,
positions and prior epochs; open new epochs; emit grade/composition; listen.
Newly encountered scopes execute their scoped steps before first admission.
Recovery failure cannot be reported as a completed reconciliation. [G17, G22]

### V — independent recipes and re-derivation (articles 2, 10, 13, 14)

**V1.** Contract `evidence.py` publishes canonical JSON, instant rendering,
length-prefixed components, preimage v1, entry hashing, chain contiguity/link
checking and manifest v1/v2/v3 recipes as normative text and executable code.
Server `domain/evidence_chain.py` and `domain/evidence_export.py` keep independent
implementations. Unknown versions, broken hashes and undeclared sequence gaps
retain their distinct chain verdicts. [G25, G26]

An offline partial export does not possess main's verified prefix used by
`_grades_before`. Therefore it supplies no trusted `grades_before` and reports
`unverified` for each connection over a range starting after sequence one,
regardless of the server's asserted prefix grade. It can still re-derive an
outcome within the range. The original server verdict is bound by its export manifest
and displayed separately from the recomputed grade; a conservative offline
grade is not itself a policy disagreement. No supporting prefix is added in
this block. Recovery context only establishes suffix closure, not prefix grades.

**V2.** Ship vectors and full recipe text in `_contracts/domain/`, listed in
`digests.json` and read from the installed wheel. `evidence-preimage-v1.json`
becomes the single normative copy of the server's existing fixture; leave a
pointer test there. `evidence-export-v1.json`, `-v2.json`, `-v3.json` cover their
exact recipes, intact/broken/gapped/unknown-version chains, partial ranges,
legacy shapes, changed verdict grades, removed attachments, changed availability
states, altered continuation and recovery context. `policy-version-v1.json`
pins exact-byte changes including trailing newline. `policy-evaluation-v1.json`
is the one arbiter between live and retrospective evaluation. [G25–G28]

**V3.** `verify_export(bundle)` validates historical/new acceptance shapes,
recomputes hashes and its export manifest under its named recipe, verifies recovery
context, derives required policy keys from included effects, checks bytes
against keys, and calls the contract's retrospective evaluator for each
hash-trusted supported effect. It produces the schema above under H1–H3.
It requires no evaluator argument, server import, installed conformance package,
connection or filesystem. A caller loads bytes outside this pure function.
A missing new-writer member in a historical shape reaches `members_absent`.
Broken chain membership yields `entry_untrusted`; computed disagreements among
other trusted entries remain visible. [G25, G28–G30]

**V4.** `sayfirst_contract.retrospective_policy.rederive_recorded_decision`
implements `sayfirst/policy-evaluation/v1`. This recipe checks the outcome,
reason and selected rule on recorded inputs, **not live admission, grant
lifetime eligibility, truthful identity or actual arguments**. Complete rules:

1. Decode UTF-8 and parse TOML 1.0; malformed bytes, duplicate keys or invalid
   shapes are `policy_unparseable`. Root keys are only `format`, `revision`,
   `rule`; format is integer 1, never boolean. Revision has only `reason`, a
   nonempty string of at most 512 characters without C0/C1 controls. Missing
   `rule` means an empty array; otherwise it is an array of tables.
2. Each rule has required `id`, `capability`, `principals`, `outcome`, `reason`;
   optional `scope`, `arguments_digest`, `grant_lifetime_seconds`; no other keys.
   IDs match `^[a-z0-9][a-z0-9._-]{0,63}$` and are unique. Capabilities match
   `^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`. Scope defaults to `local`, matches
   `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. Rule reason has the revision-reason
   bounds. Principals are a nonempty array of references under M3's name rules.
   Outcome is exactly allow/deny/suspend. Digest, if present, matches the
   published SHA-256 pattern. Lifetime, if present, is a positive non-boolean
   integer on an allow rule. Its deployment-configured upper bound is
   deliberately not reproduced: that bound affects live policy acceptance,
   not the outcome triple this recipe claims to check. No Unicode normalization,
   case folding, wildcard or inferred principal membership is applied.
3. A rule applies iff capability and scope exactly match, at least one named
   principal is in recorded references, and an optional pinned digest exactly
   equals the recorded digest. Null digest never satisfies a pin.
4. No applying rule yields `(deny, policy_absent, null)`. Otherwise take the
   strictest outcome `deny > suspend > allow`, then the first applying rule
   with that outcome in file order. Yield its ID and respectively
   `policy_denies`, `policy_requires_review`, `policy_allows`. Administrator
   reason text is not the returned closed-enum reason.
5. The recipe's own reason vocabulary is exactly `policy_allows`,
   `policy_denies`, `policy_absent` and `policy_requires_review`. The published
   `reason` enum is wider: `capability_unknown` is answered before the policy is
   evaluated at all and no policy version can produce it. A recorded reason
   outside the recipe's four is **out of scope for this recipe** and yields
   `unverifiable` with cause `reason_outside_recipe`. It is never `differs`:
   reporting a disagreement with a program that did not decide that entry is a
   claim stronger than the evidence (article 2), and H3 would promote it to a
   whole-bundle `differs`. Any later reason added to the published enum is
   likewise out of scope until a recipe that defines it is minted.
6. Otherwise compare the computed triple with the recorded triple. Equality is
   `confirmed`, inequality `differs`, failure to check `unverifiable`.

Recipe files preserve these rules permanently; semantic changes mint a new
recipe identifier and fixtures. Parser implementation versions are not a
substitute for the stable identifier. Historical untagged entries are never
assumed v1 because their policy happens to say format 1. [G27, G43]

Vectors cover no match, all strictness pairs, ties in file order, matching and
missing/mismatched digest, scope/capability mismatch, user/group matches, scoped
intersection, whitespace/256-character names, malformed/unknown members,
duplicate IDs, boolean integers, empty policy, unsupported recipe, a recorded
`capability_unknown` reason (unverifiable, never `differs`, and never lifted to
a whole-bundle disagreement), and a valid positive lifetime above a sample
deployment cap (retrospective triple check succeeds; live acceptance under that
cap refuses). On accepted-policy vectors,
run both implementations independently; on acceptance-only vectors explicitly
label the narrower retrospective claim. Finite vectors pin examples; the full
recipe text defines the remaining inputs. [G27]

**V5.** Missing or damaged policy makes affected entries unverifiable without
changing the chain's statement about stored bytes. Never evaluate a replacement
current policy. Missing metadata is `members_absent`; unsupported recipe is
`evaluation_recipe_unsupported`; a recorded reason the recipe does not define is
`reason_outside_recipe` (V4.5). None of the three is a disagreement. [G28]

**V6.** The conformance consumer holds a real stream, verifies peer credentials,
reads frames with observed timestamps, performs restart via its harness, follows
export continuation and invokes the complete contract verifier. It reports
`observed | not_observed | unknown` signal observations; EOF before the window
is unknown, not an invented heartbeat. [G30, G31]

**V7.** `sayfirst-conformance lifecycle --socket PATH --scope SCOPE
[--restart-command CMD]` runs the durable scenario. Without restart capability,
that mandatory step is not-applicable and the scenario/run is unknown, never
proven. This differs from the separately deferred sweeps, which are not steps
of the mandatory scenario (T1). [G32]

### H — what confirmed establishes (articles 1, 2, 7, 13)

**H1. Claim and inputs.** `confirmed` means that the **named, actually evaluated
records** are internally consistent with the archived policy bytes under their
recorded evaluation recipe and recorded inputs. It cannot establish historical
group membership independently, that actual arguments match a boundary-supplied
digest, receipt of an answer, execution of an effect, grant validity after
restart, protection against the daemon/root, or integrity against a writer able
to replace an observability-grade store. Grade is a separate weakest-grade
claim; a confirmed outcome is not a stronger integrity grade. [G28, G43]

**H2. Coverage.** The verdict states exact included sequence range and
continuation, the IDs actually evaluated and confirmed, and declared missing
IDs. Context entries are never counted as re-derived decisions. Coverage is
`incomplete` when a known-decision gap or counted event loss affects the included
range, `unknown` when an epoch lacks verified closure, unknown loss is declared,
historical context is missing or the range is empty, otherwise `complete` for
the included range only. A clean marker proves the emitter drained or declared
loss; it does not erase declared gaps. If both incomplete and unknown apply,
report incomplete and retain `coverage_unknown` in issues. Pre-baseline evidence
has unknown durable-decision coverage. Pagination is not itself loss, and does
not license a whole-history claim. Grade/composition-only ranges have no
historical decision to confirm. [G28, G40, G43]

**H3. Aggregate precedence.** Preserve every per-entry verdict and issue.
`overall = differs` if at least one trusted entry was actually evaluated and
differs, even when another is unverifiable. Otherwise `overall = unverifiable`
if structure/manifest/chain/context is unverified, coverage is not complete,
there are no evaluated effects, or any included effect is unverifiable.
Only otherwise is `overall = confirmed`. A known contradiction never disappears
behind missing data. Hash/manifest damage and policy disagreement remain
separate fields; none is translated into a live deny. [G28, G43]

For the graceful gate, its original decision ID must appear in both
`rederived_decision_ids` and `confirmed_decision_ids`, and the read decision's
shared facts must equal that exact effect entry. Confirmation of unrelated
surviving entries, or merely observing `overall: confirmed`, cannot satisfy it.
For the crash gate, its ID must instead be declared missing and absent from the
re-derived set. [G23, G37]

### X — scripted holder rules and observed lifecycle (articles 2, 10, 13)

**X1.** Keep all four client-bound holder scenarios: `grant_hit_within_lifetime`,
`grant_expired_by_lifetime`, `grant_void_on_connection_loss`,
`grant_void_on_arguments_change`. Their liveness is scripted; they establish
only the published holder rule. The label reaches `ScenarioReport`, the
`Report` counts a run prints, and any published conformance claim — not just a
generated README. [G33]

**X2.** Lifecycle steps use the optional versioned session extension and real
held sockets. No direct calls to server sweeps, fabricated frames or
`given.connection_live` may supply the evidence. Unsupported operations make
the scenario not-applicable and the run unknown. [G34, G35]

**X3.** The loader refuses scripted liveness/lifetime in scenarios with steps;
reports distinguish intended observed mode from successful observation. [G34]

**X4.** Add `grant_ended_on_daemon_stop` as an observed runnable scenario:
hold → graceful restart while retaining buffered frames from the old stream →
observe `grant_ended/daemon_stopping`. Record frames while restart is happening,
not by opening a new socket afterwards. Keep `grant_ended_on_policy_change` and
`heartbeat_on_held_connection` separately enumerated as not-applicable with
reason `runtime_sweeps_not_scheduled` at this base. Their restoration condition
is production scheduling of both sweeps, with bounded interval, shutdown,
policy-failure and concurrency tests in the scheduling change. That change
makes them owed observed scenarios; the harness cannot substitute a fresh ask
to provoke the reload. [G36]

### T — the release gate and measured cost (articles 1, 2, 3, 10, 13)

**T1.** Ship `durable_decision_lifecycle`, server-bound, article 10, with one
allow rule `scenario-0` for `example.effect` in `local`, a fixed digest and opaque
correlation `gate-1`. Steps are hold → close_connection → graceful restart →
read_decision (allow, policy_allows, scenario-0, grant_present true) →
export_and_verify (intact, confirmed, decision_rederived true). The original
heartbeat second step is explicitly moved to the separately reported
not-applicable scenario of X4. No mandatory step is skipped to obtain proven.
Export exactly the pre-restart epoch through its clean marker, plus required
context; do not inadvertently include an unclosed new startup epoch. H3 and
comparison of the gate's exact ID/facts are mandatory. [G37]

**T2.** `durable_decision_lifecycle_after_crash` deliberately stalls the effect
store **before any bytes of the gate's effect entry are written**, after durable
append and answer delivery. Kill that daemon process with SIGKILL, restart over
the same root, read the original decision, and export through recovery. Expect
intact surviving chain, `overall: unverifiable`, the ID named in an unflushed
gap, the ID absent from re-derived IDs and unknown event coverage. This proves
durable readability and honest declared loss, not offline re-derivation of the
missing decision. Torn partial-write recovery is a different injected test;
it cannot accidentally satisfy this zero-byte stall scenario. [G23, G39]

**T3.** The two named gate tests in
packages/control-plane/tests/e2e/test_durable_decision_lifecycle.py run a
separate daemon process and use only contract/conformance imports. A separate
server-side test launcher owns the storage double and process barrier; it is
test-only, not a production environment switch. The consumer/gate must never
import that launcher or server code. The harness reports an unavailable kill
barrier as not-applicable, which **fails an owed platform gate**. [G30, G37]

Use the existing `scripts/require_platform_guards.py`, not a second counter.
Both gate functions have globally unique names and carry
`@requires_platforms(*OS_REAL_PLATFORMS)` from `sayfirst_testing.platforms`.
`requires_platform` takes exactly one platform and cannot express this gate;
`guard_gates._gate_of` resolves the starred form, so the two-platform obligation
is read from the guard's own source. Actual same-commit unprivileged Linux
**and macOS** reports are required for release. No macOS execution is claimed by this spec. A restricted
runner must be replaced by one that can bind a Unix socket and signal its own
child process; skipping is not platform success. Add release wiring in the
implementation change to `.github/workflows/ci.yml`: run G38 and both tests,
write JUnit plus commit/platform identity, and invoke the counter with the
explicit gate test tree and `--privilege=unprivileged`. G38 must assert discovery
of both exact gate identities and reject an empty discovery set; the current
counter otherwise succeeds when no guards were discovered. Test removal,
renaming, wrong tree, missing report, skip and duplicate bare function names
must all fail the release check. [G38]

The implementation brings the executable wiring. A dedicated repository-doc
change names the same two-platform requirement in `GOVERNANCE.md` and its
activation date; this block does not edit that document. Public contract and
extension/exception changes follow article 16's fourteen-day RFC process.
Until the required decisions and release procedure are adopted, a green report
is evidence of a test run, not a claim that this draft already forbids release.
Review/merge procedure and build readiness are distinct.

**T4. Cost and measurement.** The common `local` scope serializes misses at its
append mutex/flock and at least one file sync per decision; archive misses add
write/file/directory syncs, new scope/epoch/baseline setup adds metadata syncs.
Grant hits remain local to the boundary and do not write this authority. A
policy change can cause many simultaneous misses on the same scope. The block
must measure that cost without weakening durability: report single-caller and
32-concurrent-caller runs, at least 1000 decisions each, p50/p95/p99 end-to-end
miss latency, lock wait, fsync duration, throughput, and archive-hit versus new
version cases. Record filesystem, platform, commit and sample count. [G44]

The initial engineering target is p95 ≤ 100 ms on a local SSD for an archive-hit
single-caller miss and completion of the 32-caller batch within 60 seconds.
These are explicit provisional measurement targets, not constitutional promises
or portable timing assertions in the correctness gate. Exceeding them requires
an implementation report with observed numbers and a bottleneck explanation
before release review; it never permits acknowledging before sync. The gate
also records latency observations, but asserts only its bounded operation
completion windows. Baseline/reconciliation scans are linear in retained data;
report scanned bytes and startup duration. No performance result is claimed by
this specification.

## What is copied, what is new, what is cut

Nothing is copied from outside this repository. This design uses the existing
public domain, storage and contract vocabulary; all new modules and fixtures
are authored against it. No private source path or rename table is published.

| Piece | New work and reason |
|---|---|
| File decision store and recovery store | New authoritative envelopes, baseline/epoch journal, sync/failure protocol and rebuilding indexes (articles 3, 10) |
| Archive port and file adapter | New immutable historical bytes with protection/retention and own scoped exception restoration (articles 3, 5, 7) |
| Decisions, emitter, reconciliation | Copy facts with provenance, retain exact recovery identities, compare contents, expose unknown non-decision loss (articles 2, 7, 10, 11) |
| Contract verifier and retrospective module | New independent recipes, complete offline checking and stable evaluation identifiers (articles 13, 14) |
| Contract schemas, vectors, replay extension | Add response shapes with historical acceptance, manifest v3, recovery kind, optional versioned lifecycle seam (articles 2, 8, 13) |
| Conformance consumer and test launcher | Observe sockets/restart, isolate server-side fault injection, retain scripted holder tests (articles 2, 10, 13) |
| Testing suites and release workflow | Negative crash/recovery cases, two-platform non-vacuous gate and measured cost (articles 2, 3, 13) |

Memory storage remains for tests and policy-less composition. The global
64-reference restriction, evaluator-free contract promise, timestamp exclusion,
no-baseline reconciliation and mandatory unscheduled heartbeat are removed from
the design. No live grant timer, approval persistence or policy read route is
introduced.

## Guards

These are implementation obligations, not tests claimed to exist or pass in
this specification-only change. Test-first implementation watches the relevant
negative case fail before adding the behavior. G1–G38 retain the original review
anchors with revised meanings; G39–G44 cover the newly settled sections.

| Guard | Named test(s), location and required negative witness |
|---|---|
| G1 (3, 5) | `sayfirst_testing/decision_store_contract.py`: `test_a_decision_appended_is_read_back_as_appended`, `test_a_duplicate_decision_reference_is_refused_never_upserted`, `test_a_read_without_a_scope_is_refused`, `test_another_scopes_decision_is_never_read_here`; both adapters |
| G2 (1, 3) | `tests/unit/test_decision_service.py::test_a_known_prewrite_refusal_answers_unavailable_and_cancels_the_reservation`; no effect for a known refusal; contrast indeterminate C2 |
| G3 (3) | `tests/contract/test_file_decision_store.py::test_duplicate_and_mutation_attempts_cannot_rewrite_a_committed_record`; exercise actual API/storage behavior, not merely forbidden method names |
| G4 (2, 3) | `test_torn_tail_recovery_preserves_complete_records_and_rebuilds_index`; malformed complete lines and conflicting duplicate IDs make the scope unavailable rather than disappearing |
| G5 (7) | Bootstrap protection tests for foreign-owned/group-writable/ACL-bearing directories, writable children and replacement paths; root platform test proves creation after drop at 0700/0600 |
| G6 (7) | `tests/unit/test_integrity_grade.py::test_writable_decision_archive_or_recovery_paths_lower_the_grade`; actual child access differs from its parent |
| G7 (3) | `policy_archive_contract.py`: idempotent keep, unknown-version absence, mismatched input refusal, byte snapshot consistency, archive sync before decision append |
| G8 (3) | `test_an_archive_keep_cannot_remove_or_replace_a_version`; byte comparison across repeated/damaged keeps |
| G9 (2, 3) | `test_a_damaged_version_is_reported_never_overwritten_or_evaluated_as_current_policy`; manual loss is absent, not confirmed |
| G10 (3) | `tests/unit/test_bootstrap_composition.py::test_policy_enabled_composition_uses_file_decisions_and_recovery` |
| G11 (1, 3) | `test_a_durable_decision_is_readable_from_a_second_composition`; compare the full document, not just outcome |
| G12 (2) | `test_archive_failure_refuses_before_decision_append_and_writes_no_effect` |
| G13 (2, 5, 10) | Evidence-read tests require every included policy key, exact bytes, absent state, OSError failure; whole-file policy includes a second scope and comments |
| G14 (11) | `test_default_evidence_has_no_payload_member`; full supplied payload omitted; a short content-like correlation still passes the published schema and is explicitly boundary-supplied, disproving any stronger privacy assertion |
| G15 (11) | `test_capture_redaction_does_not_change_copied_decision_identity`; verify correlation-source marking and nullable behavior |
| G16 (5, 11) | `test_references_intersect_only_rules_for_this_scope_and_capability`; competing rules, 65+ groups, 256-character/whitespace names, sorting, uniqueness and worst-case escaping at the 1 MiB policy bound |
| G17 (1, 3) | `test_decision_evidence_and_baseline_survive_process_restart`; recovery/grade/composition order and fresh connection state |
| G18 (3) | `test_policy_changed_while_down_is_reread_and_projection_rebuilt`; historical archive remains unchanged |
| G19 (10) | Regression of the already-merged issuing-connection fix: held socket remains open until stop or peer close; 65 closed asks leave no registered grants. Observe EOF and shutdown frames; do not require an unscheduled heartbeat |
| G20 (1, 10) | `test_restart_ends_grants_but_preserves_prepared_grant_id`; graceful signal and crash loss differ; no claim of peer receipt |
| G21 (3, 12) | `test_restart_derives_no_resolution_for_a_suspended_decision` |
| G22 (10) | Reconciliation exact ID/position tests; >8192 missing decisions split into bounded markers; dropped/known torn markers deduplicate; wall-clock reversal cannot exclude a later decision |
| G23 (2, 10) | `test_a_daemon_killed_with_a_record_in_flight_declares_it_at_the_next_start_and_still_explains_it` in the gate module: T2, actual separate process, missing ID not re-derived |
| G24 (2, 3) | `test_missing_postbaseline_authority_is_reported_without_global_start_refusal`; mutate only one copied reason/digest/reference and get contradicts; no silent repair; all four status states and unknown baseline |
| G25 (10, 13) | Contract evidence tests reproduce every published hash/manifest vector, including legacy recipes and changed availability/continuation/whole verdict |
| G26 (13) | Server and contract independently run the single packaged preimage/export vector sets; installed-wheel resource checks and component mutations |
| G27 (13) | `packages/contract/tests/test_retrospective_policy.py::test_contract_evaluator_runs_every_policy_evaluation_vector`; server `test_policy_evaluation_vectors.py` runs them independently; conformance installs contract and calls `verify_export` on full re-derivation bundles |
| G28 (2, 13) | Contract verification negative cases: malformed map, wrong bytes, missing members, unknown recipe, corrupt context, empty/grade-only range, mixed differs/unverifiable; asserts exact issues and precedence |
| G29 (1, 14) | `tests/test_retrospective_evaluator_boundaries.py::test_boundaries_cli_and_live_server_do_not_import_retrospective_evaluation`: resolved AST import graph including relative imports, aliases and re-exports, plus import-hook tests on executable ask/grant/CLI paths. Scan all shipped boundary packages, `sayfirstd`, contract client/transport helpers and live server; do not put retrospective imports in package init. Ban transitive reach to both `retrospective_policy` and its `evidence` wrapper on those paths. Inject direct, alias, wrapper and dynamic-import mutants and watch failure. The allowed consumers are the offline verifier, conformance audit consumer and tests; they issue no live authorization. A missing external boundary tree is reported untested; its own repository must run the published guard, never claim it was scanned here |
| G30 (14) | tests/test_verifier_independence.py: AST plus clean-installed-wheel test with no server/conformance installed runs `verify_export` through re-derivation; contract/consumer/gate imports no server; retrospective module performs no file/socket/clock/environment access |
| G31 (2) | Consumer signal tests read actual stream frames; EOF before window gives unknown, silence does not manufacture a heartbeat |
| G32 (2) | Lifecycle command without restart support is unknown and never prints proven |
| G33 (2, 13) | Four scripted scenarios labeled in the generated table and in `ScenarioReport.liveness`; `Report` carries the derived observed/scripted/not-applicable counts and `RunVerdict` keeps its three closed values; documentation-presence check is named as such and is not the executable liveness witness |
| G34 (13) | Loader rejects unknown step/member and scripted liveness inside steps; intended mode is separate from execution status |
| G35 (8, 13) | Old Session still satisfies its old protocol and runs scripted scenarios; absent/unknown lifecycle extension version yields not-applicable; observed use_grant reads the held socket |
| G36 (2, 10) | Server replay proves daemon-stop scenario; enumerates both sweep-dependent scenarios as not-applicable with restoration reason; no server-bound scenario is silently unaccounted for |
| G37 (1, 10, 13) | `test_the_release_gate_holds_one_decision_from_question_to_independent_verification` in the gate module: T1, actual process, exact gate ID in both re-derived/confirmed sets and full shared-fact comparison |
| G38 (2, 13) | tests/test_release_gate_is_owed.py: discovers G23/G37 explicitly on Linux and macOS, rejects empty/wrong tree, skipped/missing/duplicate test identity, checks release workflow runs it and counter on both same-commit reports |
| G39 (1, 2, 3) | `test_commit_fault_matrix`: crashes/failures before/after archive publish and directory sync, decision bytes and sync, index publication, emission, grant activation and response write; complete indeterminate append retained, torn append quarantined, no usable grant on failure |
| G40 (2, 7, 10) | `test_recovery_is_idempotent_across_another_crash`; zero-byte and torn writes distinct, marker/journal sync split, id-less old gaps, clock reversal, unknown lost grade/composition; verifier lowers affected epoch to unverified even when all decisions survive |
| G41 (2, 3) | `test_baseline_is_once_only_and_legacy_history_is_unknown`; crash between baseline copies, missing whole decision file, conflicting header, union of scopes and immutable cursors; only new discrepancies change post-baseline status |
| G42 (5, 7, 11) | Export entitlement, bytes/continuation bound, inaccessible versus absent archive, own exception restoration and consistent backup documentation; attachment state mutation moves v3 manifest |
| G43 (2, 13) | `test_confirmation_names_covered_ids_inputs_and_recipe`; wrong gate ID, unrelated surviving entries, support-context effects, no effects, unknown historical recipe, a reason outside the recipe's four, partial prefix grades and hidden disagreement all fail their stronger claim — and the out-of-recipe reason reaches `unverifiable`, never `overall: differs` |
| G44 (10) | `measure_durable_decision_miss_cost` writes the T4 platform/commit/sample/timing report; no timing-driven weakening of sync order; target exceedance is explicit |

Article 15's existing SPDX guard covers every new implementation artefact.

## Non-goals

- Bulk decision export or late effect reconstruction. A missing effect gets a
  declared gap; its durable decision remains readable locally but cannot be
  re-derived from that bundle (articles 3, 7, 10).
- A hash-chained decision file or a second live evaluator shared with the
  contract. Reconciliation compares authority to evidence; offline verification
  checks the latter and policy, not the authority (articles 3, 13, 14).
- Approval durability or timer scheduling. Restart never resolves suspension;
  sweep-dependent observations stay explicitly not-applicable (articles 2, 12).
- A new read authorization model. Current admission-based entitlement is
  explicitly disclosed in A6; it must not be sold as scope confidentiality
  (articles 2, 5, 6).
- Automatic purge, power-loss certification, an external witness, or newly
  established evidence grade. This block preserves main's grading limits and
  exposes unknown history; it does not strengthen them by assertion (2, 7, 11).
- Efficient indexes beyond rebuildable per-file indexes and linear reconciliation.
  Measure startup cost; no unsupported latency promise (article 10).

## Dependencies on other blocks

Block 2.1 supplies the contract package, schema loader and scenarios; this
implementation adds writer/reader shapes, recipe resources and problem codes.
Block 2.2's composition after drop, directory protection, descriptor/path checks
and the `sayfirstd` topology are already merged on the rebased main; preserve them.
Block 2.3 supplies the live evaluator and grant registry; widen LoadedPolicy
and decision facts but retain independent live evaluation and the merged
issuing-connection fix. Block 2.4 supplies the chain, bounded emitter, grade
calculation and already-v2 manifest; extend its documentation and formats with
C/S/H and v3. Block 2.5 supplies testing and provider discipline; new storage
suites remain server testing support. Block 2.6 supplies replay; keep its old
Session usable and add the optional versioned lifecycle extension.

Implementation order: contracts/recipes and recovery formats first, then
archive and durable append, baseline/epoch reconciliation and grade semantics,
then verifier/consumer and gates. Preserve main's foreign-value snapshot,
prefix-grade, held-file/path and connection-release regressions throughout.
Production sweeps are a named later change, not a hidden dependency of this
block's mandatory gate. Repository-level policy/security/release wording is a
dedicated change; executable release wiring belongs to this implementation.

## Questions resolved in this revision

1. **Facts in both authority and chain:** yes, for chain integrity and useful
   export (7, 10), with real content comparison (3) and explicit correlation
   provenance/limits (11). The offline verifier does not compare the authority.
2. **Principal intersection:** yes, narrowed to scope and capability. Match
   current parser names and remove the global 64-reference startup restriction.
   Bound by the already-bounded policy bytes; never truncate (5, 11).
3. **Unflushed gaps:** yes, with exact persistent positions, bounded ID chunks,
   idempotence, separate physical/logical accounting and unknown non-decision
   loss. Missing decisions are readable but not re-derived from export (2, 7, 10).
4. **Missing authority:** declare and continue where writes remain usable. A
   once-only durable baseline separates unknown legacy history from new
   discrepancies; contradictory facts have their own state (2, 3).
5. **Policy bytes in bundle:** yes, now **inside manifest v3**, including state
   metadata. Main's v2 already invalidates the old “leave its export manifest unchanged”
   rationale. Keep historical recipes, explicit current read entitlement and a
   total byte bound with existing continuation (2, 5, 7, 10).
6. **Archive under evidence root:** yes; inspect every child, back up/restore all
   stores together, indefinite retention, own exception with a restoration path
   for legacy content-addressed bytes (0, 5, 7, 11).
7. **Evaluator placement:** operator decided contract wheel, pure and
   retrospective. Complete offline verifier survives, evaluator-free installation
   yields. Live server remains separate; one fixture arbiter. Naming,
   documentation and G29 prevent boundary/CLI/live-path use (1, 13, 14).
8. **Compatibility:** no new route here; do not promise generation-one treatment
   of future operations. Separate historical acceptance and new-writer schemas;
   keep old Session intact with an optional versioned extension (8, 13, 16).
9. **Gate counter:** reuse it, with anti-empty discovery and explicit Linux/macOS
   same-commit release wiring. Test execution, formal adoption and actual
   platform evidence are distinct obligations (2, 13, 16).
10. **Scripted holder scenarios:** retain all four, with labels and counts in
    reports and public claims. New observed coverage is specific to the path
    exercised; unscheduled sweeps are not-applicable, not a false pass (2, 13).

No implementation-shaping question remains deliberately delegated to the
builder. Revision 3 closes the five defects the design review found; the four
things the council named as blocking — the rebase, Q7's contradiction, Q4's
baseline and the unsatisfiable gate — are settled in the text above. This is
ready for implementation;
it is not approval to merge changed contracts/exceptions without the repository's
RFC procedure or a claim that the release gate has run. Remaining work is
implementation and its negative tests, two-platform execution and measurement,
and the dedicated documentation/release adoption described above.

## Provenance and authority

This is specification revision 3. Revision 2 was written by GPT-6 on
2026-09-05 and rebased onto `origin/main` after the two merged fix series before
revising its arguments. Revision 3 is a review pass by Claude Opus 5 on the same
base and the same council inputs; it changes no answer to the ten questions and
no operator decision. It repairs five things revision 2 left unimplementable or
stronger than the code beneath it, each checked against `origin/main`
(the main of 2026-09-05, after its two merged fix series): the two-platform gate decorator is `requires_platforms(*OS_REAL_PLATFORMS)`,
because `requires_platform` takes one platform; the run-level liveness counts
belong to `Report`, because `RunVerdict` is a closed three-value `StrEnum`;
A6 no longer offers an operator a switch suppressing policy attachments that
generation one does not have; V4 gains rule 5, so a recorded reason outside the
recipe's four — `capability_unknown` is published and no policy version can
produce it — is `unverifiable` rather than a fabricated `differs`; and the
published evidence bodies are named as closed objects, so the new members are
understood as a schema change with a historical-reader counterpart. The branch
was The task report records the exact base and pushed commit; this public
design names the resulting behavior. Inputs read: the complete constitution (0–18),
governance/contribution/security rules, original block-2.7 design, both complete
independent council readings and the operator's evaluator/gate/baseline
instructions. The council records remain outside this repository; no private
finding identifier or source path is published here.

Repository code checked at that base includes policy parsing/evaluation,
bootstrap composition, evidence reads/export, the published evidence schemas,
connection/sweep documentation, current exceptions and platform-gate tooling;
the changes since the former base were inspected for stale dependencies,
including the two merged fix series. Earlier design sources remain historical
context, not a claim that absent fixes are still prerequisites. The partition
backbone, boundary-distribution design and source contract examples were consulted
read-only as background; nothing is copied from them. No implementation, private
source, repository-scope document or generated contract artefact is changed by
this specification revision.
