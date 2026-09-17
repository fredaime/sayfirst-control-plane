<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

Every deprecation of a plugin interface version (article 8) is announced here in
the release that begins its window, and the window runs for at least two minor
releases or six months from that release, whichever is longer. A deprecation
that this file does not announce under its own release fails the packaging test.

## Unreleased

- The publication checklist carries every act the constitution names, in the order
  they are performed, and a guard fails when one of them stops being a line of it.

## 0.2.0

- The four scoped reads answer from a running daemon, and a third party
  verifies an export with the contract distribution alone.
- The boundary holds a real grant over a real socket: the grant is bound to
  the channel that carried it, and only the event stream a decision may be
  answered on ends its connection.
- Approvals reach the surface: a suspended ask is read, ended by an
  approver, and the next ask runs the body once. An approved approval nobody
  has spent is the one record the store keeps for the life of the process.
- The instrumentation chain runs end to end against a daemon: a governed
  program's effects are asked about first, and the chain the daemon kept is
  read back through the transport.
- Every distribution of this repository moves to this version together. The
  contract generation is unchanged at one: a version is not a generation,
  and no client negotiates one.

- The mechanism that publishes these distributions exists, and an operator's
  tag is the only act that starts it — article 0 still decides when that act
  may be taken. The release workflow does nothing on ordinary traffic — no
  branch, no pull request, no schedule — and a tag whose name gives the
  version every distribution here carries builds all seven, checks the
  artefacts with a pinned checker, and uploads them through trusted
  publishing into the deployment environment named for that purpose. The
  person who publishes is asked to put a reviewer on that environment;
  whether it demands one is a setting of the repository that no file here can
  read. No token is stored anywhere: the index verifies the workflow's own
  identity. A tag naming any other version is refused before the build and
  publishes nothing. The same workflow can be started by hand, and then it
  builds and checks and publishes nothing at all — the input that asks to
  publish is refused by name, first, before anything is checked out, because
  an input wired to nothing is a trap for the next operator. The three tools
  that cut the release — the environment tool, the artefact checker and the
  step that uploads — are pinned to one version each; the checkout and
  artefact actions stay on their major tags, and so does the action that
  installs the environment tool: it is pinned to a major tag itself, while the
  tool it installs is pinned to one version.
- `scripts/release_version.py` is the one reader of the version this tree
  would release. It walks the project files rather than holding a copy of the
  number, refuses a repository whose distributions disagree — naming them —
  and answers whether an expected version is the one they carry, which is what
  the tag is checked against. The changelog guard reads through it, so a
  release section missing for the version being cut is red before a tag exists.
- `docs/NEUTRALITY.md` publishes the count article 18 asks for at each
  release: one row per release, newest first, with the rule it was counted by
  and who counted it. The row for this release says « not reported ». The
  number is measured on the other side of the boundary, this repository holds
  nothing that could check it and says so, the request went out and had not
  been answered when this release was cut — and an absent count is published
  as « not reported », never as a zero, because zero is a measurement and the
  two mean opposite things to a reader asking whether this core is drifting.
- `docs/publication-checklist.md` is one page for the person who publishes:
  the acts no workflow can take — confirming the public repository name, the
  display name the index shows, the reviewer on the deployment environment,
  the request for the count above — and a record of what a dry run of the
  release mechanics proved and what no dry run can.
- Every dependency of this repository must ship the TEXT of its licence, and
  not only an identifier claiming one (article 15). A classifier or a licence
  expression with no licence file behind it is somebody else's code
  redistributed with nothing attached to it, and it is now refused by the same
  guard that holds the closed list of licences; the one way in is an entry in
  the exception register naming the licence text actually found. This changes
  what a contributor's gate refuses.

- The constitution's Guard column is honest for every article: each clause of
  each Guard paragraph now names a mechanism this tree runs, admits one of the
  three deferrals and says what it defers, or cites the article that owes the
  rule. `tests/test_guard_column_is_traceable.py` reads the column back out of
  the tree clause by clause, and the sixteen rows it carried as expected-red
  under that rule are deleted: `RULE_FIVE_IS_RED_TODAY` is empty, and the
  dictionary and its parametrisation stay in place so that the next row found
  red is recorded where a repair cannot land while still claiming to be
  pending. Nothing normative moves — only Guard paragraphs — and the
  deferrals that remain are the ones this tree really has: no adapter keeping a
  governed record in a database, so no transaction to set a scope inside
  (article 5), the semantic firewall and the required statuses of a repository
  this one cannot read (articles 4 and 16), exclusivity and interval-driven
  re-evaluation of the integrity grade (article 7), the two ports the
  conformance kit does not reach and the subcommand a plugin contributes
  (article 8), the packs and their notes, which live in the client repository
  (article 9), the sweep of a connection that holds no grant and asks nothing
  (article 10), the provenance review and the body of a pull request
  (article 14), the corporate agreements (article 15) and a process this
  repository does not start (article 17).
- Three of the reasons the column carried from the reading of 2026-09-06 were
  overtaken by the tree and are recorded as overtaken rather than repeated.
  Article 17's two telemetry tests exist and run, so the row names them, the
  workflow that runs them and the guard that holds that leg reaching them, and
  keeps « cannot verify » only for a process this repository does not start.
  Article 15's third check has a producer:
  `scripts/check_developer_certificate_of_origin.py` and
  `tests/test_developer_certificate_of_origin.py` were already named in the
  row, and the dependency checker and the SPDX and NOTICE checks now are too.
  Article 12's port serves both approval operations over the socket, and the
  row names the end-to-end case that puts a person's act to a real daemon, the
  conformance kit the multi-signature provider is judged by, and the member
  that carries the person who acted.
- Article 9's Guard stops understating what exists. The instrumentation engine,
  the instrumentation verifier and three convenience packs are published in the
  project's command-line client repository, not absent; what this repository
  builds none of is still said, and what this branch runs against a real daemon
  is now named — the engine under the shipped subprocess pack, and the verifier
  against every pack that client ships. `instrument apply`, the committed code
  modification, refuses with a stated reason and gets a clause of its own.
  Article 3's Guard stops saying that no structure is yet declared an
  observation: the daemon's own event log is the information contract's first
  observation, declared under the role `trace`, and the row cites the guard
  that holds that declaration.

- `configuration_writable_by_principal` joins the published problem codes,
  additively within contract generation one, under article 8 and in the class
  `refused`: a daemon in system mode now refuses a decision request from a
  principal with effective write access to the configuration file it was
  started from, or to a directory that file could be replaced through, and says
  so under a code of its own. It is a `403` on the decision operation and is
  never retryable — the question was received and rejected, and asking again
  changes nothing until the file's permissions do. It is the sibling of
  `policy_writable_by_principal` and deliberately not the same code: an
  operator told only that a principal "could write the policy" would not learn
  that what it could write was the file that chooses which file the policy is,
  where the evidence is kept, which group is admitted and which plugins are
  composed. A client of an earlier generation reads an unknown code, which is
  never read as a refusal, so nothing is widened by not knowing it.
- The same file gains the other protection article 8 asks for, at start:
  `Settings` now carries the name the configuration was read from, and a
  system-mode daemon refuses to start on one that anyone but root or its
  administrator group could write or replace, with the server-side reason
  `configuration_unprotected` — the file, the component that decided it, the
  rule that decided it and the account that looked. The check is the whole-name
  effective-access walk the policy authority already receives, applied through
  a new adapter that holds no reading of its own, and it is made before
  anything else a start could refuse over. The consequence worth an operator's
  attention is the one the article draws: a program run as root, or run as the
  administrator group, obtains no decision in system mode — root can write every
  file there is, and a configuration group-writable by the administrator group
  starts, since that group is exactly who the article allows to write it — so a
  governed program must run as some other principal. What the per-request check
  reads is the group the program runs as, the one its peer credential carries; a
  principal admitted through a named supplementary membership is not refused by
  it, as it is not by the policy authority's own per-connection check. Mode
  `0640` is the layout that admits a group to the socket without making a
  program run as that group a configuration writer. Nothing changes in
  per-user mode, where the configuration and the daemon belong to one
  account, and nothing is claimed at all when the daemon
  was started with no `--config` to read. The limitation this closes was entry
  4 of `docs/exceptions.md`, which is now closed rather than renewed, with the
  date and the mechanism; `SECURITY.md`, `docs/deployment.md` and article 8's
  own Guard say what the daemon refuses in place of what an operator had
  instead.

- This repository's end-to-end suite runs the client distribution's
  instrumentation verifier against every pack that distribution ships, and
  fails unless the verifier's own report names each one as inspected
  (article 9); the public workflow checks out no client beside this tree
  today, so in that gate these cases are reported skips until a leg holds
  the client. The assertion belongs
  here rather than beside the packs because what it reads is a chain a real
  daemon wrote:
  `packages/control-plane/tests/e2e/test_the_verifier_inspects_every_shipped_pack.py`
  designates every shipped pack, walks one point of each from a program's own
  code, and takes the shipped set from that client's package data and the
  inspected set from the report — never from the command line, which is the
  set a run could copy from its own invocation without having watched
  anything. The verdict is watched firing beside it: the same program, run
  with nothing in front of its effects, comes back `ungoverned`, and a shipped
  pack the program leaves alone comes back `not-exercised`, which is never a
  pass. Two limits are stated because the claim is no stronger than they
  allow. A tree with no client checkout beside it cannot verify a pack it does
  not hold, so those cases are reported skips and never passes — and the
  public workflow is such a tree today. And a pack whose declared capability
  the published ask schema refuses cannot be governed by this plane at all: no
  policy rule can name that capability, no question about it can be put, and no
  run can report every point governed. The case that would prove every point
  governed carries exactly that as its reason for as long as such a pack is on
  disk — the condition is read from the packs themselves, so where there is
  none the case is a live green assertion instead.
  Article 9's Guard is amended to name the mechanism, and to keep the
  packaging test — which runs in that distribution's own gate, not this one —
  as the admission it is.

- `person` joins the published `approval-result`, additively within generation
  one: a wait somebody approved or rejected carries the reference of the person
  who acted, and a wait nobody acted on carries no such member at all — absent
  rather than null, because null would be a person the record does not have. It
  is the connection's verified principal, as it always was; what changes is that
  a reader of `read_approval` can now see who acted, where before it could see
  only that somebody had, and an approval is the one record in this core that
  exists because a person acted. A client of an earlier generation keeps the
  member it does not know, and neither client sends one: the resolution request
  still defines no member that could name a person. The shipped conformance fake
  names a person too — one of its own making, since a fake has no verified peer
  to read — so a resolved document read from it is not one that names nobody.
- The daemon composes a bounded, readable sink for its own event log in place of
  the no-op it composed before. `approval.resolved`, `approval.refused`,
  `approval.expired`, `approval.forgotten` and every other entry the core
  records went nowhere, which made the event log a mechanism indistinguishable
  from absent. The sink keeps the most recent entries, gives each one a
  sequence, and counts what it dropped past its bound, so a reader can tell
  "nothing happened" from "the sink lost it". It is an observation and never
  evidence: it is held in memory, a restart loses it, no operation of this
  generation serves it over the socket, and no decision is taken from it. The
  evidence chain remains the authority for what the daemon decided.
- The approval sweep reads what is due instead of walking the store. Both halves
  of it — ending the waits that ran out, and forgetting the records nothing can
  still need — sorted every reference the store held, on every decision request
  and every held-grant wake, so the cost of one request grew with everything the
  process had ever suspended. Two due-time indexes answer the same question from
  their front. What the sweep ends, what it forgets and the order it reports
  them in are unchanged, the approved approval nobody has spent is still never
  forgotten, and the store's record remains the authority the indexes are only
  a hint about.
- The daemon keeps a connection open after a document answer. Only the event
  stream a decision may be answered on ends its connection, and it ends it
  because the grant is bound to the channel that carried it (article 10); every
  other answer the decision surface writes — a decision read, the policy
  status, an ask the request did not select the stream for, and every refusal —
  now leaves the connection good for the next request, and no longer publishes
  `Connection: close` for one. A caller that read a decision and then its policy
  status paid a connect and a peer-credential verification for the second, and
  rule C4 forbids a client re-opening an address silently, so the cost was
  visible in every caller. Nothing about the stream moves: it still publishes
  the close, the write side is still shut down when it ends, and a grant still
  ends with its channel. The project's own transport keeps `reconnect()` and
  keeps needing it for a far end that does close.
- The shipped conformance fake serves all four reads the binding declares. A
  decision read back by reference and the policy status answered
  `operation_unknown`, so a third party could not build the pair a published
  read exists for — ask, then read back what was answered — against the fake at
  all. The decision read answers the published record and the refusal
  `decision_not_found` at the status the binding lists; the policy status
  answers `unknown` for a projection this fake keeps none of, which is the
  honest third value (article 2). A write to either target is now the method
  refusal rather than a missing route.
- The fake's two evidence reads answer from a real chain. The page and the
  export were placeholders — no entries and a verdict written by hand — so a
  conformance client could read their shape and nothing else, and the one thing
  an evidence read exists for, a chain that verifies, was proven only against
  the daemon. Entries are now placed with the published `chained_document` and
  judged by the published `verify_chain`, a page carries the grade entry its
  status read reports and then each decision's effect, and an export carries
  the v3 digest and the exact policy bytes its effects name — so an export the
  fake serves is one a holder of the contract distribution alone can verify. A
  range over a scope with no entries answers the verifier's `unverifiable`
  rather than an emptiness written here.
- The published evidence recipes move to `sayfirst_contract.evidence_recipes`,
  and `sayfirst_contract.evidence` re-exports every one of them, so no import a
  consumer writes moves and no recipe, hash or verdict changes. The split is a
  rule rather than a tidiness: the module it moved out of also holds the offline
  export verifier, which re-derives a recorded decision from the archived bytes,
  and re-deriving a decision is deciding — which article 1 keeps away from every
  boundary and every server, the shipped fake included. A writer that only
  places an entry, or a reader that only checks a chain, now reaches the recipes
  without reaching the evaluator, and the guard that resolves those import
  graphs is unchanged and still fails on a planted reach.
- `NegotiatedClient` forwards the decision read and the policy status, which
  the client protocol declares and it did not carry. A caller that negotiated
  the generation and then asked for either got an attribute error rather than a
  result.

- Within generation one, an entry whose `preimage_version` this distribution
  holds no reader for verifies as `unverifiable`, naming the sequence and the
  version, where it previously verified as `broken_at`. No recipe changes, no
  hash moves and no entry that verified before verifies differently now. What
  moves is a claim: `broken_at` is a negative fact about the chain, and a
  verifier that does not hold the recipe established none — the entry may be
  perfectly sound under a recipe published later (article 2). A reader that
  treated `broken_at` as « the chain is damaged » was reading a claim the
  verifier never made. An entry the declared recipe cannot be applied to at all
  — a delegation that is not a chain of principals, an instant outside the
  calendar — reaches the same verdict for the same reason. The daemon's
  verifier and the offline verifier in the contract distribution move together,
  and the published vectors are what hold them apart.
- The offline export verifier answers a verdict for every document it is
  handed, which is what its own description already promised. Six shapes used
  to raise instead: entries out of order and an entry of another scope, which
  are now `unverifiable` verdicts because a bundle's content is never the
  caller's argument error; a principal whose delegation is not a chain, and one
  whose delegation names something that is not a principal, both while a hash
  was being recomputed; an instant outside the calendar, which arrives as an
  arithmetic error and so passed every clause that named a value error; and a
  served grade that names no connection. The verdict gains one issue name,
  `chain_unverifiable`, beside `chain_damaged`, so that a range nothing could
  be established about is not reported as a range found damaged.
- A reply lost to a request that asks for something to be DONE — a decision, a
  person's act on a suspension — now reports `retryable` as null rather than
  true. The far end may have taken and recorded the act before the reply was
  lost, so nothing in a client may say that sending it again is safe; a request
  that never left the client took nothing, and keeps the retryability the
  registry publishes. Both clients of this contract move together, and the
  registry says so itself: the published `meaning` for `unreachable` now names
  both cases — the control plane could not be reached, or a write's reply was
  lost, in which case the occurrence states no retryability — so a third party
  implementing from the registry alone does not read the code as a licence to
  ask again. A caller
  that read `retryable` as a licence to repeat a decision now reads « unknown »
  and weighs it, which is the three-valued rule of article 2 applied to the one
  flag that can cause a second effect.
- A 200 whose body is not a document of this generation is reported as
  `answer_unreadable` rather than `unreachable`. The control plane WAS reached;
  what arrived cannot be read, and those are different facts (articles 1 and
  2). Both codes are could-not-asks, so no caller's classification moves and no
  exit code moves; what does move is the answer's retryability, which becomes
  the unknown the registry publishes for the code, where the code it replaced
  published true.
  The readers of a 200 report the same code for a body that is an array or a
  number rather than an object, and for a numeric member past the range an
  integer can hold, which used to escape the readers as an arithmetic error.
- The refusal a client mints when the generation it is asked for is not one it
  speaks takes its `retryable` from the registry that publishes the code, like
  every other problem this distribution builds. No observable change: the flag
  was written by hand and agreed with the published column. What changes is
  that it cannot silently stop agreeing.
- A peer that resets a grant's stream is the end of that stream. Article 10
  ends a grant when its channel ends, and a peer that reset is gone, so the
  holder's iteration finishes rather than raising a connection error the holder
  has to classify for itself — which is also what a real daemon looks like when
  it stops. A signal this generation cannot read still raises, unchanged: that
  one may be the signal that ends the grant.
- The problem-code registry gains a `class` member, within generation one: every
  published code says whether it is a `refused` — the question reached the
  control plane and was rejected — or a `could_not_ask` — no answer about the
  effect exists, so an effect that has not started does not start (article 1).
  Additive: no code is removed, no status moves, no meaning changes and the
  generation does not move. What it settles is a disagreement between the two
  clients of this contract, which each derived the class for themselves and
  derived it differently; both now read the one published column, and so does a
  code the reader does not know, which is a could-not-ask and never a refusal.
  Seven codes the decide route answers at 503 are now read as could-not-asks by
  the binding's client, which had read four of them as refusals —
  `decision_store_unavailable`, `policy_archive_unavailable`,
  `peer_credential_unavailable` and `principal_groups_unavailable`; a store or a
  directory that gave no usable answer took no decision, so a caller was being
  told it had been refused. `evidence_store_unavailable` moves the same way on
  the two evidence routes, for the same reason: an evidence authority that could
  not be read answered nothing about the range that was asked for. Sixteen codes
  are now read as refusals by the transport, which had read them as
  could-not-asks — `approval_resolved`,
  `approval_unknown`, `decision_not_found`, `delegation_invalid`,
  `evidence_range_invalid`, `generation_missing`, `generation_unreadable`,
  `generation_unsupported`, `member_unknown`, `operation_unknown`,
  `policy_writable_by_principal`, `principal_refused`, `request_malformed`,
  `scope_invalid`, `scope_refused` and `scope_required`; each is a verdict the
  daemon reached on the question it was given, so a caller was being told no
  answer existed when one did. A client that renders the two with distinct exit
  codes moves with the column.
- What the class column classifies is what the control plane PUBLISHED. A
  problem a client mints for itself — no address it could open, no answer it
  could read, a generation it does not speak, its own profile pinned to one it
  does not speak — is a « could not ask » by construction, whatever code it
  carries, because no control plane answered at all (articles 1 and 2). The
  same code is minted on both sides of the wire, `generation_unsupported`
  above all: a daemon that will not speak this generation has received the
  question and rejected it, and a client that will not speak the daemon's has
  dialled nothing. So the fact travels on the problem value, set where the
  value is made, and is never inferred from the code.
- The published fake reads the class column too. It already took each code's
  retryability from the registry; it now takes the class from the same row
  rather than deciding it, so `internal` answers « could not ask » from the
  fake as it does from both real clients. A consumer whose governed program
  passed against the fake and failed against a daemon on that code is the one
  outcome a conformance fake must not produce (article 13).
- Recipe `sayfirst/policy-evaluation/v1` accepts the rule member
  `review_deadline_seconds`, from this distribution version on. The identifier
  keeps its meaning: the member bounds a suspension's wait, no rule of the
  recipe reads it, and no triple any policy ever yielded moves — only bytes
  that used to re-derive `unverifiable` with cause `policy_unparseable` now
  re-derive their triple. Rule 2 names the member and states the one lane by
  which a later member that no rule reads may join it; a member any rule reads
  still mints a new identifier. Six vectors and one rederivation carry it:
  the member on a `suspend` rule re-deriving as before, each out-of-bound
  value refused, and the member misplaced on an `allow` rule re-deriving
  unparseable.
- Two decision reasons join the published enumeration within generation one:
  `approval_granted` and `approval_rejected`, what a re-ask of a suspended
  question answers once one person has acted. Additive: the three outcomes of
  article 1 are unchanged, a reader of this generation reads an unknown reason
  as unknown, and they appear in every enumeration that lists a reason — the
  decision result, the decision record, both evidence-entry schemas and the
  attribute registry.
- Both of those reasons now carry a shipped fixture. `review_approve` and
  `review_reject` each script the re-ask of the question their person answered
  and assert what it is answered — an allow on the first reason, a deny on the
  second — so each is proven by a named test against a shipped fixture rather
  than published and unreachable (article 13). The scenario document gains one
  optional member to carry it, `then.expect.after_resolution`: the generation
  does not move, every existing scenario parses unchanged, and a scenario that
  omits it scripts no re-ask. The reader that refuses an unknown scenario
  member ships in the same distribution as the fixtures it reads, so a consumer
  that takes the new fixtures takes the reader that accepts them.
- Two problem codes join the decide route within generation one, both
  could-not-asks at 503: `approval_provider_unavailable`, the approval provider
  gave no usable answer so the suspension could not be put to it, and
  `decision_contended`, another ask of the same question holds the one
  execution its approval authorises. Neither is a denial and neither takes a
  decision; a client of this generation that does not know a code cannot render
  what it means, so both are announced here.
- `approval_provider_unavailable` joins the resolution route within generation
  one, at the 503 it already carries on the decide route, and its published
  meaning now names both directions of the port: a suspension that could not be
  put to the provider, and a person's act that could not be applied to one.
  Additive — no code is removed, no status moves and the generation does not
  move — and it closes a could-not-ask that was answered as something else: a
  provider whose backend is down left the person who clicked approve reading a
  refusal, for a component outage that decided nothing and recorded no act
  (articles 1 and 2). The record stays pending and the code is retryable, so
  the act may be made again once the provider answers.
- The walking skeleton publishes `PrivacyRedactor` version 1 and
  `ApprovalProvider` version 1. Nothing is deprecated yet.
- `PrivacyRedactor` version 1 is one interface, declared once: a bounded
  capture in, a `Redaction` out. The skeleton had shipped two declarations
  under that name and version, and the daemon could compose only the no-op;
  it now composes the provider the configuration names, the conformance kit
  judges by one rule under both of its entrances and is proven against a
  second implementation, and a repository guard fails on a second
  declaration of any interface version (article 8).
- The durable decision lifecycle. The decision authority is a file per scope
  under the evidence root, so a daemon explains after a restart the
  decisions it took before it; the exact bytes of every policy version a
  decision names are archived before the decision; the effect entry carries
  the decision's reason, rule, digest, correlation and its source, principal
  references, evaluation recipe and store position inside its hashed body;
  an export attaches the policy bytes and is digested under manifest v3; and
  the contract distribution gains `sayfirst_contract.evidence`, the complete
  offline verifier, and `sayfirst_contract.retrospective_policy`, a
  historical evaluator that never authorises an effect. Response members
  added within generation one: `principal_references`, `evaluation_recipe`
  and `correlation_source` on decisions; the new-writer effect body, the
  `unflushed` gap reason and the `recovery` kind on evidence entries;
  `manifest_version`, `policy_versions` and `recovery_context` on exports;
  `decision_store` on the status result, where a scope whose authority
  cannot be read is `not_run` with null counts, never `disagrees`; problem
  codes `decision_store_unavailable` and `policy_archive_unavailable`. Two
  new internal ports at version 1: `PolicyArchive`, and `DecisionStore`
  gains `location()` and answers a position from `append`.
