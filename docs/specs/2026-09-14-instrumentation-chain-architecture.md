<!-- SPDX-License-Identifier: Apache-2.0 -->
---
kind: architecture
status: draft
date: 2026-09-14
title: The instrumentation chain — boundary, engine, packs, verifier
articles: [1, 2, 4, 9, 10, 11, 13, 14]
cuts: [boundary-runtime, interposition-engine, pack-format, verifier, convenience-packs]
---

# The instrumentation chain

## Purpose

Article 9 says the open project ships **the instrumentation engine, the
instrumentation verifier, and the convenience packs**. None of them exists, and
the article's own Guard says so: *"Not yet mechanised, because nothing it would
run exists."* This document is the architecture the implementation specs are cut
from. It builds nothing.

It is an architecture document and not a block spec because the four layers are
**a chain, not a set**. Each one is useless without the one beneath it, and the
interfaces between them are the decisions worth making once, before any of them
is written.

## What exists, measured on 2026-09-14

Read off this repository rather than recalled.

| Piece | Where | State |
|---|---|---|
| `Grant`, `GrantConditions`, `GrantSignalKind`, `GrantEndReason` | `sayfirst_contract.grants` | present |
| `ControlPlaneClient.ask_decision`, `Answered` / `Refused` / `CouldNotAsk` | `sayfirst_contract.client` | present |
| Socket transport with peer-credential verification (article 6) | `sayfirst_contract.transport.socket_client` | present |
| Daemon side: issuing grants, signalling a version change, `DecisionService.sweep()` | `sayfirst_control_plane` | present, tested |
| Exit-code vocabulary, in part: `EXIT_OK`, refused, could-not-ask, misuse | `sayfirst_contract.transport.cli` | present |
| **A boundary runtime — the in-process thing that HOLDS a grant** | — | **nothing** |
| Instrumentation engine | — | **nothing** |
| Pack format, any pack | — | **nothing** |
| Verifier | — | **nothing** |

**Corrected 2026-09-14, after the code was read rather than reasoned about.** The
row above understates how close the grant already comes. `ask_decision` selects
the stream (`DECISION_ACCEPT` names that media type first), the daemon serves the
grant in the answering frame, and `Decision.from_document` keeps unrecognised
keys — so **the grant document already reaches every caller** as
`extra["grant"]`, and always has. What was missing was not a request. It was an
obligation about the connection: `_request` closes in its `finally`, and article
10 ends a grant when its channel ends, so every grant this client was ever served
died in the same call that obtained it. `_first_frame`'s own docstring names the
reason — "a replay observes the answer; it does not hold what the connection
would go on carrying" — which is correct for a conformance replay and useless for
a holder. `hold_decision` and `GrantChannel` are what close that gap, and
`GrantSignal` gained the reader it had never needed while nothing consumed
signals.

`Grant` is consumed today only by the server, its routes, and golden fixtures.
**Nothing in an instrumented program's process holds one.** So the gap is one
layer deeper than article 9's wording suggests: the article names the engine,
the verifier and the packs, and assumes the boundary that article 10 specifies
in full. That assumption is the first thing this architecture makes real.

## The layers

### Layer 0 — `sayfirst-boundary`

The only component that speaks to the daemon while a governed program runs.

**Its one shape.** A context manager, so that there is no path into the body
that skips the ask:

```python
with boundary.request(capability, arguments) as grant:
    result = do_the_effect(**arguments)
    grant.record_outcome(digest(result))
```

**The grant cache is article 10, and most of its rule is already published.**
The holder's decision is not this layer's to invent: `sayfirst_contract.grants.grant_use`
already states it, and states it publicly on purpose — *"the rule deciding that
has to be published, or a third-party boundary and this control plane disagree
about what a grant still covers"* (article 13). The boundary **calls that
function** rather than reimplementing its reasoning, and the conformance replay
harness already exercises it against scripted arrangements.

Its order is constitutional and its misses are named, not merely counted:
`connection_live` → `now >= expires_at` → scope/capability/principal →
`arguments_digest`, yielding `HIT` · `CONNECTION_LOST` · `EXPIRED` ·
`CONDITIONS_DIFFER` · `ARGUMENTS_CHANGED`. A pinned digest is never satisfied by
an ask carrying a different one, or none (article 3).

**The holder never compares policy versions, and must not start.** `grant_use`
takes no version argument by design: a holder cannot know the current version. A
change reaches it as a `grant_ended(policy_version_changed)` **signal** on the
grant's own connection, pushed because `DecisionService` wires
`policy.on_version_change` to the registry. A holder that has read that signal
holds no grant and asks. An implementation tempted to cache a version and
compare it locally would be inventing a second answer to a question the daemon
already answers.

Two rules an implementation will be tempted to soften, so they are stated twice:
**a boundary that has lost its connection has no valid grants**, whatever their
remaining lifetime says; and **only an `allow` is ever cached** — `mint_grant`
refuses every other outcome, so there is no such thing as a cached denial.

**Silence is the one clause with a real gap, and layer 0 closes it.** Article 10
binds a boundary that "has not heard from [the control plane] within the grant's
lifetime" to treat its grants as expired. The daemon's `tick()` does write
heartbeats, so there is something to measure — but the published `grant_use`
takes no silence input, and `grant_state`, the only code implementing `SILENT`,
**has no caller outside tests.** So a third-party boundary applying the published
rule literally does not honour that clause. This layer must: it derives
`connection_live` from heartbeat recency against the grant's lifetime, and says
in its own documentation that it is doing so, because a reader comparing it
against `grant_use` will otherwise find an input that rule does not have.

Whether the silence test belongs in `grant_use` itself — which would make it
binding on every third-party boundary rather than on ours alone — is a contract
change, and therefore an article 16 question rather than this spec's to settle.
It is raised, not answered, here.

**Outcomes are article 1's closed set, and the fourth thing that is not one.**
The vocabulary is already fixed by `sayfirst_cli.exit_codes`, verified from
source, and the boundary reuses it rather than inventing a second one:

| Outcome | Boundary behaviour | Code |
|---|---|---|
| `allow` | the body runs | 0 |
| `deny` | raises `Denied` | 1 |
| refused | raises `Refused` | 3 |
| **could not ask** | raises `CouldNotAsk`, carrying whether it is retryable | 4 |
| `suspend` | raises `Suspended`, carrying the approval reference | 5 |

**Suspend raises; it never parks a thread.** Article 10's reasoning against a
decision round-trip per operation — that it "does not survive contact with a
real workload" — applies at least as strongly to a blocked thread waiting on a
person. The caller decides how to suspend: a graph checkpoints, a worker
requeues, a script exits 5.

**Could-not-ask fails closed, and is never rendered as a denial.** Doctrine D4:
the absence of a refusal is not permission. The body does not run.

**Evidence is asynchronous, bounded, and declares its gaps** (article 10):
sequence numbers and an explicit dropped marker. A boundary under pressure
never produces a clean record by losing part of one.

**Minimisation is the default** (article 11): the boundary sends an arguments
*digest*. What, if anything, is sent in full is configured explicitly and never
implicit.

### Layer 1 — the engine

A launcher that installs the boundary in front of named operations **before the
application's first import**.

```
sayfirst instrument run --pack ./packs/http-client -- python -m myapp
```

A `sys.meta_path` finder is installed in the launcher's process; on the import
of a module a designated pack names, the named attribute is replaced by a
wrapper that opens `boundary.request(...)` around the original.

**Reversible, which is what article 9 asks of the primary mode.** Nothing is
written to the customer's tree. The interposition lives and dies with the
process.

**The engine knows no library.** It reads manifests and installs what they
declare. A library name may appear in a pack; it may never appear in the engine
— not as an identifier, not as a string, not in a docstring. This is article 4's
vocabulary rule applied to the one component most likely to erode it, since an
engine is exactly where a special case for a popular library is cheapest to add
and hardest to see. The guard is written in the same change as the engine, and
it walks the engine's source rather than consulting a list of forbidden names: a
deny-list would need to know the names to forbid, and would go silent on the
first one nobody thought of.

**The hole, stated rather than hidden.** An application that binds a reference
before the hook installs, or that is started by anything other than the
launcher, escapes the interposition. This is a real limit of the mechanism. It
is documented as one, and finding it is precisely the verifier's job — which is
why the two are designed together and why the verifier does not share the
engine's bookkeeping.

### Layer 2 — the pack

Article 9, in its own words: *"a declarative manifest plus a local execution
module, explicitly designated by the user; there is no registry, no marketplace
and no signature scheme yet, and the documentation says so, with a date by which
the statement is to be re-examined — past that date the packaging test fails
until the statement is renewed or replaced."*

```
packs/http-client/
  pack.toml        what the pack declares
  interpose.py     the local execution module
  NOTE.md          convenience-pack classification, one-day justification, date
```

`pack.toml` declares, per interposition point: the **capability** — a kind of
effect, never a library name (article 4); the module and attribute to wrap; and
which call arguments form the digest (article 11).

**A naming rule, and it came from a guard rather than from taste.** This
document always names that file `pack.toml`, and never uses the general word for
it preceded by a definite article. Article 14's public-vocabulary guard reads
that construction as a reference to an unpublished planning document, and it
fired on the first draft of this spec — twice, the second time on the sentence
written to explain the first, which had quoted the offending phrase verbatim.
The words collide: article 9 uses the general term for a public pack concept,
while in this repository's firewall the same construction names something that
is not published.

Loosening a provenance guard to admit a spec is never the trade, so the
convention is to name the file instead. It is more precise anyway — a reader who
sees `pack.toml` knows what to open. **Every spec cut from this one keeps the
convention.** If the pack format genuinely needs the general term in prose, that
is a guard question for article 16, not a licence to rephrase around the rule.

**A pack is code the user chooses to run**, exactly like a dependency. It is
designated on the command line. There is no search path, no default set, and no
resolution from a name — because each of those is a registry wearing another
hat.

**The no-registry statement is dated 2027-03-14** and the packaging test fails
from that date until it is renewed or replaced. A deliberate time bomb, built as
written.

### Layer 3 — the verifier

**What it proves:** for the program under test, every effect of a named kind was
preceded by a decision.

**How:** it runs the target in a sandbox under a CPython audit hook that raises
when an effect event occurs with no live grant for the corresponding capability.
Verified empirically on 2026-09-14 before this design was written: a raising
audit hook does abort a real `subprocess.Popen`, and audit hooks stack and can
never be removed.

That irreversibility disqualifies audit hooks as the **engine** — article 9
requires the primary mode be reversible — and is exactly what you want in a
**proof harness**. The split falls along article 9's own line, "publish the
verifier, keep the compiler": the interpreter reports the effect, so a bypass
cannot hide behind bookkeeping the engine and the verifier would otherwise
share.

**A closed verdict vocabulary**, and one of its members is an absence:

- `governed` — the effect happened and a decision preceded it;
- `ungoverned` — the effect happened and no decision preceded it;
- `not-exercised` — the path was never walked by this run.

`not-exercised` is **never** rendered as a pass. A path a test did not walk is
not a path proven safe, and a verifier that reported it green would be the false
all-clear article 2 forbids.

**Anti-vacuity is article 9's explicit demand:** the verifier runs "against every
shipped pack in the public gate, failing unless it inspected each one". So the
verifier reports the set it inspected, and the gate asserts that set equals the
set of shipped packs. A verifier that inspected nothing must be red, not green.

### Layer 4 — the convenience packs

An HTTP client, a subprocess, a database driver — article 9's own three, chosen
because "a competent engineer would rebuild [them] in a day from public
documentation". Each carries `NOTE.md`: that it is a convenience pack, the
one-day justification, and its date.

Packs for sophisticated frameworks, **agent frameworks included, are not part of
the open core** (article 9). A bridge (article 4) is the one open surface where
another standard's vocabulary may exist, and a bridge is not a pack and lives in
its own repository.

## The interfaces, which are the point of specifying first

The four layers meet at three seams. Each is decided here so that no
implementation spec has to invent it.

**Boundary ← engine.** The engine calls only `boundary.request(capability,
arguments)` and the grant's `record_outcome(digest)`. The engine never reads the
cache, never sees a `Grant`, and never learns why a decision came back as it
did. Consequence: a program can use the boundary by hand with no engine at all,
and that is a supported way to use it, not a workaround.

**Engine ← pack.** The engine reads `pack.toml` and imports the execution
module. The vocabulary that file declares is the interface; the execution
module's job is to produce the wrapper given the original attribute and a
capability. No pack may reach into the engine's internals, and the engine may not
special-case a pack by name.

**Verifier ← everything.** The verifier consumes only what the interpreter
reports and what the daemon recorded. It deliberately shares no state with the
engine, because a proof that trusts the thing it is proving is not a proof.

## Readings of the constitution this design makes

Recorded because a reading is not an amendment, and whoever disagrees should be
able to find it and take it through article 16 rather than discover it in code.

**`sayfirst instrument apply` is split into three verbs.** Article 9 writes
"`sayfirst instrument apply` executes it", while also making runtime
interposition the primary mode and a committed code modification "a later
option". A verb that undoes itself when the process ends and a verb that edits
somebody's repository are not the same act, and `apply` is the ordinary name for
the second: a reader who has run any other tool will expect it to leave
something behind. One word cannot carry both meanings without one of them being
quietly wrong, so:

- `sayfirst instrument run` — the reversible, process-scoped primary mode;
- `sayfirst instrument verify` — the proof;
- `sayfirst instrument apply` — reserved for the committed modification, present
  and **refusing with a stated reason** until that mode exists.

`apply` therefore keeps the article's name for the article's later option, and
nothing is renamed into meaning its opposite. If this reading is wrong, the fix
is an amendment, not a redefinition in code.

**The boundary is treated as part of what article 9 ships.** The article names
the engine, the verifier and the packs. It does not name the boundary, because
article 10 already specifies it. Shipping an engine whose only purpose is to
install a component the open project does not ship would make article 9's first
sentence false in practice.

## What this design does not do

- **It is Python-first, and says so.** The mechanism is CPython's import system
  and CPython's audit hooks. Another runtime needs its own engine, and this
  document does not pretend otherwise.
- **It does not sandbox the program it governs.** The control plane is a
  governance and observability layer, not a confinement mechanism — the client's
  `SECURITY.md` already says this, and the engine does not change it. The
  verifier's sandbox is for the verifier's own run, not a production control.
- **It does not close the import-order hole.** It surfaces it.
- **It adds no outcome** (article 1) and no capability vocabulary of its own
  (article 4).

## Guards that arrive with each layer

Written here so that no implementation spec ships a layer without its proof.

| Layer | Guard, arriving in the same change |
|---|---|
| Boundary | a grant is not honoured after **any of four** endings — connection dropped, lifetime expired, policy version changed, or the daemon gone silent for a lifetime — each proven separately, against a real socket pair, not a mock |
| Boundary | the silence ending is watched FIRING: heartbeats stop while the connection stays open, and the next act asks instead of hitting. This is the clause `grant_state` implements and nothing calls, so it gets the harshest probe |
| Boundary | the boundary calls `grant_use` rather than reimplementing it: the guard mutates a condition and asserts the refusal carries `grant_use`'s own verdict name, so a divergent local copy cannot pass |
| Boundary | no outcome other than `allow` is ever cached, watched on a `deny` and a `suspend` |
| Boundary | `could not ask` never renders as `deny`, held apart by exit code, as article 1 already requires of the client |
| Engine | no library name appears in the engine — identifier, string or docstring — walked from source, not from a list |
| Engine | interposition leaves no trace on disk: the tree is byte-identical before and after a governed run |
| Pack | every shipped pack carries a classification note; the test walks the shipped set |
| Pack | the no-registry statement fails the packaging test from 2027-03-14 |
| Verifier | the gate fails unless the verifier inspected every shipped pack |
| Verifier | `not-exercised` is never counted as a pass, watched firing on a planted unexercised path |

## Specs to cut from this

In order, because each depends on the one before:

1. **Boundary runtime** — layer 0 entire. Independently useful on merge.
2. **Interposition engine** — layer 1, plus its agnosticism guard.
3. **Pack format** — layer 2, with one pack as its proof.
4. **Verifier** — layer 3, with article 9's anti-vacuity gate.
5. **Convenience packs** — layer 4, the remaining two.

Article 9's three mandated guards become live at step 3 and step 4, and not
before: until a pack exists there is nothing for them to walk, and a guard that
walks an empty set is the failure this article names by name.
