<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirst` control plane

This distribution is the host-scoped server core (article 6). It is a
governance and observability layer, not a confinement mechanism: a program is
governed only when it calls the boundary before an effect.

The package declares the layers the architecture separates — `domain` for
transport-free rules, `ports` for the interfaces the core owns, `application`
for the operations composed from them, `adapters` for the open implementations
of those ports, `plugins` for the versioned interfaces offered to explicitly
activated providers (article 8). The direction of dependency runs inward: an
adapter knows a port, a port does not know an adapter (article 14).

Each block of the walking skeleton adds its own rules, ports and adapters to
these layers, and describes them below.

## The daemon, composed

`bootstrap.compose` is the one place those layers are wired together, and it is
the only module that knows more than one of them. It reads the deployment's
configuration, builds each adapter through the port its block published, and
hands the result to the daemon; it reaches into no layer's internals, which is
what the port rule is for (article 4).

Composition is the deployment's choice. Three sections carry it, beside
`[socket]` and `[identity]`:

```toml
[policy]
path = "/etc/sayfirst/policy.toml"

[evidence]
path = "/var/lib/sayfirst/evidence"

[plugins.PrivacyRedactor]
provider = "none"
interface_version = 1

[plugins.ApprovalProvider]
provider = "single-approver"
interface_version = 1
```

`policy.path` names the authority every decision reads; `evidence.path` is the
root of the per-scope chains, and it is required beside an authority, because a
daemon that decides and records nowhere would answer a decision it holds no
evidence for. The `plugins` table is read by the contract distribution's own
reader rather than by a second one here, and defaults to the two shipped open
providers when it is absent.

A deployment that names no authority composes none. It still serves the
identity surface, and a decision request is answered `policy_unavailable`,
because that is the published problem for an authority that could not be read
and it is a could-not-ask, never a denial. It does not serve the four
operations that read a composed authority — the decision record, the policy
status and the two evidence reads — because none of the four publishes a code
for "there is no authority here" and answering `decision_not_found` or an empty
page would claim a store was consulted (article 2).

A deployment that names an authority and cannot have it does not start: it
writes one reason on standard error and exits 78, as `docs/deployment.md`
publishes. A daemon that cannot decide, cannot record, or does not know what it
composed serves nobody.

Composed, the daemon answers `read_status`, `read_whoami`, `ask_decision`,
`read_decision`, `read_policy_status`, `read_evidence`, `export_evidence`,
`read_approval` and `resolve_approval` over the one local socket, writes each
decision to its scope's chain at the grade the asking connection actually has,
and replays all eleven server-bound golden scenarios against its own socket as
its acceptance suite (article 13) — the three that end a wait included, each
reached by moving the clock the arranging harness composed rather than by
waiting on one.

## Plugin interfaces

The skeleton publishes `PrivacyRedactor` version 1 and `ApprovalProvider`
version 1. Providers register metadata in the `sayfirst.plugins` package entry
point group. Installation only makes that metadata discoverable: a provider is
loaded and instantiated only when configuration names it for an interface.

```toml
[plugins.PrivacyRedactor]
provider = "none"
interface_version = 1

[plugins.ApprovalProvider]
provider = "single-approver"
interface_version = 1
```

The `none` privacy provider and `single-approver` approval provider are the open
defaults when no configuration file is supplied. A supplied file is complete:
omitting either interface is refused instead of silently merging a default.
`none` performs no transformation and makes no protection claim.

`PrivacyRedactor` version 1 is one interface, declared once, in
`plugins/interfaces.py` beside `ApprovalProvider`: a provider carries an
integer `interface_version` and a `name`, and answers
`redact(*, scope, capability, content: bytes)` with a `Redaction` — the
content to record, a status of `applied`, `not_applicable` or `failed`, and
the provider's own name. It sees only the captured payload, already bounded
by the capture rule, never the identity of the effect (article 11). The daemon
composes the provider the configuration names into the evidence pipeline, so
the provider the plugin composition activates is the provider the evidence
pipeline takes, and the name on the composition evidence, on the status
surface and in every capture record is one name: a provider whose instance
answers a different name than it registered is refused at start (article 2).
`tests/test_one_declaration_per_plugin_interface.py`, at the repository root,
walks every shipped source and fails on a second declaration of any
registered interface or a second constant claiming its version (article 8).

## Interface versions and their window

Each interface carries an integer version. A provider built for a version this
release does not accept is refused before its factory runs. When a version is
deprecated, `CHANGELOG.md` announces it under the release that begins its
window, and the version keeps working for at least
two minor releases or six months from that release, whichever is longer; after
both minimums have passed it is refused. A deprecation this changelog does not announce fails the
packaging test. Nothing is deprecated yet.

## Approval actions and bounded waiting

`ApprovalRequest` carries `requested_at` and `deadline`, the bounded wait
generation 1 of the domain contract already publishes. Expiry is an approval
authority state: the core expires an approval on time or read and does not ask a
provider to evaluate an action after the deadline. The provider evaluates only
a person's `approve` or `reject` act and returns either continued suspension or
that person's resolution. Every answer passes through `resume_through_provider`,
which judges it against the act put to the provider, applies the judged
resolution through the core's own writer and appends it to the supplied
recorder before returning it, so neither a resolution the recorder could not
append nor an answer no act supports reaches a caller that would resume on it.
Ending the wait is the core's act and not the provider's: the store is the
core's record, `write_resolution` is its one writer, and the resolution route
is that writer's one caller — so a provider written elsewhere ends a wait
exactly as the shipped one does. The store a suspension waits in is the
daemon's own, in memory, on the deployment's clock: a rule member bounds each
wait, the ask path opens one and answers a re-ask from it, the two published
operations let a person read a wait and end it, and the sweep that ends the
grants expires what ran out and forgets what nothing can still need. One record
is outside that sweep and is the one growth an operator can meet: an approved
approval nobody spends is kept for the life of the process, because only the
execution it authorises being taken removes it. Every principal the socket
admits may resolve any wait in any scope and read any wait it names — the
simple form designates nobody, so the daemon takes the person from the
connection and checks nothing about them, and `docs/deployment.md` states that
beside the admission group an operator sizes. Nothing of the store survives a
restart, which the store says in its own docstring: the durable half of an
approval is the suspended decision and the resumed one, both of which are
decision records.

## What bootstrap records, and what this branch does not ship

Bootstrap discovers, activates and composes explicitly, and fails closed on an
unknown plugin interface, an unknown interface version, a provider discovery did
not find, a provider name claimed by two entry points, and a provider instance
that does not implement the interface it registered for. It refuses to compose
at all without an evidence chain sink, and refuses a sink that does not return
the composition it was asked to record.

**The sink is a protocol the caller supplies**, and the daemon supplies one
that writes to the evidence chain. The entry it returns is checked for the chain
shape — scope, kind, offset-aware instant, connection, typed principal,
positive sequence, previous hash present exactly after the first entry, entry
hash, preimage version — and for naming exactly the composition that was
resolved. That shape is one rule, held in the contract distribution: what
bootstrap may construct is exactly what the published reader accepts, so an
entry with only a kind and a body is refused on both sides. The hash linkage
itself is **not** verified here — chaining those entries, verifying them and
exporting them is the evidence chain's work, and a well-shaped entry is never
presented here as a verified one. Each provider entry
names its distribution and version, its resolved entry-point target, and a
SHA-256 digest of the loaded target module, or the string `unknown` when the
digest cannot be computed; the member is never omitted, because a missing digest
and an unhashable one are different facts.

`sayfirstd plugins list --config PATH`
reports the selections in the supplied file against discovered package
metadata; it does not claim those providers are active, and it renders a
selection this release would refuse — an unknown interface, an unsupported
version — as that refusal. `sayfirstd plugins list
--composition PATH` reads back a recorded composition evidence entry and shows
which providers it names; it refuses an entry that does not carry the whole
chain shape, and without that record the composed column reads `unknown`
rather than guessing. The composed column answers about a *selection*, never
about a provider name: it says `yes` only where the composition recorded that
provider **for that configured interface, at that configured interface
version**, which is exactly what bootstrap requires to compose. So a pair
bootstrap refuses — the same names composed for each other's ports — can never
read as composed, and neither can a selection whose version the composition does
not record or this release refuses outright. Where
the configuration names no selection for a composed provider, the column names
the interface the composition itself recorded.

## System mode, and what protects the configuration

The daemon composes in per-user mode and in system mode, and both of the
protections article 8 asks of the configuration in system mode are built and
held. The composition builds the protection expectation from the socket group,
and checks the file and every parent directory from which it could be replaced
for effective write access — the mode bits, the access control lists and the
whole naming path, never who owns the file alone, which is the same walk the
policy authority receives.

At start the daemon refuses a configuration writable by anyone other than
root or its administrator group, and exits 78 with
`configuration_unprotected`, naming the file, the component that decided it,
the rule that decided it and the account that looked. Per connection it also
refuses a decision request from a principal with that effective write access,
or with write access to a directory the file could be replaced through, under
`configuration_writable_by_principal` — its own published code, so a reader can
tell it from the policy authority's; administrative commands from that principal
remain available and are graded. Consequently a
governed program must run as another principal rather than as root or as the
administrator group. The walk runs after the privilege drop, so the account the
daemon drops to must be able to look at the file and the directories above it: a
component it cannot inspect is an unknown, and an unknown refuses the start.

Both are exercised, not configured and left.
`packages/control-plane/tests/integration/test_configuration_access.py` holds
the walk applied to the configured name and both wirings — spelled from the
repository root, as `CONSTITUTION.md` and `docs/exceptions.md` spell the same
citation, so a reader following one document to another reads one name. Three guards run
a real daemon as root against a real root-owned file, because the expectation the
start applies admits root as the only owner and no ordinary runner can lay out a
configuration that passes it:
`test_a_configuration_a_stranger_can_write_refuses_the_start_by_name`,
`test_a_configuration_only_root_and_the_administrator_group_can_write_starts`
and `test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted`,
the last holding the administrative command beside the refused decision. What the
per-request check reads is the group the program runs as, the one its peer
credential carries; a principal admitted through a named supplementary membership
is not refused by it, as it is not by the policy authority's own per-connection
check.

## The status surface for the active privacy provider (article 11)

Article 11's Guard: "`sayfirstd status` renders the active privacy provider by
name", and the surface that renders it here is `sayfirstd status`.
The status surface now renders it: composed, `read_status` answers the
provider the evidence pipeline holds; uncomposed, it answers `unknown`, which
is article 2's third value, and never the no-op rendered as protection — which
is why the default provider is named `none` and claims none. The name it
renders is the name the composition recorded: the provider the plugin
composition activates is the provider the evidence pipeline takes, one
`PrivacyRedactor` under one version (see "Plugin interfaces").

## What this block defers, and the article that permits it

A guard the constitution writes in the present tense is the guard the code must
bring with it, and the first ones land with the walking skeleton; until one
exists the rule is held by review. Article 2 is what makes each of these a
written deferral rather than a silence: this block must not read as holding a
rule it does not hold, and a reader must be able to tell "not shipped" from
"shipped and holding". The obligations deferred here are these.

## A subcommand a plugin contributes (article 8)

Article 8: "The same three steps govern a subcommand a plugin contributes to the
command-line tool." This block ships none of it — the parser is fixed, and
nothing discovers, activates or composes a plugin subcommand. When it lands it
obeys the same three steps as a provider: package entry-point metadata
discovers, the configuration activates by naming, bootstrap composes and fails
closed on an unknown plugin interface or version, and the composition it
resolves is recorded as evidence like any other. Until then, `sayfirstd
plugins list` describes providers only, and no installed package can add a
command to this tool.

## What still does not walk

Article 2 is what makes each of these a written absence rather than a silence,
and article 13 is why none of them is claimed: a conformance claim is either
proven by a named test against a shipped fixture or verified live, and there is
no third kind. Each names the change that would close it.

**Who resolved an approval is not kept past the record.** The approval record
holds the person — the verified principal of the connection the act arrived on,
which is the only place a person is ever taken from — for as long as that record
is kept, and `read_approval` renders it: the published `approval-result` carries
a `person` member on a wait somebody approved or rejected, and no such member at
all on one nobody acted on. What is not kept is everything after that record.
The durable record of the act is the resumed decision on the chain, which
carries the approval's reference and not the person; the `approval.resolved`
entry that does name the person goes to the bounded sink `bootstrap.compose`
composes, which keeps the most recent entries, declares what it dropped past its
bound, is served by no operation of this generation and is lost at a restart —
an observation and never evidence. So a deployed daemon of this version records
that an approval was acted on and, once the store has forgotten the record, no
longer which person acted. Keeping that durably is a change to what the chain
carries; this version claims none.

**Two shapes for one composition record.** The published `composition` evidence
body carries the interface, its version and the provider, and nothing else
(article 11). The composition the contract distribution shapes carries four
members more — the distribution, its version, the entry point and a content
digest. The entry kept on the chain is the published, minimised one; the value
handed back to the plugin composition is that distribution's own shape, hashed
over its own body by the same pinned recipe, and it is neither persisted nor
served. Which of the two a chain entry carries is a contract decision.

**The two runtime sweeps run on paths the daemon already has, and on no timer.**
`PolicyService.reload_if_due` and `GrantConnections.tick` are consulted
together by `DecisionService.sweep`, on every decision request before it is
answered and on each wake of the surface's watch over a connection a grant was
delivered on. A boundary holding a grant therefore learns of a version change
within the reload interval its deployment configured, and is written the
heartbeat and the expiry on the connection that holds it. Nothing scans for a
connection that holds no grant and asks nothing: it learns at its next request.

**The connection records are not on the chain.** A connection opening, a
principal changing and a connection closing are collected in memory and never
written to the evidence store, because the chain's published entry kinds are
effect, grade, gap and composition, and adding a fifth is a contract decision.

## Writing a provider

Third-party distributions expose a `PluginRegistration` object:

```toml
[project.entry-points."sayfirst.plugins"]
my-provider = "my_package:registration"
```

Provider tests use the suites published as `sayfirst.testing`:

```python
from sayfirst.testing import ApprovalProviderContract
from sayfirst_control_plane.plugins import ApprovalAction


def test_provider_contract():
    ApprovalProviderContract().assert_conforms(MyProvider)
```

The default completion fixture is the open core's single-person form. A provider
with designation or multi-signature rules supplies its own valid actors and
finite completion sequence without changing the runtime interface:

```python
def completion_actions(request, resolution):
    designated_people = my_provider_designation(request)
    return tuple(
        ApprovalAction(request.approval_ref, request.scope, person, resolution)
        for person in designated_people
    )


def test_provider_contract():
    ApprovalProviderContract(completion_actions=completion_actions).assert_conforms(
        MyProvider
    )
```

The suite judges every answer, on every path it drives, by one rule: a result
must be derivable from the acts of the people put to the provider — their
identity, their verdict, their reason, their order — and from the suspension
those acts belong to. A result no act supports fails, whichever refusal,
completion or replay produced it; `sayfirst.testing.unsupported_by_acts` is that
rule, published so a provider can hold itself to it directly. It is the core's
own rule, re-exported: the same function judges the provider at runtime.

A provider refuses by raising `ApprovalProviderError` or one of its shipped
subclasses — `ApprovalRequestMismatch`, `ApprovalAlreadyExists`,
`ApprovalAlreadyResolved`. The suite requires *a* refusal on every path where no
act is legitimately put and on a second act against a terminal approval; it
never requires a particular one of them, so the choice of error stays the
provider's. Raising anything outside that base is not a refusal the suite
recognises.

The fixture supplies the people, never the case: the suite refuses a fixture
whose acts name another approval or another scope, whose sequence is empty, or
whose terminal act does not carry the case under test, so a provider cannot bring
a fixture that never exercises rejection.

### The privacy kit

`PrivacyRedactorContract` judges a `PrivacyRedactor` version 1 provider by
one rule under two entrances — the callable above, and the pytest mixin
`sayfirst_control_plane.testing.PrivacyRedactorContract`, which a test class
subclasses with a `make_provider` method; the rule is stated once, beside the
mixin, and both entrances call it. The provider must satisfy the published
protocol, be built for the version the contract distribution registers, and
carry a non-empty name; `redact` must answer a `Redaction` whose content is
bytes, whose provider is the provider's own name and whose status is
`applied`, `not_applicable` or `failed`; the status must be true of the
content — `applied` means the content differs from what was read,
`not_applicable` means it is as given, and a no-op that answers `applied`
fails the kit, because that is a redaction nothing applied (article 2); and
an empty capture yields an empty capture. The kit asserts nothing about
*what* a provider changes. It is proven against a second, independent
implementation, `tests/digit_mask_redactor.py`, which masks digits and
answers both statuses, so the kit has judged two providers and not only the
no-op its author wrote (`tests/contract/test_privacy_redactor_digit_mask.py`).

The approval suite ships the liars it must fail, as `ADVERSARIAL_APPROVAL_PROVIDERS` and
`ADVERSARIAL_COMPLETION_FIXTURES`: providers that invert a verdict, approve on
rejection, re-attribute an act, invent a reason, answer for another approval,
another decision or another scope, wait on another decision, resolve with no act
at all, or never resolve; and fixtures that skip the rejection case, act on
another approval, act from another scope, or supply no act. The kit's own tests
assert it fails each of them, under its fixture and under every one of theirs,
and still passes the open core's provider.

The core holds that same rule itself, and does not depend on a provider having
run the kit. `resume_through_provider` is the seam every provider answer passes
through, and it admits an answer only if the answer is derivable from the act
put to the provider for that suspension: a value outside the two shapes of the
v1 contract, a result naming another approval, decision or scope (article 5), a
verdict, a person or a reason no act supports — each is **refused**, recorded as
a refusal, and never handed back to a caller that would resume on it. Because
the kit imports `unsupported_by_acts` from that seam rather than restating it,
what the kit accepts and what the control plane accepts cannot drift apart.

A refusal is recorded as a refusal, never as a decision. `RefusedProviderAnswer`
is built from the core's own facts — the approval, the decision and the scope of
the suspension, the person whose act was put, and why the core refused — and
carries nothing the provider said and no verdict of its own, because article 12
keeps the three outcomes of article 1 complete. A refusal the recorder cannot
append raises rather than returning, as an unrecordable resolution does.
## Evidence and minimisation

Evidence is an append-only chain per scope. Emission uses a bounded asynchronous
queue; overload creates a `dropped` marker rather than a silent hole. The
verifier refuses an undeclared sequence gap, and raw export is bounded to 10,000
entries per bundle.

The default capture policy is empty. An effect record therefore identifies the
capability, scope, principal, decision, and timing without an argument, content,
return value, or `capture` member. Capture must be enabled for one named
capability, is capped at 65,536 bytes, and is marked in the record. The default
privacy provider is `none`: configured captured content is recorded as given.

The memory store is held in the daemon's memory for the life of the process;
nothing survives a restart. The file store is kept until an operator removes
the file; there is no purge command in this version. Removing only part of a
chain creates an undeclared gap that verification refuses.

## Integrity grade

The grade is computed for each connection and scope from effective access to
the store and every directory that could replace it. This version emits only
`observability` when the caller can write or replace the store, and `unverified`
when access is not established or exclusivity cannot be evaluated. It does not
produce evidence grade.

Effective access is re-evaluated every 30 seconds by default, configurable from
1 to 300 seconds. That interval is the latency of detection of a permission
change. Re-evaluation also occurs before a verdict. `sayfirstd status` names
the grade, its basis, the interval, and the active privacy provider.
## Policy authority and grants

This package supplies the server-side policy and grant semantics. It is a
governance and observability layer, not a confinement mechanism: a governed
program must ask before its effect.

The daemon ships no policy. Its administrator creates a UTF-8 TOML file no
larger than 1,048,576 bytes. Format 1 is closed; unknown keys, formats,
outcomes, or principal-reference forms are refused. An absent or empty rule
list denies every question.

```toml
format = 1

[revision]
reason = "CI may send fixed build reports; reviewed 2026-09-04"

[[rule]]
id = "mail-send-for-ci"
capability = "mail.send"
scope = "local"
principals = ["group:ci", "user:build"]
outcome = "allow"
reason = "Recipients are fixed in the governed program"
grant_lifetime_seconds = 300
arguments_digest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

Capabilities, scopes, and principals are exact matches; there are no
wildcards. Applying outcomes are ordered `deny` before `suspend` before
`allow`. A digest-pinned rule applies only to an ask carrying that exact
`arguments_digest`, the generation-one request member the boundary computes; an
ask that carries no digest never satisfies a pinned rule.
The policy version is the SHA-256 digest of the file bytes, so even whitespace
changes conservatively void an issued grant.

At startup, effective access is checked on the resolved file and every parent
directory. Per-user mode permits ownership only by root or the daemon uid and
permits no group/other/foreign ACL writer. System mode requires root ownership
and permits write only to root or the configured administrator group. An
unreadable access-control list or failed metadata check is unknown and refuses
startup. In system mode, a decision is also refused when its principal can
write or replace any component; root and a component owner are writable even
when their current write bit is clear.

Every decision reads the file authority again. `PolicyService.reload_if_due`
is the cache age that detects a change while a boundary is serving only grant
hits, and `DecisionService.sweep` consults it on every decision request and on
each wake of the surface's watch over an issuing connection, so a boundary
holding a grant is signalled within that interval rather than at the time it
next asks. A connection holding no grant is watched by nothing and learns at
its next request; no timer scans for one. A load failure is
a retryable problem and leaves the last successful version—and its live
grants—unchanged. The memory and optional SQLite views are rebuildable
projections: either can be cleared and rebuilt entirely from a successful file
load, and neither is an observation or a decision authority.

Only `allow` is cached. Its grant carries the decision, policy version,
lifetime, heartbeat interval, and exact scope/capability/principal/arguments-digest
conditions. A grant is issued on any connection that can carry its signals and
never otherwise; generation one has no request member asking for one, so which
connection can carry them is read from the selector the published binding names
beside the decision operation's two answers, never from an out-of-band flag. The
lifetime is the shortest of the rule, the configured default and the configured
maximum. One grant belongs
to the connection that delivered it. Composing `DecisionService` over a policy
service and a grant registry is what ends that grant, and signals its end on
that same connection, when the policy version changes; a peer that closes its
connection ends it too. Heartbeats and expiry are `GrantConnections.tick`, and
a shutdown sweep is `GrantConnections.shutdown`; `DecisionService.sweep` calls
the first on both paths above and `ComposedServices.close` calls the second, so
a grant is heartbeaten and expired on the connection that holds it, and a stop
ends every grant it can still reach. A lost
or silent connection, an expired lifetime, a changed version, or any changed
condition is a cache miss and requires a new decision.
