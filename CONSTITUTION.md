<!-- SPDX-License-Identifier: Apache-2.0 -->
# Constitution of the `sayfirst` control plane

**Status:** draft 0.1, 2026-09-03, for the lead's reading.

This document states the properties the open-source control plane is built to
hold, why each one holds, and what enforces it. It is the first thing this
repository contains and it binds everything that comes after it. Where a later
document or a piece of code contradicts it, the constitution wins and the
contradiction is a defect to record, not a precedent to follow.

Each article has three parts. **Rule** is what binds. **Why** is the reason, so
the rule can be judged rather than obeyed. **Guard** names what enforces it
mechanically, or says "not yet mechanised", which is a statement about the
guard, never a licence to break the rule. This repository holds no code yet: a
guard written in the present tense is the guard the code must bring with it,
and the first ones land with the walking skeleton. Until a guard exists, the
rule is held by review, and the article says so where that matters.

A few words are used with care. A **governed program** is any software that
asks this control plane before acting. An **effect** is what such a program is
about to do to the world. The **boundary** is the point inside a governed
program where it asks before an effect. A **capability** names a kind of
effect, and nothing more: not a tool, a model, a framework, a workflow step or a
transport. A **port** is an interface the core defines; a **provider**
implements it; a **plugin interface** is a port seen from the plugin's side.
The **parent** is the private product family this control plane was extracted
from: a private control plane that extends this one, and the application above
it that consumes this one as a governed program.

---

## Article 0 — Name, force and amendment

**Rule.** `sayfirst` is the project's public name. Nothing may be published
under it — no package on an index, no public repository, no announcement —
until the marks are filed. The public repository is created fresh, or its
issue and pull-request record is reviewed for private material before the
change of visibility, because that record becomes public with it. The
repository becomes public and its private vulnerability reporting is enabled
in the same act, before any package or announcement, so that `SECURITY.md`
names a channel that exists from the first public minute; the hosting platform
allows that setting on a public repository only. This constitution binds this
repository and every other open repository of the project, and "this
repository" in any article reads as "each of them"; another open repository
adopts it by pointer, never by copy, because a copy drifts. The private
products that its own maintainers build on it accept it at the boundary and
only there: the direction of dependency (article 14), the port rule (article
4), the plugin interface contract (article 8) and the absence of a privileged
path (article 18) hold for them too; their internals are their own.

It is amended by the procedure in article 16, never by a change that merely
contradicts it. A property may be relaxed for a named surface, for a stated
reason, with compensating evidence and a restoration condition, through the
exception register this repository keeps for that purpose; an exception without
a path back is an amendment and is treated as one, and no exception makes an
unknown input more permissive (article 3).

**Why.** A founding document that can be overridden by whoever writes the next
file is a preface, not a constitution. Holding the private side to the boundary
is what keeps the open core from becoming the negative image of a private
product; leaving its internals alone is what keeps this document honest about
its reach.

**Guard.** `tests/test_decided_name.py` fails on any occurrence of the retired
placeholder or of either prefix it was rendered as, and on a distribution or a
command not named for the decided name; the publication checklist is
`docs/publication-checklist.md`, and
`tests/test_publication_checklist_names_every_act.py` fails when an act this
article names — the marks filed before anything is published, the public
repository created with its vulnerability reporting enabled in the same act — is
not a line of it; whether each line was performed is held by review, no file
being able to read a filing at a registry or a setting of the hosting platform.
The exception register is `docs/exceptions.md`, created with the first exception.

## Article 1 — What this software governs, and what it does not

**Rule.** The control plane governs **an execution on a host**: it is asked
before an effect, it answers **allow**, **deny** or **suspend**, and it keeps
evidence of the question, the answer and what followed. Those three outcomes are
closed. It does not govern an organisation: fleets of hosts, multi-organisation
tenancy, regulatory reporting, graphical operator consoles and central identity
are the business of products built on top of it, which depend on it and never
the reverse.

Control semantics — how a policy resolves, when a grant is valid, what satisfies
an approval — are decided here and only here. A client, whether the
command-line tool, a boundary or a console built on top, explains and invokes
them; it never defines them, never keeps a decision past the lifetime the
control plane gave it, and never derives an answer the control plane did not
give. When the control plane cannot be asked, an effect that has not started
does not start, and one already allowed may continue within the lifetime it
was given; the record says which happened, and "could not ask" is never
written as "denied" or as "allowed". A
user may choose stricter behaviour per capability; that asymmetry is the
default. Nothing widens a policy by side effect: no install, upgrade, migration
or pack makes a policy more permissive; widening happens only through the
explicit policy path, with a stated reason.

**Why.** "Governs an execution" is the one sentence that decides what belongs
here. Everything a single host and its operators need to say yes, no or
wait, and to prove it later, is in scope; everything that exists because there
are many hosts or many organisations is not. A closed set of outcomes is what
makes the evidence readable years later; an outcome added for convenience is a
vocabulary nobody can audit. A client that decided anything on its own would be
a second control plane without evidence, and a policy widened by an installer
is a decision nobody took.

**Guard.** The domain enumerates the three outcomes, held by
`packages/contract/tests/test_domain.py::test_the_outcome_vocabulary_is_closed_at_three`;
a fourth fails the domain's own tests, and
`::test_an_unknown_outcome_is_could_not_ask_and_reported_unknown` reads an
outcome word this generation does not define as "could not ask" and reports it
as unknown, while
`packages/control-plane/tests/unit/test_policy.py::test_an_unknown_outcome_word_refuses_the_file`
refuses such a word on the server's side. The project's client renders
"denied" and "could not ask" as distinct results with distinct exit codes:
`packages/contract/src/sayfirst_contract/transport/cli.py` publishes
`EXIT_REFUSED` and `EXIT_COULD_NOT_ASK`, the rule that decides which of the
two a code is belongs to the published class column and is held by
`packages/contract/tests/test_problem_classes.py`, and a test holds the two
apart —
`packages/contract/tests/identity/test_socket_client.py::test_a_refusal_and_an_absent_answer_reach_the_caller_apart`
for the lanes and
`packages/control-plane/tests/e2e/test_the_boundary_holds_a_real_grant.py::test_the_published_client_renders_every_answer_on_the_right_stream`
for the codes a shell sees. The dependency direction is checked mechanically
(article 14).

## Article 2 — Honest claims

**Rule.** This software is a governance and observability layer, not a
confinement mechanism. A governed program *calls* the boundary; a program that
does not call it is not governed, and this software must say so wherever it
describes itself, and its documentation tells the user to pair it with
operating-system sandboxing for code they do not trust. An absolute claim is
made only about a structural property — the decision precedes the effect on an
instrumented path — never about behaviour, such as "everything is governed";
the project provides a mechanism, not a conformity. Every claim the software
makes about the world is no stronger than the evidence it holds for it; every
status surface has at least three values, one of which means "unknown", because
"did not look" and "looked and found nothing" are different facts and render
differently; and an absence — a missing record, an unreachable control plane,
an empty list — is never rendered as a negative fact, a zero or a healthy
state.

**Why.** Overclaiming is this product's first legal and commercial risk. A
control plane that lets a user believe it confines what it merely observes
invites being held, at the first breach it did not prevent, to a promise it
never made. The
three-valued rule is the same discipline at the scale of one field.

**Guard.** `SECURITY.md` states the threat model in these terms. Public
documentation is held by review for absolute claims at each release.
`tests/test_status_schemas_offer_three_states.py` walks every published schema
rather than a list of the fields somebody remembered: a state-bearing member
that offers two states and no third — no unknown value, and no absence a
client renders as unknown — fails, wherever in the contract it is added,
unless it is recorded there as reporting no state, with its reason; a member
whose name says it reports a state must carry an explicit unknown value, which
is `test_every_field_that_reports_a_state_carries_an_explicit_unknown`. It
runs in the public gate, `.github/workflows/ci.yml`, and
`tests/test_public_gate_runs_the_suite.py` fails when a step that runs the
suite stops reaching it. A two-valued status inside a member the walk cannot
reach through a reference is held by review.

## Article 3 — Information authority

**Rule.** For every fact the system holds, one of three things is true and is
stated: it is an **authority** (it accepts writes and owns invariants), a
**projection** (rebuildable, and never silently promoted to authority), or an
**observation** (can be absent or stale). A mutable execution state never
rewrites an immutable governance decision; an approval or a rejection is a new
record that references the suspended decision, never an edit of it. What a
program declares about a capability — a description, a hint, a schema — is an
observation: it may describe the capability and never authorises it; a
decision is pinned to the part of the declaration the policy names — the
schema at least, the description when the policy says so — and a change to
that part is a new question. Fail-closed is never the property traded away:
no relaxation may make an unknown input more permissive.

**Why.** Governance evidence is only worth what its provenance is worth. A
projection that quietly became the source of truth, or a decision edited after
the fact by the process it governed, is evidence that proves nothing.

**Guard.** The information contract in
`packages/control-plane/src/sayfirst_control_plane/architecture/information_contract.py`:
each persisted structure declares its authority kind and the surfaces it owns.
`packages/control-plane/tests/architecture/test_persisted_structures_are_declared.py`
walks the shipped source for the surfaces that outlive a process — a table the
code creates, a module that writes durably — and fails, by module and line, on
one no declaration owns; it is a walk rather than a list, so a structure added
later is audited by existing, and
`test_this_guard_still_catches_a_planted_undeclared_structure` plants one
inside the walk's own reach and watches it fail.
`packages/control-plane/tests/architecture/test_declared_proofs_resolve.py`
resolves every declared proof against the tests pytest collects here, so a
label that names nothing fails; that the named test exercises the kind as
declared — that a projection proof really rebuilds from its authority — is
held by review. The register's first observation is the daemon's own event
log, declared under the role `trace` and held by
`packages/control-plane/tests/architecture/test_information_contract.py::test_the_daemon_event_sink_is_declared_an_observation`;
it is bounded and says how much it dropped, held by
`packages/control-plane/tests/unit/test_events.py::test_the_sink_is_bounded_and_says_how_much_it_dropped`,
and no decision is taken from it. Decisions are append-only at the store, and
`packages/control-plane/tests/unit/test_decision_store.py::test_a_duplicate_decision_id_is_refused_never_upserted`
fails when a second append of an identifier the store already holds is
upserted instead of refused, `::test_an_appended_decision_is_never_updated`
when a caller's later mutation reaches the record it stored. Every one of
those runs in the public gate, `.github/workflows/ci.yml`. A change to the
pinned part of a declaration voiding the grant taken on the old one is **not
yet mechanised**: no capability declaration is modelled here — a request, a
grant and a policy carry an optional digest of the arguments, not the schema
or the description this article pins — so no check reads a changed
declaration, and the rule is held by review.

## Article 4 — Technology neutrality and the port rule

**Rule.** The core knows nothing of any particular technology: no agent
framework, model, prompt, tool protocol, industry or transport appears in its
vocabulary, its ports or its domain contract; the one transport binding of that
contract (article 13) is published beside it, names its transport, and nothing
else. A capability names a kind of effect and nothing more. A port enters
the core only when, in the same change, it arrives with at least one real,
useful open-source implementation — never a stub — and only when its name and
its documentation can be written for an open-source user who has never heard of
any private product's feature. If the port's docstring cannot be written without
naming an organisational need, the port is premature; the private side lives,
for a release or more, with a private, uncontracted extension instead.

**Bridges.** The project may publish, under the same licence, bridges that bind
this control plane to external standards for agent governance. A bridge is not
the core: it lives in its own repository, depends on the contract distribution
(article 13) and on nothing else of the project, owns every mapping between the
standard's vocabulary and this one, and is exempt from this article's
vocabulary rule and from nothing else. No concept of the standard enters the
core or the contract through a bridge, and a bridge never adds an outcome
(article 1). A bridge references the standard's text and never incorporates
it; conformance vectors are replayed fixtures pinned by content, never a live
dependency. A bridge becomes public only when this control plane is public
and the standard it binds is stable — a tagged release, with a conformance
suite its own project has merged; until both hold it is incubated privately,
and no claim of conformance to the standard is made (article 12).

**Why.** The danger is not a reverse import, which packaging blocks trivially. It
is abstraction laundering: each private need pushing "its" port into the core
until the public surface is a row of dangling providers that reveal a private
roadmap and signal an amputated open core. The same-change rule makes every port
pay its way in the open. A bridge keeps a standard's vocabulary where it is
honest — in a component that exists to speak it — instead of letting it seep
into a core that must outlive any one standard.

**Guard.** Dependency direction and import guards are public and run in public
CI: `tests/test_direction_of_dependency.py` and
`tests/test_server_distribution_direction.py` walk the shipped imports of each
published distribution and fail on one pointing the wrong way, and
`.github/workflows/ci.yml` is the workflow that runs them. The semantic
firewall — the guard that refuses private vocabulary — is scoped to code,
contracts and their documentation, never to this constitution's own words: a
public deny-list of words would itself be the leak, so that scope is held by
review and no check in this repository reads it. It runs on the private side,
and its presence there is held by review, because nothing here can read that
side; that it gates every merge there as a required status is a setting of a
repository this one cannot read, so this document does not claim it as
verified — held by review, the same limit article 16 states for its own
required checks. A bridge repository runs the dependency-direction test of
article 14 against the contract distribution only (not yet mechanised).

## Article 5 — Opaque scope

**Rule.** Every governed record carries a **scope**, an opaque identifier,
defaulting to `"local"` for a writer that names none. A reader names its scope
or is refused; the default never applies to a read. Scope partitions policy and
evidence between applications or environments that share one host — one daemon
may govern several of them without their policies or their evidence mixing —
and it is not a security boundary: identity is (article 6). In system mode the
configuration says which principals may write which scopes. The word "tenant"
does not exist in the public vocabulary; the discipline does: scope is a field
of every port that carries a record and of every persisted structure.

**Why.** Removing scope from the core would mean drilling it back into every
table and every port later, a retrofit nobody does twice. Keeping it under a
name that owes nothing to organisations gives it an honest open-source use and
lets a private product map its own organisation onto it. The reader rule names
a failure mode: a store under row-level security hands an unscoped reader
nothing, and a reader that reports "no policy" then denies. A bare read-only
credential on such a store yields an empty answer indistinguishable from
"nothing was ever recorded", and that silence is what the rule refuses.

**Guard.** Every port carrying a record carries `scope`, held to this article
by
`packages/control-plane/tests/architecture/test_scope.py::test_every_port_and_persisted_structure_is_held_to_article_five`,
which discovers what to check by walking every source file under `ports/`, not
by naming some of them: a module joins the guard's reach by existing there,
and a structure or operation the walk finds is a failure until the scope
register declares it, scoped or exempted. The store port refuses a read that
names no scope, and two tests prove it:
`packages/control-plane/tests/contract/test_evidence_store.py::test_a_reader_must_name_its_scope`
and
`packages/control-plane/tests/unit/test_decision_store.py::test_a_read_without_a_scope_is_refused`.
A live store adapter sets the scope inside the transaction of its read and
never sets a bypass: **not yet mechanised, because no adapter here keeps a
governed record in a database** — the one evidence store this repository ships
keeps a file, and a file read has no transaction to set a scope inside; the
one database adapter that does ship,
`packages/control-plane/src/sayfirst_control_plane/adapters/sqlite/policy_projection.py`,
holds a projection that entry 1 of `docs/exceptions.md` exempts from scope,
and not a record this clause is about. An integration suite proving it against
each supported store is **not yet mechanised** for the same reason, there
being no supported-store matrix to run one against; what
`packages/control-plane/tests/contract/test_evidence_store.py` proves instead
is that the adapter this repository does ship refuses a read that names no
scope.

## Article 6 — Host scope and identity

**Rule.** The control plane is **host-scoped**. It listens on a Unix domain
socket, and only there: its HTTP surface, for tooling, is served over that same
socket. It offers no TCP listener, not even on loopback — a TCP connection
carries no peer identity, and on a shared host any local account could reach a
loopback port that the socket's permissions do not guard. A remote operator
reaches it through the socket forwarded over SSH, with the operator's own
identity; the control plane never authenticates a network peer itself. There is
no application-level authentication in the core: no tokens, no sessions, no
rotation. Identity is the operating system's: peer credentials are captured at
`accept()`; a process id is diagnostic and never decisional; an unmapped user id
from another user namespace is refused, never treated as an identity. The
kinds of principal form an open registry, never a closed enumeration; a
process acting for a human — through a privilege tool, a scheduler or a build
runner — is recorded as a delegation in evidence, never collapsed into the
human's identity. Two deployment modes exist and are named: a **per-user daemon** (socket mode 0700,
one principal) and a **system daemon** (socket 0660, root-owned, a group,
several principals — where authorisation does real work). The socket file's
permissions are the admission list, and are documented as such; the socket's
parent directory is writable by the daemon's principal and root only, since
whoever can write it can unlink the path and bind an impostor, and a client
verifies the server's peer credential at connect and refuses a server that is
not the daemon's principal. Group
membership is resolved when a connection is accepted, with a bounded,
documented lifetime; the latency of a revocation is that lifetime, and the
documentation says so. Policies bind group *names*; canonicalising them across
directory services is the administrator's stated responsibility. The trust
boundary is the user namespace: a socket mounted into a container imports the
host's meaning of identity, and the documentation says so for each deployment
form it names — a bare host, a sidecar sharing the socket's volume, a node
agent with the socket on a host path. Multi-host and central deployments are
the business of products built on this one. Community pressure for remote,
network-authenticated access is foreseeable; it reopens this article by
amendment, not by drift, and the amendment must show an identity at least as
strong as the peer credential it would replace.

**Why.** "Governs an execution" applied to topology. Allowing a remote control
plane in the core would reintroduce every piece of identity infrastructure the
open core is designed to do without, and with it the surface where governance
products fail. The peer-credential rules are the difference between an identity
and a guess: a reused pid, an overflow uid, a socket mounted into a container
that imports the host's meaning of identity. The cost of having no loopback
listener is tooling: a browser cannot reach the socket, and an ad-hoc client
needs `curl --unix-socket` or the project's own tool. That cost is accepted and
recorded here so it is not rediscovered as a bug.

**Guard.** The daemon has no TCP listener to configure, held by
`packages/control-plane/tests/identity/test_daemon_process.py::test_the_daemon_has_no_tcp_listener_to_configure`;
a test enumerates its listening endpoints and fails on anything but the
socket, `::test_the_daemon_listens_only_on_the_socket`, and the transport
builds no socket of another family either
(`packages/contract/tests/identity/test_no_tcp_fallback.py::test_the_transport_constructs_no_socket_of_another_family`
and `::test_the_connection_class_has_no_network_connect`); the daemon refuses
to start on a socket directory writable by anyone else, held by
`packages/control-plane/tests/identity/test_directory_protection.py::test_a_directory_anyone_else_may_write_is_refused`
and `::test_an_ancestor_a_stranger_can_write_is_refused_unless_it_is_sticky`;
a test binds an impostor at the path and proves the client's refusal,
`packages/contract/tests/identity/test_socket_client.py::test_an_impostor_bound_at_the_path_is_refused_by_the_client`.
Peer credentials are read through a port with one adapter per operating
system, held by
`packages/control-plane/tests/identity/test_ports.py::test_every_named_port_has_an_implementation_that_is_not_a_double`;
CI runs the identity tests on Linux and macOS, `.github/workflows/ci.yml`, and
`packages/control-plane/tests/identity/test_platform_coverage.py::test_the_macos_leg_names_the_guards_it_must_run`
fails when the workflow stops naming the second runner or stops listing a
guard that leg owes, while
`::test_the_workflow_calls_the_gate_on_both_runners` fails when a leg stops
calling the gate at all. `sayfirstd whoami` reports the principal as the
socket saw it, held by
`packages/control-plane/tests/identity/test_whoami_command.py`; the spelling
`sayfirst whoami` names the separate product client, which does not answer it,
and reconciling the two command surfaces is owed by its own amendment (article
16).

## Article 7 — Integrity grades

**Rule.** The software reports which grade it runs at, and its claims follow
the grade. At **observability grade** the governed program can write or replace
the evidence store — the per-user daemon, where program and store share one
user id, is the common case; the hash chain detects accidental corruption and
incomplete tampering, a program that can replace the store can rewrite the
chain whole and nothing would notice, and no document or surface may claim
proof or tamper detection. At **evidence
grade** the daemon runs under its own user id and no principal but that one
and root can write or replace the store, on any mutation path the store
adapter knows — the chain and the store together support a claim of
integrity against the governed program, not against the daemon's own account
or root. The grade is decided by **effective access**, never by ownership as
protection — mode bits, access control lists, and the writability or
ownership of the store and of every parent directory that would allow it to
be replaced, since an owner can change the bits — and it is a property of
a connection in one direction only: a caller that can write the store is at
observability grade whatever the others can do, while evidence grade needs
exclusivity, which is a property of the store. A store behind a database
grades `unverified` unless its adapter can enumerate every role that can
write it and prove that none is reachable by an admitted principal. When
access cannot be established, the grade is **unverified**, which claims
nothing and ranks below the other two. Access changes while a
connection lives, so the grade is re-evaluated at a bounded, documented
interval — that interval is the latency of detection, and the documentation
says so — and before every verdict the daemon issues; a change of grade is
itself recorded as evidence, and a verifier over an export reads the grades
the chain recorded and adds nothing. `sayfirst status` displays the
caller's grade; a verification
verdict carries, for every connection whose evidence it covers, the weakest
grade in effect over the period covered, and `unverified` for a connection
whose grade record is missing from the chain (article 10).

**Why.** The most convincing evidence a per-user deployment can produce is one
the program it governs could have forged. A root-owned store in a world-writable
directory is forgeable too, and a grade that read ownership would call it proof.
Saying which grade applies, in the status line and in every verdict, and saying
"unverified" when the answer is not known, is what keeps article 2 true for the
modes most people will try first.

**Guard.** The grade is computed per connection from the principal's effective
access to the store and to every directory on its path
(`packages/control-plane/tests/unit/test_integrity_grade.py::test_a_caller_that_can_write_the_store_is_at_observability`),
logged as evidence with that connection's first record and again at every
change
(`packages/control-plane/tests/unit/test_evidence_emitter.py::test_a_connections_first_record_in_a_scope_is_preceded_by_its_grade`),
refreshed before every verdict
(`packages/control-plane/tests/integration/test_grade_reevaluation.py::test_the_grade_is_reevaluated_before_a_verdict`),
and rendered in status, held by
`packages/control-plane/tests/identity/test_status_command.py`; a verdict's
schema carries the grades as a required field with three values —
`observability`, `evidence`, `unverified` — held by
`packages/contract/tests/test_evidence_contract.py::test_the_verdict_schema_requires_grades_with_three_values`,
and
`packages/control-plane/tests/unit/test_evidence_grade_provenance.py::test_the_manifest_covers_the_grades_the_export_claims`
holds an export to the grades the chain recorded;
`packages/control-plane/tests/integration/test_grade_reevaluation.py` proves
that a permission change during a connection lowers the grade of the evidence
recorded after the next re-evaluation, and fails when the interval stops being
consulted. Two clauses are **not yet mechanised, because no code implements
them**. The store adapter's proof of exclusivity is **not yet mechanised**:
`EvidenceStore` publishes no exclusivity operation, so `evaluate_grade()`
never returns `evidence` — only `observability` or `unverified`, which is the
honest answer while exclusivity is unproved, and not a licence to return
`evidence` to match this paragraph. Re-evaluation *at* the documented interval
is **not yet mechanised** either: the interval is a cache age consulted when a
connection next asks something, so an idle connection's grade is not refreshed
until it acts and no timer scans for one. Both rules stay binding and are held
by review; neither relaxation is registered as an exception,
`docs/exceptions.md` holding no entry for this article.

## Article 8 — Plugins and configuration ownership

**Rule.** Plugin discovery, activation and composition are three separate
steps. Package entry points **discover** code; they never activate it. The
configuration **activates** a provider by naming it for a port; an unnamed
provider is inert. Bootstrap **composes** the registry explicitly and fails
closed on an unknown plugin interface or version. The composition resolved at
start is logged as evidence. In system mode the configuration is protected
twice, by effective access (mode bits, access control lists, parent
directories) and never by who owns the file: at start, the daemon refuses a
configuration that anyone but root or its administrator group could write or
replace; per connection, it refuses a **decision request** from a principal
with effective write access to the configuration or to a directory that would
let it be replaced — a governed program that could write its own configuration
could activate the plugin that frees it — while administrative commands from
such a principal are admitted and graded (article 7). In consequence a program
run as root or as the administrator group obtains no decision in system mode;
a governed program runs as another principal, and the documentation says so.
The same three steps
govern a subcommand a plugin contributes to the command-line tool. Each plugin
interface carries an integer version; a provider built for an unknown
version is refused; a deprecated version keeps working for at least two minor
releases or six months, whichever is longer, and the deprecation is announced in
the changelog when it begins. The project ships a conformance kit,
`sayfirst.testing`, with a contract test suite per port; a provider that does
not pass it is not a provider.

**Why.** Letting any installed package inject a provider into a control plane is
a supply-chain catastrophe with a pleasant developer experience. The real
authority is whoever can write the configuration, and in system mode that must
not be the program being governed. A control plane that logs its own composition
is a product that verifies itself.

**Guard.** Bootstrap refuses an unnamed or unknown provider, and an interface
version it does not support:
`packages/control-plane/tests/test_plugin_composition.py` fails, in three
places, when the configuration check is made to accept everything.
`plugins list` shows discovered against active on the operator command this
repository ships, `sayfirstd`, held by
`packages/cli/tests/test_plugins_list.py`; the spelling
`sayfirst plugins list` names the separate product client, which does not
answer it, and reconciling the two command surfaces is owed by its own
amendment (article 16). The conformance kit is published — as
`sayfirst.testing`, `sayfirst_control_plane.testing` and `sayfirst_testing` —
and the public gate runs it against this repository's own adapters:
`packages/control-plane/tests/conformance/test_port_conformance.py` puts each
shipped adapter through the published suite,
`tests/test_plugin_conformance_kit_wheel.py` holds the kit inside the wheel a
third party installs, and `.github/workflows/ci.yml` is the workflow that runs
both. It does not yet reach every port: `PathAccess` and `RecoveryJournal`
carry no published suite, and those two are held by review. `EvidenceStore` is
reached — `EvidenceStoreContract`, published from
`packages/control-plane/src/sayfirst_control_plane/testing/evidence_store_contract.py`,
is run against both shipped adapters by
`packages/control-plane/tests/contract/test_evidence_store.py`, and
`tests/test_installed_wheel.py` proves it survives a clean wheel install. The
two protections of the configuration in system mode are mechanised, and
`packages/control-plane/tests/integration/test_configuration_access.py` fails
when either stops being made: `Settings` carries the name `load_settings()`
opened, `bootstrap.compose` applies at start the effective-access check the
**policy authority** already receives — before anything else that start could
refuse over, because whoever can write the configuration chooses every other
file the start then checks — and `DecisionService` applies it again per
decision request under `configuration_writable_by_principal`, a refusal of its
own so that a reader can tell « could write the policy » from « could choose
which file the policy is ». What no ordinary runner can hold runs in the root
container, since `assemble()` refuses system mode below uid 0 and the
expectation the start applies admits root as the only owner:
`packages/control-plane/tests/identity/test_root_system_mode.py` carries
`test_a_configuration_a_stranger_can_write_refuses_the_start_by_name`,
`test_a_configuration_only_root_and_the_administrator_group_can_write_starts`
and
`test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted`,
the last holding the administrative command beside the refused decision.
`packages/control-plane/tests/identity/test_platform_coverage.py` holds the
three against the workflow leg that owes them, so a guard added and not listed
is a red gate. Entry 4 of `docs/exceptions.md` is closed rather than renewed,
with the date and the mechanism; `SECURITY.md` and `docs/deployment.md` now
say what the daemon refuses, in place of the sentences that told an operator
they had ordinary filesystem permissions and nothing else. What this article
still defers to no mechanism at all is the subcommand a plugin contributes to
the command-line tool:
**not yet mechanised**, because the parser is fixed and nothing discovers,
activates or composes such a subcommand, and
`tests/test_deferred_plugin_subcommand.py::test_the_plugin_subcommand_of_article_8_is_deferred_in_writing`
fails when the documentation stops saying so.

## Article 9 — Packs

**Rule.** A pack is code the user chooses to run, exactly like a dependency;
`sayfirst instrument apply` executes it. The open project ships the instrumentation
engine, the **instrumentation verifier**, and the **convenience packs** — those
a competent engineer would rebuild in a day from public documentation (an HTTP
client, a subprocess, a database driver). Packs for sophisticated frameworks,
including agent frameworks, are not part of the open core; a bridge (article 4)
is the one open surface where a standard's vocabulary exists, and a bridge is
not a pack. In its first version a pack is a declarative manifest plus a local
execution module, explicitly designated by the user; there is no registry, no
marketplace and no signature scheme yet, and the documentation says so, with a
date by which the statement is to be re-examined — past that date the
packaging test fails until the statement is renewed or replaced. Runtime
interposition — reversible, verifiable — is the primary mode; a committed code
modification is a later option. Every pack in the open project carries a note
stating that it is a convenience pack, the one-day justification and its date.

**Why.** An open engine with no packs is a demonstration designed to be useless.
A pack that silently executes code under a promise of safety is worse. The line
"publish the verifier, keep the compiler" keeps the credibility — the
verification harness — public, and the know-how — deriving the ideal
interception point — where it is paid for.

**Guard.** What this article names exists and is published: the
instrumentation engine, the instrumentation verifier and three convenience
packs — an HTTP client, a subprocess and a database driver — ship in the
project's command-line client repository, which is a sibling checkout here
rather than a dependency (article 14), so from this branch their code and
their notes are **held by review** in that repository and no check written
here reads them. What this branch does run is the engine against a real
daemon:
`packages/control-plane/tests/e2e/test_the_chain_governs_a_program.py::test_a_governed_program_asks_once_and_the_chain_records_it`
runs a governed program as a subprocess under the shipped subprocess pack and
reads back the chain the daemon wrote, and
`::test_a_denied_program_does_not_spawn` proves a denial never lets the spawn
happen. `instrument apply` — the committed code modification — refuses with a
stated reason naming the reversible mode that does exist, and that refusal is
**held by review** in the client repository, since nothing here invokes it.
`packages/control-plane/tests/e2e/test_the_verifier_inspects_every_shipped_pack.py`
designates every pack that client ships, walks one point of each from a
program's own code against a real daemon, and requires the verifier's own
report to name every one of them as inspected — the shipped set read off the
client's package data, the inspected set off the report, and neither off the
command line, because "a verifier added now would succeed by checking nothing"
is exactly what a set copied from the invocation would satisfy. The verdict is
watched firing rather than only defined: the same program, run with nothing in
front of its effects, comes back `ungoverned`, and a shipped pack the program
leaves alone comes back `not-exercised` and never a pass (article 2). A tree
with no client checkout beside it **cannot verify** a pack it does not hold,
so those cases are reported skips and never passes, and the public workflow is
such a tree today — no leg of `.github/workflows/ci.yml` checks that
repository out — so it **cannot verify** them until one does. The packaging
test that walks the shipped packs, fails on one carrying no classification
note, and fails on a no-registry statement past its date is **not yet
mechanised here**: it belongs to that client distribution's own gate, which
this repository does not run (article 14). The notes are held by review at
each release. The rule above stays binding, and any claim made for these
components before they ship is governed by the rule about claims (article 2).

## Article 10 — Evidence and the hot path

**Rule.** The evidence chain, its verification verdict and raw export belong to
the open core. Compliance packages, disclosure registers and regulatory
workflows do not. The boundary does not ask the control plane on every
intercepted operation: a **grant** — a decision cached at the boundary with a
lifetime and conditions — answers on a hit; the control plane is consulted on a
miss and when the applicable policy changes: a grant carries the policy version
it was issued under, the control plane signals a change of version to every
connected boundary over the connection that issued the grant, and a boundary
that has lost that connection, or has not heard from it within the grant's
lifetime, treats its grants as expired — a hit is honoured only while the
version is current on a live connection. The chain is kept per scope (article
5); a verdict names the scope it covers, and a verifier may cover several
scopes, each on its own chain. Evidence is emitted
asynchronously
and bounded, and the pipeline **declares its gaps**: sequence numbers and an
explicit dropped marker, so a store under pressure never produces a clean record
by losing part of one. No latency figure is a constitutional rule; budgets belong
in the specifications that measure them.

**Why.** Integrity, chaining and raw export are the credibility of a product
called evidence and are generic; a regulatory package is a business. A decision
round-trip per operation does not survive contact with a real workload, and a
cache that hides its misses, or an evidence store that drops silently, is the
false all-clear article 2 forbids.

**Guard.** The grant is a domain object with tests for expiry and
policy-version change:
`packages/control-plane/tests/e2e/test_policy_change_grant.py` changes a real
policy file under a live grant and proves the next operation misses and the
connection is signalled. Three of its cases drive the domain objects over a
socket pair and call `PolicyService.reload_if_due()` themselves —
`test_a_policy_change_under_a_live_grant_makes_the_next_operation_miss`,
`test_a_version_change_while_the_grant_is_registered_reaches_the_boundary` and
`test_composing_the_service_ends_a_grant_of_another_connection_on_a_change`;
`test_a_policy_change_reaches_a_held_connection_that_asks_nothing_more` calls
it nowhere and asks a composed daemon nothing after the change, so what it
proves is the daemon noticing rather than the objects obeying.
`DecisionService.sweep` is what notices: it consults that reload age and ticks
`GrantConnections` in one step, and two paths the daemon already runs call it
— every decision request, before the request can be refused over anything, and
the daemon's own watch on a connection a grant was delivered on, which is the
boundary article 10 calls connected — with
`test_a_request_this_service_refuses_still_carries_the_change_to_a_held_grant`
holding the first and
`test_the_sweep_of_a_later_request_heartbeats_a_live_grant_and_ends_a_spent_one`
the second, the heartbeat and the `expired` ending being what the grant
document promises a boundary. What remains **not yet mechanised, because no
code implements it**, is any sweep of a connection that holds no grant and
asks nothing: no timer scans the registry or the authority, so such a
connection learns of a version change at its next request and not before —
that remaining case is held by review, and the rule above stays binding. A
live stream still expires at its own lifetime and ends its grants on
connection loss, held by
`packages/control-plane/tests/unit/test_grant_holds_its_connection.py::test_a_closed_connection_releases_the_grant_it_carried`
and `::test_a_grant_that_ends_lets_its_connection_go`. The evidence exporter's
tests assert the gap marker under backpressure,
`packages/control-plane/tests/unit/test_evidence_emitter.py::test_a_dropped_record_becomes_a_declared_gap_where_the_loss_happened`;
the evidence verifier refuses a chain with an undeclared gap,
`packages/contract/tests/test_evidence_verifier.py::test_a_removed_entry_is_a_gap_and_a_rewritten_one_a_break`
reading a removed entry as a gap and a rewritten one as a break, and the
daemon's own verifier is held to the same reading by
`packages/control-plane/tests/unit/test_evidence_chain.py`.

## Article 11 — Minimisation by default

**Rule.** The control plane records decisions, not payloads. By default,
evidence and traces carry the identity of an effect — capability, scope,
principal, decision, timing — and no argument, content or return value; capture
beyond that is opt-in per capability, bounded in size, and marked in the record
as captured. Retention is a property of the store with a documented default,
and a purge leaves a declared gap (article 10), never a silent hole. The
privacy port ships with a no-op default; the status surface names the active
provider — `none` included, `unknown` when it cannot tell — and a no-op is
never rendered as protection.

**Why.** Privacy by design is a discipline this project adopts as the designer
of a recorder, not one it leaves to operators alone; the operator of an
instance is the controller of what it records, and the project is neither
controller nor processor of it. A control plane that captured everything by default would create
obligations for its users before they knew they had them, and would make the
project that publishes it the author of the tool that breaks them. The open
project provides a mechanism, never a conformity, and says so wherever it
describes itself (article 2).

**Guard.** A contract test asserts that the default configuration emits no
payload member,
`packages/control-plane/tests/contract/test_minimisation.py::test_the_default_configuration_emits_no_payload_member`;
the evidence schema marks captured payload as such, and
`packages/control-plane/tests/unit/test_capture.py::test_a_capture_rule_bounds_and_marks_what_it_captures`
reads that mark, its bound and its truncation off a record a capture rule
produced; `sayfirstd status` renders the active privacy provider by name, held
by `packages/control-plane/tests/identity/test_status_command.py`. The
spelling `sayfirst status` names the separate product client, which does not
answer it, and reconciling the two command surfaces is owed by its own
amendment (article 16).

## Article 12 — Approvals

**Rule.** A suspended effect waits for a human. The simple form — one person
approves or rejects — is part of the open core. Approval by two distinct,
designated people, and the registry of designations that gives "designated" a
meaning stronger than "holds the role", are not; they arrive through the
approval port (article 8), which a product built on this one
may implement with as many signatures as its rules require. The core never
adds an outcome to express this; the three outcomes of article 1 are complete.
The project never claims conformance to an external agent-governance profile
that requires outcomes or lifecycle hooks it does not have; partial alignment is
stated as partial.

**Why.** Human approval is neither agentic nor corporate; a designation registry
is an organisational object. Keeping the outcomes closed and the evaluation
pluggable is what lets both truths hold.

**Guard.** The approval port exposes suspend and resume —
`packages/control-plane/src/sayfirst_control_plane/plugins/approval.py` is
that port and the core-owned records that cross it, reached by
`packages/control-plane/tests/test_approval_conformance_kit.py`, and
`packages/control-plane/tests/test_approval_routes.py` holds the two
operations the daemon serves over the socket; the multi-signature evaluation
is a provider behind it, with the conformance kit as its contract:
`packages/control-plane/src/sayfirst/testing/approval.py` is the kit a
provider is judged by, and `tests/test_approval_kit_rule.py` holds the
published claim about it to the one rule it judges by. The daemon serves both
operations over the socket, where an earlier reading of this column found
neither served:
`packages/control-plane/tests/e2e/test_a_person_resolves_an_approval.py` puts
a person's act to a real daemon end to end, and the record that comes back
names the person who acted — the connection's verified principal — held by
`test_the_person_of_a_resolution_is_the_one_the_caller_verified`. The registry
of designations is not in the open core, so "designated" here means no more
than admitted, and every admitted principal may resolve any wait:
`packages/control-plane/tests/identity/test_approval_documentation.py::test_the_deployment_documentation_says_every_admitted_principal_may_resolve_any_wait`
fails when the deployment documentation stops telling an operator so.

## Article 13 — Contracts and versioning

**Rule.** The public contract has two layers. The **domain contract** —
schemas, the golden scenarios, the problem codes, the attribute registry and
the contract generation marker — names no transport. Its one **transport
binding** — the OpenAPI document for HTTP over the socket (article 6) — is
derived from the domain contract, adds no vocabulary to it, and is published
beside it. Both are a separate distribution published from the control
plane's repository beside the server. The generation is negotiated in band: pinned in the contract
package, echoed on every response, recorded by the project's client at
connection, refused with a distinct problem when unsupported. Within one
generation a server may **add** response members and a client must tolerate
members it does not know; a client never **sends** a request member its
generation does not define; an unknown enum value is read as unknown, and an
unknown decision outcome stops the effect as "could not ask" does (article 1)
and is *reported* as unknown, never as a denial (article 2). Anything else — a new request member, a removed or
renamed member, a changed meaning — is a new generation, and a server accepts
every generation whose deprecation window (article 8) has not expired, however
many that makes. The golden scenarios are the
arbiter between a client and a server: the client scripts them, the server
replays them as its own acceptance suite, and when they disagree one of the two
has a defect. Any conformance claim is either proven by a named test against a
shipped fixture or verified live with a referenced piece of evidence; there is no
third kind.

**Why.** The open project's product boundary *is* the contract. Third-party
implementability is the purpose of publishing it, which is why it is a wheel of
its own under a permissive licence, and why the scenarios must be a fact both
sides test rather than a belief one side holds.

**Guard.** The contract wheel is built and installed in a clean environment in
CI, held by `tests/test_installed_wheel.py` over `.github/workflows/ci.yml`;
the scenario set is authoritative and the documentation derived from it,
`packages/contract/scripts/build_contract.py` generating the binding, the
digests and the scenario prose and byte-checking what it generated, run by
that same workflow and loaded by `packages/contract/tests/test_binding.py`; a
test holds the domain contract free of transport terms,
`packages/contract/tests/test_contract_artifacts.py::test_the_domain_contract_names_no_transport`,
proven non-vacuous beside it by
`test_the_transport_guard_catches_a_planted_term`. The server replays the
scenarios it publishes, over its own socket binding, as its own acceptance
suite: `packages/control-plane/tests/e2e/test_socket_replay.py` walks every
scenario `load_scenarios()` names as server-bound and proves every one of them
— the three that end a wait, `review_approve`, `review_reject` and
`review_expire`, included — and declares none absent; a bound scenario neither
proven nor declared absent fails the run, which is
`test_no_server_bound_scenario_leaves_this_run_unaccounted_for` holding the
replayed set and the declared-absent set together against the bound one, so a
new scenario cannot silently join either list. The run reports `proven` only
where every bound scenario was replayed, and reports unknown rather than a
completeness a declared absence has not earned (article 2).

## Article 14 — Direction of dependency

**Rule.** Products built on this control plane depend on it; it depends on none
of them. Nothing in this repository imports, names, links to or is shaped by a
private product: no private symbol, path, vocabulary or roadmap appears here.
The command-line client depends on the contract distribution and never on the
server distribution, so installing it never installs a web framework or a
database layer. Files that enter an open repository from a private one enter by
copy, each with a provenance review that records the copyright holder of every
file copied, never by history rewriting; `NOTICE` names every holder.

**Why.** A dependency pointing the wrong way is a leak that cannot be
unpublished, and a history that carries private paths is a leak that has already
happened.

**Guard.** Import guards and the dependency-direction test are public and run
on every change: `tests/test_direction_of_dependency.py` and
`tests/test_server_distribution_direction.py`, called by
`.github/workflows/ci.yml`. `tests/test_copy_note.py` holds the copy note in
the two places it lives, and fails when either carries a copy paragraph that
does not open with the recognised wording naming the copyright holder and the
licence and stop there: the tracked record `PROVENANCE.md`, which travels with
the tree, and whatever commit history the tree sits on. Both are checks on the
form of the note, not on the review that precedes it, which is held by review
and which nothing in this repository reads. Only the first runs everywhere —
the history rule is skipped where there is no history to read, so a shallow
checkout reports it as not runnable rather than as passing, and a repository
created fresh by the publication recipe of `SECURITY.md` is green on both
rules without carrying a history across. Neither can establish that the
provenance review was held, or that the pull request making the copy carried
the copyright holder and the licence and nothing more: the review is private
and the body of a pull request is read by nothing here, so both are human
steps, held by review.

## Article 15 — Dependencies, licence and marks

**Rule.** The open project is licensed under the Apache License 2.0, one licence
for code and documentation alike; examples and fixtures may additionally be
offered under MIT-0, so that copying them carries no obligation. Contributors
keep their copyright; the licence of contributed code does not change, the
project holds no right to change it and seeks none (article 16), and there is
no alternative-licence offer to sell — the constitution says so to end that
discussion. What a contributor offers under both licences is offered so at
contribution, by the contributor. Every dependency of
the open project carries a permissive licence from a closed list of SPDX
identifiers — `MIT`, `MIT-0`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`,
`ISC`, `PSF-2.0`, `Zlib`; an addition is a request for comments — verified
from installed metadata, never from a hand-written list; weak copyleft does not
enter the open core; a dependency without an identifiable licence text is
refused, and one whose metadata is defective is admitted only by an entry in
the exception register (article 0) naming the licence text actually found.
Every file the project authors — source and documentation alike, the licence
text and the NOTICE excepted, being notices rather than works — carries an
SPDX identifier naming its licence, `Apache-2.0` or, for an example or fixture
offered under both, `Apache-2.0 OR MIT-0`, in the form its format allows;
each distribution's metadata declares `Apache-2.0`, and the file-level
expression governs the file; every repository carries a NOTICE that
redistributions reproduce. Each contributor grants recipients a
patent licence for their contribution under section 3 of the licence; whoever
wishes to keep a technique out of that grant keeps it out of the open core,
decided before the mechanism is written here, not after. The project's names
and marks are not licensed by the code licence; their use is governed by
`TRADEMARKS.md`. Contributions arrive under the Developer Certificate of
Origin; a contribution made on behalf of an employer, or under a contract that
gives the employer rights in it, also needs the corporate contributor licence
agreement, signed once by that employer; no assignment of rights is ever asked.
To the extent Regulation (EU) 2021/821 on dual-use items, or the regime of a
jurisdiction whose index the project publishes through, applies to the
cryptography the project embeds at all, the project relies on the exemption
for publicly available software; the publication checklist records counsel's
confirmation of that reliance, and of the Developer Certificate of Origin's
effect as a licence grant under the law that applies to the lead, before the
first public release.

**Why.** A user embeds the instrumentation library inside their own program,
which may be proprietary; a licence that reached into that program would end
the conversation before it started. On the project's side, when the sharing of
value is architectural — what is sold is not the same binary as what is
published — the open licence can afford to be permissive, and a permissive
licence chosen once never has to be withdrawn. The dependency rule exists
because a copyleft dependency in the open core would reach every program that
embeds it, the private distributions included.

**Guard.** The dependency checker validates semantics and licence together
from installed metadata, and refuses a licence outside the closed list:
`tests/test_dependency_licences.py::test_every_dependency_carries_a_licence_from_the_closed_list`.
The same module carries a second rule and its own way back: it refuses a
dependency that ships no licence text, whatever its metadata claims, and
admits a defective one only through an entry in the exception register naming
the licence text actually found —
`tests/test_dependency_licences.py::test_every_dependency_ships_the_text_of_its_licence`
and
`tests/test_dependency_licences.py::test_every_admitted_distribution_has_an_entry_in_the_exception_register`.
The index-metadata guard refuses a distribution whose author is not the
identity its commits are signed off under, whose classifiers disagree with
what its own `requires-python` admits, or that carries a licence classifier or
a typing classifier at all — `tests/test_index_metadata_of_every_distribution.py`.
Two further
guards refuse a redistribution that does not reproduce the licence and the
notice: one for the wheel this repository ships,
`tests/test_shipped_wheel_notices.py`, and one for the source distribution it
is built from, refused because the hook that carries them into the wheel
finds nothing once the tree is unpacked two directories up if the source
distribution did not carry them too —
`tests/test_source_distribution_notices.py`.
The SPDX header check and the NOTICE presence check run in CI —
`tests/test_spdx_identifiers.py`, `tests/test_shipped_wheel_notices.py` and
`.github/workflows/ci.yml`. `scripts/check_developer_certificate_of_origin.py`
reads every non-merge commit of a pull request and refuses one carrying no
well-formed sign-off — and refuses a range it cannot read rather than
reporting it as passing, because a shallow checkout has no range; it runs on
every pull request in the public gate, and
`tests/test_developer_certificate_of_origin.py` plants an uncertified commit
and watches it refuse. The corporate agreements signed are recorded by a
maintainer (not yet mechanised). Counsel's two confirmations — the reliance on
the exemption for publicly available software, and the sign-off's effect as a
licence grant under the law that applies to the lead — are lines of
`docs/publication-checklist.md`, held there by
`tests/test_publication_checklist_names_every_act.py`; that either answer was
obtained is held by review, no check here being able to read one.

## Article 16 — Governance, contribution and amendment

**Rule.** The project is maintainer-led. Its lead is a named person who also
builds the private products on this control plane; `GOVERNANCE.md` names the
entity that holds them and the lead's role in it, or says that no such entity
exists yet, and within this project the lead acts in a personal capacity, not
as an officer of that or any company. The lead appoints
maintainers, removes them with a stated and recorded reason, and decides where
consensus does not form. Decisions that change a public contract, a plugin
interface or a constitutional article go through a request for comments, open for comment for fourteen days, decided by lazy consensus among
maintainers and, failing that, by the lead; while the lead is the only
maintainer, the fourteen days are the community's and the lead decides at their
end, and `GOVERNANCE.md` says so until it is no longer true. The licence is
outside that path altogether: the project holds no right to change the
licence of contributed code and seeks none, so no request for comments and no
tie-break can change it. Security reports go to a private channel and are
handled under coordinated disclosure with a ninety-day default. Releases are
versioned semantically, each with a changelog; the deprecation window of article
8 counts in those releases. Public CI runs without any private infrastructure: a
fork can build, test and contribute with nothing but this repository. Two
private checks exist and gate merges as required statuses set from the private
side: a compatibility check, whose failure names the port and the interface
bump required, and the vocabulary check of article 4 — scoped to code,
contracts and their documentation — whose failure names the category of
article 4 and the identifier that tripped it, never the list.
Both run only when a maintainer labels the pull request, which attests that a
maintainer has read the change; neither runs automatically on a fork's code;
neither discloses private internals. The compatibility check passes when the
change declares the interface bump it requires: it verifies the declaration,
not the private side's adaptation, so a private lag never holds a merge, and
its failure is information — the bump to declare, through the
request-for-comments path — never a veto over a decision that path has taken.
Amendments to this
constitution follow the request-for-comments path, with the lead's approval, and
each is recorded in the changelog with its rationale.

**Why.** A contributor agreement without a contribution process is a barrier
without a door. A public CI that needs private secrets is one pull request away
from exfiltration. Disclosing the lead's affiliation and naming the lead's role
in the project as a personal one is article 2 applied to governance: a
contributor needs to know both facts, and would rightly distrust a document
that stated only one.

**Guard.** `GOVERNANCE.md` and `CONTRIBUTING.md` implement this article. The
maintainer-label rule is **not yet mechanised**: the two private checks and
their `ok-to-compat` gate live on the private side, no workflow definition in
this repository triggers on a label or refuses a run without one, and the rule
is held by review until one does. The DCO check exists and runs on every pull
request of the public gate (article 15); that it is a **required** status is a
branch-protection setting of the public repository, which no check here can
read, so this document does not claim it — no test asserts it and it too is
held by review; it is a line of `docs/publication-checklist.md`, held there by
`tests/test_publication_checklist_names_every_act.py`, so that a setting no
check can read is at least an act the operator is asked for. Releases moving
together at one version is read by
`scripts/release_version.py`, and the changelog carrying that version is held
by
`tests/test_changelog_names_the_version.py::test_the_changelog_names_the_version_this_tree_would_release`.

## Article 17 — Telemetry

**Rule.** The software never phones home. Any telemetry about the software
itself is off by default, opt-in by explicit configuration, documented as to what
it sends and where, and local by default when enabled.

**Why.** A governance product that reports on its users without asking has
forfeited the trust it sells; and telemetry about people is personal data with
obligations the open project has no business creating for its users.

**Guard.** Two tests, the first of them `tests/test_no_outbound_network.py`,
which runs the integration suite with outbound network disabled and counts
every attempted connection through an audit hook below the socket, installed
in the run and inherited by every process it starts, so an attempt fails it
whether or not the code swallowed the error — proved in the same file by a
planted connection whose caller catches everything and notices nothing,
`test_a_swallowed_outbound_attempt_is_still_counted`.
`tests/test_outbound_destinations.py` enumerates the destinations by walking
every shipped source, resolving import aliases before it classifies a call,
and fails on one outside the configured set: one entry, the local address the
caller's configuration names. Both run in the public gate,
`.github/workflows/ci.yml`, and `tests/test_public_gate_runs_the_suite.py`
holds every step that runs the suite to an installed workspace and to the
recorded lock, so a leg that stopped reaching either test would be a red gate.
Neither reads a process this repository does not start — a program an operator
runs beside the daemon, a sidecar sharing its container, anything outside this
run's own process tree: **cannot verify**, and nothing here claims to. The
walk reads a destination computed at run time as configured, and the hook is
what holds that case,
`tests/test_no_outbound_network.py::test_a_swallowed_outbound_attempt_is_still_counted`.

## Article 18 — Neutrality, measured

**Rule.** The parent's application consumes this control plane as any governed
program does: through the public contract, with no privileged path. At each
release the maintainers publish the number of concepts the parent had to add on
its own side in order to integrate, with the counting rule that produced it.

**Why.** Dogfooding is the best proof that the core is neutral, and the count is
the earliest signal of a core quietly becoming agentic through internal
needs.

**Guard.** The count is published in `docs/NEUTRALITY.md` with the rule that
produced it, one row per release, as reported by the maintainers of the parent
application; this repository **cannot verify** the number it publishes, holding
nothing that could check a measurement made on the other side of the boundary,
and says so in that document. `tests/test_neutrality_count_is_published.py`
fails when the version this tree would release has no row, and when any row is
blank or carries a dash in place of a count — an absence wearing a
measurement's clothes — rather than a number with its rule or "not reported"
(article 2), a spelling the first count this project ever published, the
oldest row of the newest-first table, is free to use as well; the rule leaves
a reported zero alone — a zero is a number, and nothing here can tell a
reported zero from an absence, so the rule that an absence is never written as
zero is held by review.
The request for the next count is a line of `docs/publication-checklist.md`,
held there by `tests/test_publication_checklist_names_every_act.py`; that the
request was made is held by review, being an act of the operator rather than of
a program; a rising trend opens a release request for comments (article 16).

---

## Provenance

This constitution consolidates the constitution and dependency rule of the
control plane it is extracted from, the architecture review that preceded the
open project (2026-08-31), the decisions taken on 2026-09-01 and 2026-09-03,
the licensing rules adopted with them, the commitments of the client doctrine
that are generic to any client, and the failure mode of an unscoped reader
over a store under row-level security. The four shaping choices —
maintainer-led governance with a named lead, boundary articles binding the
private side, the brand placeholder, mechanism rather than numbers on the hot
path — were put to the lead on 2026-09-03 and taken as recommended. A fifth —
no loopback listener, HTTP served over the socket only, which tightens the
decision that read "HTTP on localhost" — was raised by the review of this
draft and is put to the lead with it: article 6 stands as written if this
document is approved, and the decision it tightens is amended to match. The
finding-by-finding mapping is kept in the private review record and is not
published.
