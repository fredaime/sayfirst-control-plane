<!-- SPDX-License-Identifier: Apache-2.0 -->
---
kind: spec
status: implemented
date: 2026-09-04
block: "2.3"
title: "Policy authority and grants"
---

# Policy authority and grants

## Constitutional basis

This block implements policy decisions for one execution on one host. The
policy file is an authority, its readable copies are projections, and decisions
are immutable authority records (article 3). A decision has exactly one of the
three outcomes defined by article 1. The authority is protected using effective
access checks (article 8), grants obey the bounded lifetime and invalidation
rules of article 10, and all published request and response shapes obey the
contract rules of article 13.

No client decides policy. Failure to load or validate the authority is reported
as an inability to ask, never as a denial or permission (articles 1 and 2).

## Contract generation

This block stays inside contract generation one and adds no request member to
it. Article 13: *"Within one generation a server may **add** response members
and a client must tolerate members it does not know; a client never **sends** a
request member its generation does not define ... Anything else — a new request
member, a removed or renamed member, a changed meaning — is a new generation."*

Generation one's `decision-ask-request` therefore keeps exactly the five members
block 2.1 published: `contract_generation`, `capability`, `scope`,
`arguments_digest` and `correlation`. The two facts this block needs from the
boundary are carried inside that set:

- the digest the boundary pins a rule and a grant condition against is
  `arguments_digest`, generation one's own optional member, used with the
  meaning block 2.1 gave it — a digest of the effect's arguments computed at the
  boundary, never the arguments (article 11);
- whether a grant is wanted is not asked for in the request at all. A grant is
  usable only on the connection that issued it (article 10), so a boundary that
  wants none carries no signal channel, exactly as the caller's identity is
  established from the connection rather than claimed in the request (article
  6).

Response members are additive within a generation, so the decision record, the
decision result, the grant, the grant signal and the policy status this block
publishes are generation-one additions and need no new generation. Opening
generation two would require a new marker, in-band negotiation, a deprecation
window in which the server still accepts generation one, and every published
artefact regenerated and byte-pinned; none of that buys a walking skeleton
anything that the members already published cannot carry.

## Policy authority

The authority is one UTF-8 TOML file, read for every decision. Reading it has no
side effects. Its maximum size is 1,048,576 bytes. The file has this public
shape:

```toml
format = 1

[revision]
reason = "Initial policy"

[[rule]]
id = "example-rule"
capability = "example.effect"
scope = "local"
principals = ["group:operators"]
outcome = "allow"
reason = "This effect is permitted for operators"
grant_lifetime_seconds = 30
arguments_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

`format` and a non-empty `revision.reason` are required. `rule` may be absent or
empty; that valid policy denies every question. Each rule requires a unique
identifier, a capability, one or more principal references, an outcome and a
reason. Scope defaults to `local`. Capabilities and scopes are exact matches;
wildcards do not widen a rule. An arguments digest, when present on a rule, is
also an exact match against the ask's `arguments_digest`; an ask that carries no
digest never satisfies a pinned rule. Grant lifetime is permitted only on an allowing rule. Unknown members,
unknown formats and unknown outcome words are refused (articles 1, 3 and 13).

The policy version is the lowercase SHA-256 digest of the file bytes, prefixed
with `sha256:`. Every byte change therefore creates a new version.

Before serving, the daemon establishes that the resolved file and every parent
component meet the configured ownership and effective-write expectations. In
system mode, a principal that can write or replace the authority receives no
decision. An access result has three values: writable, not writable and unknown.
Unknown fails closed (articles 2 and 8).

## Evaluation

A question contains `scope`, `capability`, the caller established from the
connection, and the `arguments_digest` the boundary computed. Applying rules
match all four facts. All three question members the client sends are
generation-one request members; this block adds none (article 13). If several rules apply, deny is stricter than suspend, which is stricter
than allow. If no rule applies, the decision is deny with the absent-policy
reason. Evaluation is pure and performs no I/O.

For each accepted question, the server validates the question, loads the
authority, evaluates it, appends the immutable decision, optionally issues a
grant, and only then answers. A store refuses a duplicate decision reference and
has no update operation. Reads always name a non-empty scope (articles 3 and 5).

## Published shapes

A decision records its contract generation, reference, scope, capability,
principal, arguments digest, outcome, reason, policy version, decision time,
correlation, applying rule reference, optional approval reference and optional
grant reference. A response may include the grant document; the immutable
decision record carries only its reference.

A grant contains:

- an opaque grant reference and the decision reference it caches;
- the policy version and issue time;
- its lifetime, expiry and heartbeat interval;
- closed conditions for scope, capability, principal and arguments digest.

A grant is issued only for allow and only on a connection that can carry its
signals; generation one defines no request member asking for one, so a boundary
that wants no grant carries no signal channel. Its lifetime is the shortest of
the rule, the configured default and the configured maximum. It becomes unusable when its connection is
lost, its lifetime expires, heartbeats are absent beyond that lifetime, the
policy version changes, or a condition differs (article 10).

Signals have a kind, grant reference, policy version and time. An ending signal
also has one of the published ending reasons. An ending signal is followed by
connection close. Capacity is reserved before a decision claims a grant; a full
registry still answers the decision with no grant.

Policy status reports the authority version and a projection summary. Projection
`in_step` has the values `yes`, `no` and `unknown`: equality with the authority
is `yes`, established inequality is `no`, and inability to inspect or rebuild is
`unknown` (article 2).

## Projections

The in-memory projection is always present; an optional database projection may
also be configured. A projection can be replaced only by a complete rebuild from
a loaded authority. It can be cleared and rebuilt from empty. It never serves a
decision and cannot silently become the authority (article 3).

Status combines all configured projections. It reports `yes` only when every
projection is established to match the authority, `no` when any projection is
established behind, and `unknown` when no projection is behind but at least one
cannot be inspected.

## Contract scenarios and conformance

Generation one publishes nine grant-related scenarios. Every such scenario
asserts whether a grant is present or absent. Scenarios covering a changed
policy also perform a second question and assert that the new decision is made
under the changed version. Scenario loading refuses every unknown member of
`given`, `ask`, `expect` and nested request members; it never ignores one
(article 13).

The server replays every scenario bound to the server or to both sides through
its real application service. The same report is compared with the standard
contract fake, and both reports must have no failures. This is the server's
acceptance claim under article 13.

The published conformance suites exercise positive and negative examples for
every port. In particular, the policy authority suite requires both a protected,
non-writable authority and an exposed, writable authority. An adapter returning
one fixed verdict for every path cannot pass (articles 2 and 8).

## Required guards

Tests hold the following properties:

- the generation-one request members are frozen and no scenario sends another;
- all generation-one grant scenarios make grant assertions;
- unknown scenario members are refused;
- the server and standard fake replay and agree on every server-bound scenario,
  and each scenario the server cannot yet run is recorded with its reason;
- negative adapters fail each published conformance suite;
- projection status contains an explicit unknown value;
- one failing signal writer does not prevent other connections being ended;
- status reflects every configured projection;
- contract documents are rendered by the published contract values;
- start-permission tests establish their permissions explicitly;
- database projections can be read safely from another thread;
- retryability comes from the published problem registry;
- public prose contains no non-public provenance shapes (article 14).

## Provenance

This specification is derived only from the rules and vocabulary published in
this repository. Articles 1, 2, 3, 5, 8, 10, 13, 14 and 15 are authoritative.
Code copied into this repository carries the generic provenance statement
required by article 14 and its Apache-2.0 copyright notice; this document does
not identify any non-public source.
