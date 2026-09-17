<!-- SPDX-License-Identifier: Apache-2.0 -->
# Exception register

Article 0 keeps this register for a property relaxed for a named surface, for a
stated reason, with compensating evidence and a restoration condition. An
exception without a way back is an amendment and is treated as one, through the
procedure of article 16. Nothing here makes an unknown input more permissive
(article 3).

An entry whose restoration condition has been met is **closed here rather than
deleted**: it keeps its number, says on what date it closed and by what
mechanism, and drops the four parts a live relaxation carries, because it
relaxes nothing any more. A register that removed what it retired would stop
being a record of what was ever relaxed, and a reader meeting a citation of an
entry number would find nothing where the relaxation had been.

## 1 — The policy authority surface carries no `scope`

**Article relaxed.** Article 5: "scope is a field of every port that carries a
record and of every persisted structure."

**Named surface.** `LoadedPolicy`, `ProjectedPolicy`, `PolicyStore.load`,
`PolicyProjection.rebuild` and `PolicyProjection.current`, and no other port
operation or structure. `Decision`, `DecisionStore.append` and
`DecisionStore.get` carry `scope` and are not covered.

**Stated reason.** the policy authority is one administrator-owned file whose rules each carry their own scope, so no single scope is true of the file, of a load of it, or of a rebuild from it; making the read per-scope would make the published policy status scope-dependent, which needs a request member generation one does not define and so opens contract generation two.

**Compensating evidence.** Every rule of the authority carries its own `scope`,
matched exactly with no wildcard, so the partition article 5 asks for holds
inside the file and is exercised by the evaluation tests. The scope register in
`architecture/scope.py` names each exempt operation and structure one by one,
and the architecture test enumerates the ports and the persisted structures and
fails on one that is neither scoped nor named here — including one added later.
The decision authority, which is the governed record this block writes, carries
`scope` on the structure and on the read, and its store refuses a read that
names none.

**Restoration condition.** The exception ends when the policy authority is read
per scope. That makes the policy status answer scope-dependent, which needs a
request member contract generation one does not define, so it lands with the
generation that opens — at the latest with the block that opens generation two —
and this entry is removed in the same change.

## 3 — The policy archive carries no `scope`

**Article relaxed.** Article 5: "scope is a field of every port that carries a
record and of every persisted structure."

**Named surface.** `ArchivedPolicy`, `PolicyArchive.keep` and
`PolicyArchive.read`, and the content files the file adapter keeps under the
evidence root, one per policy version, named by the digest of their bytes.
`PolicyArchive.location` carries no record. Nothing of entry 1 is extended by
this entry: entry 1 concerns reads of the live policy authority, and this one
concerns the historical bytes a decision names.

**Stated reason.** the archive keeps the exact bytes of the one administrator-owned policy file under the digest a decision names, and no single scope is true of those bytes; a scoped archive needs scope-addressed policy versions, which generation one does not define, and the legacy whole-file blobs are retained under this exception until every decision and chain segment naming them has been retired with declared loss

**Compensating evidence.** A version is addressed by content and by nothing
else, so an archive read selects nothing by scope and partitions nothing: the
decision that names a version carries its own `scope`, and the export that
attaches the bytes is read per scope. The scope register in
`architecture/scope.py` names each exempt operation and structure one by one,
and the architecture test fails on one that is neither scoped nor named here.
The deployment documentation discloses what the exception costs: every
principal admitted to export a scope receives the whole policy file of every
version an included effect names.

**Restoration condition.** The exception ends when policy versions become
scope-addressed. From that generation on, new decisions name scoped versions
and use a scoped archive; the legacy whole-file blobs are retained under this
entry until every decision and every chain segment that names one has been
explicitly retired with a declared loss, then removed with this entry in the
same change. The condition is reviewed when that generation opens; an
inability to keep this way back is an amendment under article 16, never an
indefinite waiver.

## 4 — Closed on 2026-09-16: the configuration file's effective access in system mode

**Closed, not renewed.** This entry relaxed article 8's two protections of the
configuration in system mode — "at start, the daemon refuses a configuration
that anyone but root or its administrator group could write or replace; per
connection, it refuses a decision request from a principal with effective write
access to the configuration or to a directory that would let it be replaced" —
because no code implemented them: `load_settings()` read the configuration as
TOML and kept no path, so neither the start path nor the decision path had a
file to check, and both checks that did run read the policy authority, which is
a different file. The entry is kept here, closed, rather than deleted, because
a register that drops what it retired stops being a record of what was relaxed.

**The mechanism that closed it.** Exactly the three things article 8 named as
its own way back, and nothing else.

- `Settings` carries `configuration_path`, the name `load_settings()` opened,
  made absolute against the working directory and never normalised — `normpath`
  collapses `link/..` before any component is looked at, and the component a
  `..` pops decides which file the name reaches. A deployment started without
  `--config` read no file and carries `""`, and nothing is claimed about a
  configuration nothing read (article 2).
- `bootstrap.compose` applies at start the effective-access check the policy
  authority already receives, through a `FileConfiguration` adapter beside the
  policy store's, which hands the configured name to the same walk in
  `access/effective_access.py` and holds no reading of its own. It is applied
  before anything else the start
  could refuse over, including the early return for a deployment that named no
  policy authority: whoever can write the configuration chooses the address,
  the admission group, which file is the policy authority, where the evidence
  is kept and which plugins are composed, so a start that checked those and not
  this one checked whatever the writer chose. An `unknown` verdict refuses like
  an exposed one (article 3). The refusal is `configuration_unprotected`,
  naming the file, the component that decided it, the rule that decided it and
  the account that looked.
- `DecisionService` applies the same walk per decision request, beside the
  policy check and after it, under a code of its own:
  `configuration_writable_by_principal`, article 8, class `refused`, not
  retryable, additive within contract generation one. Two facts, two codes: an
  operator told only that a principal "could write the policy" would not learn
  that what it could write was the file that chooses which file the policy is.
  The principal crosses to the check as the two integers the question is about
  rather than as a structure, so nothing of the core is handed out (article 3).

**What holds it.**
`packages/control-plane/tests/integration/test_configuration_access.py` holds
the walk applied to the configured name — protected, exposed at a stranger's
write, exposed at a directory the file could be replaced through, and giving
the same verdict as the policy authority's own adapter for the same name — and
holds both wirings: the start refusing under its own name before anything else
it could refuse over, and the decision path refusing the writer, refusing the
principal that could replace the file through its directory, and serving
everyone else. Three guards no ordinary runner can hold run in the root
container, because `assemble()` refuses system mode below uid 0 and the
expectation the start applies admits root as the only owner:
`test_a_configuration_a_stranger_can_write_refuses_the_start_by_name`,
`test_a_configuration_only_root_and_the_administrator_group_can_write_starts`
and
`test_a_program_run_as_the_administrator_group_obtains_no_decision_but_is_admitted`,
the last of which also holds the other half of the article's sentence — the
administrative commands of that principal are served and graded.
`packages/control-plane/tests/identity/test_platform_coverage.py` holds the
three against the workflow leg that owes them, so a guard that stopped running
is a failure and not a silence.

**What changed with it.** `SECURITY.md` and `docs/deployment.md` no longer tell
an operator that they have ordinary filesystem permissions and nothing else;
each now says what the daemon refuses, and both consequences of the article —
that a governed program must run as another principal, and that a program run
as root, or run as the administrator group, obtains no decision in system mode,
since a configuration group-writable by that group starts and that group is
exactly who the article allows to write it. What the per-request check reads is
the group the program **runs as**, the one its peer credential carries; a
principal admitted through a named supplementary membership is not refused by
it, as it is not by the policy authority's own per-connection check, so the
file's permissions and not this refusal are what protect the file. Article 8's
Guard names the mechanism in place of its admission. The new code is announced
in `CHANGELOG.md`.
