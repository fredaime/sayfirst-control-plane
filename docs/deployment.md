<!-- SPDX-License-Identifier: Apache-2.0 -->
# Deploying the daemon

The daemon listens on one Unix domain socket and nowhere else. Everything
below follows from that one fact, and from what the operating system means by
a peer credential.

## The two deployment modes

| | per-user | system |
|---|---|---|
| Who it serves | one account: the one it runs as | several accounts, admitted by a group |
| Default address | `$XDG_RUNTIME_DIR/sayfirst/daemon.sock`, or `~/.sayfirst/run/daemon.sock` | `/run/sayfirst/daemon.sock` (Linux), `/var/run/sayfirst/daemon.sock` (macOS) |
| Socket file | `0700`, owned by the daemon's account | `0660`, owned by `root`, group `socket.group` |
| Who creates the parent directory | the daemon, every level it creates at `0700` | the packager or the administrator, never the daemon |
| Admission | that one account. Root is refused too | uid 0, the account the daemon runs as, and the socket group |

The socket file's permissions are the admission list. The kernel enforces
them when a peer calls `connect()`; the daemon restates the same list from the
credential and the account directory, so the evidence says who was admitted
and on what basis, and so a revocation takes effect within the identity's
lifetime rather than at the peer's next login.

A per-user daemon refuses `socket.group`, `socket.run_as` and
`[identity.accounts]`: it has one principal and no admission group, and a
configuration that pretends otherwise is a mode confusion.

In system mode the group must exist and must not be a group the host gives
every account by default. The refused names are `users`, `staff`, `everyone`,
`nogroup` and `nobody`. An administrator who wants one of them as the
admission list edits the constant in the daemon and owns the consequence: an
admission list that admits everyone is a loopback port with extra steps.

The daemon refuses to start if anyone but its own account or root can write
the directory that holds the socket — group-writable included, and including
an ancestor a stranger could rename away. Whoever can write that directory
can unlink the name and bind an impostor in its place. The same rule binds
what the daemon itself creates: a per-user daemon creates every level of its
parent directory at `0700`, whatever the umask it inherited, because a level
it created and the check refuses is a daemon that cannot start until a human
repairs it by hand.

## Deployment forms

### Bare host

The daemon runs as a service of the host; callers are local processes of that
same host, and nothing else is consulted. Even here the rule that governs the
other two forms applies the moment anything shares the address: a socket
mounted into a container imports the host's meaning of identity: the uids the
daemon sees are the host kernel's, a container's uid that the host maps is
admitted as that host uid, and one it does not map is refused as unmapped.

### Sidecar sharing the socket's volume

The daemon runs beside the governed program and they share the volume that
holds the socket. A socket mounted into a container imports the host's
meaning of identity: the uids the daemon sees are the host kernel's, a
container's uid that the host maps is admitted as that host uid, and one it
does not map is refused as unmapped. Run the sidecar and the governed program
under the same user namespace, or map their uids explicitly, and set
`socket.group` to a group both hold.

### Node agent with the socket on a host path

One daemon per node, its socket on a host directory mounted read-write into
the pods that may reach it. A socket mounted into a container imports the
host's meaning of identity: the uids the daemon sees are the host kernel's, a
container's uid that the host maps is admitted as that host uid, and one it
does not map is refused as unmapped. A pod's `runAsUser` is therefore
admitted as the host uid the node maps it to, and refused when the node maps
it to nothing. The host directory must satisfy the
same protection rule as any other: nobody but root or the daemon's account
may write it.

## The tooling cost

No browser reaches the socket, and no HTTP debugging tool that only speaks to
a URL does either. An ad-hoc client uses:

```
curl --unix-socket /run/sayfirst/daemon.sock http://sayfirst/whoami
```

The host in that URL is a placeholder; the daemon ignores it. The operator
surface does the same thing and verifies the server first:

```
sayfirstd whoami --socket /run/sayfirst/daemon.sock --mode system --daemon-user sayfirst
```

What the daemon says about itself — the integrity grade, its basis, the
interval it is re-evaluated on, and the active privacy provider — is read the
same way:

```
sayfirstd status --socket /run/sayfirst/daemon.sock --mode system --daemon-user sayfirst
```

`sayfirstd` is this repository's one operator binary — the commands that inspect
the daemon: `whoami`, `status`, `plugins list`, `conformance replay`. The
account the daemon runs as is `sayfirst` here only as an example; it is a Unix
account name and nothing reads it as a command.

A remote operator forwards the socket over SSH and arrives with their own
identity on the remote host:

```
ssh -L /tmp/remote-daemon.sock:/run/sayfirst/daemon.sock operator@host
```

This is an accepted cost, not a limitation to fix. A transport reachable by a
browser is a transport with no peer identity, and identity is the whole point
of this boundary.

## What ends a connection

One connection carries as many requests as the caller wants to put on it, with
one exception. A decision asked for over the event stream is answered on a
connection that becomes the grant's channel: article 10 binds a grant to the
channel that carried it, so the answer publishes `Connection: close`, the
daemon shuts its write side down when the stream ends, and nothing else may be
asked there. Every other answer — the two document reads, the approval pair,
the evidence reads, an ask whose request did not select the stream, and every
refusal — leaves the connection open for the next request.

This matters to a caller because the client verifies the server's peer
credential at connect and never re-opens an address by itself: a connection
the daemon closes costs the caller a connect and a second verification, and
the caller has to ask for it. So a tool that reads a decision and then the
policy status makes one connection, not two. An earlier version closed after
every answer the decision surface wrote, which is why the project's own client
carries `reconnect()` and documents when it is needed.

`curl --unix-socket` reuses one connection across several URLs in the same
invocation, and that works here for everything but the stream.

## The revocation latency

Group membership is resolved when a connection is accepted and re-resolved
when its lifetime expires, on the live connection.

> a group membership revoked in the directory takes effect on a live
> connection within `group_lifetime_seconds` (default 60 seconds), plus the
> host's name-service cache, which this daemon neither controls nor observes

Beside it: a grant already issued lasts its own lifetime (article 10).

`identity.group_lifetime_seconds` accepts 1 to 3600. A lower value bounds
revocation more tightly at the cost of one directory lookup per connection
per period; a host with a slow name service raises it and accepts the longer
latency. `identity.resolution_timeout_seconds` (1 to 60, default 5) bounds one
lookup; a lookup that exceeds it makes the connection's identity `unknown`,
and every request that needs a principal is answered as retryable until a
later attempt succeeds. An unknown identity is never served a decision.

## Group names

Group names are recorded exactly as the directory returns them: no case
folding, no trimming, no domain stripping.

> Policies bind group names; canonicalising them across directory services is
> the administrator's responsibility.

## What a peer credential means

The credential is the kernel's record of the process that called `connect()`,
captured before the daemon reads a byte of the connection.

- **Passing the connected file descriptor to another process does not change
  it.** The credential stays that of the process that connected. This is the
  operating system's meaning of identity, which this daemon adopts and does
  not second-guess.
- **Under a privilege tool, the principal is the account the tool switched
  to.** A process running under `sudo` connects as root, and root is the
  principal. Who invoked the tool travels as a declared delegation beside the
  principal in evidence: declared by the peer, not verified by the daemon,
  and never collapsed into the principal.
- **A process id is shown for diagnosis and decides nothing.** It is on the
  peer record and in connection evidence; it is not on the principal, it is
  not a parameter of admission, and no policy can name it. A pid the kernel
  does not report is `null`, never `0`.
- **An unmapped user id is refused.** A credential whose uid or gid is the
  kernel's overflow id comes from a user namespace this host does not map. It
  is refused, the account directory is never asked about it, and it is never
  mapped to `nobody`.

## macOS

Two differences, both stated rather than hidden.

- **Access control lists on the socket's directory are not checked.** No
  reader for them exists in the standard library on that platform. The start
  line of a daemon there says `acl: not checked on this platform`, and the
  directory's mode and ownership are checked as everywhere else. The
  restoration condition is an ACL reader for macOS.
- **The overflow-id rule is vacuous there.** macOS has no user namespaces and
  no overflow ids, so nothing is read at start and no credential is ever
  refused as unmapped.

## Ownership after the drop

A system daemon starts as root and drops to `run_as`. Everything the daemon
must be able to do for the rest of its life, it must be able to do as that
account, and the daemon checks so *as that account*: the policy authority is
read, and the evidence store is opened and first written, after the drop and
before the daemon listens. A deployment the dropped account cannot use is
refused at start, by name, rather than started and left answering every ask
as unavailable.

| | per-user | system |
|---|---|---|
| `[policy] path` | readable by the daemon's account; writable by nobody else | owned by `root`, readable by `run_as` through a group it is a member of: `root:sayfirst 0640`; writable by no group but root's or `socket.group` |
| `[evidence] path`, the directory | the daemon creates it, every level at `0700` | the packager or the administrator creates it, owned by `run_as` and its own group at `0700`; never the daemon |
| the chain files inside it | the daemon's, created at `0600` | the daemon's, created after the drop as `run_as`, at `0600` |
| `decisions/` and `policy/` inside it | the daemon creates them at `0700`, their files at `0600` | the daemon creates them after the drop as `run_as`, at `0700`, their files at `0600` |
| checked as | the daemon's account | `run_as`, once dropped |

The evidence root follows the same rule as the socket's parent directory: in
system mode the packager creates the directory and the daemon creates the
files inside it. A daemon that created the directory itself would create it as
root, before the drop, and be unable to write into it after; so it does not,
and refuses `evidence_root_unusable` naming the directory and the account it
must belong to. The daemon never changes the owner or the mode of the policy
file.

The daemon reads that layout as the account it dropped to, and reads it
literally: the owner is `run_as`, the group is `run_as`'s own, the mode is
`0700`, and no access control list widens it. What decides the refusal is what
other principals can effectively do with the directory, not who owns it: a root
the governed principal owns, a root every account can write, and a root
carrying the admission group with the setgid bit — which hands every chain file
created in it to that group — are each refused `evidence_root_unusable`,
naming the directory, what was found, and the account and group it must belong
to. The parents are read by the same walk as the socket directory's, because
whoever can write a parent can rename the store away and put another at its
path: a correctly owned root under a parent anyone or a group can write, and
that is not sticky, is refused naming that parent. A parent the dropped
account cannot traverse is refused under the same reason, naming the fact that
access could not be established, and never as a traceback.

Before it listens the daemon also proves the store it will keep every chain
in, and says no more than that. The scope of a decision is the caller's field,
not the policy's: a request may name a scope no rule reaches, is answered with
a deny, and is owed a record on that scope's chain. So no start check can
enumerate the chains the daemon will be owed a record on, and none claims to.
What the start proves is the directory and what is in it. The layout above is
what lets the dropped account create a chain for any scope; every chain
already in the root — whatever scope it belongs to, named by a rule or not —
is reopened for append, and one the account cannot append to, an existing
`audit.jsonl` root owns whether or not any rule names `audit`, refuses the
start naming the file and the scope; the chain of every scope the policy's
rules name is created at start as well, at `0600` — a mode held whatever the
umask — so a root at `0500` with no `audit.jsonl` yet is refused before any
decision is served. A chain for a scope with no chain yet is created on first
use, as `run_as`, at `0600`, under the same rule, and the decision is on it.
None of these permissions repairs itself, so none is left to a later retry.

The daemon drops to `run_as`'s own group, with the memberships the directory
records for that account, and never takes `socket.group` — the admission list
— as its own. A `run_as` that is not a member of the admission group has no
access through that group, to a policy file whose group is the admission list
included; give the policy file a group `run_as` really belongs to, its own
being the simplest.

Laid out on a bare host, with `sayfirst` as `run_as` and `sayfirst-operators`
as the admission group:

```
install -d -m 0755 -o root -g root /run/sayfirst
install -m 0640 -o root -g sayfirst policy.toml /etc/sayfirst/policy.toml
install -d -m 0700 -o sayfirst -g sayfirst /var/lib/sayfirst/evidence
```

A policy file copied into place as root can arrive `root:root 0600` — the
mode of a source the operator kept private, or of any source copied under a
umask of `077` — which root can read and `sayfirst` cannot; the daemon
refuses it at start with `policy_unavailable_at_start`, naming the path and
the account that could not read it.

## What survives a restart, and who may read it

Beside the chains, the evidence root holds two more stores the daemon creates
as its own account. `decisions/<scope>.jsonl` is the durable decision
authority: one append-only file per scope, a header naming the scope's opaque
store identifier, then one envelope per committed decision with its position
and the complete published record. A decision is answered only after its
envelope is written and synced, so a daemon that restarts reads back every
decision it answered — outcome, reason, rule, arguments digest, correlation
and who supplied it, the principal references the evaluation read and the
recipe it was taken under — from this file and never from the chain. A torn
final line, the trace of a process that died mid-append, is quarantined at the
next start and its byte count noted; a malformed complete line or two records
of one identity make that scope unavailable for new decisions and for reads
(`decision_store_unavailable`), while every other scope keeps serving; the
status result carries it as a reconciliation `not_run` with every count null,
because a store that cannot be read is no evidence that a decision is missing.
Two daemons over one root are refused: the second exits `decision_store_unusable`.

`policy/<hex>.toml` is the archive of every policy version a decision has
named: the exact bytes the authority read, under the SHA-256 of those bytes,
written once and never rewritten. The version the daemon starts on is archived
before it listens, and every version it decides on later is archived before
the first decision on it; a version that cannot be kept refuses the question
with `policy_archive_unavailable`, a could-not-ask, never a denial. Bytes that
no longer hash to their name are reported `damaged` and never overwritten or
evaluated; the current policy file never stands in for them. The archive is
addressed by content and carries no scope, under entry 3 of
`docs/exceptions.md`.

Retention of all three — chains, decisions, archive — is indefinite: nothing
expires, and this version has no purge command. A backup takes the whole
evidence root together and a restore puts the whole of it back, because a
decision names a policy version and an effect names a decision position, and a
partial restore is a declared discrepancy at the next start, not a repair. A
file removed by hand is disclosed — as `absent` in an export, as a missing
authority in the status result — and is never recreated from another copy.

**Who may export.** Every principal the socket admits may read and export any
scope it names; there is no read authorisation in this version, and scope
partitions selection, not confidentiality. An export attaches, for every
policy version an included effect names, the whole administrator policy file
of that version — every rule, reason and principal name it holds, for every
scope. A system daemon must therefore admit only readers entitled to that
complete history. This version has no configuration that suppresses the
attachments: leaving them out would remove a published response member, and
refusing them per caller is a read-authorisation model this version does not
have. The remedies are compositional — run a per-user daemon rather than a
system one, or restrict the admission group to principals entitled to the
whole history — or declining to deploy this version where neither is
acceptable.

**Who may resolve a suspended effect.** Every principal the socket admits may
resolve any wait in any scope, and read any wait it names. The simple form of
approvals is one person approving or rejecting; who that person may be is a
designation, which is an organisational object this version does not hold and
does not pretend to. So the daemon takes who acted from the connection — its
verified principal, never a member of the request — and checks nothing about
them, and `read_approval` lets any admitted principal see that a wait exists,
which decision it suspends and which capability it is for.

Where that person is kept is worth stating plainly, because it is both more and
less than an operator would assume. The person is on the approval record, for as
long as the store keeps that record, and `read_approval` renders it: the
published `approval-result` carries a `person` member on a wait somebody
approved or rejected, and no such member at all on one nobody acted on. The
`approval.resolved` entry that also names the person goes to the events sink
this version composes, which is bounded at 1024 entries — it keeps the most
recent in memory, discards the oldest past that bound and counts what it
discarded, and a restart loses all of it. That sink is an observation and not
a record: no operation of this generation serves it, so it is read where the
daemon runs and
nowhere else. And the durable record of the act is the resumed decision on the
chain, which carries the approval's reference and not the person. A deployment
that must attribute an act to a named person an hour later gets that from
`read_approval` for as long as the store keeps the wait, and from nothing this
version writes down.

A system daemon must therefore admit only principals entitled to approve
whatever any of its callers may suspend. The remedies are the two of "Who may
export" — a per-user daemon rather than a system one, or an admission group
restricted to principals entitled to that authority — plus the third that
belongs to this one: an approval provider of your own behind the port, which is
where designation and a second signature live (article 12).

**What a restart loses.** The store a suspended approval waits in is in memory.
A restart therefore loses every pending wait: the reference a caller was told
to have answered is gone, `read_approval` on it says `approval_unknown`, and
the program's next ask suspends anew with a new reference — so a daemon
restarted during a review window silently re-asks every effect then waiting,
and a person who approves after it has restarted approves something nobody is
waiting on. A resolution that was already spent is not lost, because the
durable halves of an approval are decision records: the suspended decision and
the resumed one, both in `decisions/<scope>.jsonl` above. Plan restarts around
open reviews, or expect the reviews to be asked again.

A restart is also the only thing that clears one kind of record, and that one
is a limit rather than a loss: an approved approval nobody spends is kept for
the life of the process. The sweep forgets a wait that ran
out, a rejection and a spent approval, but not that one — only the execution it
authorises being taken removes it, because discarding it at a deadline would
throw away a person's act and ask another human for an effect already approved.
So a deployment whose approved effects are never re-asked — a job that suspended,
was approved and was then cancelled — accumulates one record per act, bounded by
nothing but the process lifetime. Size for it, or arrange that approved waits are
spent.

**Grades.** A caller who can write the decision file, the archive or any of
their parents can forge what the chain would then confirm, so the grade a
connection carries inspects all three stores, their parents and their actual
files, and a caller who can write any of them is at observability grade.

## Starting the daemon

The daemon is started by the server distribution's own console script, which is
a different binary from the operator surface above:

```
sayfirst-daemon serve --config /etc/sayfirst/daemon.toml
```

```toml
# SPDX-License-Identifier: Apache-2.0
[socket]
mode = "system"
path = "/run/sayfirst/daemon.sock"
group = "sayfirst-operators"
run_as = "sayfirst"

[policy]
path = "/etc/sayfirst/policy.toml"

[evidence]
path = "/var/lib/sayfirst/evidence"

[identity]
group_lifetime_seconds = 60
resolution_timeout_seconds = 5

[identity.accounts]
"svc-build" = { kind = "service" }
```

In system mode the daemon checks who can write this configuration file, and
refuses to start when the answer is anyone but `root` or the group named by
`socket.group`. What is read is effective access along the whole name — the mode
bits, the access control lists, and every parent directory that would let the
file be replaced — and never who owns it alone: `configuration_unprotected`
names the file, the component that decided it and the rule that decided it, and
exits 78 before the daemon listens. The same check is made again, per decision
request, against the principal asking: a principal with effective write access
to the configuration, or to a directory it could be replaced through, is
answered `403 configuration_writable_by_principal` and obtains no decision,
while its administrative commands are served and graded as any other
connection's. So lay the file out owned by `root`, mode `0640` or `0644`, under
a directory no other account can write — because whoever can write it chooses
the address the daemon binds, the group admitted to it, which file is the
policy authority, where the evidence is kept and which plugins are composed.

**The account the daemon drops to must be able to look at the file and every
directory above it.** The walk runs after the privilege drop, as `run_as`, so an
answer that account cannot obtain is not an answer: a component it cannot `stat`
is an unknown, and an unknown refuses the start rather than passing as safe. A
configuration under a `0700 root:root` directory is therefore refused too — not
because it is exposed but because the daemon cannot establish that it is not,
and the refusal names the component it could not look at and the account that
could not look. `0755` on the directories above and `0640` on the file is the
layout that satisfies both halves.

One consequence follows, and it is deliberate. A program run as `root`, or run
as the group named by `socket.group`, obtains no decision in system mode: root
can write every file there is, and a configuration group-writable by
`socket.group` starts — that group is exactly who article 8 allows to write it —
so a program running as it can rewrite its own configuration. A governed program
must therefore run as some other principal. Mode `0640` is the layout that
admits a group to the socket without making a program run as that group a
configuration writer.

What the per-request check reads is the group the program **runs as**, which is
the group its peer credential carries. A principal admitted through a *named
supplementary* membership is not refused by this check even where that
membership grants it write access to the file — the principal a decision is
evaluated against carries the credential's own group and the group ids the
directory could not name, and nothing else — and the same is true of the policy
authority's own per-connection check. Do not read the refusal as a substitute
for the file's permissions: the permissions are what protect it, and the check
is what stops the daemon from deciding for a principal it can see holds them.

The check is skipped in per-user mode, where the configuration and the daemon
belong to one account and the rule has nothing to separate, and there is no
file to check at all when the daemon was started without `--config`.

`[identity.accounts]` maps an account name to the kind recorded for it. It
changes the recorded kind and the principal's reference, and nothing in
admission or in policy. Every name in it is looked up when the daemon starts:
one absent from the directory then is written to the start log — after the
line that says the daemon is serving — and refuses nothing, because a name
the host does not have yet decides nothing either.

A system daemon binds as root, sets the socket's owner and group, drops to
`run_as` with the irreversible calls, composes the policy authority and the
evidence store as that account, and only then listens — so the credential a
client reads at connect is the daemon's running principal, which is what the
client verifies, and what the daemon proved it could read and write it proved
as the account that will.

A daemon that cannot hold one of these rules does not start with fewer of
them: it writes one reason on standard error and exits 78. The reasons are
`socket_directory_unprotected`, `socket_directory_missing`,
`socket_mode_invalid`, `socket_path_too_long`, `socket_path_not_absolute`,
`socket_in_use`, `socket_group_unknown`, `socket_group_is_everyone`,
`socket_not_unix`, `socket_abstract_or_unnamed`, `run_as_unknown`,
`run_as_requires_root`, `peer_identity_unsupported`, `overflow_id_unreadable`,
`mode_invalid`, `group_lifetime_out_of_bounds`, `configuration_unreadable`,
`configuration_unprotected`,
`socket_address_denied`, `socket_permissions_denied`,
`privileges_not_dropped`, `policy_unavailable_at_start`,
`evidence_root_unusable`, `plugin_composition_refused`,
`decision_store_unusable`, `policy_archive_unusable` and
`recovery_store_unusable`.

Four of these name a call the host itself refused rather than something the
configuration asked for: a configuration file that could not be read or parsed,
a `bind` or `listen` the kernel would not perform, a `chown` or `chmod` that
could not install the socket's owner and mode, and a privilege drop that did
not happen. One names the configuration file itself: in system mode, one an
account other than `root` or `socket.group` could write or replace, which is
refused before the daemon listens because whoever can write that file chooses
every other file the start then checks. The last three name what the composition
refused: a policy
authority that could not be read by the account the daemon runs as or is not
protected where it stands, an evidence root the daemon cannot keep a chain in
— absent in system mode, where the packager creates it; not laid out as the
packager owes it; under a parent the dropped account cannot look through, or
one another principal could rename it away through; or holding a chain that
account cannot create or append to — and a plugin
composition that could not be resolved. The final three name a durable
authority the daemon could not prove usable after the drop and before
listening: a decision root another daemon holds, or holding a scope file this
account cannot recover; a policy archive that cannot keep the exact bytes of
the policy the daemon starts on; and a recovery journal this account cannot
read or append. Each is a storage or protection failure; a
historical discrepancy between the decision authority and the chain is
reported in the status result and refuses no start. A daemon that cannot
decide, cannot
record, or does not know what it composed serves nobody. Each is still one
reason on standard error and still exit 78 — a daemon that cannot say what
stopped it is a daemon that stopped for no published reason.
