<!-- SPDX-License-Identifier: Apache-2.0 -->
---
kind: spec
status: draft
date: 2026-09-04
block: "2.2"
title: Walking skeleton, block 2.2 — host scope, socket and identity (article 6)
---

# Block 2.2 — host scope, socket and identity

> **Note, 2026-09-05.** Where this document writes `sayfirst whoami`, that is what the
> command was when the design was approved on 2026-09-04. On 2026-09-05 the
> operator settled a collision between two repositories: `sayfirst` — the
> distribution `sayfirst-cli`, the import package `sayfirst_cli` and the console
> script `sayfirst` — belongs to the product command-line interface, and the
> operator surface that inspects this repository's daemon is `sayfirstd` in all
> three forms. Nothing else in this design changes. The sentences below are left
> as they were written, because a design note records the decision of its own
> date.

## Purpose

This block is the transport and the identity of the daemon: the one Unix
domain socket it listens on, the peer credential captured when a connection
is accepted, the principal built from that credential, the admission rule of
each deployment mode, the protection of the socket's directory, the client's
verification of the server, and `sayfirst whoami`. It implements article 6
in full and nothing of any other article beyond what article 6 obliges it to
hand over: the principal that article 11 puts in every evidence record, the
connection on which article 7 computes a grade and article 10 issues grants,
and the uid and groups from which article 8's per-connection configuration
check is computed. It is new code: the private control plane this project
was extracted from carried no socket transport and no peer-credential
identity, so this block copies one domain module and rewrites everything
else. The article's own words are the acceptance criteria — "a Unix domain
socket, and only there", "peer credentials are captured at `accept()`", "a
process id is diagnostic and never decisional", "an unmapped user id … is
refused" — and each rule below points back to the sentence it holds.

## Interfaces

### Distributions and packages

Two distributions of this repository take code from this block (article 13,
article 14):

| Distribution | Package | What this block puts there |
|---|---|---|
| `sayfirst-contract` | `sayfirst_contract.transport` | the socket transport of the one binding: the peer-credential readers (one per operating system), the `PeerCredential` value, the socket client that verifies the server before it sends a byte, and the `whoami` client operation. Both sides of the socket verify the other with the same code, which is why it lives in the distribution both may depend on and never in the server. |
| `sayfirst-control-plane` | `sayfirst_control_plane` | the domain (`Principal`, `Delegation`, the kind registry, the admission rule), the `PeerIdentity` and `AccountDirectory` ports, the socket server (bind, protect, accept, capture, bind identity to connection), the `whoami` operation on the served surface. |

The `transport` subpackage of the contract distribution is part of the
**transport binding**, not of the domain contract: block 2.1's guard that
holds the domain contract free of transport terms (article 13) is scoped to
the artefacts (schemas, scenarios, registries) and must exclude this
subpackage, exactly as it excludes the HTTP client that already lives beside
them. The subpackage imports the standard library only.

### Ports (server side; integer versions per article 8)

**`PeerIdentity` v1** — reads the operating system's record of the peer of a
connected `AF_UNIX` stream socket.

```python
class PeerIdentity(Protocol):
    """One adapter per operating system. `establish` is called on the
    accepted socket before the first byte of the connection is read."""
    VERSION: int = 1
    def establish(self, connection: socket.socket) -> PeerCredential: ...
        # raises PeerCredentialUnavailable when the OS does not deliver one
```

Adapters, both in `sayfirst_contract.transport.peer` and registered on the
server side as the port's implementations:

| Adapter | Platform (`sys.platform`) | Mechanism |
|---|---|---|
| `LinuxPeerIdentity` | `linux` | `getsockopt(SOL_SOCKET, SO_PEERCRED)` → `struct ucred {pid, uid, gid}` |
| `DarwinPeerIdentity` | `darwin` | `getsockopt(SOL_LOCAL=0, LOCAL_PEERCRED=1)` → `struct xucred` (uid, primary gid as `cr_groups[0]`); `getsockopt(SOL_LOCAL, LOCAL_PEERPID=2)` → pid. `xucred.cr_version` must be `0` (`XUCRED_VERSION`) or the credential is `PeerCredentialUnavailable`. `getpeereid(3)` is not used: it reads the same kernel record and would add a `ctypes` binding for nothing |

`select_peer_identity(platform: str) -> PeerIdentity` returns the adapter for
the platform and raises `PeerIdentityUnsupported` for any other value. There
is no generic adapter and no fallback.

**`AccountDirectory` v1** — resolves ids to names and memberships. It exists
so that group revocation can be tested without a directory service, and so
that the one blocking call this block makes (a name-service lookup) is behind
a seam with a timeout.

```python
class AccountDirectory(Protocol):
    VERSION: int = 1
    def account(self, uid: int) -> Account | None: ...        # name and primary gid, or None when the uid has no account
    def group_ids(self, name: str, primary_gid: int) -> tuple[int, ...]: ...  # every gid the account is a member of, primary included
    def group_name(self, gid: int) -> str | None: ...        # None when the gid has no group entry
```

Adapters: `NssAccountDirectory` (the real one: `pwd.getpwuid`,
`os.getgrouplist`, `grp.getgrgid` — the same name-service switch the host
uses for `login`), and, in the conformance kit `sayfirst.testing`,
`StaticAccountDirectory` (a scripted table, mutable between calls so a test
can revoke a membership). A `StaticPeerIdentity` (a scripted credential) is in
the kit for the same reason. Both are test doubles of the kit, never
providers activated by a configuration; the configuration cannot name them
(article 8: the kit is the contract of the port, not a provider of it).

The `Clock` port (v1, block 2.1/2.4) supplies every instant this block
records.

### Domain shapes

`PeerCredential` — what the kernel said. Immutable.

| Member | Type | Meaning |
|---|---|---|
| `uid` | int | effective user id of the process that called `connect()` |
| `gid` | int | its effective primary group id |
| `pid` | int or null | its process id as seen from the daemon's pid namespace; `null` when the kernel reports none (Linux reports `0` for a peer outside the daemon's pid namespace; `0` is rendered as `null`). **Diagnostic** (rule P4). |
| `captured_at` | instant | when `establish` returned |

`Principal` — the identity a decision is evaluated against and evidence
records. Immutable. **It has no `pid` member**; a `Principal` cannot carry
one (rule P4, guard `test_a_process_id_is_diagnostic_and_never_decisional`).

| Member | Type | Meaning |
|---|---|---|
| `kind` | string | from the open registry (rule K1); `user` for every principal this block establishes unless the configuration says otherwise (rule K3) |
| `uid` | int | the credential's uid |
| `gid` | int | the credential's primary gid |
| `name` | string or null | account name from the directory; `null` when the uid has no account |
| `groups` | list of string, or null | group **names** the directory resolved for the account, primary group included, order as returned, no normalisation (rule G6); `null` when `groups_status` is `unknown` |
| `groups_status` | `resolved` \| `partial` \| `unknown` | three values (article 2): `resolved` — every gid the directory listed has a name; `partial` — at least one gid had no name (those gids are absent from `groups` and listed in `unnamed_group_ids`); `unknown` — the directory could not be consulted |
| `unnamed_group_ids` | list of int | empty unless `partial` |
| `established_by` | string | open registry of establishment methods; this block produces exactly one value, `peer_credential` |
| `established_at` | instant | when this principal was resolved (first resolution or last re-resolution, rule G3) |
| `reference` | string | `"{kind}:{uid}"` — the opaque actor string write-side ports record; two kinds with one uid are two references |

`Delegation` — a declaration by the peer that it acts for someone else
(rule D1). An **observation** in the sense of article 3: recorded verbatim,
never verified, never decisional.

| Member | Type | Bound |
|---|---|---|
| `status` | string, open registry | this block produces `declared` only |
| `chain` | list of `DelegatedIdentity`, nearest first | 1 to 4 entries (`MAX_DELEGATION_DEPTH = 4`) |
| `DelegatedIdentity.kind` | string | registry of rule K1; ≤ 64 bytes |
| `DelegatedIdentity.name` | string or null | ≤ 256 bytes |
| `DelegatedIdentity.uid` | int or null | as declared |
| `DelegatedIdentity.via` | string | how the delegation happened: `privilege_tool`, `scheduler`, `build_runner` are documented; any other value ≤ 64 bytes is accepted and recorded as given |

`ConnectionIdentity` — the mutable per-connection state the transport holds
and every handler reads.

| Member | Type | Meaning |
|---|---|---|
| `connection_id` | string | opaque, unique per `accept()` within the daemon's lifetime (uuid4) |
| `accepted_at` | instant | |
| `socket_path` | string | the listening socket's path |
| `mode` | `per_user` \| `system` | the daemon's mode (rule M1) |
| `peer` | `PeerCredential` | |
| `status` | `established` \| `unknown` \| `refused` | three values: `established` — a `Principal` is bound; `unknown` — the credential was read but the directory could not be consulted, so no principal is bound yet (rule G5); `refused` — admission refused (rule A5), `refusal` names why |
| `principal` | `Principal` or null | null unless `established` |
| `refusal` | problem code or null | null unless `refused` |
| `resolved_at` | instant or null | when the directory was last consulted |
| `refresh_due_at` | instant or null | `resolved_at + group_lifetime` (rule G2) |

### Public identity vocabulary (the contract, block 2.1)

Block 2.1 owns the schemas; this block names what they contain. The shapes
below are members of the domain contract in generation 1, transport-free, and
byte-pinned like every other artefact.

`principal` (object) — as the table above, members `kind`, `uid`, `gid`,
`name`, `groups`, `groups_status`, `unnamed_group_ids`, `established_by`,
`established_at`, `reference`. `groups_status` is an enum with at least the
three values named and is read as `unknown` by a client that meets a fourth.
It appears in every evidence record that names an actor (block 2.4) and in
the `whoami` result.

`peer` (object) — `uid`, `gid`, `pid` (nullable), `captured_at`. Appears in
connection evidence and in `whoami`; never in a decision record, so that the
pid is structurally absent from the decisional shapes.

`delegation` (object, optional) — as the table above. An **optional request
member** of the decision request (block 2.3's shape, block 2.1's schema):
absent means "no delegation declared", which the daemon renders as
`delegation: null` and never as "no delegation". It appears in the decision's
evidence record beside `principal`, never inside it.

`whoami` (result object) — `generation` (block 2.1's marker), `connection_id`,
`socket_path`, `mode`, `peer`, `principal` (nullable), `status` (the
connection's, three values), `refresh_due_at` (nullable),
`group_lifetime_seconds` (int, the daemon's configured value), `delegation`
(always `null` here: `whoami` accepts no declaration).

`connection` evidence records (block 2.4 stores them, this block emits them):
`connection_opened` {`connection_id`, `accepted_at`, `socket_path`, `mode`,
`peer`, `status`, `principal`, `refusal`}, `principal_changed`
{`connection_id`, `at`, `before`: principal, `after`: principal},
`connection_closed` {`connection_id`, `at`}.

### Problem codes block 2.1 must provide

Exact names, public vocabulary, one fact each (article 2). The HTTP status is
the binding's business and is given here so the binding adds no meaning the
domain contract lacks.

| Code | Emitted by | Status | Retryable | Fact |
|---|---|---|---|---|
| `peer_not_admitted` | server | 403 | no | the peer's credential is not on this daemon's admission list (rule A2, A3) |
| `peer_uid_unmapped` | server | 403 | no | the kernel reported the overflow id: a uid from another user namespace with no mapping here (rule P5) |
| `peer_credential_unavailable` | server | 503 | yes | the operating system did not deliver a credential for the connection (rule P6) |
| `principal_groups_unavailable` | server | 503 | yes | the directory could not be consulted within the timeout; the connection's identity is `unknown` (rule G5) |
| `delegation_invalid` | server | 400 | no | the declared delegation breaks a bound of rule D3 |
| `server_not_the_daemon_principal` | client | — | no | the process listening at the socket path is not the daemon's principal; nothing was sent (rule C2) |
| `peer_identity_unsupported` | client | — | no | this platform has no peer-credential adapter; the client refuses to connect (rule C5). On the server the same condition is a start refusal (rule L6), not a problem document |

Client-side rendering (article 1: "denied" and "could not ask" are distinct;
the client block owns the exit codes, this block owns the classification):
`peer_not_admitted` and `peer_uid_unmapped` are **refusals** — the daemon was
asked and answered no; `peer_credential_unavailable`,
`principal_groups_unavailable`, `server_not_the_daemon_principal` and
`peer_identity_unsupported` are **could not ask** — no answer about the
effect exists, and the effect that has not started does not start.

Codes this block does **not** ask for, because the facts do not exist here:
`identity_rejected`, `verification_unavailable`, anything naming a token, a
session, a credential string or an issuer (article 6: "no tokens, no
sessions, no rotation").

### Daemon start refusals (not problem codes)

The daemon exits with status 78 (`EX_CONFIG`) and one of these reasons on
standard error, before it listens. They are an enumeration in the server
package, tested by name, and not part of the contract.

`socket_directory_unprotected`, `socket_directory_missing`,
`socket_mode_invalid`, `socket_path_too_long`, `socket_path_not_absolute`, `socket_in_use`,
`socket_group_unknown`, `socket_group_is_everyone` (rule S7),
`socket_not_unix` (rule L4), `socket_abstract_or_unnamed` (rule L4),
`run_as_unknown`, `run_as_requires_root`, `peer_identity_unsupported`,
`overflow_id_unreadable`, `mode_invalid`, `group_lifetime_out_of_bounds`.

### Configuration keys this block reads

Block 2.6 (or whichever block owns the configuration file) carries the file;
its protection is article 8's rule and not this block's. Keys, with defaults:

```toml
[socket]
mode = "per_user"                    # "per_user" | "system"; no default in system deployments' packaged config — the packager writes it
path = "<default of rule L2>"        # absolute
group = ""                           # system mode only: the admission group's name; required
run_as = ""                          # system mode only: account the daemon drops to after listen(); empty = stay root

[identity]
group_lifetime_seconds = 60          # bounds: 1 ≤ value ≤ 3600 (rule G2)
resolution_timeout_seconds = 5       # bounds: 1 ≤ value ≤ 60 (rule G5)

[identity.accounts]                  # system mode only; optional
# "svc-build" = { kind = "service" } # rule K3
```

### The client side (contract distribution)

```python
def connect(profile: SocketProfile, *, peer_identity: PeerIdentity | None = None) -> VerifiedConnection
    # opens the socket, reads the listener's credential, compares it with the profile's expected principal,
    # returns a connection on which no byte has yet been written; raises/returns the client problems above
class SocketProfile: socket_path: str; mode: "per_user" | "system"; daemon_user: str | None   # required when mode == "system"
def whoami(connection) -> WhoAmI
```

The profile of the client block records `socket_path`, `mode`, `daemon_user`
and the generation (block 2.1) in place of a URL and a token.

## Behaviour

Each rule names the article that binds it and is held by a named guard (see
Guards). "Refused" on the server side means: the connection is kept open,
its `status` becomes `refused` with the named code, the first HTTP request
on it is answered with that problem document, and the connection is then
closed by the server. A refused connection therefore always yields a problem
document, never a bare EOF, so a client can tell "refused" from "could not
ask" (article 1, article 2).

### L — listening (article 6: "a Unix domain socket, and only there")

- **L1.** The daemon creates exactly one listening socket, of family
  `AF_UNIX` and type `SOCK_STREAM`, bound to a filesystem path. Its whole
  served surface — decisions, evidence, `whoami`, health, every tooling
  endpoint of the binding — is HTTP/1.1 over that socket. There is no second
  socket for tooling.
- **L2.** Default path. Per-user mode: `$XDG_RUNTIME_DIR/sayfirst/daemon.sock`
  when `XDG_RUNTIME_DIR` is set and names an existing directory, otherwise
  `~/.sayfirst/run/daemon.sock`; the daemon creates the parent directory
  with mode `0700` if absent. System mode: `/run/sayfirst/daemon.sock`
  (Linux) or `/var/run/sayfirst/daemon.sock` (macOS); the parent
  directory is created by the packager or the administrator, never by the
  daemon (`socket_directory_missing` otherwise).
- **L2a. The evidence store and the policy authority, after the drop.** In
  system mode with `run_as`, every check `start()` makes before the drop is
  made as root, and root is refused nothing: a policy file read as root and a
  chain file created as root prove nothing about the account that reads and
  appends once the daemon has dropped. A check that proves something the drop
  invalidates is a claim outrunning its evidence (article 2), so:
  - *When.* The composition of the other blocks — the policy authority's
    start check and first load, the evidence root's opening and the first
    append (the composition record) — happens **after** the irreversible calls
    of M3 and **before** `listen()`, as the account the daemon runs as. A
    deployment its running account cannot compose never listens; the refusal
    is a start refusal like every other (exit 78, one reason, before
    `listen()`), never a daemon that reports healthy and answers every ask as
    retryable for the rest of its life. In per-user mode, and in system mode
    without `run_as`, the account is the same before and after the drop and
    the same order holds.
  - *The evidence root* (`evidence.path`). Per-user mode: the daemon creates
    it if absent, every level at `0700`, as its own account. System mode: the
    packager or the administrator creates it, owned by `run_as` and its own
    group at mode `0700`, never the daemon (`evidence_root_unusable`
    otherwise, naming the directory and the account it must belong to). The
    daemon reads that layout literally, as the dropped account — owner, group,
    mode, and no access control list widening it — because what other
    principals can effectively do with the directory, not the owner alone,
    decides the article 7 claim. The parents are held to rule S4's walk, the
    one the socket directory has — one rule, two callers — because article 7
    grades the store by "every parent directory that would allow it to be
    replaced": a correctly owned root under a parent anyone or a group can
    write, and that is not sticky, is refused naming that parent; a parent
    that account cannot traverse is refused under the same reason, naming
    that access could not be established, never as a traceback. The chain
    files inside it are the daemon's: created by the daemon, after the drop,
    as its own account, at `0600` — a mode held against the umask, not asked
    of it. Before `listen()` the daemon proves the store and what is in it,
    and claims no more: the scope is the caller's field, not the policy's — a
    request may name a scope no rule reaches, is answered with a deny, and is
    owed a record on that scope's chain — so no start check can enumerate the
    chains a decision will be owed to, and the daemon does not say it has.
    The layout above is what lets the dropped account create a chain for any
    scope; every chain already in the root, whatever its scope and whether or
    not a rule names it, is reopened for append, and one the account cannot
    append to refuses the start naming the file and the scope; the chains of
    the scopes the current policy's rules name are created at start as well.
    A chain for a scope with no chain yet is created on first use, as the
    daemon's own account, at `0600`, under the same rule. None of these
    permissions repairs itself and a later retry would find them unchanged.
    Article 7 decides the ownership: at
    evidence grade "the daemon runs under its own user id and no principal but
    that one and root can write or replace the store", and a chain file root
    created inside a directory the packager had laid out correctly was one the
    dropped daemon could not append to.
  - *The policy authority* (`policy.path`). The daemon assumes nothing about
    the file's readability after the drop. Its protection is checked and it is
    first read by the account the daemon runs as, once dropped; a file that
    account cannot read is `policy_unavailable_at_start`, naming the path, the
    fact (`unreadable`) and the account that looked (article 3: the start
    refusals name what stopped the daemon, and an unknown is never rendered
    as a pass). The daemon never changes the file's owner or mode (article 8:
    the configuration is the administrator's). The layout that satisfies it:
    owned by root, readable by `run_as` through a group that account is a
    member of (`root:<run_as's group> 0640`), and writable by no group but
    root's or the admission group (article 8's start check refuses any other).
  - *The group after the drop.* The daemon drops to `run_as`'s own primary
    group, with the memberships the directory records for that account, and
    never takes the admission group as its own (article 7). A `run_as` that
    is not a member of the admission group has no access through that group,
    to the policy file included.
  - *An address left behind.* A start refused after the drop cannot always
    unlink the socket it bound, because the parent directory is root's; the
    next start clears it under L7.
- **L3.** The daemon offers no way to listen on TCP: its command line has no
  `--host` or `--port`, its configuration has no such key, and the server
  package constructs no socket of a family other than `AF_UNIX`. Loopback is
  not an exception (article 6 names it).
- **L4.** A socket that is not `AF_UNIX`, or whose bound name is empty or
  begins with a NUL byte (Linux abstract namespace), is refused at start.
  The abstract namespace has no file, so it has no permissions, so it has no
  admission list; it is not a deployment form.
- **L5.** The path is absolute and its byte length, including the terminating
  NUL, fits `sun_path` (108 on Linux, 104 on macOS); otherwise
  `socket_path_too_long` / `socket_path_not_absolute`.
- **L6.** On a platform for which `select_peer_identity` has no adapter, the
  daemon refuses to start (`peer_identity_unsupported`). A daemon that cannot
  read a peer credential has no identity to offer and does not run
  "without identity" (article 6: identity is the operating system's; article
  3: fail-closed).
- **L7.** Before `bind()`, if a file exists at the path: the daemon attempts
  `connect()` to it; success means a daemon is listening — refuse
  (`socket_in_use`); `ECONNREFUSED` means a stale socket — unlink it and
  proceed; any other error refuses. Nothing but a socket file is ever
  unlinked (a regular file at the path is `socket_in_use`).
- **L8.** The daemon reads the overflow ids at start on Linux
  (`/proc/sys/kernel/overflowuid`, `/proc/sys/kernel/overflowgid`); if
  either cannot be read, it refuses to start (`overflow_id_unreadable`),
  because it could not then tell an identity from a non-identity (rule P5).
  On macOS there are no user namespaces and no overflow ids; the rule is
  vacuous there and the documentation says so.

### S — the socket file and its directory (article 6: "the socket file's permissions are the admission list"; "whoever can write [the directory] can unlink the path and bind an impostor")

- **S1.** Mode. Per-user: the socket file is `0700`, owned by the daemon's
  effective uid. System: `0660`, owned by uid 0, group = the configured
  `socket.group`. The daemon verifies the file's mode and owner by `stat`
  after its own `chmod`/`chown` and before `listen()`; any other value is a
  start refusal (`socket_mode_invalid`). Once listening, the daemon does not
  police the file: only root or the owner can change it, and both are on
  the admission list already.
- **S2.** The socket is never briefly more permissive than its final mode:
  the daemon sets its umask to `0o077` (per-user) or `0o117` (system)
  immediately before `bind()` and restores it after, so the file is created
  at its final mode; `chown` (system) precedes `listen()`. A test starts the
  daemon under umask `000` and proves the mode.
- **S3.** Parent directory protection, checked at start and refused with
  `socket_directory_unprotected` on any failure. The directory (after
  resolving symlinks) must: be a directory; be owned by the daemon's
  principal (rule M2) or by uid 0; carry neither `S_IWGRP` nor `S_IWOTH`;
  and, on Linux, carry no access ACL (the `system.posix_acl_access`
  extended attribute is absent — `ENODATA`/`ENOTSUP` both count as absent).
  "Writable by the daemon's principal and root only" is read literally: a
  group-writable directory is refused even when the group has one member,
  because the daemon cannot prove the group's membership will stay at one.
- **S4.** Every ancestor of the parent directory must be owned by the
  daemon's principal or uid 0, and — unless it carries the sticky bit — must
  carry neither `S_IWGRP` nor `S_IWOTH` and, on Linux, no access ACL;
  otherwise `socket_directory_unprotected` naming the ancestor. (An ancestor
  a stranger can write lets the stranger rename the whole directory away and
  put another in its place, so the daemon's published address is gone in the
  same act that takes it over.) The three grants of write are one rule, as in
  S3: the group bit is not an exception one level up any more than it is at
  the leaf, and a grant made through a list is a grant the mode does not
  show. The sticky bit is the one exemption, and only here: it bars everyone
  but an entry's owner, the directory's owner and root from unlinking,
  removing or renaming what is under the directory, which is exactly the act
  this rule exists to stop. It exempts nothing at the leaf, where the attack
  is on the socket file and not on the directory's own name. An ancestor
  whose list could not be read is refused for the reason S3 gives: a check
  that could not run is not a check that passed.
- **S5.** The check is a pure function over `stat` results,
  `directory_protection(st, ancestors, daemon_uid, platform) -> Verdict`, so
  the ownership cases can be tested without a second account; an integration
  test proves the world-writable and group-writable cases with a real
  `chmod`.
- **S6.** On macOS, an access ACL on the directory is **not detected** in
  this version (no standard-library binding exposes it); the documentation
  says so in the deployment section and the start log names the check as
  `acl: not checked on this platform`. It is the one item of S3 the guard
  does not hold on macOS; it is recorded in `docs/exceptions.md` at the
  first release that ships a macOS system daemon, with the restoration
  condition "an ACL reader for macOS exists" (article 0).
- **S7.** In system mode the configured group must exist
  (`socket_group_unknown`) and must not be a group that, on the host, every
  account belongs to by default (`socket_group_is_everyone`: gid 0's group
  is not refused — only root has it — but a group whose name is `users`,
  `staff` (macOS), `everyone`, `nogroup`, `nobody` is). The list is a
  positive, documented list of five names; an administrator who wants such a
  group as the admission list edits the constant and owns the consequence.
  Rationale: the socket group **is** the admission list (article 6), and an
  admission list that admits everyone is a loopback port with extra steps.

### M — modes (article 6: "two deployment modes exist and are named")

- **M1.** `socket.mode` is `per_user` or `system`; anything else is
  `mode_invalid`. The mode is recorded in every `connection_opened` record
  and in `whoami`.
- **M2.** The daemon's principal is: per-user — its effective uid at start;
  system — uid 0 when `run_as` is empty, otherwise the uid of `run_as`. It
  is the owner the directory check accepts (S3) and the uid the client
  expects (C1).
- **M3.** System mode requires starting as root (`run_as_requires_root` when
  `mode = "system"` and euid ≠ 0). Sequence: check directory (S3, S4) →
  `bind()` under umask (S2) → `chown root:group`, `chmod 0660` → if
  `run_as`: `initgroups`, `setgid`, `setuid` (the irreversible calls, never
  the effective-only variants) → compose the other blocks as the account the
  daemon now is (L2a) → `listen()` → accept loop. `listen()` comes
  **after** the drop so that the credential a connecting client reads (the
  kernel records the listener's credentials at `listen()`) is the daemon's
  running principal, which is what the client verifies (C1).
- **M4.** In per-user mode `socket.group`, `run_as` and `identity.accounts`
  are refused if set (`mode_invalid` naming the key): a per-user daemon has
  one principal and no admission group, and a configuration that pretends
  otherwise is a mode confusion.

### P — the peer credential (article 6: "peer credentials are captured at `accept()`"; "a process id is diagnostic and never decisional"; "an unmapped user id from another user namespace is refused")

- **P1.** On every accepted connection, before any byte is read from it, the
  transport calls `PeerIdentity.establish(socket)` and binds the result to
  the connection. No request handler runs on a connection that has no
  `ConnectionIdentity`; a request whose scope lacks one is a programming
  error answered `internal_error` (block 2.1's code) and logged — it cannot
  be reached by a client.
- **P2.** The credential is read once per connection. HTTP keep-alive reuses
  the connection and therefore the credential; every request on the
  connection carries the same `connection_id` and `peer`.
- **P3.** The credential the adapter returns is the kernel's record of the
  peer at `connect()` time. Passing the connected descriptor to another
  process afterwards does not change it; the documentation states this as
  the operating system's meaning of identity, which this daemon adopts and
  does not second-guess (article 6: "identity is the operating system's").
- **P4.** The pid is diagnostic. It is stored on `PeerCredential` and in
  connection evidence, rendered by `whoami`, and used for nothing else: the
  admission function's signature has no pid parameter; `Principal` has no
  pid member; block 2.3's policy language offers no pid term (a dependency
  this block states). A `0` pid from Linux (peer outside the pid namespace)
  is recorded as `null`, not as pid 0.
- **P5.** A credential whose uid or gid equals the overflow id read at start
  (Linux) is refused with `peer_uid_unmapped`; no `Principal` is built from
  it, the directory is not consulted for it, and the refusal is recorded
  with the raw credential (uid, gid, pid) as evidence. It is never mapped to
  `nobody`, never admitted "as the overflow user", never treated as root's
  or the daemon's.
- **P6.** A credential the adapter could not obtain — the sockopt failed,
  the buffer had the wrong length, the two macOS sources disagreed, or the
  uid is `2**32 - 1` (the kernel's "no id") — is `peer_credential_unavailable`:
  the connection's status is `refused` with that code, retryable, and the
  refusal is recorded. Absence of a credential is not an identity and not a
  denial; it is an unknown (article 2).

### A — admission (article 6: "the socket file's permissions are the admission list"; per-user "one principal"; system "several principals — where authorisation does real work")

- **A1.** The kernel already enforced the socket file's permissions at
  `connect()`; the daemon's admission check restates that list from the
  credential and the directory so that the evidence says who was admitted
  and on what basis, and so that a revocation in the directory takes effect
  within the identity lifetime rather than at the peer's next login (G2).
- **A2.** Per-user mode admits exactly one uid: the daemon's principal (M2).
  Every other uid — root included — is `peer_not_admitted`. Root can become
  the user; it does not need a side door, and "one principal" is read
  literally.
- **A3.** System mode admits a credential when at least one holds: `uid == 0`;
  `uid == daemon principal` (M2); the socket group's gid is among the gids
  the directory resolves for the peer's account (`AccountDirectory.group_ids`),
  or is the credential's primary gid. Otherwise `peer_not_admitted`.
- **A4.** Admission is decided from `uid`, `gid` and the directory's answer,
  and from nothing else: not the pid, not the process name, not an
  environment variable, not a request header, not a request body.
- **A5.** A refused connection is recorded (`connection_opened` with
  `status: refused` and the code) on the daemon's own chain under scope
  `local` (article 5: the daemon is the writer and names no scope for a
  peer that never got to name one), and is closed after the first request's
  problem document is written, or after `resolution_timeout_seconds` if no
  request arrives.
- **A6.** Admission is re-evaluated at every re-resolution (G3); a
  connection that no longer passes A3 is refused from that point (`peer_not_admitted`,
  `principal_changed` recorded first) and closed after the next response.

### G — group membership and its lifetime (article 6: "group membership is resolved when a connection is accepted, with a bounded, documented lifetime; the latency of a revocation is that lifetime")

- **G1.** At accept, after P5/P6 pass, the daemon consults `AccountDirectory`:
  `account(uid)` → name and primary gid; `group_ids(name, primary_gid)` →
  gids; `group_name(gid)` for each. From these it builds the `Principal`.
  A uid without an account yields `name: null` and groups resolved from the
  primary gid alone (`group_name(gid)`, giving one name or `partial`).
- **G2.** `group_lifetime_seconds` bounds how long a resolution is used:
  `refresh_due_at = resolved_at + lifetime`. Default 60; bounds 1..3600
  inclusive; a value outside is `group_lifetime_out_of_bounds` at start. The
  documented revocation latency is this value **plus** whatever the host's
  name-service cache adds, and the documentation says both (rule Doc3).
- **G3.** Before serving a request on a connection whose `refresh_due_at`
  has passed, the daemon re-resolves (G1) in place on the live connection.
  If the resulting `Principal` differs from the bound one in any member but
  `established_at`, a `principal_changed` record is emitted and the new
  principal is bound; the connection is not closed (article 10 binds grants
  to the connection that issued them; block 2.3 is told of the change —
  see Dependencies). Uid and gid cannot change on a live connection; name
  and groups can.
- **G4.** Directory calls run off the event loop with
  `resolution_timeout_seconds` as their bound; a blocking name service never
  stalls other connections.
- **G5.** When the directory cannot be consulted (exception or timeout), at
  accept or at re-resolution, the connection's `status` becomes `unknown`:
  `principal` stays as it was (null at accept), every request that needs a
  principal is answered `principal_groups_unavailable` (retryable) until a
  later attempt succeeds, and the attempt is repeated on the next request.
  `whoami` and health are served on an `unknown` connection so an operator
  can see the state. The daemon never serves a decision on a principal whose
  groups it could not resolve, in either mode (article 3: fail-closed;
  article 2: unknown is not a negative fact).
- **G6.** Group names are used exactly as the directory returns them: no
  case folding, no trimming, no domain stripping. Canonicalising names
  across directory services is the administrator's responsibility, and the
  documentation says so in those words (article 6).

### K — principal kinds (article 6: "the kinds of principal form an open registry, never a closed enumeration")

- **K1.** `kind` is a string. The documented, well-known kinds are exactly
  four: `user`, `service`, `workload`, `process`. The registry is open: a
  value outside the four is accepted wherever a kind is read (evidence
  import, a declared delegation, the configuration of K3) and recorded as
  given. There is no `Enum` for it anywhere in the core, and no kind named
  after a technology or a product (article 4).
- **K2.** A principal established from a peer credential is of kind `user`:
  a uid is an account, and an account is what the operating system calls a
  user whether a person or a job holds it.
- **K3.** In system mode, `[identity.accounts]` may map an account name to a
  kind (`"svc-build" = { kind = "service" }`). It changes the recorded kind
  and the `reference`; it changes nothing in admission or policy (kind is
  vocabulary for evidence and for products built above, not a decisional
  attribute in this generation). An account name absent from the directory
  at start is logged, not refused.

### D — delegation (article 6: "a process acting for a human — through a privilege tool, a scheduler or a build runner — is recorded as a delegation in evidence, never collapsed into the human's identity")

- **D1.** A peer may declare, in the optional `delegation` member of a
  decision request, for whom it acts. The daemon records the declaration in
  the decision's evidence record beside the principal, marked
  `status: declared`. The principal of the decision, of the admission and of
  the policy evaluation remains the peer credential's principal. Nothing
  the peer declares changes who it is.
- **D2.** The daemon does not verify a declaration: it may name an account
  that does not exist or a uid that does; it is an observation (article 3)
  and is rendered as one — the documentation and the evidence schema say
  "declared by the peer, not verified by the daemon".
- **D3.** Bounds: chain length 1..4, `kind` ≤ 64 bytes, `name` ≤ 256 bytes,
  `via` ≤ 64 bytes, no member the schema does not name. A declaration
  outside the bounds is `delegation_invalid`, and the decision is not taken
  (a request refused before evaluation produces no decision record; the
  refusal is recorded as a request refusal by block 2.4's rules).
- **D4.** The project's own client declares a delegation when it can see
  one: run under a privilege tool that exports the invoking user
  (`SUDO_UID`/`SUDO_USER`, `DOAS_USER`), it declares
  `{kind: "user", name, uid, via: "privilege_tool"}`. It declares nothing
  otherwise; absence is "nothing declared".

### C — the client verifies the server (article 6: "a client verifies the server's peer credential at connect and refuses a server that is not the daemon's principal")

- **C1.** The expected principal of a profile is: per-user — the client's
  own effective uid; system — the uid of `daemon_user`, resolved through
  the directory at connect time; a system profile without `daemon_user` is
  a usage error, never a default to root (a default would let a profile
  written for one host verify the wrong thing on another).
- **C2.** After `connect()` and before writing any byte, the client reads
  the listener's credential with the same `PeerIdentity` adapter the server
  uses (the connecting side of an `AF_UNIX` stream reads the credentials the
  kernel recorded for the listener at `listen()` — measured on Linux, stated
  by the manual page on macOS, proven by the conformance suite on both). If
  the uid differs from the expected principal, the client closes
  the socket and returns `server_not_the_daemon_principal`, carrying the
  observed and expected uids in the message. The request is never sent: an
  impostor receives zero bytes.
- **C3.** The client's HTTP layer runs over the already-verified socket
  (`http.client.HTTPConnection` with its `sock` set is the recommended
  standard-library shape; any HTTP implementation is acceptable if it can be
  proven to write nothing before C2 completes). The `Host` header is the
  placeholder `sayfirst`; the server ignores it (a dependency on block
  2.1's binding: the OpenAPI `servers` entry names the socket and says the
  host is a placeholder).
- **C4.** The client verifies on every connection it opens, including
  reconnections after a keep-alive drop; there is no "verified once per
  profile".
- **C5.** On a platform without an adapter the client refuses to connect
  (`peer_identity_unsupported`). It does not fall back to an unverified
  connection.
- **C6.** The client never sends a credential of its own: no header, no
  cookie, no body member names who it is. Who it is, the socket says.

### W — `whoami` (article 6: "`sayfirst whoami` reports the principal as the socket saw it")

- **W1.** The served surface has a `whoami` operation (block 2.1 binds it; the
  recommended path is `GET /v1/whoami`). It answers with the `whoami` result
  of the connection it arrives on: the `peer`, the `principal` (or null),
  the `status`, the mode, the socket path, `refresh_due_at` and the
  configured lifetime. It reads the connection's bound identity and performs
  no lookup of its own, so it can only report what the accept path saw.
- **W2.** `whoami` is served on `established` and `unknown` connections; on a
  `refused` connection the problem document is the answer (rule "Refused"
  above).
- **W3.** `sayfirst whoami` (the client distribution's command) connects
  with the active profile (C1–C5), calls the operation, and renders the
  result plus the client-side verification: `server_uid` observed,
  `expected` uid, `verified: true`. It exits with the could-not-ask code on
  `server_not_the_daemon_principal`. Its JSON envelope contains the `whoami`
  result verbatim under `result`, so a script reads the same shape the
  daemon served.

### E — evidence (article 6 via articles 10 and 11: the principal is part of the identity of every effect)

- **E1.** The first record a connection causes on a scope's chain is its
  `connection_opened` record (block 2.4 appends it, together with article
  7's first grade record, before the connection's first decision record on
  that chain). A connection touching two scopes has its record on both
  chains.
- **E2.** Every decision record carries `principal` as this block shapes it,
  and `delegation` (nullable) beside it.
- **E3.** `principal_changed` is recorded on every chain the connection has
  touched; `connection_closed` likewise.
- **E4.** A refused connection's record (A5) carries the raw `peer` and the
  code; it never carries a `principal`, because none was established.

### Doc — documentation duties (article 6 names them; each is a rule because a test reads the document)

The deployment document is `docs/deployment.md`, created by this block. It
must contain, in sections a test can find by heading:

- **Doc1. Deployment forms.** Three named forms — *bare host*, *sidecar
  sharing the socket's volume*, *node agent with the socket on a host path* —
  and for each, the sentence that a socket mounted into a container imports
  the host's meaning of identity: the uids the daemon sees are the host
  kernel's, a container's uid that the host maps is admitted as that host
  uid, and one it does not map is refused as unmapped (P5). Plus the
  per-user/system table of S1 and the sentence "the socket file's
  permissions are the admission list".
- **Doc2. The tooling cost.** No browser reaches the socket; an ad-hoc
  client uses `curl --unix-socket <path> http://sayfirst/v1/whoami` or the
  project's own tool; a remote operator forwards the socket over SSH
  (`ssh -L <local.sock>:<remote.sock>`) and arrives with their own identity
  on the remote host. The cost is stated as accepted, not as a limitation to
  fix (article 6, Why).
- **Doc3. The revocation latency.** The exact sentence "a group membership
  revoked in the directory takes effect on a live connection within
  `group_lifetime_seconds` (default 60 seconds), plus the host's name-service
  cache, which this daemon neither controls nor observes" and, beside it,
  "a grant already issued lasts its own lifetime (article 10)". The default
  in the document is read by a test and compared with the constant.
- **Doc4. Group names.** "Policies bind group names; canonicalising them
  across directory services is the administrator's responsibility."
- **Doc5. The credential's meaning.** The fd-passing caveat (P3), the
  privilege-tool case (root is the principal, the human is a declared
  delegation, D4), and that a process id is shown for diagnosis and decides
  nothing.
- **Doc6. macOS.** The ACL check not performed (S6); the overflow-id rule
  vacuous (L8).
- **Doc7.** `SECURITY.md` already states the admission model; this block
  changes nothing there and adds a pointer to `docs/deployment.md`.

## What this block delivers, and why each shape is what it is

Every module below is authored in this repository against the interfaces
above. This section states the **rule** that fixes each shape and the article
the rule comes from; a shape is what it is because an article requires it,
never because something else already had it. Target paths are in this
repository unless marked `<cli>` (the client repository, for information
only).

Where any file entered an open repository from a closed one, it entered by
copy under article 14, whose provenance review is a **private** record: the
public artefact is the note on the copying commit — the copyright holder and
the licence, nothing more — so no public document of this repository carries
an inventory of what a copy brought, what it left behind, or what it was
called before.

| Module or artefact | The rule that fixes its shape | Article |
|---|---|---|
| `src/sayfirst_control_plane/domain/principal.py` | the principal is the account the kernel named, so `kind` is an open `str` with the four kinds K1 documents and no closed enum a host cannot extend; `established_by` is `peer_credential` because that is the only way an identity is established here; no member names an organisation or a membership of one, because article 5's word is `scope` and a scope is not a property of a principal; a delegation is a `Delegation` record **beside** the principal rather than a nesting inside it (D1), bounded by `MAX_DELEGATION_DEPTH`; `reference()` is `"{kind}:{uid}"` | 4, 5, 6 |
| `src/sayfirst_control_plane/ports/peer_identity.py` | the port reads the operating system's own record — `establish(socket)` returning a `PeerCredential`, not `verify()` of something a caller supplies — because article 6 puts identity in the peer credential of the connection; there is no credential-safe error hierarchy, because there is no credential string that could reach a traceback, and no rejection taxonomy of an identity provider, because there is no identity provider | 6, 3 |
| `src/sayfirst_control_plane/ports/account_directory.py` | the one blocking call this block makes (a name-service lookup) is behind a seam with a timeout, so revocation can be tested without a directory service | 3, 6 |
| `src/sayfirst_control_plane/domain/admission.py` | admission is pure and total: A1–A6 decide from the credential and the configuration alone, so the decision can be proven without a kernel | 6, 9 |
| `src/sayfirst_control_plane/domain/directory_protection.py` | S3–S5 are pure, so the protection of the directory is stated as a rule rather than as a property of one filesystem | 6, 7 |
| `src/sayfirst_control_plane/adapters/nss_directory.py` | `NssAccountDirectory` is the one adapter that talks to the host's name service, and it is the only place a timeout is spent | 3, 6 |
| `src/sayfirst_control_plane/adapters/socket_server.py` | the daemon listens on the socket and on nothing else (L1–L8, S1–S2, M1–M4, P1–P2, G1–G5), because article 6 confines the surface to one local endpoint | 6, 4 |
| `src/sayfirst_control_plane/application/whoami.py` | W1–W2: the surface reports the principal it established, and reports an unverified reading as unverified rather than as an identity | 2, 6 |
| `packages/contract/src/sayfirst_contract/transport/peer.py` | one adapter per operating system, no generic adapter and no fallback: `PeerCredential`, `LinuxPeerIdentity`, `DarwinPeerIdentity`, `select_peer_identity` — a platform without an adapter gets no layout by resemblance | 3, 6 |
| `packages/contract/src/sayfirst_contract/transport/socket_client.py` | the connection **is** the verified socket (C1–C6): no base URL and no authorization header, because article 6 admits no application-level authentication; `whoami` is carried here, and decision submission is kept for block 2.3 | 6, 13 |
| the `whoami` operation and its result | the result carries the peer, the status, the mode and the lifetime, and carries no issuer, no authentication time, no organisation, no membership list and no step-up posture: article 6 establishes identity from the peer credential, and article 5 keeps organisational concerns out of this software | 5, 6 |
| `packages/testing/src/sayfirst_testing/peer_identity_contract.py` | the port's contract suite exercises `establish(socket)` over a socketpair, so every adapter is held to one contract and an adapter that cannot be exercised is reported, not passed | 9, 13 |
| `<cli>` connection options and profile | the client names a socket, a mode and a daemon user — `--socket`, `--mode`, `--daemon-user`, and a profile carrying `socket_path`, `mode`, `daemon_user` and `scope`; there is no token option and no credential store anywhere in the client, because article 6 leaves nothing for the client to hold | 5, 6 |

**What this block deliberately does not carry.** No application-level
authentication of any kind — no bearer dependency on the served surface, no
local shared-secret identity provider, no development-environment allowance
(article 6). Article 9 forbids a shape that proves nothing, so none of these
is carried in a hollowed form.
## Guards

Test names are exact; each names the article it holds. "OS-real" tests
exercise the kernel; "scripted" tests use the kit's `StaticPeerIdentity` and
`StaticAccountDirectory` because CI has one uid. Tests under
`tests/identity/` run on Linux and macOS in CI (a matrix of `ubuntu-latest`
and `macos-latest`); on any other host the macOS-only ones are skipped with
the reason string `not runnable on this host (requires darwin)`, and the
Linux-only ones symmetrically. A skip is reported, never counted as a pass in
the identity summary the job prints.

### Article 6, the guards the article names

- `test_the_daemon_listens_only_on_the_socket` (OS-real) — starts the daemon
  in a subprocess with a temporary per-user socket; enumerates its listening
  endpoints from outside the daemon: Linux — every socket inode in
  `/proc/<pid>/fd`, matched against `/proc/net/tcp`, `/proc/net/tcp6`
  (state `0A`) and `/proc/net/unix` (flags with the listening bit); macOS —
  `lsof -p <pid> -a -i -P -n` (must list nothing) and `lsof -p <pid> -a -U`
  (must list exactly the socket path). Fails on any TCP listener and on any
  unix listener but the configured path. Anti-vacuity: fails unless exactly
  one unix listener was found.
- `test_the_daemon_has_no_tcp_listener_to_configure` (static) — the daemon's
  command-line parser and configuration schema have no member whose name
  contains `host` or `port`; an AST walk of the server package finds no
  `socket.socket(` call, `create_server(` or `start_server(` with a family
  other than `AF_UNIX`, and every `socket.socket(` call names `AF_UNIX`
  positionally or by keyword. Anti-vacuity: at least one `AF_UNIX`
  construction is found.
- `test_the_daemon_refuses_to_start_on_a_socket_directory_writable_by_anyone_else`
  (OS-real) — parent directory `chmod 0777` → exit 78,
  `socket_directory_unprotected`; `chmod 0770` (group-writable) → the same;
  `chmod 0700` → starts. Plus the pure cases (scripted stats):
  foreign owner, ACL present (Linux), other-writable ancestor without sticky,
  other-writable ancestor with sticky (accepted).
- `test_an_impostor_bound_at_the_path_is_refused_by_the_client` (OS-real) —
  an impostor listener (the test process) binds the path; a system profile
  with `daemon_user` = an account whose uid is not the test's (the test
  picks `root` when the test does not run as root, and skips with a reason
  when it does); the client returns `server_not_the_daemon_principal`; the
  impostor's `accept()`ed socket has received **zero bytes** (asserted with
  a non-blocking `recv` after the client returned). Variant (scripted): a
  per-user profile with a `StaticPeerIdentity` reporting a foreign uid on the
  connecting side, same assertions.
- `test_peer_credentials_are_read_through_the_platform_adapter`
  (OS-real, the conformance suite `peer_identity_contract.py`) — over a
  `socketpair`, `establish` returns the test process's `geteuid`, `getegid`,
  `getpid`; over a real listener, the connecting side sees the listener's
  credentials and the accepting side sees the connector's. Runs against
  `LinuxPeerIdentity` on Linux and `DarwinPeerIdentity` on macOS.
- `test_an_unsupported_platform_fails_closed` (static) —
  `select_peer_identity("win32")` and `select_peer_identity("freebsd14")`
  raise `PeerIdentityUnsupported`; the daemon's start with the platform
  patched to `win32` exits 78 `peer_identity_unsupported`; the client's
  `connect` with the same patch returns `peer_identity_unsupported`.
- `test_whoami_reports_the_principal_as_the_socket_saw_it` (OS-real,
  end-to-end) — daemon in a subprocess, the contract client connects,
  `whoami` returns `peer.uid == geteuid()`, `peer.gid == getegid()`,
  `peer.pid == getpid()` of the client, `principal.name == pwd name of
  geteuid()`, `principal.groups` equal to the names of `os.getgrouplist`,
  `status == "established"`, `mode == "per_user"`.

### Article 6, the rules

- `test_an_unmapped_uid_is_refused` (scripted) — credential uid = overflow
  uid → `peer_uid_unmapped`; gid = overflow gid → the same; the directory
  double records **zero** calls; the refusal record carries the raw
  credential and no principal.
- `test_the_overflow_ids_are_read_at_start_or_the_daemon_does_not_start`
  (Linux) — with the `/proc` paths patched to a missing file, exit 78
  `overflow_id_unreadable`.
- Rule L2a, scripted — `test_the_composition_happens_after_the_drop_and_before_listen`
  records `setuid`, then the composition, then `listen`;
  `test_a_composition_refused_after_the_drop_stops_the_start_with_nothing_listening`
  — a composition that refuses leaves `listen` uncalled and nothing composed.
  `test_an_authority_the_composing_account_cannot_read_is_refused_naming_that_account`
  (unprivileged) — a policy with no mode bits refuses `policy_unavailable_at_start`
  naming the path, `unreadable`, and the uid that looked;
  `test_in_system_mode_an_evidence_root_the_packager_did_not_create_refuses_the_start`
  — `evidence_root_unusable` naming the directory, the packager and `run_as`;
  `test_a_per_user_daemon_creates_its_evidence_root_at_0700_whatever_the_umask`.
  The layout, enforced:
  `test_in_system_mode_an_evidence_root_another_account_owns_refuses_the_start_by_name`,
  `test_in_system_mode_an_evidence_root_carrying_another_group_refuses_the_start_by_name`,
  `test_in_system_mode_an_evidence_root_not_at_mode_0700_refuses_the_start_by_name`
  (0777, 02700, 0750, 0500, each named), and (unprivileged)
  `test_in_system_mode_an_evidence_parent_the_daemon_cannot_traverse_refuses_the_start_by_name`
  — "access could not be established", never "not a directory". What one
  append does not prove: `test_the_chain_the_daemon_creates_holds_mode_0600_whatever_the_umask`,
  `test_a_chain_is_created_at_start_for_every_scope_the_policy_reaches`, and
  (unprivileged)
  `test_an_existing_chain_the_composing_account_cannot_append_to_refuses_the_start_by_name`,
  `test_an_evidence_root_no_chain_can_be_created_in_refuses_the_start_by_name`
  — each `evidence_root_unusable` naming the chain file, the scope and the
  account. The store as a whole:
  `test_in_system_mode_an_evidence_root_under_a_replaceable_parent_refuses_the_start_by_name`
  (a parent at 0777, at 0770, each refused naming the parent and the fact),
  `test_in_system_mode_a_sticky_parent_is_the_exemption_rule_s4_grants`,
  and (unprivileged)
  `test_a_chain_already_in_the_store_for_a_scope_no_rule_names_refuses_the_start_by_name`
  — `audit.jsonl` unappendable beside a policy naming `local` alone, refused
  naming the file and the scope — with
  `test_a_file_in_the_store_that_is_not_a_chain_is_not_proved_as_one`.
- Rule L2a, root container (Linux and root; `docs/testing/root-container.md`) —
  `test_the_composed_evidence_store_is_owned_by_the_account_that_must_append_to_it`:
  a real daemon dropped to a real account serves a governed principal an
  allow, the chain file is that account's, and the decision's `effect` entry
  — by kind, by the decision id the daemon answered with, by scope, outcome
  and principal — is on the chain after the composition entry (a guard that
  waited for two entries passed with every `effect` record dropped);
  `test_a_policy_the_dropped_daemon_cannot_read_refuses_the_start_by_name`:
  `root:root 0600` refuses before `listen()` naming the path and the account;
  `test_an_evidence_root_the_packager_did_not_create_refuses_the_start_by_name`:
  an absent evidence root refuses by name and the daemon creates nothing.
  The layouts the rule refuses, each of which a check of "is a directory"
  started and served on:
  `test_an_evidence_root_a_governed_principal_owns_refuses_the_start_by_name`,
  `test_an_evidence_root_every_account_can_write_refuses_the_start_by_name`
  (0777), `test_an_evidence_root_carrying_the_admission_group_refuses_the_start_by_name`
  (02700, the chain inheriting the admission gid), and
  `test_an_evidence_parent_the_dropped_daemon_cannot_traverse_refuses_the_start_by_name`
  — a correct root under a parent root owns at 0700, refused naming the fact
  and not as a traceback at exit 1. What one append does not prove:
  `test_the_chain_the_dropped_daemon_creates_holds_mode_0600_whatever_the_umask`
  — under umask 0777 the chain is 0600 and the decision is on it;
  `test_an_existing_chain_the_dropped_daemon_cannot_append_to_refuses_the_start_by_name`
  — `audit.jsonl` as `root:root 0600` beside a policy allowing `audit`,
  refused naming the file and the scope, the chain left empty;
  `test_an_evidence_root_no_chain_can_be_created_in_refuses_the_start_by_name`
  — a root at 0500 with a writable `local.jsonl`, refused before any chain is
  tried and nothing left behind. The store as a whole, each executed by the
  second review against a daemon that served:
  `test_an_evidence_root_under_a_world_writable_parent_refuses_the_start_by_name`
  — a correct root under a `0777` parent, refused naming the parent;
  `test_a_chain_already_in_the_store_for_a_scope_no_rule_names_refuses_the_start_by_name`
  — `audit.jsonl` as `root:root 0600` beside a policy naming `local` alone,
  refused naming the file and the scope, the chain left empty; and
  `test_a_decision_in_a_scope_no_rule_names_is_recorded_on_a_chain_created_on_first_use`
  — the policy names `local`, a governed principal asks for `audit`, is
  answered `200 deny`, and the deny is on `audit.jsonl`, created on first
  use as the dropped account at `0600`.
- `test_a_process_id_is_diagnostic_and_never_decisional` (static +
  scripted) — `dataclasses.fields(Principal)` contains no field named
  `pid`; `inspect.signature(admit)` has no parameter named `pid`; two
  credentials differing only in pid (`1` and `None`) produce equal admission
  verdicts and equal principals.
- `test_a_credential_the_os_did_not_deliver_is_unknown_not_refused`
  (scripted) — adapter raises `PeerCredentialUnavailable` → status `refused`,
  code `peer_credential_unavailable`, `retryable: true`; uid `2**32-1` → the
  same.
- `test_the_per_user_daemon_admits_one_principal` (scripted) — own uid
  admitted; own uid + 1 refused; uid 0 refused; each refusal
  `peer_not_admitted`.
- `test_the_system_daemon_admits_root_the_owner_and_the_socket_group`
  (scripted) — table: uid 0 → admitted; `run_as` uid → admitted; a uid whose
  directory groups include the socket gid → admitted; a uid whose primary
  gid is the socket gid and whose directory lists nothing → admitted; a uid
  with neither → `peer_not_admitted`.
- `test_admission_reads_nothing_but_the_credential_and_the_directory`
  (static) — `inspect.signature(admit)` parameters are exactly
  `{credential, mode, daemon_uid, socket_gid, directory}`.
- `test_group_membership_is_re_resolved_within_the_documented_lifetime`
  (scripted, fixed clock) — establish; revoke the socket group in the
  directory double; advance the clock by `lifetime - 1`: the next request is
  served on the old principal; advance to `lifetime`: the next request
  triggers re-resolution, a `principal_changed` record is emitted, and (in
  system mode) the request is answered `peer_not_admitted`; the connection
  is closed after that response.
- `test_a_principal_change_keeps_the_connection_open` (scripted) — a group
  added (not the admission group) → `principal_changed`, the request served,
  the connection still open, same `connection_id`.
- `test_the_group_lifetime_is_bounded` (static) — `0` and `3601` → exit 78
  `group_lifetime_out_of_bounds`; `1` and `3600` accepted.
- `test_a_directory_outage_makes_the_identity_unknown_not_a_verdict`
  (scripted) — the directory double raises: at accept, status `unknown`,
  decision requests answered `principal_groups_unavailable` (retryable),
  `whoami` served with `principal: null`, `status: "unknown"`; the double
  then answers: the next request is served and `status` is `established`.
  At re-resolution: the old principal is kept, requests refused the same
  way until the directory answers.
- `test_a_directory_lookup_is_bounded_by_the_timeout` (scripted) — the
  double sleeps longer than `resolution_timeout_seconds`; a second
  connection is served meanwhile (G4); the first is `unknown`.
- `test_group_names_are_not_canonicalised` (scripted) — directory returns
  `Ops`, `ops ` and `DOMAIN\ops`; `principal.groups` is that list verbatim.
- `test_a_uid_without_an_account_is_named_null` (scripted) — `account()`
  returns None; `name` is null; groups come from `group_name(gid)`;
  `groups_status` is `resolved` (or `partial` when the gid has no name).
- `test_groups_status_has_three_values` (static; article 2's guard applied
  here) — the schema enum of `groups_status` and of the connection `status`
  each have at least three members, one of which is `unknown`.
- `test_the_well_known_principal_kinds_are_the_documented_four` (static) —
  the registry's documented set is exactly `{user, service, workload, process}`;
  no `Enum` subclass in the server package or the contract package has a
  member named after one of them; a `Principal` with `kind="janitor"` is
  constructible and its `reference` is `janitor:<uid>`.
- `test_a_configured_account_kind_changes_evidence_and_nothing_else`
  (scripted) — with `"svc" = { kind = "service" }`, the principal's kind and
  reference change; the admission verdict for the same credential is equal
  with and without the mapping.
- `test_a_delegation_is_recorded_as_evidence_and_never_collapses_the_principal`
  (scripted) — a decision request with `delegation` for `alice` from a peer
  `bob`: the decision record's `principal` is `bob`'s, `delegation.chain[0].name`
  is `alice`, `delegation.status` is `declared`; the policy evaluation
  received `bob`'s principal (asserted on block 2.3's evaluation input).
- `test_a_delegation_outside_its_bounds_is_refused` (scripted) — chain of 5
  → `delegation_invalid`; `via` of 65 bytes → the same; an unknown member →
  the same; no decision record exists afterwards.
- `test_a_request_without_a_delegation_renders_null` (scripted) — the
  evidence record has `delegation: null`, and the key is present.
- `test_the_socket_is_created_at_its_final_mode` (OS-real) — daemon started
  under `umask 000`: the socket file's mode is exactly `0700` (per-user);
  for system mode the pure `umask_for(mode)` returns `0o117` and the sequence
  of calls recorded by a scripted `os` seam is `umask, bind, chown, chmod,
  listen`, with `setgroups/setgid/setuid` between `chmod` and `listen`
  when `run_as` is set.
- `test_an_abstract_or_unnamed_socket_is_refused` (Linux, OS-real) — a
  listener bound to `\0name` handed to the verifier → `socket_abstract_or_unnamed`;
  a `socketpair` end → the same.
- `test_a_stale_socket_is_replaced_and_a_live_one_is_not` (OS-real) — a
  socket file with no listener at the path: the daemon starts; a listener
  at the path: exit 78 `socket_in_use`; a regular file at the path: the same.
- `test_a_system_daemon_refuses_an_everyone_group` (scripted) — group
  `users` → `socket_group_is_everyone`; an unknown name →
  `socket_group_unknown`.
- `test_per_user_mode_refuses_system_keys` (static) — `socket.group` set
  with `mode = "per_user"` → `mode_invalid` naming `socket.group`.
- `test_the_client_sends_nothing_before_it_has_verified_the_server`
  (static) — the socket client's `connect` calls `PeerIdentity.establish`
  before any `send`/`sendall`/`write` on the socket: proven with a scripted
  socket that records the order of calls, and by the impostor test's
  zero-byte assertion.
- `test_a_system_profile_names_its_daemon_user` (static) —
  `SocketProfile(mode="system", daemon_user=None)` is refused at
  construction; there is no default.
- `test_the_client_never_sends_a_credential` (static) — the request the
  client writes contains no `Authorization`, `Cookie` or `X-*` header and no
  body member named `principal`, `uid`, `token` or `credential`; asserted on
  the bytes written to a scripted socket for `whoami` and for a decision
  request.
- `test_the_connection_identity_is_bound_once_per_connection` (OS-real) —
  two `whoami` calls on one keep-alive connection return the same
  `connection_id` and `peer.captured_at`; a new connection returns a new id.
- `test_a_refused_connection_answers_a_problem_document_not_eof`
  (scripted) — a refused connection's first request yields a 403 problem
  document with the code, then the connection is closed.
- `test_the_first_record_of_a_connection_on_a_chain_is_its_identity`
  (scripted, with block 2.4's memory store) — a connection's first decision
  in scope `s1` is preceded on `s1`'s chain by `connection_opened`; a second
  scope `s2` gets its own `connection_opened` before its first decision.

### Documentation guards

- `test_the_deployment_documentation_names_each_form_and_the_lifetime`
  (static) — `docs/deployment.md` has headings containing "bare host",
  "sidecar" and "node agent", each section containing the phrase "imports
  the host's meaning of identity"; contains the phrase "the socket file's
  permissions are the admission list"; contains `curl --unix-socket`;
  contains the sentence of Doc3 with the number equal to
  `DEFAULT_GROUP_LIFETIME_SECONDS`; contains Doc4's sentence.
- `test_every_authored_file_carries_an_spdx_identifier` (article 15, shared)
  — covers the new files.

### Article 14

- `test_the_contract_distribution_imports_nothing_of_the_server` (shared,
  block 2.1) — extended to the `transport` subpackage: it imports the
  standard library and the contract package only.

## Non-goals

- **Network authentication, tokens, sessions, rotation, a TCP listener of any
  kind, a loopback listener** — forbidden by article 6, not deferred.
- **Socket activation** (an inherited listening descriptor from a service
  manager) — deferred. Article 6 names two modes and says nothing of how the
  socket is acquired; the system daemon of this version binds as root and
  drops (M3). See open question 1.
- **Verification of a declared delegation** — not deferred: article 3 makes
  it an observation, and article 6 asks that it be recorded, not proven.
- **Article 8's per-connection check of write access to the configuration**
  — belongs to the block that owns the configuration; this block supplies
  the uid and gids it needs (`Principal.uid`, `gid`, the directory's gids).
- **Article 7's grade** — block 2.4; this block supplies the connection it
  is computed on and the `connection_opened` record it is written beside.
- **Scope-to-principal authorisation in system mode** (article 5: "the
  configuration says which principals may write which scopes") — block 2.3
  or the configuration block; this block supplies `name` and `groups`.
- **A macOS ACL reader** — deferred with an exception-register entry (S6,
  article 0).
- **Multi-host, central identity, a directory of its own** — article 1 and
  article 6: products built on this one.
- **Group membership from the kernel's supplementary group list**
  (the kernel's peer-groups socket option on Linux, `xucred.cr_groups` on
  Darwin) — not used: unavailable on Linux
  before 4.13 and truncated at 16 on macOS, so it cannot be the identity;
  the directory is (G1). Reconsidered if the directory proves too slow —
  open question 3.

## Dependencies on other blocks

- **Block 2.1 (contract)** must provide: the seven problem codes of the
  table, with the statuses given; the `principal`, `peer`, `delegation` and
  `whoami` schemas in generation 1; `delegation` as an optional member of
  the decision request; the `whoami` operation in the binding (recommended
  `GET /v1/whoami`); the OpenAPI `servers` entry naming the socket with a
  placeholder host; the exclusion of `sayfirst_contract.transport` from
  the domain-contract vocabulary guard; the `binds` of any golden scenario
  that exercises `whoami` set to `both`.
- **Block 2.3 (policy, grant)** must: evaluate against `Principal` as shaped
  here, binding group *names* (`groups`) and account `name`; offer no `pid`
  term in the policy language (a guard there); receive a `principal_changed`
  signal for a live connection and treat it as it treats a policy-version
  change for the grants issued over that connection (recommendation — the
  alternative, letting a grant outlive the principal that earned it, makes
  the revocation latency the grant's lifetime, which Doc3 then must say).
- **Block 2.4 (evidence, grade)** must: append `connection_opened`,
  `principal_changed`, `connection_closed` as shaped here; write the
  connection's identity record and its first grade record together as the
  connection's first records on a chain (E1); carry `principal` and
  `delegation` on every decision record; record refused connections on the
  `local` chain (A5).
- **The client block** must: replace URL and token with `socket_path`,
  `mode`, `daemon_user` in the profile; map the client-side classification
  of the codes to its exit lanes; ship `sayfirst whoami` as W3; declare a
  delegation under a privilege tool (D4).
- **The configuration block** must: carry the keys listed; protect the file
  as article 8 says; expose to this block the uid the daemon runs as.

## Open questions

1. **Socket activation in v1?** Without it, a system daemon that must run
   under its own uid (article 7's evidence grade) starts as root and drops.
   *Recommendation:* ship the drop now (portable, ~10 lines, fully
   specified in M3), add socket activation — the service manager's
   inherited-descriptor protocol — in the next wave with the same
   verification path (L4, S1–S4 applied to the inherited descriptor's
   `getsockname()`); an inherited descriptor changes what the client sees at
   C2 (the manager, root, called `listen()`), so the wave that adds it also
   adds a `daemon_user` note to the deployment document.
2. **Default `group_lifetime_seconds` = 60.** Lower bounds revocation
   tighter at the cost of one `getgrouplist` per connection per minute.
   *Recommendation:* 60; a host with a slow directory raises it and the
   document says what it costs.
3. **Directory or kernel for group membership?** The directory (G1) is what
   an administrator revokes in; the kernel's list is what the peer's
   processes actually hold. *Recommendation:* the directory, with the
   kernel's primary gid honoured for admission (A3) so a process whose
   account has no directory entry can still be admitted by its primary
   group; revisit only if `getgrouplist` latency is measured as a problem.
4. **`whoami` in the contract's generation 1, or a tooling-only endpoint?**
   *Recommendation:* in the contract, bound to `both`: it is the guard the
   article names, and a guard that a third-party implementation need not
   satisfy is not a contract.
5. **The `delegation` request member in generation 1.** Adding it later is a
   new generation (article 13). *Recommendation:* include it now, optional;
   its cost is one schema and one bound check.
6. **Everyone-groups list (S7).** Five names is a judgement. *Recommendation:*
   keep the list short and documented, refuse by name only, and let an
   administrator who knows better edit the constant with a stated reason.

## Provenance and authority

This document is a design of this repository, and its authority is the
constitution it cites. Every rule above names the article that makes it a
rule, so a reader can judge the design against `CONSTITUTION.md` in this tree
and needs nothing else to do it: the articles were read in full, with 0, 1, 2,
3, 5, 6, 7, 8, 10, 11, 13, 14, 15 and 16 re-read against each interface,
together with `GOVERNANCE.md`, `CONTRIBUTING.md`, `SECURITY.md` and
`README.md` from the same tree.

Where a shape entered an open repository from a closed one, article 14 governs
it: the copy carries the note on its own commit — the copyright holder and the
licence, nothing more — and the provenance review that authorised it is a
**private** record. A public document therefore records no closed source, no
closed path, no closed identifier and no state of a closed tree, because a
reference pointing the wrong way is the leak that cannot be unpublished.

The approved contracts boundary design of 2026-08-19 fixes the boundary rule,
the distribution shape (B1) and the in-band generation negotiation.

Measured on this host (Linux) while writing: the connecting side of an
`AF_UNIX` stream reads the listener's credentials through `SO_PEERCRED`; a
`socketpair` end reports the process's own; `getsockname()` of a `socketpair`
end is empty. `/proc/sys/kernel/overflowuid` reads `65534`. The macOS claims
(the local peer-credential and peer-pid options on the connecting side,
`getpeereid`) are stated from the platform's manual pages and are proven by
the CI matrix, not by this host: "not runnable on this host".

Nothing outside this repository was executed or modified while this document
was written.