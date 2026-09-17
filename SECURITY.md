<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security

## What this software is, and is not

This control plane is a **governance and observability layer, not a confinement
mechanism**. A governed program *calls* the boundary before it acts; a program
that does not call it is not governed, and nothing here stops it. Pair this
software with operating-system sandboxing for code you do not trust. Every
claim it makes is no stronger than the evidence it holds; where it does not
know, it says "unknown" (constitution, article 2). By default it records
decisions, not payloads (article 11).

## Integrity grades

The daemon reports which grade it runs at (constitution, article 7):

- **Observability grade** — the governed program can write or replace the
  evidence store (the per-user daemon, where program and store share one user
  id, is the common case). The program could rewrite its own evidence; the hash
  chain detects accidental corruption and incomplete tampering, and a program
  that can replace the store can rewrite the chain whole without anything
  noticing. No claim of proof or of tamper detection is made at this grade.
- **Evidence grade** — **no deployment of this version obtains it.** It will
  require the daemon under its own user id and a governed program that can
  neither write the store nor replace it, judged by effective access (mode
  bits, ACLs, ownership — an owner can change the bits — and every parent
  directory), never by ownership as protection; a store behind a database is
  unverified unless its adapter can prove that no admitted principal reaches a
  writing role. No store adapter here can make that proof of exclusivity yet,
  so the evaluator returns the grade below instead of guessing. Once it can,
  the chain and the store together support a claim of integrity against the
  governed program, not against the daemon's account or root.
- **Unverified** — effective access could not be established, or it was and the
  caller cannot write the store, which is not by itself the exclusivity
  evidence grade needs. Nothing is claimed.

So a deployment of this version is graded **observability** or **unverified**,
and never **evidence**. Article 7 defines all three and this repository is held
to all three; the third is a rule to meet, not a capability to install.

The grade is re-evaluated when a connection next asks something, and before
every verdict: the documented interval is a cache age consulted on that next
request, not a scan, so a connection that sits idle keeps the grade it was last
given until it acts, and nothing here scans for one that does not (article 7,
whose Guard says the same). `sayfirst status` shows the caller's grade; every
verification verdict carries the weakest grade in effect over the period it
covers.

## Admission and identity

The daemon listens on a Unix domain socket and only there; its HTTP surface is
served over that socket, and there is no TCP listener, loopback included — a
TCP connection carries no peer identity, and a loopback port is reachable by
every local account. Identity is the operating system's: peer credentials
captured at `accept()`; a process id is never decisional; an unmapped user id is
refused. The socket file's permissions **are** the admission list (0700
per-user, 0660 root-owned with a group for a system daemon).
`docs/deployment.md` states the deployment forms, the revocation latency and
what a peer credential means on each platform.

What **is** checked by effective access along its whole path — mode bits,
access control lists, ownership and every parent directory that would let the
file be replaced — is the **policy authority**, the file whose rules decide
outcomes. The daemon refuses to start when that file is not protected where it
stands, and in system mode it refuses a decision request from a principal with
effective write access to it or to a directory it could be replaced through
(constitution, articles 6 and 8).

The **configuration file** is checked the same way, and by the same walk, in
system mode. Article 8 asks for two protections of it and both are made. At
start the daemon refuses a configuration that anyone but root or its
administrator group could write or replace, naming the file, the component that
decided it and the rule; and per decision request it refuses a principal with
effective write access to that file or to a directory it could be replaced
through, under a code of its own — `configuration_writable_by_principal`, which
an operator can tell from the policy authority's — while that principal's
administrative commands are still served and graded. The consequence the article
draws is worth stating plainly: a program run as root, or run as the
administrator group, obtains no decision in system mode — root can write every
file there is, and a configuration group-writable by the administrator group
starts, since that group is exactly who the article allows to write it — so a
governed program must run as some other principal. What the per-request check
reads is the group the program **runs as**, the one its peer credential carries;
a principal admitted through a named supplementary membership is not refused by
it, as it is not by the policy authority's own per-connection check, so the
file's permissions and not this refusal are what protect the file. Lay it out
owned by root, mode `0640`, under directories the account the daemon drops to
can traverse and no other account can write, the way `docs/deployment.md` says.
There is no check to make in per-user mode, where the configuration and the
daemon belong to one account, and none to make at all when the daemon was
started without `--config`.

## What counts as a vulnerability

Anything that breaks a claim the constitution makes: a peer credential
attributed to the wrong principal; a socket-permission bypass; evidence forged
or altered without detection at evidence grade; a scoped read or write
reaching records of another scope (a partition defect, not an access-control
bypass); a plugin activated without being named in the configuration; a
payload captured under the default configuration; a network destination the
daemon reaches without being configured to. A weakness in a governed program
itself is not one — this software does not confine it (above). The third item
names a claim this version cannot yet make: no deployment reaches evidence
grade (above), and the item stands for the day one does.

## Publication is a fresh repository

Article 0 offers two paths to a public repository: it is **created fresh**, or
an existing repository's record — issues, pull requests and, with them, the git
history — is reviewed for private material before its visibility is changed,
because that record becomes public with it.

**For the private repository this tree was reviewed in, the second path is
closed, and closed by measurement.** A document merged into its `main` was
found to carry material that repository may not publish (article 14). Its tip
is redacted, but a removal does not unpublish an object a history still holds.
Every skeleton branch has since been merged and every merged branch deleted, on
the remote and on the mirror, which removes the branch refs that reached the
pre-redaction object; it does not remove the object. The hosting platform keeps
a permanent read-only reference for every pull request ever opened; one of
those references still carries the file as it stood before the redaction; no
rewrite of `main` touches them and no interface deletes them. That was
**verified, not assumed** — the references were fetched and the file was found
in one of them.

So the lead decided, on 2026-09-04, that **that repository is never made
public.** The public repository is created fresh, which is article 0's first
path. Whoever performs the publication does this and nothing else:

- **Create a new repository and push the reviewed tree as its first commit**,
  with no history behind it. That repository's visibility is never changed, and
  no branch, tag, issue or pull request is carried across.
- **Carry the licence, the provenance record and the guards over with the
  tree** — `LICENSE`, `NOTICE`, `PROVENANCE.md`, the per-file SPDX identifiers
  and the repository-scope guards under `tests/` — and run the whole guard
  suite over exactly what is pushed, so that every claim those guards hold,
  public vocabulary among them, is checked rather than asserted (article 2).
- **Keep that repository afterwards, private. Do not delete it.** It is the
  private record of how the open one was built, and this document's account of
  why the fresh path was taken is worth no more than the record it rests on.
- **Enable private vulnerability reporting in the same act as the first push**
  (article 0), so that the channel named below exists from the first public
  minute.

The tree is pushed as it stands: no step of this recipe asks for a commit
message, a branch or any other historical material to be reconstructed in the
new repository, and no guard in the tree asks for one either. That is a
property the guards themselves hold, so it cannot quietly stop being true:
`tests/test_copy_note.py` builds a repository the way this recipe describes,
from the tracked tree with one commit whose message records nothing, and holds
it to the same rules it holds this one to. Article 14's provenance record is a
tracked file for that reason — a record that lived only in commit messages
would either be lost at publication or be the thing whoever publishes carries
across, which is the leak article 0's fresh path exists to prevent.

One thing the tree carried was about that repository's history rather than
about the tree: an entry of the exception register naming a paragraph of one of
its commits, and the constant that mechanised it in `tests/test_copy_note.py`.
Both left in the change that prepared the reviewed tree, which is why the
register skips a number. An exception with nothing to except relaxes nothing: a
repository created fresh records no copy in its history, so there is nothing
there for a register to relax.

This records a fact about that repository, not a change to the rule. Article
0's second path stands for repositories where no such object exists; removing
it from the constitution would be an **amendment under article 16**, and this
document does not make one.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's **private vulnerability reporting**
on this repository (Security → Report a vulnerability); only the repository's
administrators and security managers see such a report. Article 0 asks for that
channel to be enabled in the same act as the first push, so that this document
names one that exists from the first public minute, and the act is a line of
`docs/publication-checklist.md`, which
`tests/test_publication_checklist_names_every_act.py` holds against that
article. We aim to acknowledge within seven days.
Coordinated disclosure applies, with a ninety-day default that can
be shortened by agreement or extended when a fix needs it. Reporters are
credited unless they prefer not to be.
