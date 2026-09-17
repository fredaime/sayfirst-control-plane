<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing

Thank you. This file implements articles 15 and 16 of
[`CONSTITUTION.md`](CONSTITUTION.md); read the constitution first, it explains
the rules below.

## Before you write code

- Read the article your change touches. A change that alters a public
  contract, a plugin interface or a constitutional article starts as an RFC
  issue (see [`GOVERNANCE.md`](GOVERNANCE.md)), not as a pull request. The
  licence of contributed code does not change (article 15).
- A new port needs, in the same pull request, a real open-source implementation
  and a name an open-source user understands without knowing any private
  product (article 4).
- No agent framework, model, prompt, tool protocol, industry or transport
  enters the core's vocabulary (article 4).

## Documents the repository owns

Seven documents state the rules of the whole repository, not of any part of it:
[`CONSTITUTION.md`](CONSTITUTION.md), [`GOVERNANCE.md`](GOVERNANCE.md),
[`SECURITY.md`](SECURITY.md), this file, [`TRADEMARKS.md`](TRADEMARKS.md),
[`README.md`](README.md) and `NOTICE`. They belong to the repository. A change
that implements a block of the walking skeleton does not edit them: it records
in its report what such a document must say, and leaves the writing to a
dedicated change that does nothing else (article 16).

The reason is the reason article 0 gives for adopting this constitution by
pointer and never by copy — a copy drifts. Blocks are built in parallel from
one base, so when two of them discover the same rule, each writes it in its own
words, and the repository ends with two rules where it needs one: two sentences
that a later reader must reconcile, and that a later change must amend twice.
One rule, written once, in the place that owns it.

A change may add a line to such a document when the constitution requires that
line of it and the line names the change: a block whose article obliges it to
declare something at repository scope declares it, and its report says which
article obliged it. Nothing else is an exception. A rule discovered while
implementing a block is not required of the block; it is required of the
repository, and it waits for the change that owns it.

## Licensing your contribution

- **Individuals** sign off each commit under the Developer Certificate of
  Origin (`git commit -s`, which adds `Signed-off-by: Your Name <email>`). By
  signing off you certify the DCO at <https://developercertificate.org>. Your
  contribution is licensed under the Apache License 2.0; you keep your
  copyright.
- **Employers.** A contribution made on behalf of an employer, or under a
  contract that gives the employer rights in it, also needs the corporate
  contributor licence agreement, signed once by that employer; it confirms the
  employer's authority to contribute and licenses the contributions under the
  same terms. Its text will be `CCLA.md` in this repository once counsel has
  approved it; until then such contributions wait, and this sentence says so.
- No assignment of rights is ever requested.

Every file the project authors (`LICENSE` and `NOTICE` excepted) carries
`SPDX-License-Identifier: Apache-2.0` — or `Apache-2.0 OR MIT-0` for an example
or fixture offered under both — in the form its format allows: a comment line at the top of a source file, an HTML
comment at the top of a Markdown file.

## Dependencies

A new dependency must carry a permissive licence from the closed list of SPDX
identifiers — `MIT`, `MIT-0`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`,
`ISC`, `PSF-2.0`, `Zlib`; adding to the list is an RFC — verified from
its installed metadata by the dependency checker, which also refuses any agent
framework or model client in the core (article 4). A dependency without an
identifiable licence text is refused; one whose metadata is defective needs an
entry in the exception register naming the licence text found; weak copyleft
does not enter the open core (article 15).

## Pull requests

- One change per pull request; tests first, then the change, then the
  documentation it touches.
- Public CI must be green; it runs with nothing but this repository.
- A maintainer may add the `ok-to-compat` label to run the two private checks:
  the compatibility check, whose failure names the port and the interface bump
  required, and the vocabulary check, whose failure names the category and the
  identifier that tripped it. Neither runs automatically on a fork.
- Provenance: code copied from elsewhere is either yours, or permissively
  licensed with its notice preserved; you say which, and whose copyright it is.

## Security

Never report a vulnerability in a public issue; see
[`SECURITY.md`](SECURITY.md).
