<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirst` control plane

The open-source control plane: a host-scoped daemon that a governed program asks
before it acts, and that answers **allow**, **deny** or **suspend** and keeps
the evidence. A deployment of this version is graded **observability** — the
governed program can write or replace the evidence store, so the record it
keeps is one that program could have forged — or **unverified**, which claims
nothing, and which is also the answer where the program *cannot* write the
store, exclusivity being a separate thing to prove. At neither grade is any
claim of proof or of tamper detection made.

Article 7 of the constitution defines a third grade, **evidence**, and no
deployment of this version reaches it. It will require the daemon under its own
user id, no principal but that one and root able to write or replace the store
on any mutation path the store adapter knows, and a store adapter that can
prove that exclusivity. It is a rule this project holds itself to, not a
capability shipped here — which is why the grade this version reports is the
conservative one. [`SECURITY.md`](SECURITY.md) states all three.

This repository was born empty on 2026-09-01 under the Apache License 2.0. Its
first content is its constitution — [`CONSTITUTION.md`](CONSTITUTION.md) — which
binds everything that arrives after it. Code arrives in small, complete slices;
the first is one port, one capability, one decision, over a Unix socket.

- Governance and how decisions are made: [`GOVERNANCE.md`](GOVERNANCE.md)
- What this software does and does not protect against: [`SECURITY.md`](SECURITY.md)
- Contributing, the DCO and the corporate CLA: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Names and marks: [`TRADEMARKS.md`](TRADEMARKS.md)
- Licence: [`LICENSE`](LICENSE) (Apache-2.0) and [`NOTICE`](NOTICE)
