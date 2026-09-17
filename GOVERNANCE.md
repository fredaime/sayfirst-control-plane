<!-- SPDX-License-Identifier: Apache-2.0 -->
# Governance

This file implements article 16 of [`CONSTITUTION.md`](CONSTITUTION.md). Where
the two differ, the constitution wins.

## Roles

- **Lead.** Frédéric Aime, who also builds the private products on this
  control plane. The company intended to hold them does not exist yet; this
  line names it and the lead's role in it when it does. Within this community
  the lead acts in a personal capacity, not as an officer of that or any
  company.
  The lead appoints maintainers, removes them with a stated and recorded
  reason, decides where consensus does not form, and approves amendments to the
  constitution. While the lead is the only maintainer, the fourteen days below
  are the community's and the lead decides at their end; this sentence is
  removed when it stops being true.
- **Maintainers.** People with merge rights, appointed by the lead. A maintainer
  reviews, merges, labels pull requests for the two private checks (below),
  and takes part in decisions. The list lives in `MAINTAINERS.md` once
  there is more than one name to list.
- **Contributors.** Anyone who opens an issue or a pull request under the terms
  of [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Decisions

Routine changes are pull requests reviewed and merged by a maintainer.

A change that alters a public contract, a plugin interface or a constitutional
article goes through a **request for comments**:

1. an issue titled `RFC: …` stating the change, the reason and the alternatives
   considered;
2. fourteen days open for comment;
3. lazy consensus among maintainers — silence is assent; a sustained objection
   with a stated reason blocks;
4. failing consensus, the lead decides and records the reason on the issue.

The licence is outside this path: the project holds no right to change the
licence of contributed code and seeks none (constitution, articles 15 and 16).

Amendments to the constitution follow the same path with the lead's approval
required, and are recorded in the changelog with their rationale.

## Security disclosure

Report a vulnerability privately (see [`SECURITY.md`](SECURITY.md)); never in a
public issue. Coordinated disclosure with a ninety-day default; the reporter is
credited unless they ask not to be.

## Releases

Semantic versioning. Every release carries a changelog, the neutrality count of
article 18 (published as reported, "not reported" when absent), and any
deprecation it begins (article 8: a deprecated plugin
interface version keeps working for at least two minor releases or six months,
whichever is longer).

## Continuous integration

Public CI runs with nothing but this repository: a fork builds, tests and
contributes without private infrastructure. Two private checks exist and gate
merges as required statuses: a compatibility check, which verifies that a
change does not break products built on this control plane and whose failure
names the port and the interface bump required; and the vocabulary check of the
constitution's article 4, whose failure names the category and the identifier
that tripped it, never the list. Both run only when a maintainer applies the
`ok-to-compat` label to a pull request, which attests that a maintainer has
read the change; neither runs automatically on a fork's code; neither discloses
private detail. The compatibility check passes when the change declares the
interface bump it requires; it verifies the declaration, not the private
side's adaptation, so a private lag never holds a merge.
