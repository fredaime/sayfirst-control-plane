<!-- SPDX-License-Identifier: Apache-2.0 -->
# Neutrality, measured

Article 18 of [`CONSTITUTION.md`](../CONSTITUTION.md) asks for one number at each release: how
many concepts the parent application had to add on its own side in order to integrate through the
public contract. Dogfooding is the best proof that this core is neutral, and a rising count is the
earliest signal of a core quietly becoming agentic through internal needs.

## What this repository can and cannot say about the number

It is measured on the other side of the boundary, by the people who did the integrating. This
repository holds nothing that could check it, and does not pretend otherwise: the number is
published **as reported**, attributed to whoever reported it, with the rule they counted by.

An absent number is published as **not reported**. It is never published as zero. Zero is a
measurement — nothing had to be added — and « not reported » is the absence of one; a reader
deciding whether this core is drifting needs the two to look different, and article 2 requires it.

## The counting rule

A concept counts when the integrating side had to introduce a name of its own, in its own code or
configuration, that exists only because of this control plane and has no meaning without it:

- a type, structure or enumeration that mirrors one of the published contract, because the
  published one could not be used as it stands;
- a configuration key, an environment variable or a file format that this control plane requires
  and that the integrating side would not otherwise have;
- a translation layer between a published vocabulary and the integrating side's own, where the
  published vocabulary could not be adopted directly.

A concept does **not** count when it is imported from the contract distribution and used under its
published name; when it belongs to the integrating side's own domain and would exist anyway; or
when it is a test double, a fixture or a piece of scaffolding that does not ship.

The rule travels with the number, in its own column, because a count without the rule that
produced it is not comparable to the next one.

## The counts

Newest first. One row per release.

| Release | Concepts added | Counting rule, and who counted |
|---|---|---|
| 0.2.0 | not reported | not reported — the count was requested from the maintainers of the parent application and had not been answered when this release was cut |

## Asking for the next one

The request goes out with the release. It is a line of
[`publication-checklist.md`](publication-checklist.md), and the answer lands here as a row, with
the rule as it was actually applied rather than as it is written above — if the two differ, the
row says so and this page is corrected.

A rising trend opens a release request for comments, by the procedure of
[`GOVERNANCE.md`](../GOVERNANCE.md).
