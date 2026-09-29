<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirst` server conformance

This control-plane distribution exposes only the `sayfirst-conformance`
command and depends only on the public contract distribution. It replays the
authoritative server conformance scenarios:

```console
sayfirst-conformance replay --socket allow=/run/conformance/allow.sock
```

Complete runs exit 0 as `proven`, disagreements exit 1 as `failed`, invalid
invocations exit 2, and incomplete runs exit 3 as `unknown`. A run is complete
when every server-bound scenario has a `--socket` and is replayed, and the daemon
for `grant_miss_after_policy_version_change` is given `--change-policy-command`,
the command that changes its policy. A `--socket` for that scenario without
`--change-policy-command` is not an incomplete run but an invalid invocation,
refused (exit 2) before anything is replayed. A scenario declared with
`--expected-absent SCENARIO=REASON` leaves the run incomplete, and one named by
neither fails it. The contract distribution's README shows a run that names all
of them, and what each daemon must be arranged to do.

The `sayfirst-cli` distribution, the `sayfirst_cli` import package and the
`sayfirst` console script are the product command-line interface's, and are
not published from this repository (the operator's decision of 2026-09-05).

What this repository publishes beside the daemon is the operator surface that
inspects it, from `packages/cli`: the distribution `sayfirstd`, the import
package `sayfirstd` and the console script `sayfirstd`. The constitution names
one command with subcommands and one console script can point at one module, so
that surface re-exports replay as `sayfirstd conformance replay` by handing the
operation to the contract distribution that implements it — with the options,
the whole-run verdict and the exit statuses of this command. This distribution
claims neither set of names; it exposes `sayfirst-conformance` and nothing else,
so a deployment that wants the replayer alone installs one wheel and no operator
surface at all — one command, and it is the replayer's (article 14).
