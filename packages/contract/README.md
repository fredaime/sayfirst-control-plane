<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirst` contract

This distribution publishes generation 1 of the transport-neutral domain
contract and its generated HTTP-over-Unix-socket binding. It has no runtime
dependencies. The scriptable fake is available only through the `stub` extra.

## Scenarios

<!-- BEGIN GENERATED SCENARIOS -->

| Scenario | Binds | Article | Expected |
|---|---|---:|---|
| `allow` | both | 1 | `grant=present`, `outcome=allow`, `reason=policy_allows` |
| `deny` | both | 1 | `outcome=deny`, `reason=policy_denies` |
| `grant_expired_by_lifetime` | client | 10 | `grant=present`, `grant_use=expired`, `outcome=allow`, `reason=policy_allows` |
| `grant_hit_within_lifetime` | client | 10 | `grant=present`, `grant_use=hit`, `outcome=allow`, `reason=policy_allows` |
| `grant_miss_after_policy_version_change` | both | 10 | `after_policy_change={'grant': 'absent', 'outcome': 'deny', 'reason': 'policy_denies'}`, `grant=present`, `outcome=allow`, `reason=policy_allows` |
| `grant_void_on_arguments_change` | client | 3 | `grant=present`, `grant_use=arguments_changed`, `outcome=allow`, `reason=policy_allows` |
| `grant_void_on_connection_loss` | client | 10 | `grant=present`, `grant_use=connection_lost`, `outcome=allow`, `reason=policy_allows` |
| `missing_policy` | both | 1 | `outcome=deny`, `reason=policy_absent` |
| `no_grant_on_deny` | both | 10 | `grant=absent`, `outcome=deny`, `reason=policy_denies` |
| `no_grant_without_signal_channel` | both | 10 | `grant=absent`, `outcome=allow`, `reason=policy_allows` |
| `policy_unavailable_is_could_not_ask` | both | 1 | `grant=absent`, `problem=policy_unavailable`, `result=could_not_ask` |
| `review_approve` | both | 12 | `outcome=suspend`, `reason=policy_requires_review`, `state=approved`, `after_resolution.outcome=allow`, `after_resolution.reason=approval_granted` |
| `review_expire` | both | 12 | `outcome=suspend`, `reason=policy_requires_review`, `state=expired` |
| `review_reject` | both | 12 | `outcome=suspend`, `reason=policy_requires_review`, `state=rejected`, `after_resolution.outcome=deny`, `after_resolution.reason=approval_rejected` |
| `strictest_rule_wins` | server | 1 | `grant=absent`, `outcome=deny`, `reason=policy_denies` |
| `unknown_outcome` | client | 13 | `problem=outcome_unknown`, `reported_outcome=unknown`, `result=could_not_ask` |
| `unreachable` | client | 1 | `problem=unreachable`, `result=could_not_ask` |

<!-- END GENERATED SCENARIOS -->

## Server conformance replay

Run each server-bound scenario against a daemon instance already arranged for
that scenario:

```console
sayfirst-conformance replay \
  --socket allow=/run/conformance/allow.sock \
  --socket deny=/run/conformance/deny.sock \
  --socket missing_policy=/run/conformance/missing_policy.sock \
  --socket review_approve=/run/conformance/review_approve.sock \
  --socket review_expire=/run/conformance/review_expire.sock \
  --socket review_reject=/run/conformance/review_reject.sock
```

Repeat `--socket SCENARIO=PATH` for every available server scenario. A scenario
whose implementation block has not landed must instead be named with
`--expected-absent SCENARIO=REASON`; an absent socket without that declaration
is failed. Client-only scenarios are reported as not applicable because their
`binds` value does not include `server`. Every result line contains the scenario
name, `proven`, `failed`, or `not-applicable`, and a reason. A run proves
conformance only if every server-bound scenario is proven. A disagreement makes
the run `failed`; an expected absence makes it `unknown`, with exit code 3, even
when another scenario was proven.

The default expects each per-user daemon to run as the invoking user. System
daemon tests name its numeric account with `--expected-uid`. The client checks
that identity before sending each request. `review_expire` waits 61 seconds by
default; a test harness can inject its clock through `SocketHarness` instead.

The repository acceptance suite uses the same mapping convention under
`SAYFIRST_CONFORMANCE_SOCKET_DIR`: it looks for `<scenario>.sock` there and
uses `SAYFIRST_CONFORMANCE_EXPECTED_UID` when the daemon does not run as the
test user. When the socket directory is not configured, each case is an
expected absence whose reason states that observed configuration fact. When it
is configured, the same inventory runs live and carries no absence claim.

## Distribution boundary

The reusable replayer and its HTTP-over-Unix-socket client remain in this
contract distribution. The client verifies the server's peer credential and
maps failures to `impostor`, `unreachable`, and `answer_unreadable`. The
socket client is published from `binding.http_unix_socket.client`; the replay
harness is in the sibling `replay` module.

This repository publishes the `sayfirst-conformance` distribution, the
`sayfirst_conformance` import package and the `sayfirst-conformance` script;
it also publishes the operator surface that inspects the daemon, from
`packages/cli`, as the distribution `sayfirstd`, the import package `sayfirstd`
and the console script `sayfirstd`. Each of those names is claimed once, by one
distribution, and `tests/test_client_distribution_names.py` holds that against
the `[project]` tables. The surface re-exports this operation as `sayfirstd
conformance replay` while depending on this contract and on no server
distribution.

The distribution `sayfirst-cli`, the import package `sayfirst_cli` and the
console script `sayfirst` belong to the product command-line interface and are
not published from this repository; the operator settled that on 2026-09-05.

This distribution installs no console script of its own, so nothing here is
bound to the name of a surface that forwards to it. The operator surface
`sayfirstd` is the one that reaches this operation today; the product
command-line interface may reach it through these same modules, and no release
of it does so yet.

## Server conformance replay

Run each server-bound scenario against a daemon instance already arranged for
that scenario:

```console
sayfirstd conformance replay \
  --socket allow=/run/conformance/allow.sock \
  --socket deny=/run/conformance/deny.sock \
  --socket missing_policy=/run/conformance/missing_policy.sock \
  --socket review_approve=/run/conformance/review_approve.sock \
  --socket review_expire=/run/conformance/review_expire.sock \
  --socket review_reject=/run/conformance/review_reject.sock
```

Repeat `--socket SCENARIO=PATH` for every available server scenario. A scenario
whose implementation block has not landed must instead be named with
`--expected-absent SCENARIO=REASON`; an absent socket without that declaration
is failed. Client-only scenarios are reported as not applicable because their
`binds` value does not include `server`. Every result line contains the scenario
name, `proven`, `failed`, or `not-applicable`, and a reason. A run proves
conformance only if it has no failed scenario and at least one proven scenario.

The default expects each per-user daemon to run as the invoking user. System
daemon tests name its numeric account with `--expected-uid`. The client checks
that identity before sending each request. `review_expire` waits 61 seconds by
default; a test harness can inject its clock through `SocketHarness` instead.

The repository acceptance suite uses the same mapping convention, reading the
socket directory from the environment — it looks for `<scenario>.sock` there —
and an expected numeric account from the environment when the daemon does not
run as the test user. The block that implements the suite fixes the two
variable names, so this document names none that nothing here reads. Until the daemon blocks land, each case is an expected absence with
its prerequisite stated in the test result.
