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

Run each server-bound scenario — every row of the table above whose `binds` is
`both` or `server` — against a daemon instance already arranged for that
scenario:

```console
sayfirst-conformance replay \
  --socket allow=/run/conformance/allow.sock \
  --socket deny=/run/conformance/deny.sock \
  --socket grant_miss_after_policy_version_change=/run/conformance/grant_miss_after_policy_version_change.sock \
  --socket missing_policy=/run/conformance/missing_policy.sock \
  --socket no_grant_on_deny=/run/conformance/no_grant_on_deny.sock \
  --socket no_grant_without_signal_channel=/run/conformance/no_grant_without_signal_channel.sock \
  --socket policy_unavailable_is_could_not_ask=/run/conformance/policy_unavailable_is_could_not_ask.sock \
  --socket review_approve=/run/conformance/review_approve.sock \
  --socket review_expire=/run/conformance/review_expire.sock \
  --socket review_reject=/run/conformance/review_reject.sock \
  --socket strictest_rule_wins=/run/conformance/strictest_rule_wins.sock
```

Name every server-bound scenario once: with `--socket SCENARIO=PATH`, or, for
one the deployment cannot arrange a daemon for, with
`--expected-absent SCENARIO=REASON`. A scenario named by neither has no daemon
to replay against, and it fails. Client-only scenarios are reported as not
applicable because their `binds` value does not include `server`. Every result
line contains the scenario name, `proven`, `failed`, or `not-applicable`, and a
reason, and the last line is the whole run's verdict: `proven` when every
server-bound scenario is proven, `failed` when any one failed, and `unknown`
when none failed and not every one was replayed — an expected absence, or a
platform the client cannot verify a peer on — even when another scenario was
proven. The exit status is that verdict's: `0` proven, `1` failed, `3` unknown.
An invalid invocation replays nothing and exits `2`.

Three arrangements are the deployment's to make, and the command reaches the one it
can. The daemon for `grant_miss_after_policy_version_change` is asked the same
question twice and must answer the second under a policy that denies it: name the
deployment's own command with `--change-policy-command CMD`. The replayer runs it once,
between the two asks, split without a shell, with `SAYFIRST_CONFORMANCE_SCENARIO` and
`SAYFIRST_CONFORMANCE_POLICY` (the scripted policy as JSON, `{"example.effect": "deny"}`)
in its environment; it writes the policy the daemon must answer under and exits `0`
once the daemon has read it — for this daemon, as soon as the new file is completely
written, because it reads its policy afresh for every decision. A non-zero
exit, a command that cannot be run, or one that outlasts `--change-policy-timeout`
(default 30 seconds) fails that scenario and says which. A socket for that scenario
with no command is an invalid invocation (`2`): the run could only fail.

Such a command can be a few lines of `sh`. This one, installed as
`/usr/local/bin/conformance-deny-example-effect`, writes a policy denying
`example.effect` to the policy file that daemon's `--config` names, and returns once
the new policy is in place — this daemon reads the policy file as it is when a question
arrives, so the command need only return once the new file is completely written (another
daemon may need the command to wait for its own reload):

```sh
#!/bin/sh
# SAYFIRST_CONFORMANCE_POLICY is {"example.effect": "deny"} for this scenario.
policy=/etc/sayfirst/conformance/grant-miss/policy.toml
cat > "$policy.tmp" <<'EOF'
format = 1
[revision]
reason = "conformance: example.effect denied"
[[rule]]
id = "changed"
capability = "example.effect"
scope = "local"
principals = ["user:conformance"]
outcome = "deny"
reason = "changed"
EOF
mv "$policy.tmp" "$policy"
```

The path and the principal are this example's, not a convention: write to the policy
path your daemon's configuration names, for the account the replay asks as.

The daemon for `policy_unavailable_is_could_not_ask` must be unable to read its
policy when it is asked; since a daemon refuses to start on a policy it cannot read, the file is removed
after the start. The daemons for the three that end a wait serve both approval
operations — the one for `review_expire` suspending with a wait shorter than the
replay's `--deadline-wait-seconds`, and rendering it `expired` as of the instant a
read is taken, not only after a sweep it schedules itself.

A replay leaves its daemons as it found them only where the scenario says so: a wait
it rejected stays rejected until its deadline. Replay against freshly started daemons;
a second run against the same ones is a different run.

The request a scenario scripts is the request the replayer sends:
`no_grant_without_signal_channel` asks for the answer that carries no event stream.

A complete run adds the policy-change command to the sockets above:

```console
sayfirst-conformance replay \
  --socket allow=/run/conformance/allow.sock \
  --socket deny=/run/conformance/deny.sock \
  --socket grant_miss_after_policy_version_change=/run/conformance/grant_miss_after_policy_version_change.sock \
  --socket missing_policy=/run/conformance/missing_policy.sock \
  --socket no_grant_on_deny=/run/conformance/no_grant_on_deny.sock \
  --socket no_grant_without_signal_channel=/run/conformance/no_grant_without_signal_channel.sock \
  --socket policy_unavailable_is_could_not_ask=/run/conformance/policy_unavailable_is_could_not_ask.sock \
  --socket review_approve=/run/conformance/review_approve.sock \
  --socket review_expire=/run/conformance/review_expire.sock \
  --socket review_reject=/run/conformance/review_reject.sock \
  --socket strictest_rule_wins=/run/conformance/strictest_rule_wins.sock \
  --change-policy-command /usr/local/bin/conformance-deny-example-effect \
  --deadline-wait-seconds 5
```

A run that names every server-bound scenario and the policy-change command is
complete, and proves a conforming daemon with exit 0.

`sayfirstd conformance replay` is the same replay under the operator surface:
the same options, the same whole-run line and the same exit statuses. Its
scenario lines carry the name, the verdict and the reason; those of
`sayfirst-conformance` add whether the scenario binds the server and how many
expected members its verdict rests on.

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
contract distribution. The client verifies the server's peer credential through
the same adapters as the transport client, `transport.peer`, and maps failures
to `impostor`, `peer_credential_unavailable`, `unreachable`, and
`answer_unreadable`. A platform no adapter covers is not applicable to a
replay, and on the path a boundary asks through, `hold_decision`, it is the
could-not-ask `peer_identity_unsupported`. The socket client is published from
`binding.http_unix_socket.client`; the replay harness is in the sibling
`replay` module.

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
