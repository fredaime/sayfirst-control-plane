<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirst-contract-stub`

A scriptable, **non-authoritative** fake of the control plane contract.

It exists so that a client can be exercised without a daemon: it answers the routes the binding
declares, from answers a test writes into it, and it decides nothing. Nothing it returns is a
decision of this control plane, and no deployment installs it to obtain one — it is installed by
the `stub` extra of `sayfirst-contract` and it belongs in a test environment.

What it is good for: proving that a client renders an answer as it was given, that it exits on the
code it published, and that it refuses a peer it did not verify. What it is not good for: any
claim about what the control plane would decide. For that, the conformance replay
(`sayfirst-conformance`) drives a real server against the published scenarios.

Licensed under the Apache License 2.0; see `LICENSE` and `NOTICE` in the distribution.
