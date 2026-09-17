<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirstd` — the operator surface

This distribution is the command the operator of a daemon of this repository
types. It inspects; it starts nothing.

```console
sayfirstd plugins list --config /etc/sayfirst/plugins.toml
sayfirstd whoami --socket /run/sayfirst/daemon.sock
sayfirstd status --socket /run/sayfirst/daemon.sock
sayfirstd conformance replay --socket allow=/run/conformance/allow.sock
```

## The three names

The distribution is `sayfirstd`, the import package is `sayfirstd`, and the
console script is `sayfirstd`. One name in all three forms, held by
`tests/test_client_distribution_names.py` against the `[project]` tables and
against the source tree.

The distribution `sayfirst-cli`, the import package `sayfirst_cli` and the
console script `sayfirst` were claimed here until 2026-09-05. Two repositories
claimed them, and the operator settled it: in all three forms they belong to the
product command-line interface, and are not published from this repository.
Nothing had been published under either claim (article 0), so the collision was
a fact about two source trees and is now closed in both.

`sayfirst` remains the project's public name wherever it names the *product*
— article 0, `TRADEMARKS.md`, the contract's attribute namespace, the sibling
distributions `sayfirst-contract`, `sayfirst-control-plane`,
`sayfirst-conformance` and `sayfirst-testing`. Only the three claims moved.

## Why `sayfirstd`

The conventional Unix shape: the daemon and the commands that inspect it share
one binary. Article 6's `whoami`, article 7's `status` and article 8's
`plugins list` all ask the daemon about itself, so they belong with it.

## What starts the daemon

Not this. `sayfirst-daemon serve`, from the `sayfirst-control-plane`
distribution, starts it. The two are not yet one binary because folding `serve`
in would make this distribution depend on the server it inspects, and article
14 points the dependency the other way: this package depends on
`sayfirst-contract` and on nothing else of this repository, which
`packages/cli/tests/test_plugins_list.py` holds. A remote operator forwards a
socket over SSH and inspects a daemon on a host where this wheel is the only
one installed (`docs/deployment.md`); a fold would put the whole server in that
install.

## What it answers, and what it forwards

`plugins list` is answered here: it reports configured selections against
discovered package metadata and against a recorded composition, and it claims no
provider is active that bootstrap would refuse. `whoami`, `status` and
`conformance replay` are handed whole to `sayfirst-contract`, which implements
them, so their parsers and exit codes stay in one place.

`status` reads the daemon's own account of itself over the same verified
connection `whoami` uses: the integrity grade of article 7 with its basis and
the interval it is re-evaluated on, the active privacy provider of article 11,
and whether evidence is being delivered. Each of those has a value for "the
daemon did not report it", and the command renders that value rather than a
plausible one (article 2).
