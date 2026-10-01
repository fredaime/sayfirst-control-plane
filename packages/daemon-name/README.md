<!-- SPDX-License-Identifier: Apache-2.0 -->
# `sayfirst-daemon`

This distribution holds a name and installs one thing: the open control
plane's daemon, `sayfirst-control-plane`, at the same version.

The daemon's command is spelled `sayfirst-daemon`, so that is the name a
reader is most likely to hand an installer. This distribution makes that
install do what the reader meant:

```console
$ pip install sayfirst-daemon
$ sayfirst-daemon --help
```

It installs no code and declares no command of its own. The command arrives with
`sayfirst-control-plane`, which is where it is declared and documented:
[`packages/control-plane`](https://github.com/fredaime/sayfirst-control-plane/tree/main/packages/control-plane).

A tool installer that exposes only the commands of the package it was given
finds none here. Give it the owning distribution instead:

```console
$ uv tool install sayfirst-control-plane
```
