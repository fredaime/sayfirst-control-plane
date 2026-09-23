# SPDX-License-Identifier: Apache-2.0
"""The quickstart launcher: what starts a first per-user daemon, and is not the daemon.

It ships in the server's distribution, because it has to start the server and
there is nothing to install beside it, and it lives OUTSIDE the server's
package on purpose.

The server's package holds the control plane, and everything that package
writes down is a fact the control plane holds: article 3 has its information
contract declare each one as an authority or a projection, article 5 has each
one carry a scope, and a walk of that package fails on a durable write no
declaration owns. A launcher's files are none of those things. A log of what a
process printed, a note of which process was started, a starter file created
once for an administrator who owns it from then on — none is a governed record,
none has a scope, no decision is ever taken from any of them. Declaring them
there would have meant either calling them records they are not, or teaching
that contract a category for « not a fact of the control plane », which is a
change to what the contract means rather than an entry in it.

So the line is drawn where it already was: the daemon is `serve`, in its
package, under its contract, unchanged; this package is a program that writes
two starter files, starts that daemon, asks it whether it is up, and later asks
the kernel which process to stop. It imports the server's settings reader and
the contract's transport; the server imports it only to dispatch the two verbs.

What it persists is held where it is used: the lifecycle suite lists every name
it leaves under `~/.sayfirst/quickstart/`, with the permissions of each, and
fails on one more.
"""
