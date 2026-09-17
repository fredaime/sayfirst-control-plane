<!-- SPDX-License-Identifier: Apache-2.0 -->
# sayfirst-boundary

The in-process boundary. A governed program opens `Boundary.request(...)` around
an effect; the decision lands before the body runs, or the body does not run.

This distribution holds no policy and decides nothing. It asks the control plane
over a socket whose peer it verified, caches an `allow` as a grant for exactly
the question it answers, and stops honouring that grant the moment any of four
things happens: the connection carrying it ends, its lifetime runs out, the
policy version it was issued under changes, or the control plane goes silent for
a lifetime.

It publishes no exit codes. Outcomes leave as exceptions, and a caller that runs
a process decides what to exit with.
