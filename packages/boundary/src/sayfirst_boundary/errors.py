# SPDX-License-Identifier: Apache-2.0
"""The outcomes a caller catches.

Article 1 closes the outcome set: allow, deny, suspend. Article 2 insists on the
fourth thing, which is not an outcome — the question could not be asked — and on
its never being rendered as a refusal. So there are four types here, none of
them a subclass of another, and an `allow` is not among them because an allow is
the body running.

`CouldNotAsk` shares a name with `sayfirst_contract.client.CouldNotAsk`
deliberately: the phrase is the project's, and the two are different kinds of
thing in different namespaces — that one is a RESULT a client returns, this one
is an EXCEPTION a caller catches. Importing both in one module is the only place
the collision can bite, and an explicit import says which is meant.

This module publishes no exit code. `sayfirst_contract.transport.cli` publishes
`EXIT_OK`, `EXIT_REFUSED`, `EXIT_COULD_NOT_ASK` and `EXIT_MISUSE`; the two codes
for deny and suspend belong to the product command-line interface, which is
another repository's distribution. A library that chose a process's exit status
would be deciding something that is not its to decide.
"""

from __future__ import annotations


class BoundaryError(Exception):
    """Base of every outcome that stops the body from running."""


class Denied(BoundaryError):
    """The control plane answered `deny`. An answer, not a failure to obtain one."""

    def __init__(self, *, decision_ref: str, capability: str, reason: str) -> None:
        super().__init__(f"denied: {capability} ({reason}, {decision_ref})")
        self.decision_ref = decision_ref
        self.capability = capability
        self.reason = reason


class Suspended(BoundaryError):
    """The control plane answered `suspend`: the effect waits for a person.

    Raised rather than waited on. Article 10 refuses a decision round trip per
    operation because it "does not survive contact with a real workload"; a
    thread parked until a human answers survives it even less. The caller
    decides how to suspend — a graph checkpoints, a worker requeues, a script
    ends — and this type carries the reference that person will answer.
    """

    def __init__(self, *, approval_ref: str, decision_ref: str, capability: str) -> None:
        super().__init__(f"suspended: {capability} awaits approval {approval_ref}")
        self.approval_ref = approval_ref
        self.decision_ref = decision_ref
        self.capability = capability


class AskRefused(BoundaryError):
    """The question was received and rejected. Distinct from `deny`, which answers it."""

    def __init__(self, *, problem_code: str, detail: str) -> None:
        super().__init__(f"refused: {problem_code}: {detail}")
        self.problem_code = problem_code
        self.detail = detail


class CouldNotAsk(BoundaryError):
    """No answer was obtained, and that is never permission.

    Doctrine D4: the absence of a refusal is not a refusal, and it is not an
    allowance either. The body does not run.
    """

    def __init__(self, *, detail: str, retryable: bool) -> None:
        super().__init__(f"could not ask: {detail}")
        self.detail = detail
        self.retryable = retryable
