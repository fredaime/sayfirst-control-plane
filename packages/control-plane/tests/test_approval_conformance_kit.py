# SPDX-License-Identifier: Apache-2.0
"""The kit judged by its own catalogue: article 8's sentence, made testable.

"The project ships a conformance kit … a provider that does not pass it is not a
provider." That sentence is a claim about the kit, and article 2 makes it no
stronger than the evidence held for it. The evidence is here: the kit fails every
deliberately wrong provider it ships, under its own fixture and under every
deliberately wrong fixture a provider could bring, and still passes the open
core's honest one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sayfirst.testing import (
    ADVERSARIAL_APPROVAL_PROVIDERS,
    ADVERSARIAL_COMPLETION_FIXTURES,
    ApprovalProviderContract,
    unsupported_by_acts,
)
from sayfirst_control_plane.plugins.defaults import SingleApprover
from sayfirst_control_plane.plugins.interfaces import (
    ApprovalAction,
    ApprovalAlreadyResolved,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ApprovalResolution,
    ResolvedApproval,
    SuspendedApproval,
)

REQUIRED_LIES = frozenset(
    {
        "inverts-the-verdict",
        "approves-on-rejection",
        "re-attributes-the-act",
        "answers-for-another-approval",
        "answers-for-another-decision",
        "answers-for-another-scope",
        "resolves-with-no-act",
        "rewrites-itself-after-the-check",
        "rewrites-the-act-put-to-it",
        "rewrites-the-suspension-put-to-it",
        "rewrites-the-request-put-to-suspend",
    }
)

ADVERSARY_IDS = [item.name for item in ADVERSARIAL_APPROVAL_PROVIDERS]
FIXTURE_IDS = [item.name for item in ADVERSARIAL_COMPLETION_FIXTURES]


def _kit_callers_of(member: str) -> set[str]:
    """The kit's own functions that call ``member`` on the provider."""
    source = Path(ApprovalProviderContract.__module__.replace(".", "/"))
    module = Path(__file__).parents[1] / "src" / f"{source}.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    return {
        function.name
        for function in ast.walk(tree)
        if isinstance(function, ast.FunctionDef)
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == member
    }


@pytest.mark.parametrize(("member", "seam"), [("resume", "_answer"), ("suspend", "_suspend")])
def test_the_kit_puts_every_call_through_the_one_guarded_seam(member: str, seam: str) -> None:
    """The rule is structural: no path in the kit may call a provider unjudged.

    A path added later that called ``resume`` directly would be a path the
    derivation rule does not see — which is exactly how the list-of-paths kit
    kept re-opening. This fails such a path at the moment it is written.

    ``suspend`` is the same rule and was not held to it: two paths called it
    directly, each keeping the request it had just handed over, so a provider
    that rewrote that request in place was judged by what it wrote.
    """
    assert _kit_callers_of(member) == {seam}


def test_the_catalogue_names_every_lie_the_kit_must_catch() -> None:
    lies = {item.lie for item in ADVERSARIAL_APPROVAL_PROVIDERS}

    assert lies >= REQUIRED_LIES
    assert len({item.name for item in ADVERSARIAL_APPROVAL_PROVIDERS}) == len(
        ADVERSARIAL_APPROVAL_PROVIDERS
    )


@pytest.mark.parametrize("adversary", ADVERSARIAL_APPROVAL_PROVIDERS, ids=ADVERSARY_IDS)
def test_the_kit_fails_every_adversary_in_its_own_catalogue(adversary) -> None:  # type: ignore[no-untyped-def]
    """Article 8: a provider that does not pass the kit is not a provider."""
    with pytest.raises(AssertionError):
        ApprovalProviderContract().assert_conforms(adversary.factory)


@pytest.mark.parametrize("fixture", ADVERSARIAL_COMPLETION_FIXTURES, ids=FIXTURE_IDS)
@pytest.mark.parametrize("adversary", ADVERSARIAL_APPROVAL_PROVIDERS, ids=ADVERSARY_IDS)
def test_no_adversary_escapes_through_the_fixture_it_supplies(adversary, fixture) -> None:  # type: ignore[no-untyped-def]
    """The fixture owns the people; it never owns which act the case puts."""
    with pytest.raises(AssertionError):
        ApprovalProviderContract(completion_actions=fixture.fixture).assert_conforms(
            adversary.factory
        )


@pytest.mark.parametrize("fixture", ADVERSARIAL_COMPLETION_FIXTURES, ids=FIXTURE_IDS)
def test_an_honest_provider_cannot_be_passed_by_a_dishonest_fixture(fixture) -> None:  # type: ignore[no-untyped-def]
    """Even the open core's provider fails a fixture that does not put the case."""
    with pytest.raises(AssertionError):
        ApprovalProviderContract(completion_actions=fixture.fixture).assert_conforms(SingleApprover)


def test_the_kit_still_passes_the_honest_provider_it_must_not_fail() -> None:
    """Non-vacuity: a kit that failed everything would prove nothing."""
    ApprovalProviderContract().assert_conforms(SingleApprover)


REQUESTED_AT_HINT = "conformance"


def _request() -> ApprovalRequest:
    from sayfirst.testing.approval import DEADLINE, REQUESTED_AT

    return ApprovalRequest(
        approval_ref="approval-1",
        decision_ref="decision-1",
        scope="scope-a",
        capability="storage.write",
        requested_at=REQUESTED_AT,
        deadline=DEADLINE,
    )


def _act(request: ApprovalRequest, resolution: ApprovalResolution) -> ApprovalAction:
    return ApprovalAction(
        approval_ref=request.approval_ref,
        scope=request.scope,
        person="uid:1000",
        resolution=resolution,
        reason="reviewed",
    )


def _resolved(request: ApprovalRequest, **changes: object) -> ResolvedApproval:
    members: dict[str, object] = {
        "approval_ref": request.approval_ref,
        "decision_ref": request.decision_ref,
        "scope": request.scope,
        "person": "uid:1000",
        "resolution": ApprovalResolution.APPROVE,
        "reason": "reviewed",
    }
    members.update(changes)
    return ResolvedApproval(**members)  # type: ignore[arg-type]


def test_the_derivation_rule_supports_exactly_what_the_acts_say() -> None:
    """The one relation, stated directly: what the acts support, and nothing else."""
    request = _request()
    acts = (_act(request, ApprovalResolution.APPROVE),)

    assert unsupported_by_acts(_resolved(request), request, acts) is None
    assert unsupported_by_acts(SuspendedApproval(request, request.scope), request, ()) is None
    assert unsupported_by_acts(_resolved(request), request, ()) == (
        "no act of any person was put to it"
    )
    assert "another approval" in str(
        unsupported_by_acts(_resolved(request, approval_ref="other"), request, acts)
    )
    assert "another decision" in str(
        unsupported_by_acts(_resolved(request, decision_ref="other"), request, acts)
    )
    assert "another scope" in str(
        unsupported_by_acts(_resolved(request, scope="other"), request, acts)
    )
    assert "attributes the act" in str(
        unsupported_by_acts(_resolved(request, person="other"), request, acts)
    )
    assert "where the person's act was" in str(
        unsupported_by_acts(_resolved(request, resolution=ApprovalResolution.REJECT), request, acts)
    )
    assert "rewrites the reason" in str(
        unsupported_by_acts(_resolved(request, reason="invented"), request, acts)
    )


class HonestApproverRefusingWithTheOtherError(SingleApprover):
    """An honest provider whose refusals raise the other shipped error.

    Article 8 makes the kit the contract, so what the kit demands is part of the
    contract and must be published. `ApprovalProviderError` is the base the two
    shipped errors share; a provider that refuses with either of them refuses.
    """

    def resume(
        self, suspended: SuspendedApproval, action: ApprovalAction
    ) -> SuspendedApproval | ResolvedApproval:
        try:
            return super().resume(suspended, action)
        except ApprovalAlreadyResolved as resolved:
            raise ApprovalRequestMismatch(str(resolved)) from None
        except ApprovalRequestMismatch as mismatch:
            raise ApprovalAlreadyResolved(str(mismatch)) from None


def test_the_kit_accepts_any_refusal_the_published_base_error_names() -> None:
    """The kit judges that a provider refused, never which error it chose."""
    ApprovalProviderContract().assert_conforms(HonestApproverRefusingWithTheOtherError)
