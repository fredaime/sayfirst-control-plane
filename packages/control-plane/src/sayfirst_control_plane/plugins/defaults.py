# SPDX-License-Identifier: Apache-2.0
"""Open providers shipped with the two plugin interfaces."""

from __future__ import annotations

from .interfaces import (
    APPROVAL_PROVIDER_INTERFACE,
    APPROVAL_PROVIDER_VERSION,
    PRIVACY_REDACTOR_INTERFACE,
    PRIVACY_REDACTOR_VERSION,
    ApprovalAction,
    ApprovalAlreadyExists,
    ApprovalAlreadyResolved,
    ApprovalRequest,
    ApprovalRequestMismatch,
    ResolvedApproval,
    SuspendedApproval,
)
from .privacy.none import NoRedaction
from .registration import PluginRegistration


class SingleApprover:
    """Resolve a suspended request with the first action from one person.

    The reference implementation of the port, kept in memory: what the
    conformance kit of article 8 is proven against and what its adversaries
    wrap to lie in one member at a time. The daemon composes the store-backed
    provider below instead, because a suspension has to outlive the call that
    opened it and be readable by reference — so this class is the port's
    worked example, not the deployment's provider.
    """

    def __init__(self) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        self._resolved: dict[str, ResolvedApproval] = {}

    def suspend(self, request: ApprovalRequest) -> SuspendedApproval:
        if request.approval_ref in self._pending or request.approval_ref in self._resolved:
            raise ApprovalAlreadyExists(f"approval {request.approval_ref!r} already exists")
        self._pending[request.approval_ref] = request
        return SuspendedApproval(request=request, scope=request.scope)

    def resume(self, suspended: SuspendedApproval, action: ApprovalAction) -> ResolvedApproval:
        approval_ref = suspended.approval_ref
        if action.approval_ref != approval_ref:
            raise ApprovalRequestMismatch(
                f"action for {action.approval_ref!r} cannot resolve {approval_ref!r}"
            )
        if action.scope != suspended.scope:
            raise ApprovalRequestMismatch(
                f"action scope {action.scope!r} cannot resolve scope {suspended.scope!r}"
            )
        if approval_ref in self._resolved:
            raise ApprovalAlreadyResolved(f"approval {approval_ref!r} is already resolved")
        request = self._pending.get(approval_ref)
        if request is None or request != suspended.request:
            raise ApprovalRequestMismatch(f"approval {approval_ref!r} is not this suspension")
        resolved = ResolvedApproval(
            approval_ref=approval_ref,
            decision_ref=request.decision_ref,
            scope=request.scope,
            person=action.person,
            resolution=action.resolution,
            reason=action.reason,
        )
        del self._pending[approval_ref]
        self._resolved[approval_ref] = resolved
        return resolved


NO_OP_PRIVACY_REGISTRATION = PluginRegistration(
    provider_name="none",
    interface_name=PRIVACY_REDACTOR_INTERFACE,
    interface_version=PRIVACY_REDACTOR_VERSION,
    factory=NoRedaction,
)


def _store_backed_approver() -> object:
    """The shipped one-person provider: the one that keeps its waits in the core's store.

    The name `single-approver` says « one person », which is what this is; what
    changed is where the wait lives. A registration's factory takes no
    arguments, so the provider brings a store of its own and the composition
    root reads it back, and the daemon and the provider keep one store.

    The import is inside the call because the provider lives in the
    application layer, which imports this package's port declarations: a
    module-level import here would make the two import each other.
    """
    from ..application.approvals import SimpleApprovalProvider

    return SimpleApprovalProvider()


SINGLE_APPROVER_REGISTRATION = PluginRegistration(
    provider_name="single-approver",
    interface_name=APPROVAL_PROVIDER_INTERFACE,
    interface_version=APPROVAL_PROVIDER_VERSION,
    factory=_store_backed_approver,
)
