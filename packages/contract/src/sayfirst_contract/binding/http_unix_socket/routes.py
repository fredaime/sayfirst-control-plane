# SPDX-License-Identifier: Apache-2.0
"""The binding-owned route table and its domain operation names."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

ACCEPT_HEADER: Final = "Accept"
DOCUMENT_MEDIA_TYPE: Final = "application/json"
STREAM_MEDIA_TYPE: Final = "text/event-stream"


def selects_stream(accept: str | None) -> bool:
    """Answer which of the two published 200 media types a request selects.

    An operation that publishes a stream beside a document answers the stream
    when, and only when, the request explicitly accepts the stream media type
    with a non-zero quality. Anything else — no header, a wildcard, an
    unreadable quality — selects the document, because the document is the
    answer that carries no connection-bound state (articles 10 and 13).

    Nothing else conditions the choice: an answer that mints no grant is still
    served as the stream the request selected, one frame and then the close.
    The published selector names the 200 response it governs, because a
    refusal publishes one media type and there is nothing to choose.
    """
    for entry in (accept or "").split(","):
        parts = [part.strip() for part in entry.split(";")]
        if parts[0].lower() != STREAM_MEDIA_TYPE:
            continue
        qualities = [part[2:] for part in parts[1:] if part[:2].lower() == "q="]
        if not qualities:
            return True
        try:
            if float(qualities[0]) > 0:
                return True
        except ValueError:
            return False
    return False


@dataclass(frozen=True)
class Route:
    operation: str
    method: str
    path: str
    request: str | None
    response: str
    problems: Mapping[int, tuple[str, ...]]
    stream: tuple[str, ...] = ()


ROUTES: Final[tuple[Route, ...]] = (
    Route(
        "read_status",
        "GET",
        "/status",
        None,
        "status-result",
        {
            403: ("principal_refused", "peer_not_admitted", "peer_uid_unmapped"),
            500: ("internal",),
            503: ("peer_credential_unavailable", "principal_groups_unavailable"),
        },
    ),
    Route(
        "read_whoami",
        "GET",
        "/whoami",
        None,
        "whoami-result",
        {
            403: ("peer_not_admitted", "peer_uid_unmapped"),
            500: ("internal",),
            503: ("peer_credential_unavailable",),
        },
    ),
    Route(
        "ask_decision",
        "POST",
        "/decisions",
        "decision-ask-request",
        "decision-result",
        {
            400: (
                "request_malformed",
                "member_unknown",
                "generation_missing",
                "generation_unreadable",
                "delegation_invalid",
            ),
            403: (
                "principal_refused",
                "scope_refused",
                "peer_not_admitted",
                "peer_uid_unmapped",
                "policy_writable_by_principal",
                "configuration_writable_by_principal",
            ),
            409: ("generation_unsupported",),
            500: ("internal",),
            503: (
                "policy_unavailable",
                "approval_provider_unavailable",
                "decision_contended",
                "decision_store_unavailable",
                "policy_archive_unavailable",
                "peer_credential_unavailable",
                "principal_groups_unavailable",
            ),
        },
        ("decision-result", "grant-signal"),
    ),
    Route(
        "read_decision",
        "GET",
        "/decisions/{decision_ref}",
        None,
        "decision-record",
        {
            400: ("scope_required", "generation_missing", "generation_unreadable"),
            403: ("principal_refused",),
            404: ("decision_not_found",),
            409: ("generation_unsupported",),
            500: ("internal",),
            503: ("decision_store_unavailable",),
        },
    ),
    Route(
        "read_policy_status",
        "GET",
        "/policy/status",
        None,
        "policy-status",
        {
            400: ("generation_missing", "generation_unreadable"),
            403: ("principal_refused",),
            409: ("generation_unsupported",),
            500: ("internal",),
        },
    ),
    Route(
        "read_approval",
        "GET",
        "/approvals/{approval_ref}",
        None,
        "approval-result",
        {
            400: ("scope_required", "generation_missing", "generation_unreadable"),
            403: ("principal_refused", "peer_not_admitted", "peer_uid_unmapped"),
            404: ("approval_unknown",),
            409: ("generation_unsupported",),
            500: ("internal",),
            503: ("peer_credential_unavailable", "principal_groups_unavailable"),
        },
    ),
    Route(
        "resolve_approval",
        "POST",
        "/approvals/{approval_ref}/resolution",
        "approval-resolve-request",
        "approval-result",
        {
            400: (
                "request_malformed",
                "member_unknown",
                "generation_missing",
                "generation_unreadable",
            ),
            403: (
                "principal_refused",
                "scope_refused",
                "peer_not_admitted",
                "peer_uid_unmapped",
            ),
            404: ("approval_unknown",),
            409: ("generation_unsupported", "approval_resolved"),
            500: ("internal",),
            503: (
                "approval_provider_unavailable",
                "peer_credential_unavailable",
                "principal_groups_unavailable",
            ),
        },
    ),
    Route(
        "read_evidence",
        "GET",
        "/scopes/{scope}/evidence",
        None,
        "evidence-page-result",
        {
            400: (
                "scope_required",
                "scope_invalid",
                "evidence_range_invalid",
                "generation_missing",
                "generation_unreadable",
            ),
            # These reads never consult a permission, so they never answer the
            # code that says a principal may not write the scope (article 2).
            403: ("principal_refused",),
            409: ("generation_unsupported",),
            500: ("internal",),
            503: ("evidence_store_unavailable",),
        },
    ),
    Route(
        "export_evidence",
        "GET",
        "/scopes/{scope}/evidence/export",
        None,
        "evidence-export-result",
        {
            400: (
                "scope_required",
                "scope_invalid",
                "evidence_range_invalid",
                "generation_missing",
                "generation_unreadable",
            ),
            # These reads never consult a permission, so they never answer the
            # code that says a principal may not write the scope (article 2).
            403: ("principal_refused",),
            409: ("generation_unsupported",),
            500: ("internal",),
            503: ("evidence_store_unavailable",),
        },
    ),
)
