<!-- SPDX-License-Identifier: Apache-2.0 -->
# How sayfirst compares

Four names were put to this page, and they belong to five other projects: four
describe themselves as governance or control planes for AI agents, and one as a
private network for agents. This page sets their documented facts beside sayfirst's, one cell per
fact, each with the page it comes from. "Not documented" means the project's
public pages and code did not say, not that the feature is absent. Words such
as "tamper-proof" or "immutable" in another project's row are that project's
own claims, quoted, and not checked here.

Read on 2026-11-07. Projects change; a cell older than its source is a bug in
this page, and a report is welcome.

sayfirst is not a sandbox: a program that does not call the boundary is not
governed, and nothing here stops it. It provides a mechanism, never a
conformity ([`CONSTITUTION.md`](../CONSTITUTION.md), articles 2 and 11).

## Which projects these are

- **Nomotic** — [nomotic.ai](https://nomotic.ai): a hosted platform with an
  open-source runtime. Its runtime repository, `github.com/nomoticai/nomotic`,
  answered 404 on 2026-11-07, so what it said is cited from the
  [Internet Archive's copies](https://web.archive.org/web/*/github.com/nomoticai/nomotic),
  the one used here being of 10 March 2026.
- **TENIR-Gov** — [`skiredj-prog/tenir_governance`](https://github.com/skiredj-prog/tenir_governance),
  published on the package index as
  [`tenir-governance`](https://pypi.org/project/tenir-governance/).
- **agentmesh-control-plane** names two unrelated projects, and both are shown:
  - the package index project
    [`agentmesh-control-plane`](https://pypi.org/project/agentmesh-control-plane/),
    from [`microsoft/agent-governance-toolkit`](https://github.com/microsoft/agent-governance-toolkit),
    last published under that name as 3.7.0 and since renamed in its source;
  - the `agentmesh-control-plane` program of
    [`google/agentmesh`](https://github.com/google/agentmesh), a private network
    for agents rather than a product that calls itself governance.
- **Agentic Control Plane** — [agenticcontrolplane.com](https://agenticcontrolplane.com),
  a hosted product whose open core is
  [GatewayStack](https://github.com/agentic-control-plane/GatewayStack).

## The table

| | Transport and identity | Outcomes | Human approval | Evidence verifiability | Licence | Deployment scope |
|---|---|---|---|---|---|---|
| **sayfirst** | A Unix domain socket and nothing else, no TCP listener; the caller is identified by the kernel's peer credentials, with no token ([`SECURITY.md`](../SECURITY.md)) | allow, deny, suspend, closed at three; "could not ask" is its own result, never written as denied ([`CONSTITUTION.md`](../CONSTITUTION.md), article 1) | One person approves or rejects a suspension from the command line, before a deadline the policy sets; an approval authorises one execution ([README](../README.md)); every admitted principal may resolve any wait ([`docs/deployment.md`](deployment.md)) | Hash-chained record, exported as a bundle and checked offline with the contract distribution alone; graded observability or unverified, with no claim of proof or tamper detection, and no deployment of this version reaches evidence grade ([`SECURITY.md`](../SECURITY.md)) | Apache-2.0 ([`LICENSE`](../LICENSE)) | One host, per-user or system daemon; no fleet, no tenancy, no console; the boundary and packs are Python; Linux and macOS ([README](../README.md)) |
| **Nomotic** | Hosted REST API with a bearer API key ([docs](https://nomotic.ai/docs/authentication-and-api-keys/)); an MCP proxy ([integration](https://nomotic.ai/integration/)); the archived runtime was an in-process Python library ([archive](https://web.archive.org/web/*/github.com/nomoticai/nomotic)) | allow, escalate, deny in the hosted docs ([docs](https://nomotic.ai/docs/understanding-verdicts-allow-escalate-and-deny/)); the archived runtime listed allow, deny, escalate, block ([archive](https://web.archive.org/web/*/github.com/nomoticai/nomotic)) | Approval queue in a dashboard; an escalation expires after a policy window, 24 hours by default, and "an expired escalation is treated as a denial" ([docs](https://nomotic.ai/docs/escalations-approving-and-denying-agent-actions/)); its home page describes an "Approval queue with multi-sig" for its dashboard, and its paid plans' buttons read "Join Waitlist" ([site](https://nomotic.ai)) | SHA-256 hash chain; exports include it "so integrity can be independently verified"; calls the trail "tamper-proof" ([docs](https://nomotic.ai/docs/reading-the-audit-trail/)); how to verify offline: not documented | Hosted platform licence: not documented; the site's footer reads "All rights reserved" ([integration](https://nomotic.ai/integration/)); archived runtime Apache-2.0 ([archive](https://web.archive.org/web/*/github.com/nomoticai/nomotic)); SDK `managed-agents` MIT ([index](https://pypi.org/pypi/managed-agents/json)) | SaaS with dashboard; the runtime "free for self-hosted use"; on-premise and air-gapped deployment offered ([site](https://nomotic.ai)) |
| **TENIR-Gov** | HTTP API and Python SDK; "API token is a shared bearer credential, not per-user IAM" ([security](https://github.com/skiredj-prog/tenir_governance/blob/main/SECURITY.md)) | pass, flag, hold, hard veto ([code](https://github.com/skiredj-prog/tenir_governance/blob/main/tenir_governance/composition/decisions.py)); for its demonstrator policy profile, pass, flag and hard veto are mapped to allow, allow with alert and block, and hold is not mapped ([README](https://github.com/skiredj-prog/tenir_governance/blob/main/README.md)) | A hold waits for approval given through a Python call; an unresolved hold fails closed when it expires ([code](https://github.com/skiredj-prog/tenir_governance/blob/main/tenir_governance/operations/hold.py)) | SHA-256 chain with Merkle proofs served through the authenticated API; "tamper evidence, not resistance against a compromised host or administrator" ([security](https://github.com/skiredj-prog/tenir_governance/blob/main/SECURITY.md)); third-party offline verification: not documented | Apache-2.0 ([pyproject](https://github.com/skiredj-prog/tenir_governance/blob/main/pyproject.toml)) | Self-hosted, "bounded to a single host"; Python ([README](https://github.com/skiredj-prog/tenir_governance/blob/main/README.md)) |
| **agentmesh-control-plane** (Microsoft package) | In-process Python library; the agent is named by an `agent_id` string ([module](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-os/modules/control-plane)); caller authentication: not documented | Verdicts allowed or blocked ([code](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/flight_recorder.py)); rule types allow, deny, require approval ([code](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/constraint_graphs.py)) | A require-approval rule type exists ([code](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/constraint_graphs.py)); an approval workflow, interface or deadline: not documented | SQLite log with a SHA-256 hash chain and an integrity check; its code calls this "tamper-proof integrity" ([code](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/flight_recorder.py)); third-party offline verification: not documented | MIT ([index](https://pypi.org/pypi/agentmesh-control-plane/json)) | Local Python library, "Public Preview" ([module](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-os/modules/control-plane)); console: not documented |
| **agentmesh-control-plane** (Google Agent Mesh) | Control plane off the data path ([docs](https://github.com/google/agentmesh/blob/main/site/content/docs/concepts/architecture.md)); a node enrols with an OpenID Connect or bootstrap token and receives "a short-lived, offline-verifiable credential bound to the node's own key" ([README](https://github.com/google/agentmesh/blob/main/README.md)) | allow or deny per call, enforced at the destination node ([docs](https://github.com/google/agentmesh/blob/main/site/content/docs/concepts/authorization.md)) | An approval queue for node enrolment ([docs](https://github.com/google/agentmesh/blob/main/site/content/docs/reference/control-plane.md)); per-action approval: not documented | One "Audit Traceability" log line per decision on the node ([docs](https://github.com/google/agentmesh/blob/main/site/content/docs/guides/egress-destinations.md)); integrity of those logs: not documented | Apache-2.0 ([README](https://github.com/google/agentmesh/blob/main/README.md)) | Self-hosted: one binary with a web console, Cloud Run; pre-1.0 ([README](https://github.com/google/agentmesh/blob/main/README.md)); a Helm chart ([guide](https://github.com/google/agentmesh/blob/main/site/content/docs/guides/kubernetes.md)) |
| **Agentic Control Plane** (GatewayStack) | Hosted gateway reached by agent hooks ([docs](https://agenticcontrolplane.com/docs/policies)) or a REST API, with a bearer API key ([docs](https://agenticcontrolplane.com/docs/api/)); the open core is server middleware that verifies RS256 tokens from your OpenID Connect provider ([README](https://github.com/agentic-control-plane/GatewayStack/blob/main/README.md)) | allow, flag, ask, deny in the hosted product ([docs](https://agenticcontrolplane.com/docs/policies)); allow or deny, deny by default, in the open core ([code](https://github.com/agentic-control-plane/GatewayStack/blob/main/packages/validatabl-core/src/types.ts)) | Console page and an email to the workspace owner; an approval "grants a single retry of the exact action within the grant window"; 24-hour default hold; unanswered requests count as denied; standing "Allow always" rules ([docs](https://agenticcontrolplane.com/docs/approvals)) | Per-call records it calls "immutable" ([guide](https://agenticcontrolplane.com/guides/soc2-audit-trails)), kept 12 months in the hosted product, Enterprise workspaces indefinitely ([trust](https://agenticcontrolplane.com/trust)); hash chain, signatures or offline verification: not documented | GatewayStack MIT; the hosted product is a service whose licence is not stated ([README](https://github.com/agentic-control-plane/GatewayStack/blob/main/README.md)) | Hosted console on Google Cloud, a local mode, and a self-hostable open core in TypeScript ([trust](https://agenticcontrolplane.com/trust)) |

## Where sayfirst is weaker

- **No fleet, no tenancy, no console.** One daemon governs one host. Nomotic,
  Agentic Control Plane and Google's Agent Mesh each document a web console;
  sayfirst has none, and its constitution keeps fleets, tenancy and consoles
  out of the open core on purpose (article 1).
- **Python only.** The boundary and the instrumentation packs are for Python
  programs. A program in another language can only ask by implementing the
  socket contract itself. Nomotic's REST API, GatewayStack's TypeScript
  middleware and Agent Mesh's JavaScript, Python and Go SDKs reach further.
- **Observability grade, at best.** In the common per-user setup the governed
  program can write the evidence store, so the chain detects accidental
  corruption only and makes no claim of proof or tamper detection. No
  deployment of this version reaches evidence grade, because no store adapter
  can yet prove that the governed program cannot write the store
  ([`SECURITY.md`](../SECURITY.md)).
- **One approver, from a terminal.** One person approves or rejects a
  suspension, with the command line; there is no console, email or chat
  approval, and approval by two people is not in the open core (article 12).
  Nomotic's home page describes a multi-signature approval queue, beside paid
  plans that are on a waitlist.
- **Local only.** The socket is the only way in. A program on another host can
  ask only through the socket forwarded onto this host, where it arrives as an
  account of this host ([`docs/deployment.md`](deployment.md)); nothing here is
  a hosted service.
- **Young and small.** Version 0.3.3, with one maintainer
  ([`GOVERNANCE.md`](../GOVERNANCE.md)).

## Where it differs by design

- **No credential to steal.** Identity comes from the kernel at `accept()`, not
  from an API key or a token the program holds.
- **"Could not ask" is never written as an answer.** When nobody can be asked,
  an effect that has not started does not start, and the program is told so in
  its own words, exit `4`, never as a denial (article 1).
- **The verifier says what it could not check.** A bundle taken while the
  daemon's epoch is open reports coverage `unknown`, and a decision a person
  granted re-derives as `unverifiable`, rather than either being counted as a
  pass ([README](../README.md)).
- **The grade is computed, printed, and stated as a limit.** The daemon
  reports, for every connection, the grade its access allows, and the
  documentation states what that grade does not support.
