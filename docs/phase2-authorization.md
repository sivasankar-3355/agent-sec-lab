# Phase 2 — Authorization & Policy Enforcement

This document describes the authorization architecture added in Phase 2. It
builds on Phase 1's identity model (HS256 user JWTs at the gateway, RS256
workload/run JWTs issued only by the STS).

## 1. Goals

- Every agent independently decides whether an incoming request is authorized,
  even if the requesting agent is compromised ("compromise-tolerant" design).
- Default deny, least privilege, fail closed.
- Authorization context is taken from **verified** state (signed tokens and
  trusted repositories), never from request bodies or model output.
- All decisions are audited.

## 2. RBAC model

Roles are bound to workload identities (agents/gateway) and to user scopes:

| Principal (role)            | Allowed operations                                                        |
|-----------------------------|---------------------------------------------------------------------------|
| `workload:gateway`          | Dispatch `run.start` to the orchestrator; API calls on behalf of a user.  |
| `workload:orchestrator`     | `tasks/send` (and poll/cancel) to `recon`, `knowledge`, `report` only.    |
| `workload:recon`            | `recon.run` on approved targets.                                          |
| `workload:knowledge`        | `knowledge.search` / `knowledge.index` on accessible documents.           |
| `workload:report`           | `report.generate` for the run's owner.                                    |
| user (`sub = user:<id>`)    | API actions whose scope is present in the user JWT (`runs:create`,
                               `runs:read`, `knowledge:write`, `knowledge:read`).        |

Capability data lives in `policies/v1/authz.rego` (`recon_actions`,
`knowledge_actions`, `report_actions`, `api_scopes`, `child_agents`).

## 3. ABAC attributes

Each PEP provides a normalized attribute set to OPA:

| Attribute | Source | Trust |
|---|---|---|
| `workload` | verified token actor/caller | trusted |
| `agent` | receiving agent identity | trusted (process) |
| `user` | verified token subject | trusted |
| `runId` | verified token run grant | trusted |
| `approvedTargets` | verified token (`reg.targets`) | trusted |
| `approvedActions` | verified token (`reg.actions`) | trusted |
| `tenantId` | verified token (`reg.tenantId`) | trusted |
| `requestedAction` / `requestedTarget` / `requestedRunId` / `requestedDocIds` | request body | **untrusted intent, bounded by policy** |
| `resourceOwner` / `resourceTenantId` | trusted repository lookup at the enforcing agent | trusted |
| `scopes` | user JWT scopes | trusted |

The policy only ever compares untrusted `requested*` values against trusted
`approved*` / `resource*` values. A compromised caller can lower its own
intent but cannot widen it.

## 4. OPA architecture

```
            ┌─────────────────────────┐
  PEPs ───▶ │  PolicyEngine (OPA)      │ ──▶ { allow: bool, rule, reason }
 (a2a, api, │  • embedded Rego engine  │
  executor, │  • or remote OPA_URL     │
  orchestr.)└─────────────────────────┘
```

- **Central decision**: one Rego package `agentseclab.authz`, versioned under
  `policies/v1/authz.rego` (`version := "1.0.0"`).
- **Evaluation interface**: `PolicyEngine.evaluate(input)` returns
  `{ allowed, rule?, reason? }`. Two implementations:
  - `EmbeddedRegoPolicyEngine` — evaluates the checked-in bundle in-process
    (local dev / tests / single-binary deploys).
  - `OpaHttpPolicyEngine` — `POST $OPA_URL/v1/data/agentseclab/authz` with
    `{ input }` and reads `result.allow` (production OPA sidecar).
- **Input schema**: `{ kind, version, attributes, context }` (see
  `src/security/opa/types.ts`).
- **Policy versioning**: the bundle directory (`policies/v1`) selects the
  version; the file declares the semantic version (`1.0.0`), which is recorded
  on every audit event. New versions are added as `policies/v2`, and
  `OPA_POLICY_VERSION` selects one.
- **OPA never trusts unverified context**: `approved*`, `resource*`, `user`,
  `workload` are populated by the PEP from verified state. OPA also receives a
  `context.decisionId` for correlation and refuses anything not explicitly
  allowed (`default allow := false`).

The embedded engine implements a deliberately restricted Rego subset
(`==`, `!=`, `in`, conjunctive bodies, single-line collections, boolean rules).
The `.rego` file is kept within that subset, so the same file behaves
identically in a real OPA. The embedded engine is not a general Rego runtime.

## 5. Rego policy summary

File: `policies/v1/authz.rego`

- Discovery: `initialize` / `agentCard` for any authenticated workload.
- Gateway → orchestrator `run.start`, bound to the run grant.
- Orchestrator → child `tasks/send` / `message/send`, with per-agent action
  ceilings and (for recon) target-in-scope; poll/cancel for held runs.
- Operation-level (executors): recon target in scope; knowledge document
  ownership + tenant; report run ownership + tenant.
- API: action ∈ `api_scopes` **and** present in the user JWT scopes, plus
  resource ownership.
- Helpers: `tenant_matched` (both empty, or equal) and `resource_owned`
  (no owner / global, or owner == user).

## 6. PEP placement

Authorization is enforced at multiple, independent points:

1. **A2A server (each agent)** — before any handler runs, `src/a2a/server.ts`
   calls `authz.authorize("a2a:<method>", …)` with verified-context attributes
   and untrusted intent. This is the primary per-agent PEP.
2. **Worker executors** (`recon`, `knowledge`, `report`) — each executor calls
   `assertAuthorized(...)` for its domain operation. Knowledge additionally
   checks each document (`authorizeDocumentAccess`) on search (filter) and
   index (deny). This survives a compromised orchestrator and any future
   bypass of stage 1.
3. **Orchestrator** (`OrchestratorHandler.driveRun`) — before dispatching a
   child task, authorizes `a2a:tasks/send` for the target agent/operation.
4. **API gateway** — `requireAuthorized` on every route, with resource owner
   loaded from the repository for read paths; knowledge search filters results
   per document.

No component relies exclusively on the orchestrator to authorize workers.

## 7. Authorization flow

```
User JWT (HS256) ─▶ Gateway requireAuth ─▶ requireAuthorized(action) ──▶ OPA
                                              │ allow
                                              ▼
                                   create run + STS run token
                                              ▼
        Orchestrator A2A PEP ──▶ OPA (gateway may send run.start)
                                              ▼
        driveRun child PEP ──▶ OPA (orchestrator may invoke agent/op)
                                              ▼
        Child token (aud a2a:<agent>, actions=[kind])
                                              ▼
        Agent A2A PEP ──▶ OPA (caller may send this op for this run)
                                              ▼
        Executor PEP ──▶ OPA (operation on this resource is allowed)
                                              ▼
                          execute (sandbox / knowledge / report)
```

Every `AuthorizationProvider.authorize` call emits an `authz.decision` audit
event with the decision, policy version, kind, action, workload, agent, user,
rule and reason.

## 8. Attack scenarios and defenses

| # | Scenario | Defense | Test |
|---|----------|---------|------|
| 1 | Compromised orchestrator invokes an unauthorized tool | Orchestrator grant only has `RUN_ACTIONS`; policy denies ops outside the child's role/run grant | `escalation S1` |
| 2 | Recon receives a target outside the approved scope | Policy `requestedTarget in approvedTargets`; executor re-checks the signed scope | `escalation S2` |
| 3 | Knowledge accesses another tenant's data | Per-document `resourceOwner`/`resourceTenantId` + tenant match; search filters results | `escalation S3` |
| 4 | Report accesses another user's run | `resourceOwned` check against the run owner, plus tenant match | `escalation S4` |
| 5 | Agent modifies its authorization context | Inputs come from the signed token; tampered tokens fail signature/audience checks; body fields only set bounded `requested*` | `escalation S5` |
| 6 | Agent invokes another agent's privileged operation | Only `workload:orchestrator` may send; audience binding + policy workload check | `escalation S6` |
| 7 | OPA becomes unavailable | Any engine/parse/transport error is converted to a denial | `escalation S7`, `opa "fails closed"` |
| 8 | Invalid or missing authorization attributes | Normalization + `default allow := false`; missing run grant rejected before handlers | `escalation S8`, `opa "defaults to deny"` |

## 9. Running and testing

- Policy unit tests: `tests/security/opa.test.ts` (engine decisions, version,
  audit, fail-closed, remote OPA data-API client, input-builder trust).
- Escalation tests: `tests/security/escalation.test.ts` (the eight scenarios).
- End-to-end: `tests/api/pipeline.test.ts` now runs the full flow with the real
  OPA engine at every hop.
- Full suite: `pnpm test` (128 tests), `pnpm typecheck`, `pnpm lint`,
  `pnpm build`.

## 10. Limitations / follow-ups

- The embedded engine supports only the restricted Rego subset used here; use
  a real OPA (`OPA_URL`) for full Rego features such as comprehensions,
  `every`, functions and `some`.
- Tenant IDs are plumbed through tokens/records but user tokens do not yet
  carry a tenant claim (tenant-aware IdP is future work). `resource_owned`
  protects run/report/document access in the meantime.
- Policy distribution/rotation (OPA bundles, signatures) is deployment-owned.
- The gateway's `PolicyProvider.evaluate` (domain rule refs, e.g. recon
  "rulesRef") remains a separate, user-owned control; it is not the
  authorization engine.
