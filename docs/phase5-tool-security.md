# Phase 5 — Tool Security

This document describes the tool-security controls added to the existing
multi-agent application. It builds on Phase 1 (separated user/workload
identity), Phase 2 (OPA-backed authorization with a PEP at every agent),
Phase 3 (prompt-injection defenses) and Phase 4 (centralized Memory Service).

Constraints honored: no new dependencies (Node built-ins only), no second
policy engine, no Docker/Kubernetes/AWS deployment change, and no model-driven
tool-calling loop was introduced.

## 1. Existing tool architecture and execution flow (before this phase)

The application had **no model-driven tool-calling loop**. Tool names and
arguments were selected by code, not parsed from model output:

| Agent | Code-selected tool | What actually ran |
|---|---|---|
| Recon | `recon.snapshot` | `PolicyProvider.evaluate`, `NetworkPolicyProvider.assertEgress`, `SandboxProvider.run` |
| Knowledge | `knowledge.search` | `MemoryService.searchDocuments` (Mongo/Qdrant inside the service) |
| Knowledge | `knowledge.index` | `MemoryService.indexDocuments` |
| Report | `report.generate` | Code-owned report renderer + Mongo `reports` repository + `CryptoProvider.sign` |
| Orchestrator | none | A2A child dispatch only (`tasks/send`); no tool execution |

Definitions lived in `src/agents/tools.ts` as `defineTool` specs registered in
an in-memory `ToolRegistry`. Each executor independently:
1. built an `AuthzResource` and called `assertAuthorized` (OPA);
2. called `validateToolCall` for the strict zod schema and a basic
   target/run grant check;
3. invoked the implementation directly (`sandbox.run`, `ctx.memory`, repos).

There was no central execution point, no per-agent allowlist in the registry,
no execution limits, no output schema validation and no trusted-run-record
derivation for targets. `validateToolCall` compared the target string exactly
and did not canonicalize it, resolve DNS or reject private addresses.

There are **no shell, process, filesystem, or arbitrary-code execution paths**
in the application. The only external execution is the user-owned
`SandboxProvider`; the only network gate is the user-owned
`NetworkPolicyProvider`. Both default to fail-closed.

## 2. Tool registry design

Implementation: `src/security/tools/registry.ts`, `src/security/tools/types.ts`,
`src/agents/tools.ts`.

Every `ToolSpec` now carries:

| Field | Meaning |
|---|---|
| `name` | Code-owned identifier (`recon.snapshot`, ...) |
| `description` | Trusted source-code description |
| `schema` | Strict zod object schema; unknown fields are rejected |
| `allowedAgents` | Per-agent allowlist; no tool is shared by default |
| `requiredAction` | Existing OPA operation action (`recon.run`, ...) |
| `risk` | `low` / `medium` / `high`, used for audit and gate strictness |
| `target` | Optional target rule: argument field, `host`/`url`/`host-or-url`, DNS resolution, private-address policy |
| `limits` | Timeout, max output bytes, max concurrency, rate window |
| `outputSchema` | Structural validation for application-owned output |

The registry is **sealed at module load**:
- registration after sealing throws;
- duplicate names throw;
- invalid limits/allowlists/target rules throw;
- specs, allowlists, limits and target rules are frozen.

The Tool Broker verifies object identity (`registeredSpec === passedSpec`) in
addition to the name. A caller cannot create a permissive spec with the same
name: it is rejected as `tool_not_registered`.

## 3. Per-agent tool permissions

`ToolRegistry.requireForAgent(name, agent)` is the first gate. It fails closed
for an unknown tool or an agent that is not on the tool's allowlist.

| Tool | Allowed agent | Required action | Risk | Timeout | Max output | Concurrency | Rate |
|---|---|---|---|---|---|---|---|
| `recon.snapshot` | `recon` | `recon.run` | medium | 30 s | 256 KiB | 4 | 30/min |
| `knowledge.search` | `knowledge` | `knowledge.search` | low | 10 s | 256 KiB | 8 | 60/min |
| `knowledge.index` | `knowledge` | `knowledge.index` | medium | 30 s | 64 KiB | 4 | 30/min |
| `report.generate` | `report` | `report.generate` | medium | 30 s | 128 KiB | 4 | 20/min |

The orchestrator has no tools. An agent cannot gain another agent's tools
because the orchestrator asks for them: task dispatch is per-agent A2A, child
tokens are narrowed by the STS to `ACTIONS_BY_AUDIENCE`, and the receiving
agent's registry allowlist is independent of the request.

Task instruction schemas are strict (`validateTaskInput`), so an ordinary task
input cannot add a `tool`, `allowedTools`, `permissions` or similar field. The
Orchestrator's `planRun` constructs inputs from the trusted run record, not
from model output.

## 4. Centralized execution architecture

Implementation: `src/security/tools/broker.ts`, `src/agents/tooling.ts`,
`src/agents/tool-actor.ts`.

The `ToolBroker` is an **in-process module**, analogous to the Phase 4 Memory
Service. No new service, container or deployment change was introduced. Each
worker creates one broker at boot (`createAgentToolBroker`) and exposes it on
`WorkerContext.tools`; executors no longer call tool implementations directly.

Every call goes through:

```
executor
  -> ctx.tools.execute(spec, actor, request, handler, { signal })
       -> registry allowlist + spec identity
       -> verified actor binding (run, task, user, workload, audience)
       -> strict argument schema + safe-key check
       -> trusted run lookup + owner/tenant binding
       -> terminal-run denial (COMPLETED / CANCELLED / FAILED)
       -> target canonicalization + signed/trusted scope checks
       -> OPA decision for the tool's required action
       -> DNS resolution + private/reserved IP denial
       -> network egress policy
       -> rate limit + concurrency limit
       -> handler (only after all gates)
       -> output size + output schema
       -> prompt-injection inspection + provenance
       -> audit
```

The handler receives only:
- validated/canonicalized `args`;
- the actor derived from `VerifiedContext`;
- the trusted `RunRecord`;
- the resolved target envelope;
- an `AbortSignal`;
- the OPA `Decision`.

It does not receive DB clients, credentials or unrestricted request data.

`WorkerExecuteInput` now carries an `AbortSignal`. `BaseWorkerHandler` creates
one `AbortController` per task and aborts it on `tasks/cancel`; the broker maps
that to a `tool_cancelled` error and the handler can observe `call.signal`.

## 5. OPA authorization integration

No second policy engine was introduced. The broker calls the existing
`AuthorizationProvider` (embedded Rego or remote OPA) with `kind: "operation"`
and the tool's `requiredAction`:

| Tool | Action evaluated |
|---|---|
| `recon.snapshot` | `recon.run` |
| `knowledge.search` | `knowledge.search` |
| `knowledge.index` | `knowledge.index` |
| `report.generate` | `report.generate` |

The policy input is built only from verified/trusted state:

- `workload` from the verified caller (`workload:orchestrator` → `orchestrator`);
- `agent` from the receiving agent;
- `user`, `runId`, `tenantId`, `scopes` from the verified token context;
- `approvedTargets` / `approvedActions` from the signed run grant;
- `resourceOwner` / `resourceTenantId` from the trusted run record;
- requested intent only in `requested*` fields (`requestedTool`,
  `requestedAction`, `requestedTarget`, `requestedRunId`,
  `requestedDocIds`).

Policy changes in `policies/v1/authz.rego`:
- recon, knowledge search, knowledge index and report now all require
  `requestedAction in approvedActions` at the operation PEP (previously
  knowledge operations relied only on the A2A layer);
- the target must already be in `approvedTargets` for recon;
- default deny remains for missing identity, missing grant, owner/tenant
  mismatch, unknown action and engine failure.

The broker additionally requires the grant's targets to be a subset of the
trusted run record's scope. A stale or over-broad signed grant cannot widen
the run.

## 6. Argument and target validation

### Arguments

- The registered zod schema is strict: required fields, types, enum values,
  string length, array size and unexpected-field rejection.
- Reserved keys (`__proto__`, `constructor`, `prototype`) are rejected
  recursively.
- The request object itself is checked for unknown fields and an own `name`.
- No request supports a raw command, shell string, script, file path or
  arbitrary URL field. Tools expose only their typed business arguments.

### Targets

`src/security/tools/targets.ts` implements:

1. **Syntax validation** — length, no whitespace/control characters, no
   backslashes, no scheme-relative strings; host targets reject path/query/
   fragment/userinfo.
2. **Canonicalization** — lowercase host, IDN/punycode via URL parsing,
   trailing dots stripped, default ports removed, IPv6 normalized, URL fragment
   removed. Scope comparisons use only the canonical form.
3. **Scope derivation** — the requested target must be present in **both** the
   trusted `runs` record scope and the signed run grant. The grant must not
   contain a target absent from the run record.
4. **DNS resolution** — all A/AAAA answers are resolved before execution, but
   only after the OPA decision succeeds, so an unauthorized request cannot
   trigger a DNS lookup. Any resolution failure fails closed. Every answer is
   checked; a mixed public/private answer set is denied.
5. **Private/reserved address denial** — IPv4 and IPv6 checks cover:
   - loopback, private, link-local (including `169.254.169.254`), CGNAT,
     multicast, reserved and documentation ranges;
   - `::1`, `::`, ULA, link-local, multicast, IPv4-mapped, NAT64, 6to4,
     Teredo, benchmarking, ORCHID and discard-only ranges;
   - known metadata hostnames (`localhost`, `*.local`, `metadata.google.internal`,
     `instance-data`).
6. **Pinned target envelope** — the sandbox receives
   `target: { input, canonical, host, addresses, allowPrivate }` and
   `constraints: { maxRedirects: 0, allowPrivate: false }`. The addresses are
   the exact resolved set that passed validation.

## 7. Execution restrictions

- **Timeout** — per-tool `timeoutMs`; the broker rejects with `tool_timeout`
  (504). The handler receives an abort signal.
- **Cancellation** — task cancel aborts the controller; the broker rejects
  with `tool_cancelled` (499).
- **Maximum output** — serialized output above `maxOutputBytes` is rejected
  with `tool_output_too_large` (502); partial/structured output is never
  silently truncated.
- **Concurrency** — per agent+tool in-process counter; over the limit returns
  `tool_concurrency_exceeded` (429).
- **Rate limit** — per agent+tool sliding window; over the limit returns
  `tool_rate_limited` (429).
- **Error handling** — unknown handler errors become a generic
  `tool_execution_failed` (502); `AppError` messages and causes are passed
  through `redactSecrets` before leaving the broker. Audit records contain the
  tool, agent, code and duration, not raw arguments or output.
- **No arbitrary execution** — the application contains no `child_process`,
  shell, script, filesystem or arbitrary-code tool. The recon tool only calls
  the user-owned sandbox adapter with a typed target envelope.

## 8. Tool output handling

All successful output is returned as:

```ts
{
  tool: string,
  trust: "untrusted",
  authoritative: false,
  provenance: { tool, agent, runId, taskId, target? },
  data: T,
  bytes: number,
  durationMs: number,
}
```

- The registered `outputSchema` is validated where the application owns the
  output (`knowledge.search`, `knowledge.index`, `report.generate`). Recon's
  sandbox output is adapter-defined, so it is size-bounded, inspected and
  tagged rather than structurally asserted.
- Output is serialized and inspected with the Phase 3
  `inspectUntrustedContent` (`tier: "tool-output"`,
  `source: "tool:<name>"`). Suspicious content emits
  `prompt.injection.detected`; it is never promoted to an instruction.
- Recon places the output in an `UNTRUSTED_DATA` prompt segment with
  `source: tool:recon.snapshot`; the finding stores only provenance metadata
  (`tool`, `trust`, `authoritative`, target, bytes), not raw sandbox output.
- Knowledge output is returned to the orchestrator as an A2A artifact, which
  the orchestrator already inspects as `agent-output` before parsing.
- Audit events (`tool.execution.completed`, `tool.execution.denied`,
  `tool.execution.failed`) record identifiers, target, decision rule, duration,
  byte count and detection metadata. Raw arguments/output are not logged.

## 9. Files created and modified

**Created**
- `src/security/tools/types.ts` — specs, actors, results, limits, target rules.
- `src/security/tools/registry.ts` — sealed registry, allowlists, legacy validator.
- `src/security/tools/targets.ts` — canonicalization, scope checks, DNS/IP/SSRF checks.
- `src/security/tools/output.ts` — safe serialization, size checks, secret redaction.
- `src/security/tools/broker.ts` — centralized Tool Broker.
- `src/security/tools/index.ts` — public exports.
- `src/agents/tool-actor.ts` — verified actor construction.
- `src/agents/tooling.ts` — worker broker wiring.
- `tests/security/tools.test.ts` — registry, allowlist, scope, SSRF, limits,
  output and real-OPA control tests.

**Modified**
- `src/agents/tools.ts` — specs with allowlists, risk, limits, output schemas; sealed registry.
- `src/agents/recon/handler.ts` — all execution through `ctx.tools`; pinned target to sandbox.
- `src/agents/knowledge/handler.ts` — all execution through `ctx.tools`; Memory Service remains the only memory interface.
- `src/agents/report/handler.ts` — all execution through `ctx.tools`; trusted run supplied by broker.
- `src/agents/base.ts` — `WorkerContext.tools`, task abort controller, `AbortSignal`.
- `src/agents/boot.ts` — creates the worker Tool Broker.
- `src/security/protocols.ts` — `ResolvedTarget`, sandbox target/constraints contract.
- `src/security/opa/types.ts`, `src/security/opa/input.ts`, `src/security/opa/provider.ts` — `requestedTool` attribute and audit field.
- `policies/v1/authz.rego` — operation rules require the action in the signed grant.
- `src/security/prompt/tool.ts` — compatibility re-export of the new tool module.
- `tests/helpers/testkit.ts` — test target resolver, broker factory, seeded runs.
- `tests/api/pipeline.test.ts`, `tests/security/{context-binding,escalation,opa}.test.ts`,
  `tests/contract/a2a.test.ts` — wiring and new control assertions.

## 10. Remaining direct tool execution paths and limitations

- **In-process broker.** The broker is a module, not a separate service. A
  compromised worker process has the same code-level reach as before. True
  process isolation would require a separate tool-execution service; that is
  deferred and was explicitly out of scope.
- **DNS rebinding and redirects are adapter contracts.** The broker resolves
  every A/AAAA answer, rejects any private/reserved answer, and passes the
  pinned address set plus `maxRedirects: 0` to the sandbox. The application
  itself does not open the recon connection; the user-owned sandbox adapter
  must connect only to the pinned addresses and must not follow redirects.
  The broker cannot enforce connection behavior for an adapter that ignores
  the envelope. This is documented rather than claimed as end-to-end.
- **Per-process limits.** Rate and concurrency counters live in the worker
  process. Horizontal scaling gives each process its own budget; a shared
  limiter (Redis) would be a separate change.
- **Timeout is cooperative.** The broker rejects the call at the deadline and
  aborts the signal, but an in-process handler that ignores the signal may
  continue running in the background until it finishes.
- **`network` and `sandbox` are user-owned and fail-closed by default.** No
  real network policy or sandbox is wired in this repository. Recon tool calls
  deny until those adapters are provided. The broker does not replace them.
- **No model-driven tool calling exists.** Tool names and arguments are
  selected by application code. The broker rejects a request whose tool name is
  not registered/permitted, but there is no LLM tool-call parser to attack
  today. If one is added, it must route through `ToolBroker.execute` and must
  never accept model-supplied allowlists or permissions.
- **Gateway API routes are not agent tools.** `/knowledge/search`,
  `/knowledge/documents` and `/memory` continue to call the Memory Service
  directly; they keep their own API-scope, owner and tenant checks and never
  invoke an agent tool. `/runs` dispatches to the orchestrator over A2A, which
  is protected by the STS grant narrowing described above.
- **`knowledge.index` is grantable by audience but not present in
  `RUN_ACTIONS`.** The STS cannot issue a normal run token containing
  `knowledge.index`; the broker still enforces the signed grant if such a
  token is presented. This is a pre-existing grant-policy limitation, not a
  broker bypass.
- **Target scope is host/URL based.** CIDR ranges, wildcards and non-HTTP
  schemes are not accepted as target-tool scope entries; they fail closed.
- **No container sandboxing.** That belongs to the later container-security
  phase.
- **No attack-scenario testing in this phase.** Project-wide security
  validation, including prompt-injection and tool-abuse scenarios, remains for
  the final review.

## 11. Verification

```
pnpm typecheck   # pass
pnpm lint        # pass
pnpm build       # pass
pnpm test        # 176 tests, 21 files, pass
```
