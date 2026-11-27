# Phase 5 — Tool Security

This document describes the tool-security controls in the existing multi-agent
application. It builds on Phase 1 (separated user/workload identity), Phase 2
(OPA-backed authorization with a PEP at every agent), Phase 3
(prompt-injection defenses) and Phase 4 (centralized Memory Service).

Constraints honored:

- no new dependencies (Node built-ins only);
- no second policy engine;
- no Docker/Kubernetes/AWS deployment change;
- no new microservice — the Tool Execution Layer is an in-process logical
  module;
- no model-driven tool-calling loop was introduced;
- no attack-scenario testing was performed (final review owns that).

## 1. Existing architecture and every tool execution path

Before this phase, there was **no model-driven tool-calling loop**. Tool names
and arguments were selected by code:

| Agent | Tool | What actually ran |
|---|---|---|
| Recon | `recon.snapshot` | policy check → egress check → `SandboxProvider.run` |
| Knowledge | `knowledge.search` | `MemoryService.searchDocuments` |
| Knowledge | `knowledge.index` | `MemoryService.indexDocuments` |
| Report | `report.generate` | renderer → Mongo `reports` → `CryptoProvider.sign` |
| Orchestrator | none | A2A child dispatch only (`tasks/send`); no tool execution |

Definitions lived in `src/agents/tools.ts`; each executor independently built
an OPA resource, called a validation helper, then invoked the implementation
directly. There was no central enforcement point, no per-agent allowlist in the
registry, no execution limits, no output schema validation, and target checks
were exact-string comparisons only.

There are **no shell, process, filesystem, or arbitrary-code tools** in the
application. The only external effect is the user-owned `SandboxProvider`; the
only network gate is the user-owned `NetworkPolicyProvider`. Both default to
fail-closed.

## 2. Trusted registry and sealed operation catalog

### Tool spec (`src/security/tools/types.ts`, `src/agents/tools.ts`)

Every tool declares:

| Field | Meaning |
|---|---|
| `name` | Code-owned identifier (`recon.snapshot`, ...) |
| `description` | Trusted source-code description |
| `schema` | Strict zod object schema; unknown fields rejected |
| `allowedAgents` | Per-agent allowlist; no tool is shared by default |
| `requiredAction` | Existing OPA operation action |
| `risk` | `low` / `medium` / `high` |
| `target` | Optional target rule (field, host/url, DNS, private-address policy) |
| `limits` | Timeout, max output bytes, max concurrency, rate window |
| `outputSchema` | Structural validation for application-owned output |

The registry (`src/security/tools/registry.ts`) is sealed at module load:
duplicates, invalid specs and post-seal registration throw; specs, allowlists,
limits and target rules are frozen.

### Operation catalog (`src/agents/tool-catalog.ts`)

A separate sealed `ToolCatalog` binds each registered spec to its **code-owned
operation**. The catalog verifies that the spec is the exact registered object,
refuses duplicate operations, and on `seal()` requires every registered tool to
have exactly one operation.

The executor looks up the operation by tool name from the catalog. Agents
**cannot pass a handler, operation, executable or permission** into execution.
`ToolBroker.execute(actor, request)` accepts only a tool name and typed args.

### Per-agent permissions

| Tool | Allowed agent | OPA action | Risk |
|---|---|---|---|
| `recon.snapshot` | `recon` | `recon.run` | medium |
| `knowledge.search` | `knowledge` | `knowledge.search` | low |
| `knowledge.index` | `knowledge` | `knowledge.index` | medium |
| `report.generate` | `report` | `report.generate` | medium |

The orchestrator has no tools. Task input schemas are strict, so a task
instruction cannot add `tool`, `allowedTools`, permissions, etc. Child tokens
are narrowed by the STS to `ACTIONS_BY_AUDIENCE` and the parent run grant.

## 3. Centralized execution architecture

`src/security/tools/broker.ts` is the single enforcement point. Every agent
tool call goes through:

```
executor
  -> ctx.tools.execute(actor, { name, args }, { signal })
       -> registry allowlist
       -> verified actor binding (run, task, user, workload, audience)
       -> strict argument schema + safe-key check
       -> trusted run lookup + owner/tenant/terminal-state binding
       -> target canonicalization + signed-grant/run-scope checks
       -> OPA decision for the tool's required action
       -> DNS resolution + private/reserved IP denial
       -> network egress policy
       -> rate limit + concurrency limit
       -> ToolExecutor (pluggable execution isolation)
       -> output size + output schema
       -> prompt-injection inspection + provenance
       -> audit
```

### Executor abstraction

`src/security/tools/executor.ts` defines:

```ts
interface ToolExecutor {
  readonly kind: "local" | "sandbox";
  execute(request: ToolExecutionRequest): Promise<unknown>;
}
```

`ToolExecutionRequest` contains only authorized/validated state: tool name,
args, resolved target envelope, signal, verified actor, trusted run, OPA
decision and code-owned limits. It has **no command, shell, executable,
handler or permission field**.

`src/agents/tool-executor.ts` implements the Phase 5 controlled local executor:

- looks up the code-owned operation from the sealed catalog;
- builds a `ToolOperationContext` with audit/policy/model/crypto/repos/memory
  and a `ToolRuntime`;
- runs the operation in-process;
- implements `runtime.runStep(step)` by re-checking the pinned target envelope
  (address policy, `maxRedirects === 0`, `pinAddresses === true`) and calling
  the configured `SandboxProvider`.

Authorization and argument validation stay in the broker. Execution isolation
is the executor's responsibility. Phase 7 can replace `LocalToolExecutor` with
a `SandboxToolExecutor` implementing the same interface without changing the
broker, registry, catalog or policy logic.

### Worker context hardening

`WorkerContext` is now only:

```ts
{ log, audit, tools }
```

It deliberately exposes **no raw repositories, memory stores, sandbox/network
providers or credentials**. Tool operations receive their dependencies through
the local executor's `ToolOperationContext`, after broker authorization. This
removes the previous direct `ctx.security.sandbox.run` / `ctx.memory` /
`ctx.repos` access from agent executors.

## 4. OPA authorization integration

No second policy engine was introduced. For **every** execution request the
broker calls the existing `AuthorizationProvider` with `kind: "operation"`, the
tool's required action and verified/trusted attributes:

| Tool | Action evaluated |
|---|---|
| `recon.snapshot` | `recon.run` |
| `knowledge.search` | `knowledge.search` |
| `knowledge.index` | `knowledge.index` |
| `report.generate` | `report.generate` |

Policy input fields:

- `workload` from the verified caller (`workload:orchestrator` → `orchestrator`);
- `agent` from the receiving agent;
- `user`, `runId`, `tenantId`, `scopes` from the verified token context;
- `approvedTargets` / `approvedActions` from the signed run grant;
- `resourceOwner` / `resourceTenantId` from the trusted run record;
- requested intent only in `requested*` fields (`requestedTool`,
  `requestedAction`, `requestedTarget`, `requestedRunId`, `requestedDocIds`).

Policy changes in `policies/v1/authz.rego`:

- recon, knowledge search, knowledge index and report require
  `requestedAction in approvedActions` at the operation PEP;
- recon requires the target in `approvedTargets`;
- default deny remains for missing identity, missing grant, owner/tenant
  mismatch, unknown action and engine failure.

The broker also requires the grant's targets to be a subset of the trusted run
record's scope. A stale or over-broad signed grant cannot widen the run.

**OPA failures are always denials.** The OPA provider catches engine/transport
errors and returns a denial; the broker also catches any thrown provider error
and denies. Missing/invalid decisions and timeouts cannot allow a tool call. A
control test covers a throwing authorization provider.

## 5. Argument and target validation

### Arguments

- strict zod schema: required fields, types, enums, string length, array bounds,
  unexpected-field rejection;
- recursive rejection of `__proto__`, `constructor`, `prototype`;
- request object rejects unknown fields and requires an own `name`; a request
  cannot smuggle `operation`, `approvedTargets`, `permissions`, etc.;
- no tool accepts a shell string, command, script, file path or raw executable.

### Targets

`src/security/tools/targets.ts` implements:

1. **Syntax validation** — length, no whitespace/control characters, no
   backslashes, no scheme-relative strings; host targets reject path/query/
   fragment/userinfo.
2. **Canonicalization** — lowercase host, IDN/punycode via URL parsing,
   trailing dots stripped, default ports removed, IPv6 normalized, URL fragment
   removed. Scope comparisons use only the canonical form.
3. **Scope derivation** — the requested target must be in **both** the trusted
   `runs` record scope and the signed run grant; the grant must not contain a
   target absent from the run record.
4. **DNS resolution** — all A/AAAA answers are resolved before execution, but
   only after the OPA decision succeeds, so an unauthorized request cannot
   trigger a DNS lookup. Any resolution failure fails closed; a mixed public/
   private answer set is denied.
5. **Private/reserved address denial** — IPv4 and IPv6 checks cover loopback,
   private, link-local (including `169.254.169.254`), CGNAT, multicast,
   reserved and documentation ranges; `::1`, `::`, ULA, link-local, multicast,
   IPv4-mapped, NAT64, 6to4, Teredo, benchmarking, ORCHID and discard-only
   ranges; and known metadata hostnames (`localhost`, `*.local`,
   `metadata.google.internal`, `instance-data`).
6. **Pinned target envelope** — the executor receives
   `{ input, canonical, host, addresses, allowPrivate }` and
   `constraints: { maxRedirects: 0, allowPrivate: false, pinAddresses: true }`.
   The addresses are the exact resolved set that passed validation.

The local executor re-checks the pinned envelope immediately before dispatching
the sandbox step: a missing target, a redirect policy other than zero, a
`pinAddresses` flag other than true, or an address that is now disallowed
rejects the step. The step target must also match the broker-authorized target
(canonical host and address set), so an operation cannot substitute a different
target. No re-resolution happens between validation and dispatch.

### Actual connection-time enforcement

The application does not itself open the recon connection. The user-owned
sandbox adapter receives the pinned address set and the zero-redirect
constraint and **must** connect only to `step.target.addresses`, not re-resolve
`step.input`, and must not follow redirects. The application-level
broker/executor cannot verify the internal socket behavior of an external
adapter; true connection-time enforcement (connect-to-pinned-IP, redirect
re-validation, network namespace) belongs to the sandbox adapter and will be
provided by the Phase 7 sandboxed executor. This limitation is stated
explicitly rather than claimed as end-to-end.

For any future application-owned network tool, the same `ResolvedTarget`
envelope must be used with a pinned-lookup transport; the executor must not
re-resolve the hostname.

## 6. Execution restrictions and command safety

- **Timeout** — per-tool `timeoutMs`; rejects with `tool_timeout` (504). The
  executor receives an abort signal.
- **Cancellation** — task cancel aborts the controller; rejects with
  `tool_cancelled` (499). Handlers/operations receive `request.signal`.
- **Maximum output** — serialized output above `maxOutputBytes` is rejected
  with `tool_output_too_large` (502); no silent partial truncation.
- **Concurrency** — per agent+tool in-process counter; `tool_concurrency_exceeded`
  (429).
- **Rate limit** — per agent+tool sliding window; `tool_rate_limited` (429).
- **Error handling** — unknown operation/executor errors become a generic
  `tool_execution_failed` (502); `AppError` messages/causes are redacted for
  bearer tokens, JWTs, API keys and private keys. Audit records contain tool,
  agent, executor kind, code and duration, not raw arguments/output.
- **No arbitrary command execution** — there is no `child_process`, shell,
  script, filesystem or arbitrary-code tool. Operations use typed business
  arguments only.
- **Future process execution rules** — if a process-based tool is added, the
  executor must use a fixed executable path from a code-owned allowlist and an
  argument array with `spawn(executable, args, { shell: false })`. No shell
  interpolation, no string concatenation, no model-selected executable. This
  is not implemented now because no such tool exists.
- **No OS isolation claim** — these are application-level deadlines, caps and
  counters. They are not process/container isolation.

## 7. Output handling

Successful output is returned as:

```ts
{
  tool, trust: "untrusted", authoritative: false,
  provenance: { tool, agent, runId, taskId, target? },
  data, bytes, durationMs
}
```

- Registered `outputSchema` is validated where the application owns the output
  (`recon.snapshot` → `{ findings: string[] }`, `knowledge.search`,
  `knowledge.index`, `report.generate`).
- Output is serialized and inspected with the Phase 3
  `inspectUntrustedContent` (`tier: "tool-output"`,
  `source: "tool:<name>"`). Suspicious content emits
  `prompt.injection.detected`; it is never promoted to an instruction.
- Recon places sandbox output in an `UNTRUSTED_DATA` prompt segment; findings
  persist only provenance metadata (tool, trust, authoritative, target), not
  raw sandbox output.
- Knowledge output is returned to the orchestrator as an A2A artifact, which
  the orchestrator already inspects as `agent-output` before parsing.
- Audit events (`tool.execution.completed`, `.denied`, `.failed`) record
  identifiers, target, decision rule, executor kind, duration, byte count and
  detection metadata. Raw arguments/output are not logged. Injection
  inspection is bounded to the first 64 KiB.

## 8. Can an agent bypass the Tool Execution Module?

At the code/type level:

- `WorkerContext` exposes only `{ log, audit, tools }`; there is no raw
  repository, memory store, sandbox or network provider on the agent context.
- Executors call only `ctx.tools.execute`; they cannot pass a spec, handler,
  operation or executable.
- The registry and catalog are sealed; tool operations are selected by the
  executor from the sealed catalog.
- The local executor's external step is only `runtime.runStep`, which validates
  the pinned target and calls the sandbox provider.
- No source path calls `SandboxProvider.run` outside the local executor, and no
  source path calls `MemoryService` outside the knowledge operation/API.

Residual in-process trust: a compromised worker process has code-level reach
(TypeScript `private` is not a runtime security boundary) and could import
modules or construct its own executor. Preventing that requires process/OS
isolation, which is the Phase 7 sandbox and later container phases. Phase 5
does not claim to prevent a malicious in-process module; it prevents the
application’s normal agent/tool interfaces from bypassing authorization.

## 9. What Phase 7 must add for isolated execution

A `SandboxToolExecutor` can implement the existing `ToolExecutor` interface and
be passed to `createToolBroker` without changing the broker, registry, catalog
or policy logic. It must enforce:

- **Process privileges** — non-root user, dropped capabilities, no privilege
  escalation, seccomp/AppArmor (or equivalent), user/PID namespaces, read-only
  root filesystem, minimal tool image.
- **Filesystem** — no host mounts, no workspace/credential mounts, per-run
  writable scratch with a size quota, explicit input/output exchange only.
- **Network** — isolated network namespace; egress only to validated pinned
  addresses/ports; no direct DNS or DNS pinning at connect time; deny private,
  loopback, link-local and metadata ranges; disable redirects (or re-validate
  every `Location` against the same scope); TLS SNI/Host allowlist; no raw
  sockets or arbitrary protocols unless a tool explicitly requires them.
- **Resources** — CPU, memory, pids, disk, wall-clock deadline, output byte cap,
  concurrency cap, cancellation/kill, and log size limits.
- **Command execution** — fixed executable paths and argument arrays, no shell,
  per-tool executable allowlist, argument validation before spawn.
- **Credentials** — no DB, OPA, STS, model or cloud credentials inside the
  sandbox; use a narrow tool protocol with per-call authorization.
- **Observability** — exit code, duration, output size, target/addresses used,
  policy decision id; never log secrets or raw sensitive output.

## 10. Files created and modified

**Created**
- `src/security/tools/types.ts` — specs, actors, results, limits, target rules.
- `src/security/tools/registry.ts` — sealed registry/allowlists.
- `src/security/tools/executor.ts` — pluggable `ToolExecutor` interface.
- `src/security/tools/targets.ts` — canonicalization, scope/DNS/IP/SSRF checks.
- `src/security/tools/output.ts` — serialization, size checks, secret redaction.
- `src/security/tools/broker.ts` — centralized Tool Broker.
- `src/security/tools/index.ts` — public exports.
- `src/agents/tool-operation.ts` — operation context/runtime types.
- `src/agents/tool-catalog.ts` — sealed spec→operation catalog.
- `src/agents/tool-executor.ts` — controlled local executor.
- `src/agents/tool-actor.ts` — verified actor construction.
- `src/agents/tooling.ts` — worker broker/executor wiring.
- `tests/security/tools.test.ts` — registry, catalog, allowlist, scope, SSRF,
  limits, output and real-OPA control tests.
- `docs/phase5-tool-security.md` — this document.

**Modified**
- `src/agents/tools.ts` — allowlists, risk, limits, target rules, output schemas,
  sealed registry; recon `rulesRef` and `{ findings }` output schema.
- `src/agents/recon/handler.ts` — code-owned recon operation + thin executor.
- `src/agents/knowledge/handler.ts` — code-owned knowledge operations + thin executor.
- `src/agents/report/handler.ts` — code-owned report operation + thin executor.
- `src/agents/base.ts` — narrow `WorkerContext { log, audit, tools }`, task
  abort controller, `AbortSignal`.
- `src/agents/boot.ts` — broker/executor wiring.
- `src/security/protocols.ts` — `ResolvedTarget`, sandbox target/constraints.
- `src/security/opa/{types,input,provider}.ts` — `requestedTool` input/audit.
- `policies/v1/authz.rego` — operation rules require the action in the grant.
- `src/security/prompt/tool.ts` — compatibility re-export.
- `tests/helpers/testkit.ts`, `tests/api/pipeline.test.ts`,
  `tests/security/{context-binding,escalation,opa}.test.ts`,
  `tests/contract/a2a.test.ts` — wiring and control assertions.

## 11. Remaining direct execution paths and limitations

- **Local in-process executor.** Phase 5 uses `LocalToolExecutor`; it is not a
  sandbox. It runs code-owned operations in the worker process and delegates
  `runtime.runStep` to the user-owned sandbox provider.
- **Sandbox-backed network step.** The app does not open recon sockets. Target
  validation is complete at the broker/executor boundary, but actual
  connect-to-pinned-IP and redirect enforcement depend on the sandbox adapter
  and Phase 7 sandbox executor. Not claimed as end-to-end today.
- **In-process trust boundary.** A compromised worker can bypass TypeScript
  interfaces; OS/process isolation is Phase 7/container work.
- **Per-process limits.** Rate/concurrency counters are per worker process.
- **Cooperative timeout.** The broker rejects at the deadline and aborts the
  signal, but an operation that ignores the signal may finish in the
  background.
- **`network` and `sandbox` are user-owned and fail-closed by default.** Recon
  tool calls deny until those adapters are provided.
- **No model-driven tool calling.** Tool names/args are code-selected. If one
  is added, it must route through `ToolBroker.execute` and cannot supply
  permissions or handlers.
- **`knowledge.index` is not in `RUN_ACTIONS`.** The STS cannot issue it through
  the normal run plan; the broker still enforces the grant if presented. This
  is a pre-existing grant-policy limitation.
- **Target scope is host/URL based.** CIDR/wildcard/non-HTTP scope entries fail
  closed.
- **Gateway API routes** (`/knowledge`, `/memory`, `/runs`) call the Memory
  Service or A2A orchestrator directly; they are not agent tool executions and
  retain their own scope/owner/tenant checks.
- **No container sandboxing and no attack-scenario testing** in this phase.

## 12. Final implementation report (explicit answers)

**Remaining direct tool execution paths.**
- `LocalToolExecutor.execute` is the only executor called by the broker; it is
  constructed only in `src/agents/tooling.ts`.
- `LocalToolExecutor.runStep` is the only source path that calls
  `SandboxProvider.run`; it is reached only through the recon operation's
  `runtime.runStep`.
- Knowledge operations call `MemoryService`; report/recon operations call
  operational MongoDB repositories. These are not raw tool implementations and
  are reached only through the sealed catalog/executor after broker checks.
- Gateway `/knowledge`, `/memory` and `/runs` routes are not agent tool paths.

**Can an agent bypass the Tool Execution Module?**
At the normal code/type level, no: `WorkerContext` is only
`{ log, audit, tools }`, executors cannot pass handlers/operations, and the
registry/catalog are sealed. A malicious in-process module could still import
modules and construct its own executor because TypeScript `private` is not a
runtime boundary. Preventing that requires OS/process isolation (Phase 7).

**How the authenticated agent identity is established.**
The A2A server verifies the workload/run JWT (signature, issuer, audience, expiry,
run grant) before invoking the handler. `toolActorOf` builds a `ToolActor` only
from that `VerifiedContext`; the broker re-checks run/task/user/workload and
that the token audience matches the receiving agent. The tool request itself
carries only a tool name and args — never an agent identity, permission or
run id.

**How OPA failures are handled.**
The OPA provider converts engine, transport and timeout errors into a denial;
the broker also catches any thrown authorization error and denies. There is no
allow-on-error path and no cached authorization decision: every execution
request is evaluated independently.

**How target validation is enforced at actual connection time.**
The broker validates and canonicalizes the target, checks it against the
trusted run record and signed grant, resolves every A/AAAA answer, rejects any
private/loopback/link-local/metadata answer, and passes a pinned envelope
(`addresses`, `pinAddresses: true`, `maxRedirects: 0`) to the executor. The
executor re-checks that envelope and binds the step target to the authorized
target. The application does not itself open the recon socket; the user-owned
sandbox adapter must connect only to the pinned addresses and honor the
zero-redirect policy. Socket-level enforcement is therefore a Phase 7 sandbox
requirement, not an application-level claim.

**What remains dependent on future sandbox/infrastructure phases.**
OS/process/container isolation, process privileges, filesystem isolation,
network namespace and connect-time IP pinning, redirect re-validation inside
the sandbox, hard resource quotas, and credential-free execution. Phase 7 can
provide a `SandboxToolExecutor` implementing the same `ToolExecutor` interface
without changing the broker, registry, catalog or policy logic.

## 13. Verification

```
pnpm typecheck   # pass
pnpm lint        # pass
pnpm build       # pass
pnpm test        # 179 tests, 21 files, pass
```
