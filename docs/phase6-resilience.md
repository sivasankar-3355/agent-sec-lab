# Phase 6 — Agent Resilience and Cascading-Failure Defense

This document describes the resilience controls added to the existing
multi-agent application. It builds on Phase 1 (separated identity), Phase 2
(OPA-backed authorization), Phase 3 (prompt-injection defenses), Phase 4
(centralized Memory Service) and Phase 5 (centralized Tool Execution Module).

Constraints honored:

- no new dependencies (Node built-ins and the existing Redis client only);
- no Docker/Kubernetes/AWS deployment change;
- no new microservice — the controls are in-process modules, with the existing
  Redis store reused for cross-process run budgets;
- the four agents, three stores and Phase 1–5 security paths are unchanged;
- no attack-scenario testing was performed (final project validation owns it);
- controls are described as enforced only where the execution path actually
  enforces them. Cooperative limits are called out explicitly.

## 1. Existing request and failure flow

Before this phase, a run followed this path:

```
POST /api/v1/runs
  -> gateway writes the run record
  -> gateway mints a run token through the STS
  -> A2AClient tasks/send -> orchestrator
       -> root task + driveRun(runId, rootTaskId)
       -> planRun: recon per target, knowledge.search, report.generate
       -> per child: STS exchange -> OPA PEP -> A2AClient tasks/send
            -> worker A2A server -> BaseWorkerHandler
                 -> WorkerExecutor -> ctx.tools.execute
                      -> ToolBroker -> LocalToolExecutor -> operation
                           -> SandboxProvider / MemoryService / Mongo / crypto
       -> orchestrator polls tasks/get until terminal
       -> child artifact is inspected and parsed as untrusted JSON
       -> report artifact is persisted
       -> run COMPLETED / FAILED / CANCELLED
```

The failure paths that existed before Phase 6:

| Path | Existing behavior | Weakness |
|---|---|---|
| Gateway → orchestrator dispatch | 5s client timeout, no retry | one transient failure leaves the run `CREATED`; only a log line |
| Orchestrator → child `tasks/get` / `tasks/cancel` | client retried 3 times on **any** error, linear 50ms backoff | retried 401/403/404, no jitter, nested inside the poll loop |
| Child polling | 25 attempts × 200ms (~5s) | shorter than the 30s tool timeout; synthetic failure; no cancellation |
| First child failure | entire run marked `FAILED` | no isolation or partial results |
| Cancellation | root task/run marked `CANCELLED` | no child cancel; poll sleep not abortable; in-flight worker kept working |
| Worker task | no wall-clock bound | a hung executor held the task forever |
| A2A server handler | no handler deadline | a hung handler held the HTTP request open |
| Tool execution | timeout/cancel/rate/concurrency per tool | no run-wide tool budget |
| Memory operation | storage driver timeouts only | no caller-visible per-operation deadline |
| LLM call | no timeout/signal | a hung provider blocked recon |
| Run lock | 30s TTL, no renewal | a long run could lose the lock and allow a duplicate drive |
| Run budget | none | no cap on agent calls, tool calls, duration, retries, LLM calls |

Existing observability was pino logs plus `AuditProvider.emit` events for
accepted/rejected A2A calls, run/task state, tool execution and prompt
injection. There was no metrics/tracing backend, retry/circuit state audit, or
run-budget audit.

There was no circuit breaker, no retry classification, no run-scoped budget and
no cancellation propagation from orchestrator to child agents/tools.

## 2. Timeout enforcement

The shared primitive is `withDeadline` in `src/core/resilience/abort.ts`. It
combines a timeout and an optional parent signal, aborts a cooperative signal,
and rejects with `TimeoutError` or `CancelledError`.

| Operation | Default | Configuration | Enforcement |
|---|---|---|---|
| A2A client call (headers **and** body) | 5s | `A2A_CALL_TIMEOUT_MS` | `A2AClient.request` wraps fetch + `response.text()` |
| A2A server handler invocation | 5s | `A2A_REQUEST_TIMEOUT_MS` | `createA2ARouter` wraps the method dispatch |
| Worker task | 120s | `AGENT_TASK_TIMEOUT_MS` | `BaseWorkerHandler.run` wraps the executor |
| LLM completion | 30s | `LLM_TIMEOUT_MS` | recon wraps `ModelProvider.complete` with a deadline + signal |
| Memory operation | 30s | `MEMORY_TIMEOUT_MS` | each public `MemoryService` method is bounded |
| Tool prechecks (OPA/DNS/egress) | 5s | Tool Broker option | `withDeadline` around each precheck |
| Tool execution | 10–30s per spec | code-owned `ToolLimits` | Tool Broker, capped by remaining run duration |
| Run execution | 30m default / 24h hard | trusted `run.config.budget.maxDurationMs` | Run Governor checks at every agent/tool/LLM step |
| OPA remote evaluation | 3s | existing engine | `OpaHttpPolicyEngine` |
| Mongo / Qdrant | 3s driver timeouts | existing clients | driver-level |
| STS client | 5s | existing client | headers + body (`withDeadline`) |
| Redis | 3s connect, bounded retries | existing client | driver-level |

Propagation:

- the 30s run lock is renewed every ~10s while `driveRun` is active, so a
  long run does not silently lose its lock; a crashed process still releases it
  on TTL;
- a run deadline shortens each tool timeout (`min(tool limit, remaining run
  time)`), so a tool cannot outlive the run;
- host cancellation aborts the orchestrator run signal, which aborts the child
  A2A request, which the worker receives as a task abort, which reaches the
  executor signal and the Tool Broker;
- an LLM call receives the tool signal and the remaining run deadline;
- a server request timeout/client disconnect aborts the handler's `CallContext`
  signal, and the client-side deadline also covers reading the response body.

**Cooperative caveat:** a timeout rejects the caller and aborts the signal. Code
that ignores the signal (an external sandbox adapter, a provider SDK, a storage
driver) may finish later. Mongo/Qdrant have their own driver timeouts; hard
process termination is a Phase 7 sandbox concern.

## 3. Circuit breaker design

`src/core/resilience/circuit.ts` implements one breaker per peer:

```
CLOSED  --failureThreshold consecutive transient failures-->  OPEN
OPEN    --recoveryIntervalMs elapsed------------------------>  HALF_OPEN
HALF_OPEN --success (last probe)-------------------------->   CLOSED
HALF_OPEN --any probe failure------------------------------>   OPEN
```

- `failureThreshold` — consecutive transient failures that open the circuit.
- `recoveryIntervalMs` — time before a probe is allowed.
- `halfOpenMaxCalls` — maximum concurrent probes admitted in `HALF_OPEN`.
- only transient transport/server failures are recorded; authorization,
  validation, permanent, budget, cancellation and circuit-open errors do not
  trip the breaker (a reachable 4xx is recorded as a successful transport);
- the breaker is applied in `AgentClientsBroker` (orchestrator → recon /
  knowledge / report) and in the gateway’s orchestrator link;
- an open circuit throws `circuit_open` (503) immediately, so an unhealthy
  agent receives no repeated requests;
- state changes emit `resilience.circuit.state` audit events and a warning log.

Configuration: `CIRCUIT_FAILURE_THRESHOLD`, `CIRCUIT_RECOVERY_INTERVAL_MS`,
`CIRCUIT_HALF_OPEN_MAX_CALLS`.

The breaker is process-local. Multiple orchestrator replicas each maintain
their own view; sharing breaker state would need a distributed counter/lease
and is not claimed here.

## 4. Retry strategy

Retries are a **single layer** owned by the caller. `A2AClient` does not retry
by default (`retries: 0`); the orchestrator and gateway each add one bounded
retry loop, and the worker/tool path does not add another.

`src/core/resilience/retry.ts` classifies failures:

| Class | Examples | Retry? |
|---|---|---|
| `transient` | HTTP 5xx, JSON-RPC `-32000`/`-32603`, network `TypeError` | yes |
| `timeout` | A2A deadline | only for explicitly idempotent calls |
| `authorization` | 401/403, JSON-RPC `-32001`/`-32003` | no |
| `validation` | 400/422, JSON-RPC `-32602`/`-32600` | no |
| `permanent` | 404/409, `-32004`/`-32601`/`-32700` | no |
| `budget` | 429/run budget | no |
| `cancelled` | cancellation/disconnect | no |
| `circuit_open` | breaker refusal | no |

Mechanics:

- total attempts are bounded (`A2A_RETRY_MAX_ATTEMPTS`, hard cap 5; helper cap
  10);
- exponential backoff with bounded jitter
  (`A2A_RETRY_BASE_DELAY_MS`, `A2A_RETRY_MAX_DELAY_MS`);
- the orchestrator charges every retry to the run’s `maxRetries` budget before
  sleeping;
- authorization/validation/permanent/budget/cancellation failures are never
  retried;
- a `CircuitOpenError` is never retried.

Idempotency protection:

- `taskId` is the idempotency key at the receiver; `tasks/send` does not create
  a second task for the same `taskId`;
- the gateway’s run token is single-use (`jti` replay protection). A gateway
  retry therefore mints a **fresh** run token from the STS while reusing the
  same `taskId`. If only a static token is configured, gateway retries are
  disabled;
- the orchestrator mints a fresh per-hop child token per attempt; the worker’s
  task table deduplicates by `taskId`;
- no retry loop is nested inside another.

Gateway dispatch retries occur before the run is executing and are therefore
bounded by configuration, not by the run budget. Orchestrator child retries are
budgeted by the run.

## 5. Run-scoped resource and execution budgets

`src/core/resilience/budget.ts` defines the trusted budget and
`src/db/run-budget-store.ts` provides the Redis-backed counter store.

| Budget | Default | Hard ceiling | Enforced at |
|---|---|---|---|
| `maxAgentCalls` | 50 | 500 | orchestrator before every child dispatch |
| `maxToolCalls` | 100 | 2,000 | Tool Broker before every execution attempt |
| `maxDurationMs` | 30m | 24h | orchestrator, poll loop, Tool Broker, LLM, retries |
| `maxConcurrentAgentTasks` | 4 | 16 | orchestrator agent-slot gate |
| `maxRetries` | 5 | 50 | orchestrator before every retry |
| `maxLlmCalls` | 10 | 100 | recon before every model call |

Derivation:

- budgets come from the **trusted run record** (`run.config.budget`);
- every value is clamped to the code-owned hard ceiling; the authenticated run
  creator may choose a value up to that ceiling, but no agent can write the run
  record or raise its own budget;
- unknown fields, non-numbers and task/model input are ignored;
- `RunBudget` is passed to the executor inside the authorized
  `ToolExecutionRequest` as a frozen snapshot; operations cannot supply or
  mutate their own budget, and the governor uses that snapshot for LLM calls.

Example trusted run configuration (all fields optional; values are clamped to
the code-owned hard ceilings):

```json
{
  "budget": {
    "maxAgentCalls": 20,
    "maxToolCalls": 40,
    "maxDurationMs": 600000,
    "maxConcurrentAgentTasks": 2,
    "maxRetries": 2,
    "maxLlmCalls": 5
  }
}
```

Enforcement details:

- **shared counters** — in production the orchestrator and every worker use
  `RedisRunBudgetStore` and the existing Redis instance, so agent/tool/LLM/retry
  counters are shared across processes;
- **in-memory fallback** — tests and embedded use use
  `InMemoryRunBudgetStore`; that is process-local;
- **fail closed** — a Redis error throws `budget_store_unavailable` (503) and
  refuses execution rather than running without a budget;
- **tool retries** — a retried agent/task that reaches the Tool Broker again
  consumes another tool-call credit;
- **deadline** — a run past its deadline accepts no new agent/tool/LLM work;
- **concurrency** — the orchestrator acquires/releases one agent slot around
  each child task. The current plan is sequential, so the limit is not stressed;
  the gate is implemented for future parallel driving;
- **LLM tokens** — the existing `ModelProvider` returns completion text only,
  with no token usage, so token counts are not enforced. LLM **calls** are.

Concurrency slots and counters expire with the budget TTL
(`maxDurationMs + 60s`, capped at the hard ceiling + 60s). A crashed process can
therefore leave a slot held until that TTL, bounded by the run deadline.

## 6. Cancellation propagation

Host cancellation (`tasks/cancel` on the orchestrator) now:

1. marks the task and run `CANCELLED` (CREATED → CANCELLED is allowed);
2. aborts the run’s `AbortController`;
3. marks the active child task `CANCELLED`;
4. sends `tasks/cancel` to the active child with a 2s bound;
5. the child worker marks its task canceled, aborts its task controller;
6. `withDeadline` aborts the executor signal;
7. the Tool Broker aborts the tool controller and the operation sees
   `request.signal` aborted;
8. recon’s model call and the poll/retry sleeps are abortable.

Cancellation also prevents new work:

- `driveRun` checks the run signal and root task state before each child;
- the broker checks the parent signal before execution;
- the worker task signal is passed to the executor;
- a root task that was canceled before the async drive starts is not reset to
  `RUNNING`.

The same cooperative caveat applies: an executor or external adapter that
ignores the signal may continue in the background. If the child A2A cancel
itself cannot be delivered, the orchestrator still marks the run/task canceled,
audits `run.cancel.propagation_failed`, and the worker’s own task deadline
bounds the orphaned work.

## 7. Failure isolation

- **Worker isolation** — executor errors are caught per task, recorded as a
  failed task with `<code>: <message>`, audited, and do not crash the worker.
- **Worker task timeout/capacity** — a task over its deadline or a worker over
  `AGENT_MAX_CONCURRENT_TASKS` fails fast with a structured error instead of
  hanging or queueing without bound.
- **Orchestrator isolation**:
  - recon targets are independent: one failed target does not stop the other
    targets;
  - `knowledge.search` is independent: its failure is recorded and the report
    can still run with recon findings;
  - `report.generate` is dependent: it only runs when at least one recon target
    succeeded for a non-empty scope; if all recon targets fail, the run fails
    with `dependency_failed`;
  - a failed report fails the run;
  - dispatch/poll/artifact failures are isolated the same way by task kind.
- **Partial results** — when some independent work fails but the report is
  produced, the run is `COMPLETED` with root output
  `{ runId, partial: true, failures: [...] }` and an
  audit event `run.completed_partial`. Failed child tasks remain visible.
- **Global failures** — run deadline, budget exhaustion and cancellation stop
  the run rather than continuing into unrelated work.
- **Structured errors** — A2A JSON-RPC errors use stable codes (including
  `-32005` timeout, `-32006` cancelled, `-32009` conflict and `-32010` budget),
  task errors carry a `<code>: <message>` prefix, and audit events record the
  code. The A2A task schema itself only has an `error` string; it was not
  expanded.
- **Retry storms** — permanent/auth/validation failures are not retried, the
  run retry budget is finite, and an unhealthy peer’s circuit opens.
- **One driver per run** — a second `run.start` with a different `taskId` while
  a drive is active is rejected with 409; it cannot overwrite the active drive
  promise or start a second task graph.

## 8. Tool execution integration (Phase 5 preserved)

Phase 5 remains the only tool path:

```
ctx.tools.execute -> ToolBroker -> LocalToolExecutor -> sealed operation
```

Phase 6 adds:

- the broker checks the run deadline after loading the trusted run record;
- the broker consumes one trusted tool-call credit after authorization, target
  validation, rate limiting and concurrency acquisition, immediately before
  execution; denied authorization/target/rate requests do not consume execution
  budget;
- the execution timeout is `min(tool limit, remaining run duration)`;
- `ToolExecutionRequest` carries the trusted `RunBudget`;
- `ToolOperationContext.budget` exposes `remainingMs()` and `consumeLlm()` to
  code-owned operations; recon skips optional model reasoning when the LLM
  budget is exhausted or the call times out;
- every retry that reaches the broker consumes another tool-call credit, so
  agent-level retries cannot bypass the run tool budget;
- the existing per-tool timeout/cancel/rate/concurrency/output/target/OPA/audit
  controls are unchanged.

The broker is constructed once per worker with the shared Redis governor; the
local executor receives the same governor so operation LLM consumption and
broker tool consumption use one budget.

## 9. Files created and modified

**Created**

- `src/core/resilience/errors.ts` — timeout/cancellation/circuit/budget errors.
- `src/core/resilience/abort.ts` — deadlines, abortable sleep, signal mapping.
- `src/core/resilience/circuit.ts` — CLOSED/OPEN/HALF_OPEN breaker.
- `src/core/resilience/retry.ts` — classification, backoff with jitter, single
  retry layer.
- `src/core/resilience/budget.ts` — trusted run budget, counters, governor.
- `src/core/resilience/index.ts` — public exports.
- `src/db/run-budget-store.ts` — Redis-backed shared counters.
- `tests/unit/resilience.test.ts` — breaker, retry, budget, deadline controls.
- `tests/security/resilience.test.ts` — orchestrator isolation/cancel/budget/
  retry, circuit breaker, server/worker/memory timeouts.
- `docs/phase6-resilience.md` — this document.

**Modified**

- `src/a2a/client.ts` — deadline covering headers+body, caller signal, optional
  circuit breaker, no default client retries.
- `src/a2a/sts.ts` — end-to-end bounded token issue/mint/exchange calls.
- `src/a2a/server.ts` — bounded handler invocation, JSON-RPC timeout/cancel
  codes, client-disconnect signal.
- `src/a2a/handler.ts` — optional `CallContext.signal`.
- `src/agents/base.ts` — worker task deadline, local capacity limit,
  cancellation reason, structured task failures.
- `src/agents/orchestrator/handler.ts` — run signal/cancel registry, child
  cancellation, lock heartbeat, budget/deadline checks, single retry layer,
  failure isolation/partial results, `CREATED → CANCELLED`.
- `src/agents/orchestrator/broker.ts` — per-child circuit breaker, caller
  signal, no nested retries.
- `src/agents/orchestrator/state.ts` — allow cancellation before start.
- `src/agents/recon/handler.ts` — budgeted/timed/cancellable LLM call.
- `src/agents/memory.ts` — per-operation deadline around public methods.
- `src/agents/tool-operation.ts`, `src/agents/tool-executor.ts`,
  `src/agents/tooling.ts` — operation budget view, shared governor wiring.
- `src/security/tools/broker.ts`, `src/security/tools/executor.ts` — run
  deadline/tool budget and trusted budget in the execution request.
- `src/security/protocols.ts` — optional model deadline/signal.
- `src/core/config.ts` — timeout/circuit/worker/memory/LLM settings.
- `src/db/coordinator.ts` — lock extension for long runs.
- `src/orchestrator/main.ts`, `src/agents/boot.ts` — Redis governor, circuit
  configuration, request/task deadlines.
- `src/api/main.ts`, `src/api/routers/runs.ts`,
  `src/api/routers/contract.ts` — gateway retry, fresh-token retries, circuit
  breaker, dispatch-failure audit.
- `tests/helpers/testkit.ts`, `tests/security/tools.test.ts`,
  `tests/unit/config.test.ts`, `tests/unit/orchestrator-state.test.ts` —
  governor, budget, config and cancellation-transition tests.

## 10. Remaining limitations and future infrastructure requirements

- **Cooperative, not preemptive.** Timeouts/cancellation reject the caller and
  abort a signal; they do not kill a process or forcibly stop an external
  provider. Hard CPU/memory/process limits belong to the Phase 7 sandbox.
- **Circuit breakers are per process.** They are not shared across orchestrator
  replicas. A distributed breaker would need shared state and is not claimed.
- **Budget store dependence.** Shared enforcement requires Redis. If Redis is
  unavailable, execution fails closed with `budget_store_unavailable`; there is
  no allow-on-error fallback. The in-memory store is process-local.
- **Lease leak window.** A crashed process can leave a concurrency slot or
  counter until the budget TTL. The TTL is bounded by the run deadline.
- **Concurrency gate is not stressed today.** The orchestrator drives children
  sequentially; the gate is implemented and tested at the governor level, not
  exercised by parallel planning.
- **LLM token budgets are not enforced.** The existing provider interface has no
  usage metadata; only call counts are budgeted.
- **Memory timeout is caller-visible.** The service rejects at the deadline;
  an underlying driver operation may finish later (driver timeouts bound it).
- **A2A handler timeout is caller-visible.** The router stops waiting and
  returns a structured error; a handler that ignores its signal may continue.
- **Gateway retries need STS re-minting.** With a static orchestrator token,
  replay protection intentionally disables retries.
- **No distributed rate limit.** Tool rate/concurrency limits remain
  per-process, as in Phase 5.
- **Long runs vs token lifetime.** Run budgets may be configured up to 24h, but
  workload/run token TTLs remain 30m by default; token renewal/rotation is a
  pre-existing identity concern and is not added here.
- **No OS/process/container isolation.** Phase 5’s in-process trust boundary is
  unchanged; a malicious in-process module can still import modules or build
  its own broker, exactly as documented in Phase 5. Phase 6 budgets/breakers are
  enforced on the normal application paths, not against a compromised process.
  Phase 7 must provide the sandboxed executor.
- **No metrics backend.** Resilience events are emitted through the existing
  audit provider and pino logs; there is no Prometheus/dashboard change.
- **`knowledge.index` remains absent from `RUN_ACTIONS`.** Pre-existing grant
  limitation; not changed here.
- **No attack-scenario testing** was performed in this phase.

## 11. Verification

```
pnpm typecheck   # pass
pnpm lint        # pass
pnpm build       # pass
pnpm test        # 202 tests, 23 files, pass
```

The added tests cover breaker transitions/probe limits, retry classification
and backoff, budget clamping/counters/concurrency, deadline/cancellation,
orchestrator child-cancel propagation, partial-result isolation, all-recon
failure dependency, agent/tool budget exhaustion, transient-vs-auth retry,
circuit-open fast failure, A2A handler timeout, worker task timeout/capacity,
and memory-operation timeout.
