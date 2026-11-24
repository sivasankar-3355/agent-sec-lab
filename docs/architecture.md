# AgentSecLab — Application Architecture (Draft for Approval)

Status: **PROPOSED — not implemented**. Security-relevant decisions require approval.

Scope of this document: application engineering only. The security engineering roadmap
(AI Agent Security, Sandboxing, Linux/Container/Kubernetes, Supply Chain, AWS, DevSecOps,
Observability) is owned separately. The application exposes *integration interfaces* for
security controls (Section 9) and never implements them or compensates for missing controls.

## 0. Design principles and assumptions

- Exactly four agents: `orchestrator`, `recon`, `knowledge`, `report`. No more.
- Exactly three data stores: MongoDB, Qdrant, Redis. No PostgreSQL.
- Inter-agent communication uses **A2A** (Agent-to-Agent protocol: JSON-RPC 2.0 over HTTP),
  with each agent exposing an A2A server endpoint; the HTTP API is the only *external* boundary.
- Minimal functionality. Each agent does the smallest thing needed to support the run lifecycle.
- Secure-by-default: every security integration defaults to **fail-closed**. If a control
  is not wired, the action is denied, not allowed.
- Secrets never appear in code, config files, logs, or sentence-history. Provided at runtime only.
- One codebase, one dependency set (Node 22 + TypeScript + Express), process-per-agent deployment.
- AI capability provider is **OpenAI** — embeddings and chat reasoning via the **OpenAI
  AgentKit (TypeScript) framework**. It powers agent reasoning *inside* the four agents only;
  it never adds agents and never bypasses a security gate.

Assumed product behavior: a user creates a **run** against a declared **scope**. The
orchestrator drives reconnaissance, knowledge indexing/retrieval, and reporting. The
knowledge agent is also available as a standalone semantic store (ingest/search).

## 1. Application architecture

Event-driven, agent-to-agent via A2A. Each agent runs a small A2A server (JSON-RPC 2.0 over
HTTP); the orchestrator is additionally an A2A client that submits child tasks to the other
agents. The HTTP API is the only external entry point and itself submits runs to the
orchestrator as A2A tasks. MongoDB is the system of record; Qdrant holds vectors; Redis holds
transient cache, locks, and coordination primitives (no longer the inter-agent bus).

```
                 ┌───────────────────────────────┐
  HTTP           │         API (Express)         │
  ──────────────▶│  REST · authN/authZ (interface)│
                 └──────────────┬────────────────┘
                                │ A2A task (tasks/send)
                 ┌──────────────▼────────────────┐
                 │        Orchestrator agent       │  A2A server + client
                 └───┬───────────────┬─────────────┘
                     │ A2A           │ A2A          │ A2A
          ┌──────────▼──┐     ┌──────▼──────┐   ┌────▼───────┐
          │ Recon agent │     │ Knowledge   │   │ Report     │
          │ (A2A server)│     │ agent (A2A) │   │ (A2A server)│
          └─────────────┘     └─────────────┘   └────────────┘
      MongoDB (record) · Qdrant (vectors) · Redis (cache/locks/idempotency)
```

Notes:
- Every agent exposes an A2A endpoint (method surface in Section 5); the API is the only
  HTTP user-facing boundary. Agent endpoints are internal-only.
- `orchestrator` is the sole agent that advances run state; it owns the A2A task graph and
  correlates child task results with the run.
- API is the only component that writes the initial run record; agents update only documents
  they own or are assigned.
- Transport security for agent links (TLS / mutual auth) is a security-engineering adapter
  (Section 9); the application never assumes an open internal network.

## 2. Component responsibilities

| Component | Responsibilities |
|---|---|
| API (Express) | REST for users: run start/status, findings/report retrieval, knowledge ingest + search, health/readiness probes. Wraps the orchestrator A2A endpoint as its only downstream. Every external read/write gated by the authN/authZ interface (fail-closed). No business logic beyond validation and persistence. |
| A2A layer | JSON-RPC 2.0 client/server over HTTP: agent card + `initialize`, `message/send`, `tasks/*`. Envelope, method, and payload schemas validated with zod. Transport security is a security adapter, not part of this layer's logic. |
| Orchestrator agent | A2A server + client. Owns the run state machine, plans child tasks, submits them to recon/knowledge/report via A2A, tracks their task lifecycle, records progress in MongoDB, handles retry/cancel, marks run complete/cancelled. |
| Recon agent | A2A server. Executes a small set of recon steps against the declared scope, writes findings. Every step executed via the sandbox + policy + egress interfaces. Produces findings only; no autonomous follow-on actions. |
| Knowledge agent | A2A server. (a) Ingest: chunk → embed (OpenAI `EmbeddingProvider`) → upsert into Qdrant with immutable hash-based IDs; record documents in MongoDB. (b) Search: embed query → retrieve top-k with payload metadata. |
| Report agent | A2A server. Assembles a run's findings (optionally with knowledge context) into a report document in MongoDB. Signs the artifact via the crypto interface. |
| DB repositories | Thin data-access layer for MongoDB / Qdrant / Redis. No logic beyond queries; single place storing connection handling. |
| Security layer | Interface definitions + fail-closed defaults + provider wiring only. Contains **no** security implementation decisions (owned by security engineering). |

Every agent-to-agent call is also audited: a correlation id (run_id + task_id) rides each A2A
message, and the audit interface mirrors each accepted/rejected task.

## 3. Repository structure

```
agent-sec-lab/
├── package.json              # single project, single toolchain (pnpm + Node 22)
├── tsconfig.json
├── pnpm-lock.yaml
├── .env.example              # non-secret placeholders only
├── Makefile                  # lint / test / run target shortcuts
├── src/
│   ├── api/                  # Express app, routers, request/response schemas
│   │   ├── app.ts            # Express app assembly
│   │   ├── deps.ts           # DI / provider access
│   │   ├── auth.ts           # JWT middleware → AuthTokenProvider (fail-closed)
│   │   └── routers/{health,runs,reports,knowledge}.ts
│   ├── a2a/                  # A2A protocol implementation (minimal, in-repo)
│   │   ├── server.ts         # JSON-RPC server over HTTP for an agent
│   │   ├── client.ts         # typed A2A client (tasks/send, tasks/get, …)
│   │   ├── schema.ts         # zod schemas for methods, Task, Message, Artifact
│   │   └── agentCard.ts      # A2A agent card + capabilities
│   ├── agents/
│   │   ├── base.ts           # Worker base: A2A server + task handler wiring
│   │   ├── orchestrator/{handler.ts, workflows.ts, state.ts}
│   │   ├── recon/{handler.ts, steps.ts}
│   │   ├── knowledge/{handler.ts, indexing.ts, search.ts}
│   │   └── report/{handler.ts, renderer.ts}
│   ├── core/
│   │   ├── config.ts         # env validation (zod); secrets never here
│   │   ├── events.ts         # audit events + per-type payload schemas (zod)
│   │   ├── ids.ts            # uuid7 / stable hash id generation
│   │   ├── errors.ts         # typed error hierarchy
│   │   └── logger.ts         # structured logs, no secrets
│   ├── ai/                   # AI provider wiring (OpenAI), behind interfaces
│   │   ├── client.ts         # AgentKit/openai client construction (runtime secrets)
│   │   ├── embedding.ts      # EmbeddingProvider → OpenAI embeddings
│   │   └── reasoning.ts      # ModelProvider → OpenAI chat completion (sandbox-gated)
│   ├── db/
│   │   ├── mongo.ts          # repos: runs, tasks, findings, reports, documents, audit
│   │   ├── qdrant.ts         # collections + upsert/search
│   │   └── redis.ts          # cache, locks, idempotency
│   └── security/
│       ├── protocols.ts      # integration interfaces (TS interfaces + types)
│       ├── defaults.ts       # fail-closed default implementations
│       └── container.ts      # provider wiring; replaced by security engineering
├── tests/
│   ├── unit/  integration/  contract/  api/  e2e/  security/
├── deploy/
│   ├── Dockerfile            # non-root, minimal base; node 22 alpine, dist only
│   ├── compose.yaml          # dev only (local Mongo/Qdrant/Redis + api/workers)
│   └── k8s/                  # manifests sketch, no privileged overrides
└── docs/
```

Rationale: one `package.json`, one lockfile (pnpm), and a `dist/` build keeps supply-chain
surface and image size small; `security/` is isolated behind `core` so provider swap does not
touch application code. Build with `tsc` (ESM), run app/workers via `node dist/...`. (A
TypeScript-aware dev runner is acceptable for dev only.)

## 4. API contracts (REST, JSON, `/api/v1`)

All endpoints authenticate via the authN/authZ interface; a denied decision returns `403`.
Errors are consistent `{ "error": { "code", "message", "request_id" } }`.

| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| POST | `/runs` | `{name, scope:{targets:string[]}, config?:{recon?:{},report?:{}}}` | `202 {run_id, state}` | Starts run async; orchestration via A2A task to orchestrator. |
| GET | `/runs/{run_id}` | — | `{run_id, state, timeline:[{state,ts}], task_summary}` | Current run status. |
| GET | `/runs/{run_id}/findings` | `?severity=&limit=` | `{findings: [{finding_id, severity, title, status}]}` | Findings list for a run. |
| GET | `/runs/{run_id}/report` | `?version=latest` | `{report_id, run_id, summary, content, checksum, signature?}` | Latest or pinned report version. |
| POST | `/knowledge/documents` | `{source, content, content_type, metadata?}` | `201 {doc_id, chunk_count}` | Ingest for semantic storage. |
| GET | `/knowledge/search` | `?q=&limit=` | `{hits:[{doc_id, score, snippet}]}` | Semantic search; used internally too. |
| GET | `/healthz` `GET /readyz` | — | `200/503` | Liveness; readiness checks Mongo/Qdrant/Redis. |

Boundaries: API never executes agent steps, never touches Qdrant directly for writes, and
never blocks a run waiting synchronously.

## 5. Agent communication contracts (A2A)

Communication follows the **A2A protocol** (JSON-RPC 2.0 over HTTP), pinned to a single
protocol version. Each agent and the API-to-orchestrator link use the same method surface.

Supported A2A methods (our minimal subset):

| Method | Direction | Purpose |
|---|---|---|
| `agentCard` (GET) | any → any agent | Capabilities discovery (serves the A2A card). |
| `message/send` | any → any agent | Unsolicited message exchange (e.g. contextual hints to recon). |
| `tasks/send` | API → orchestrator; orchestrator → recon/knowledge/report | Submit an agent task; returns task + id. |
| `tasks/get` | caller → agent | Poll task state and result. |
| `tasks/cancel` | caller → agent | Request cancellation of a task. |
| `initialize` | caller → agent | Handshake; protocol/version negotiation. |

Each JSON-RPC request carries a correlated, versioned message (A2A `Message`), e.g.:

```json
{
  "jsonrpc": "2.0",
  "id": "494f...",
  "method": "tasks/send",
  "params": {
    "task": {
      "taskId": "0195...",
      "runId": "0195...",
      "kind": "recon",
      "input": { "target": "…", "rulesRef": "…", "metadata": { "correlationId": "run:task" } }
    }
  }
}
```

A2A task states used: `submitted → input-required | working | completed | failed | canceled`
(with `completed` or `failed` carrying the result `Artifact`/`Message`). The `metadata` field
always carries `run_id` + `task_id` so every message is auditable end-to-end.

Task kinds per link (payload rides the A2A input artifact/message):

| Link | Kind | Input | Result artifact |
|---|---|---|---|
| API → orchestrator | `run.start` | `{scope, config}` | run id |
| orchestrator → recon | `recon.run` | `{task_id, target, rules_ref}` | `{findings:[finding_id]}` |
| orchestrator → knowledge | `knowledge.index` | `{task_id, doc_ids[]}` | `{indexed:[doc_id]}` |
| orchestrator → knowledge | `knowledge.search` | `{task_id, query}` | `{hits[]}` |
| orchestrator → report | `report.generate` | `{task_id, report_kind}` | `{report_id}` |

Execution model: `tasks/send` returns immediately with the task; the caller polls `tasks/get`
for completion (interval configurable). This is the minimal surface — no streaming or push
subscriptions. Orchestrator persists each child task in MongoDB (the `tasks` collection) and
updates it from `tasks/get` responses.

Delivery guarantees: A2A is request/response over HTTP; retries are capped, idempotent
(stable `task_id`), and backoff-limited. Consumers are the single writer for their own
artifacts (dedupe via `findings.hash` / stable upsert IDs). Every accepted task and every
rejected task is mirrored to the append-only audit sink via the audit interface.

## 6. MongoDB schemas

System of record. All documents carry `_id: ObjectId`, `run_id`/business ids as strings,
and `ts.created/updated`. No secrets stored.

### `runs`
```
{ _id, run_id, name, scope:{targets:[str]}, config:{recon:?, report:?},
  state: CREATED|STARTED|RECON|KNOWLEDGE|REPORT|COMPLETED|FAILED|CANCELLED,
  timeline:[{state, ts}], error?, version:int }
```
Index: `{state}`, `{ts.created}`, unique `{run_id}`.

### `tasks`
```
{ _id, task_id, run_id, agent: recon|knowledge|report, kind, parent_task_id?,
  input, output?, status: PENDING|ASSIGNED|RUNNING|SUCCEEDED|FAILED|CANCELLED,
  error?, attempts:int, ts:{created,started,completed?} }
```
Index: `{run_id, status}`, unique `{task_id}`.

### `findings`
```
{ _id, finding_id, run_id, task_id, agent, severity: info|low|medium|high|critical,
  title, description, evidence?, refs:[str], tags:[str],
  status: open|accepted|mitigated|verified|closed,
  hash: str,   # dedupe/content hash
  ts:{created,updated} }
```
Index: unique `{hash}`, `{run_id, severity}`, `{run_id, status}`.

### `reports`
```
{ _id, report_id, run_id, status: generating|ready|failed,
  kind, summary, content, checksum, signature?, format,
  version:int, ts:{created,completed} }
```
Index: unique `{run_id, version}`, unique `{report_id}`. (One report per run version; latest retrieved by max version.)

### `documents`
```
{ _id, doc_id, source, title, content_hash, content_type,
  chunk_count:int, status: pending|indexed|failed, run_id?, metadata?, ts }
```
Index: unique `{content_hash}`.

### `audit`
Append-only mirror of internal events (via audit interface; retention owned by security/observability).

## 7. Qdrant collection design

| Collection | Vector | Distance | Payload | Point ID |
|---|---|---|---|---|
| `knowledge` | embedding of document chunk (size = model output, config) | Cosine | `{doc_id, chunk_index, source, content_hash, title, run_id?}` | `sha256(doc_id + chunk_index)` — idempotent upsert |
| `findings` | embedding of `title + description` | Cosine | `{finding_id, run_id, task_id, agent, severity, tags[], status}` | `sha256(finding_id)` |

Payload index: `run_id`, `severity` (payload indexes). No user data is stored in payload beyond
IDs/metadata; raw content stays in MongoDB. Collections declared in code, created at startup
(create-on-demand is a Qdrant-native, non-privileged operation).

## 8. Redis data structures

| Purpose | Structure | Key pattern | TTL | Notes |
|---|---|---|---|---|
| Run state cache | Hash | `run:{id}` | 24h | `{state, counters}` hot mirror of MongoDB |
| Task poll cache | String | `a2a:task:{task_id}` | 1h | short JWT/auth hint cache for agent links (content decided by security), not secrets |
| Idempotency | String SETNX | `seen:{run_id}:{task_id}` | 24h | dedupe of A2A task submission/retry |
| Locks | String SET NX PX | `lock:run:{id}` | 30s | prevent duplicate run start / double dispatch |
| Rate/dedup guard | ZSET | `emit:{agent}:{ts}` | 1h | burst guard for audit/events |

Ephemeral only: no authoritative state lives in Redis. Redis is not interleaved with app secrets.

## 9. Security integration interfaces

The application defines **ports** (TypeScript interfaces; all methods async). Security
engineering owns the **adapters**. The app ships `defaults.ts` with fail-closed stubs so
nothing runs unanchored, but never pretends a control exists.

| Interface | Methods (async) | Used by | Fail-closed default |
|---|---|---|---|
| `AuthorizationProvider` | `authorize(action, ctx) -> Decision` | API, orchestrator before dispatch | `Deny` (403/abort) |
| `SandboxProvider` | `run(step, timeout_s?) -> Result` | every recon / agent step execution | raises `SandboxUnavailable` |
| `PolicyProvider` | `evaluate(target, action, rule_refs) -> Violations` | recon before executing a target | denies unlisted actions |
| `NetworkPolicyProvider` | `assert_egress(target) -> Decision` | recon before touching a target | deny (no egress) |
| `SecretProvider` | `get(name) -> Secret` | runtime config, creds bootstrap | raises if missing |
| `CryptoProvider` | `sign(data) -> sig; verify(data,sig,purpose) -> bool` | report integrity, event integrity | verify=False |
| `EmbeddingProvider` | `embed(texts: string[]) -> number[][]` | knowledge ingest/search | raises `NotConfigured` |
| `ModelProvider` | `complete(req, ctx) -> Completion` | orchestrator/recon reasoning inside sandbox | raises `NotConfigured` |
| `AuthTokenProvider` | `create_token(subject,scopes); verify_token(tok)` | API JWT boundary | verify → invalid |
| `AuditProvider` | `emit(event) -> None` | API, all agents | non-blocking local structured log |

Integration points (where roadmaps plug in, decided by security engineering, not here):

- **AI Agent Security / Sandboxing / Linux / Container / K8s runtime**: `SandboxProvider`,
  `NetworkPolicyProvider` adapters → gVisor/seccomp/NetworkPolicy-backed later; every recon
  or agent step executes only inside the sandbox.
- **Agent-to-agent transport security**: separate from external API auth. mutual auth/TLS
  between agent endpoints is an `AuthTokenProvider`/mTLS adapter on the A2A layer; the app
  treats agent links as untrusted until a control is wired (no open-internal-network
  assumption).
- **External API authentication (decided)**: simple **JWT** between user requests and the API
  gateway boundary (the Express app). HS256 via `jsonwebtoken`; signing secret obtained at
  runtime only through `SecretProvider`. Claims are minimal: `sub`, `scopes`
  (`runs:read|write`, `knowledge:read|write`), `exp`. A signed, non-expired token with the
  required scope is accepted; anything else is rejected. Upscoping/RS256/OIDC and revocation
  are security-roadmap extensions, not built in.
- **Supply chain / DevSecOps**: dependency lock, image scans + `CryptoProvider`/`Signature`
  for artifact verification; `verify` gates on build.
- **AWS cloud security**: `SecretProvider` → AWS Secrets Manager/SSM; `AuthTokenProvider` →
  IAM/OIDC-backed tokens.
- **Security observability**: `AuditProvider` → structured sink consumed by observability the
  user defines; application emits structured, correlation-id-carrying events only.
- **AI Agent Security**: recon/agent reasoning is powered by OpenAI (AgentKit TS) *inside*
  the existing four agents only — AgentKit never adds agents or bypasses gates. Posture:
  model inputs and outputs are untrusted data; model-requested actions only change state
  through validated, policy-checked channels (never via privileged tools); prompt
  instructions from retrieved content are inert (retrieval treated as untrusted input);
  every model call is audit-emitted with run/task correlation.
- **AI provider egress & keys**: calls reach `api.openai.com` only after an egress decision
  (`NetworkPolicyProvider`); the OpenAI API key comes exclusively from `SecretProvider` at
  runtime and is never in config, images, or logs.

Rules honored: no privileged configs, no unrestricted egress, no intentionally vulnerable
components, controls never relaxed to fix app bugs.

**Pending approval (security decisions, not taken here):** enforcement depth of each adapter,
sandbox technology, audit retention, policy rule sources, JWT signing secret path +
algorithm/expiry tuning, OpenAI API key secret path (SecretProvider), allowed egress to
`api.openai.com`, concrete model IDs (embedding + chat) and AgentKit version, and
agent-to-agent transport security (mTLS) — pinned at implementation time with security review.

## 10. Functional testing strategy

| Layer | Scope | Tooling |
|---|---|---|
| Unit | state machine, A2A message schema validation, chunking, renderer, hashing | vitest |
| Contract | A2A messages/tasks validate against `a2a/schema.ts`; method surface + agent cards | vitest |
| Integration | real Mongo/Qdrant/Redis via testcontainers (ephemeral, unprivileged) | vitest + `@testcontainers/*` |
| API | Express app under test; auth interface stubbed to allow (test scope only) | vitest + supertest |
| E2E | full in-process pipeline over real HTTP A2A: create run → orchestrator submits child A2A tasks → recon → knowledge → report → report ready | vitest + testcontainers |
| Security-interface | prove fail-closed defaults (Deny/SandboxUnavailable/verify=False) | vitest |

Deterministic embeddings via a test embedding provider (hash-based) so all layers are
reproducible offline. Stores wiped per-test; unique run/task ids avoid cross-test bleed.
`tests/security/` exercises each interface's deny behavior; a test that passes while the
fail-closed default is absent fails the suite. Contract tests pin the A2A protocol version.

Acceptance: `make test` green locally and in CI leaving no demonstrable fail-open state.

## 11. Application development milestones

Gates: each milestone ends with approval before the next; security engineering reviews the
integration points at each gate.

| # | Milestone | Content | Acceptance |
|---|---|---|---|
| M0 | Foundation | Repo, toolchain, config, logging, db repos, health/ready probes, `security/` interfaces + fail-closed defaults | `make test` green; health probes pass against dev stores; defaults deny |
| M1 | API + domain | Mongo documents/schemas, run creation, status/findings/report GET, knowledge ingest/search | API integration tests pass; schemas validated |
| M2 | A2A layer + orchestrator | `a2a/` client/server + zod schemas, agent cards, orchestrator handler + run state machine, child task submission/polling, idempotency/locks | contract + e2e skeleton passes; cancels/failures handled |
| M3 | Agent workers | Recon (sandbox-gated steps, AgentKit reasoning), Knowledge (OpenAI embeddings → Qdrant index/search), Report (render + sign) | full E2E pipeline green |
| M4 | Hardening + obs | Structured audit events everywhere, idempotency audit, functional suite fully green in CI | `make test` + CI green; no fail-open state |
| M5 | Deploy scaffold | Non-root Dockerfile, dev compose, minimal k8s manifests (no privileged), readiness wiring | deploy dry-run in dev; manifests reviewed at security gate |

Parallel: security roadmap proceeds independently; application code only consumes the
interfaces in Section 9, so adapter work by security engineering never blocks M0–M5.