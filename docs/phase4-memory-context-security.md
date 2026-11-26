# Phase 4 — Memory and Context Security

This document describes the memory/context controls added on top of Phase 1
(separated user and workload identity), Phase 2 (OPA-backed RBAC/ABAC with a PEP
at every agent) and Phase 3 (prompt trust boundaries).

## 1. Components inspected

| Component | What was examined |
|---|---|
| MongoDB schema | `src/db/repositories/mongo.ts`: `runs`, `tasks`, `findings`, `reports`, `documents`, `users`, `audit` and their indexes |
| Repository contracts | `src/db/repositories/contracts.ts`, `build.ts` |
| Qdrant | `src/db/qdrant.ts`, `src/db/knowledge.ts`, `src/db/knowledge-contract.ts` — collection `knowledge`, payload fields, query path |
| Retrieval | `src/agents/knowledge/retrieval.ts`, `src/agents/knowledge/handler.ts`, `src/api/routers/knowledge.ts` |
| Conversation/context storage | `tasks.input`/`tasks.output`, orchestrator child-artifact ingestion, A2A `message/send` |
| Agent memory | `src/agents/base.ts` (`MemoryTask` is per-process task state only), agent handlers |
| Memory-like API surface | `/knowledge/documents`, `/knowledge/search`, `/runs/:id/report`, `/runs/:id/findings` |
| Authorization | `src/security/opa/*`, `policies/v1/authz.rego`, `src/agents/authz.ts`, `src/api/routers/contract.ts` |
| Trust/detection | `src/security/prompt/*` |
| Wiring | `src/api/app.ts`, `src/api/main.ts`, `src/agents/boot.ts` |

**Important finding:** there was no durable agent-memory store and no
conversation-history collection. `tasks.output` is operational state, and
`MemoryTask` in `base.ts` is an in-process task map. The only durable
content stores were `documents` (Mongo) + the `knowledge` vector collection
(Qdrant), findings and reports.

## 2. Security gaps identified

1. **No durable memory abstraction.** There was no provenance, trust, owner,
   tenant, run, version or TTL metadata for stored context, and no explicit
   memory read/write/update/delete authorization.
2. **Qdrant filtering was client-side only.** `QdrantKnowledgeVectorStore.search`
   queried the top-k globally with no filter; owner/tenant decisions were applied
   afterwards in application code. Payloads did not contain `owner_user_id` or
   `tenant_id`.
3. **Ingest trusted a caller-supplied `run_id`.** `/knowledge/documents`
   accepted `run_id` without verifying that the run belonged to the caller and
   did not stamp a tenant on the document.
4. **Report reads lacked ownership enforcement.** `/runs/:runId/report` called
   `runs:read` without the run's `resourceOwner`/`resourceTenantId`, so any user
   with `runs:read` could read another user's report.
5. **No retrieval owner-identity guard.** The secured retrieval boundary could
   be called with an authorization layer but an empty user, which would produce
   an unscoped query.
6. **No context minimization/lifecycle controls** for stored memory (bounded
   results, snippets, expiry, TTL, authorized deletion).
7. **No poisoning controls** such as immutable provenance, version lineage,
   conflict flagging, trust promotion prevention or suspicious-content
   annotation for durable memory.

## 3. Files changed

### New

| File | Purpose |
|---|---|
| `src/core/memory.ts` | Memory domain model: source types, scopes, provenance, integrity/version, trust derivation, collection derivation, limits, retention, expiry, snippet bounding, best-effort secret redaction |
| `src/db/repositories/memory.ts` | MongoDB `memories` repository with mandatory isolation predicates, version-pinned updates, TTL index, bounded search, append-only lineage |
| `src/agents/memory.ts` | `MemoryService` — the only application path for memory and knowledge document I/O: authorization, identity/tenant/run derivation, admission, Qdrant filtering, poisoning rules, lifecycle, audit |
| `src/db/memory-store.ts` | The single wiring point for memory-owned MongoDB (`memories`, `documents`) and Qdrant (`knowledge`) stores; kept out of `Repositories` |
| `src/api/routers/memory.ts` | `/memory` insert/read/search/update/delete endpoints with strict schemas |
| `tests/api/memory.test.ts` | Functional control tests for CRUD, provenance/trust derivation, run binding, retention clamping, default-deny, real OPA policy |
| `tests/unit/memory-model.test.ts` | Unit tests for trust/source derivation, retention clamping, content/snippet bounds, expiry |
| `docs/phase4-memory-context-security.md` | This document |

### Modified

| File | Purpose |
|---|---|
| `policies/v1/authz.rego` | Memory API/operation rules, strict `memory_owned` (empty owner is never public), memory tenant matching; memory scopes excluded from the generic API rule |
| `src/security/audience.ts` | Adds one of `memory:search`, `memory:read`, `memory:insert`, `memory:update`, `memory:delete` to default user scopes |
| `src/api/routers/contract.ts` | `RouterDeps.memory` + `readMemoryActor` helper |
| `src/api/app.ts` | `AppDeps.memory` + registers the memory router |
| `src/api/main.ts` | Builds `MemoryService` over `createMemoryStores` |
| `src/agents/base.ts` | `WorkerContext.memory` (agents see the service, never the raw stores) |
| `src/agents/boot.ts` | Builds one `MemoryService` per worker over the shared memory stores |
| `src/agents/knowledge/handler.ts` | Uses `ctx.memory.searchDocuments` / `indexDocuments`; no direct document/Qdrant repository access |
| `src/agents/knowledge/retrieval.ts` | Removed; retrieval logic now lives inside `MemoryService.searchDocuments` |
| `src/db/repositories/build.ts` | `Repositories` narrowed to operational stores only (no documents/knowledge/memories) |
| `src/db/repositories/mongo.ts` | Exposes `createDocumentsRepository`; `createMongoRepositories` no longer returns documents |
| `src/db/knowledge-contract.ts` | Typed `VectorSearchFilter`, owner/tenant in `UpsertChunksInput`, filtered `search` signature |
| `src/db/knowledge.ts` | Qdrant payload owner/tenant, server-side filter translation, payload indexes, hard result cap |
| `src/api/routers/knowledge.ts` | Delegates ingest/search entirely to `MemoryService`; no direct MongoDB/Qdrant access |
| `src/api/routers/reports.ts` | Enforces run ownership/tenant when reading a report |
| `src/api/deps.ts`, `src/orchestrator/main.ts`, `src/sts/main.ts` | Updated for the narrowed `createRepositories` signature |
| `tests/helpers/testkit.ts` | `FakeMemoryStores` + `makeMemoryService`; `FakeRepositories` no longer holds memory stores |

## 3.1 Centralized Memory Service (Option A)

**Decision:** the Memory Service is an **in-process module of the existing
application**, not a separate deployment. It is the only component that owns
the memory-related MongoDB collections (`memories`, `documents`) and the Qdrant
`knowledge` collection.

```
Recon Agent ─┐
Knowledge Agent ─┼──> MemoryService ──> MongoDB (memories, documents)
Report Agent ───┘                  └──> Qdrant (knowledge vectors)
```

| Concern | Location |
|---|---|
| Service implementation | `src/agents/memory.ts` (`MemoryService`) |
| Memory-owned stores | `src/db/memory-store.ts` (`createMemoryStores`) |
| MongoDB memory repo | `src/db/repositories/memory.ts` |
| MongoDB documents repo | `src/db/repositories/mongo.ts` (`createDocumentsRepository`) |
| Qdrant knowledge adapter | `src/db/knowledge.ts` |

Access is centralized as follows:

- `Repositories` contains only operational stores (`runs`, `users`, `tasks`,
  `findings`, `reports`). `documents`, the Qdrant knowledge store and the memory
  repository are **not** part of it, so `ctx.repos.documents` /
  `ctx.repos.knowledge` do not compile.
- `createMemoryStores` is the only wiring point for the memory-owned stores.
  It is called in `src/api/main.ts` and `src/agents/boot.ts`; the resulting
  object is held privately by `MemoryService` and never placed on
  `WorkerContext`.
- Every worker (Recon, Knowledge, Report) receives `ctx.memory`. The Knowledge
  Agent uses it for document search/index; Recon and Report can use the same
  interface if they later need memory, but currently have no memory reads.
- The orchestrator does not read memory today; because `Repositories` exposes no
  memory stores, any future need must go through `MemoryService` as well.
- MongoDB/Qdrant connection strings and clients are created at process boot and
  are never passed to an executor.

## 4. Memory metadata schema

Stored in MongoDB collection `memories`; the API returns the same fields in
snake_case. Application memory is **always** `trust: "untrusted"` and
`authoritative: false`.

```jsonc
{
  "memoryId": "uuidv7",
  "scope": "user | tenant | run | agent",
  "collection": "user-notes | document-notes | tool-notes | agent-notes",
  "memoryType": "user-note | document-context | tool-observation | agent-context | system",
  "status": "active | conflicted",
  "key": "optional logical key",
  "content": "bounded content",
  "contentHash": "sha256",
  "trust": "untrusted",
  "authoritative": false,
  "ownerUserId": "verified user id",
  "tenantId": "optional trusted tenant",
  "runId": "optional trusted run id",
  "agent": "optional agent name (agent scope)",
  "tags": ["bounded", "tags"],
  "conflict": false,
  "provenance": {
    "sourceType": "user | external_document | tool_output | agent_output | system",
    "sourceId": "document/tool/agent/user identifier",
    "createdBy": "user id or agent name",
    "conversationId": "optional"
  },
  "integrity": {
    "version": 1,
    "previousVersion": 0,
    "supersedes": "prior memory id"
  },
  "injection": {
    "suspicious": false,
    "score": 0.0,
    "categories": []
  },
  "expiresAt": "ISO-8601",
  "tsCreated": "ISO-8601",
  "tsUpdated": "ISO-8601"
}
```

Notes:

- `sourceType: "system"` exists only so the vocabulary can classify system
  content. It is **not writable** through any API or agent path; system
  instructions remain code-owned in `src/agents/prompts.ts`.
- `collection` and `memoryType` are derived from `sourceType`; callers cannot
  choose either.
- `status` is server-derived (`conflicted` when a logical key collides) and
  `trust` is always `untrusted` for application memory.
- `ownerUserId`, `tenantId`, `runId`, `trust`, `authoritative`, `contentHash`,
  `integrity`, `status`, `memoryType` and `provenance` are all server-derived.
  Strict request schemas reject unknown fields.
- `expiresAtDate` exists in Mongo only to drive the TTL index; it is never
  returned.

## 5. Authorization enforcement points

Every memory operation passes through **two** checks, both using the existing
`AuthorizationProvider` (OPA):

1. **API scope gate** — `requireAuthorized` in `src/api/routers/memory.ts`
   (one of `memory:search`, `memory:read`, `memory:insert`, `memory:update`, `memory:delete`) with `resourceOwner = caller`.
2. **Resource PEP** — `MemoryService.authorize` in `src/agents/memory.ts`, with
   the verified resource owner/tenant and the exact operation:
   - API: one of `memory:search`, `memory:read`, `memory:insert`, `memory:update`, `memory:delete` (`kind: "api"`), scope list from the
     user JWT.
   - Agents: the matching `memory.search` / `memory.read` / `memory.insert` / `memory.update` / `memory.delete` (`kind: "operation"`), requiring the
     action in the run token's `approvedActions`, `requestedRunId == runId`,
     `agent != ""`, owner match and tenant match.

Policy rules (`policies/v1/authz.rego`):

- `memory_api_scopes := {"memory:search", "memory:read", "memory:insert", "memory:update", "memory:delete"}` — deliberately **not**
  in `api_scopes`, so the generic `resource_owned` rule (which treats an empty
  owner as public) cannot authorize memory.
- `memory_owned` requires a non-empty `resourceOwner` that equals the caller.
- `memory_tenant_matched` accepts either both tenants empty or an exact match.
- The operation rule requires an agent identity and a run-bound grant.

Enforcement points:

| Operation | API route | Service | Repository |
|---|---|---|---|
| insert | `POST /memory` | `write` | owner/tenant/scopes derived, insert |
| read | `GET /memory/:id` | `get` | owner/tenant/scope + run/agent checks |
| search | `GET /memory` | `search` | required owner + scopes; run requires run id |
| update | `PATCH /memory/:id` | `update` | version-pinned filter + owner/tenant/scopes |
| delete | `DELETE /memory/:id` | `remove` | owner/tenant/scopes |

Default deny applies at each layer: absent policy, denied policy, unknown scope,
empty owner, unknown tenant, missing run binding or expired record all deny.

**Alternate-path prevention:** `Repositories` contains only operational stores.
The memory repository, document repository and Qdrant knowledge store are
constructed by `createMemoryStores` (called only in `src/api/main.ts` and
`src/agents/boot.ts`) and held privately by `MemoryService`. Agents receive
`ctx.memory` (the service), so `ctx.repos.documents` / `ctx.repos.knowledge` do
not compile and no raw store is passed to an executor. The memory repository
itself refuses unbounded queries (`assertIsolation`), so even a future caller
cannot dump memory without an owner and scope.

## 6. Qdrant filtering changes

`src/db/knowledge.ts`:

- Payload now includes `owner_user_id` and `tenant_id` (plus the existing
  `doc_id`, `chunk_index`, `content_hash`, `source`, `title`, `run_id`).
- `search(queryVector, limit, filter?)` translates a **closed, typed**
  `VectorSearchFilter` into Qdrant conditions:
  - `tenantId` known → `must: { key: "tenant_id", match: { value } }`;
  - no tenant → `must: { is_empty: { key: "tenant_id" } }`, so tenant-scoped
    documents cannot match a tenant-less caller.
  - `ownerUserId` known → `should: [owner match, owner is_empty]` (owned plus
    global documents), or owner-only when `includeUnowned` is false;
  - no owner → `must: { is_empty: { key: "owner_user_id" } }`.
- Callers cannot supply a collection name or raw Qdrant filter. The collection
  is the module constant `knowledge`, and `limit` is capped at 100.
- Payload indexes on `owner_user_id` / `tenant_id` are created best-effort once
  per process. They are an optimization only: the filter is always sent, so a
  missing index cannot widen results.
- Per-document authorization (`authorizeDocumentAccess`) remains inside
  `MemoryService.searchDocuments` as defense in depth after the server-side
  filter.

Ingest now resolves `run_id` through the trusted run record, verifies the
caller owns it, takes the tenant from the run, and stamps both owner and tenant
on the document and vector payload.

## 6.1 Remaining direct database access

Memory and knowledge-document access is centralized. The following operational
MongoDB access remains intentionally direct, through typed repositories, and
does **not** expose memory/knowledge stores:

| Process / agent | Repositories | Why |
|---|---|---|
| Recon Agent | `findings` | Persists validated security evidence. Findings are a separate collection, not trusted instructions and not memory. |
| Report Agent | `runs`, `findings`, `reports` | Reads the run/finding context needed to render a report and stores the report artifact. |
| Orchestrator | `runs`, `tasks` | Workflow state, idempotency and child-task bookkeeping. |
| API gateway | `runs`, `tasks`, `findings`, `reports`, `users` | User-facing run/report/auth operations. |
| STS | `runs` | Validates the trusted run record before minting/exchanging tokens. |

None of these repositories is a memory or knowledge-document store; none
accepts a caller-selected collection or unbounded query from an agent. The
Memory Service owns `memories`, `documents` and the Qdrant `knowledge`
collection exclusively.

## 7. Memory poisoning protections

These are enforced in code, not by prompt text:

1. **No trust promotion.** `trust` is derived from provenance and is always
   `untrusted` for writable sources; `authoritative` is always `false`.
   `sourceType: "system"` is rejected by the request schema and the service.
2. **No instruction coupling.** Memory is never read by the policy engine and
   never rendered into system/developer instructions. System instructions stay
   in `src/agents/prompts.ts`. A memory write cannot modify them.
3. **No permission expansion.** Memory records have no permission, action or
   scope-grant fields; strict schemas reject extras. Memory content is never
   used to compute `approvedActions`/`scopeTargets`, and policy decisions read
   only signed token attributes.
4. **No automatic agent-output promotion.** `agent_output` is a valid
   provenance label but is still untrusted. No orchestrator/agent path
   automatically writes child artifacts into memory; a future explicit write
   would still be storage-only, untrusted data.
5. **Explicit update rules.** Updates require the same authorization as writes,
   pin the prior version in the storage filter (optimistic concurrency), and
   cannot change provenance, owner, tenant, run, source or trust. A stale
   `expected_version` returns `409`.
6. **Conflict lineage.** A different value under the same logical key creates a
   new version with `conflict: true`, `previousVersion` and `supersedes`; the
   earlier record is retained instead of silently overwritten.
7. **Suspicious content retained and flagged.** The multi-signal detector runs
   on write/update. Suspicious memories are stored with an `injection` summary
   and audited (`prompt.injection.detected`, `memory.write`/`memory.update`);
   they are never marked authoritative.
8. **Secret minimization.** Private key blocks, bearer credentials, OpenAI-style
   keys and AWS access key ids are redacted before storage (best effort).
9. **Audit trail.** `memory.write`, `memory.read`, `memory.search`,
   `memory.update`, `memory.delete`, `memory.expired` record ids, scope,
   collection, source type, trust, conflict and suspicion — never raw content.

## 8. Context minimization and lifecycle

- Search is bounded: default 5, maximum 20 results; query text capped at 200
  characters; snippets capped at 1,200 characters with a `truncated` flag.
- API search defaults to `user` scope; run scope requires an owned `run_id`;
  agent search defaults to user/run memory.
- Stored content is capped at 8,000 characters (explicit truncation marker).
- Retention is clamped per source type: user 30 days, external document 90 days,
  tool output 7 days, agent output 14 days; minimum TTL 60 seconds.
- Expired records are excluded by both query predicates and a MongoDB TTL index
  on `expiresAtDate`. Expiry checks never mutate the store from an
  unauthenticated request.
- Delete is authorized and owner/tenant/scope-filtered; the response reports
  whether a row was actually removed.
- Sensitive content minimization is described in §7.

## 9. Known limitations and infrastructure dependencies

1. **Live-store verification pending.** Mongo TTL, Qdrant payload filters and
   payload indexes are exercised by unit/API tests with fakes; they have not
   been run against real MongoDB/Qdrant in this phase (no Docker run here).
2. **Legacy Qdrant points lack owner/tenant payload.** Documents indexed before
   this change have no `owner_user_id`/`tenant_id`, so the server-side filter
   treats them as global. The per-document authorization check still denies
   access to another user's document, but a re-index is required to make the
   server-side filter equally strict for historical data.
3. **User JWTs do not carry a tenant claim.** A user token therefore cannot
   access tenant-scoped memory; tenant/bound memory is available to
   tenant-bearing workload identities and to run-scoped memory whose tenant is
   derived from the trusted run record. Adding an IdP tenant claim is required
   for cross-user tenant sharing.
4. **Durable memory-record I/O is not wired to an agent task yet.** Knowledge
   document search/index does go through `MemoryService`, but the separate
   durable memory records (`/memory`) are used only by the gateway today. The
   service is wired into every worker (`ctx.memory`), and the policy has
   run-bound `memory.read`/`memory.write` rules, but no run token currently
   grants those actions. Enabling agent memory-record writes requires an
   explicit change to `RUN_ACTIONS`/`ACTIONS_BY_AUDIENCE` and the corresponding
   token exchange; it was not enabled silently.
5. **Memory has no vector index.** Memory search is structured (owner, scope,
   key, substring, recency) over MongoDB. If semantic memory is added later, it
   must reuse the same closed filter pattern and server-side tenant/owner
   conditions used for knowledge.
6. **Conflict detection is key-based.** Memories written without a `key` have
   no automatic conflict comparison; provenance and versioning still apply.
7. **Secret redaction is best effort.** Novel secret formats may not match the
   patterns; memory must not be used as a secret store.
8. **The detection layer remains supplementary.** It flags suspicious content
   for audit/telemetry but never authorizes or denies memory access.
9. **Report/task context is not memory.** `tasks.output` and report content are
   operational artifacts. They are already treated as untrusted agent output by
   Phase 3, but they do not carry memory provenance/version metadata.
10. **In-process service shares the worker process.** Option A centralizes all
    memory *access paths*, but the worker process still holds the MongoDB/Qdrant
    connection at boot. Database clients and connection strings are never passed
    to an executor, and `ctx.repos` exposes no memory store; true credential
    isolation would require a separate Memory Service process/deployment, which
    is deferred (no Docker/Kubernetes changes in this phase).

## 10. Decisions and assumptions

- **Memory is a new subsystem, not a new architecture.** It reuses MongoDB,
  the existing `AuthorizationProvider`, the existing audit interface and the
  Phase 3 detector; no new dependency, service or authz mechanism was added.
- **The Memory Service is an in-process module (Option A).** It is not a
  separate application service; this avoids new deployment/infrastructure work
  while still centralizing all memory-owned Mongo/Qdrant access.
- **Centralization is structural.** `Repositories` exposes only operational
  stores; memory stores are created by `createMemoryStores` and held privately
  by `MemoryService`. Agents receive `ctx.memory`.
- **Collections are code-owned.** Source type determines the logical
  collection. This satisfies "only authorized collections can be queried"
  without exposing a collection parameter.
- **Storage is the service boundary.** Raw memory repositories are deliberately
  absent from `Repositories`; agents only get `MemoryService`.
- **Trust is derived and conservative.** Application memory is untrusted and
  non-authoritative by construction; the only trusted instructions remain
  code-owned prompts.
- **Default deny at three layers.** Route scope, OPA resource decision, and the
  repository's mandatory isolation predicate must all succeed.
- **Scope mapping.** Each operation has a separate scope: `memory:search`,
  `memory:read`, `memory:insert`, `memory:update`, `memory:delete`. Operation
  actions use the same names with a dot (`memory.search`, etc.). There is no
  combined read/write scope.
- **Tenant source of truth.** For run-scoped memory, tenant and owner come from
  the trusted `runs` record; for user memory, from the verified identity. No
  request body field can set them.

## 11. Verification

```
pnpm typecheck   # pass
pnpm lint        # pass
pnpm test        # 147 tests, 20 files, pass
pnpm build       # typecheck + emit
```

No attack-scenario testing was performed in this phase; that remains part of
the final project-wide security review.
