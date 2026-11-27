import { AppError, AuthorizationDeniedError, NotFoundError, ValidationError } from "../core/errors.js";
import { chunkText } from "../core/chunking.js";
import { newId, stableHash } from "../core/ids.js";
import {
  derivedMemoryTrust,
  isMemoryExpired,
  isWritableMemorySource,
  limitMemoryContent,
  MEMORY_LIMITS,
  memoryCollectionFor,
  memorySnippet,
  memoryStatusFor,
  memoryTypeFor,
  redactSensitiveMemoryContent,
  retentionSecondsFor,
  type MemoryInjectionSummary,
  type MemoryIntegrity,
  type MemoryProvenance,
  type MemoryRecord,
  type MemoryScope,
  type MemoryStatus,
  type MemoryTrust,
  type MemoryType,
  type WritableMemorySource,
} from "../core/memory.js";
import type { RunRecord } from "../core/domain.js";
import type { RunsRepository } from "../db/repositories/contracts.js";
import type { MemoryStores } from "../db/memory-store.js";
import type {
  MemoryIsolation,
  MemoryUpdatePatch,
  MemoriesRepository,
} from "../db/repositories/memory.js";
import type {
  AuditProvider,
  AuthorizationProvider,
  AuthzResource,
  EmbeddingProvider,
} from "../security/protocols.js";
import { inspectUntrustedContent } from "../security/prompt/index.js";
import type { DetectionResult, UntrustedTier } from "../security/prompt/types.js";
import { withDeadline } from "../core/resilience/abort.js";
import { authorizeDocumentAccess } from "./authz.js";

/** Default caller-visible deadline for a memory operation. */
export const DEFAULT_MEMORY_TIMEOUT_MS = 30_000;

/**
 * Verified caller identity for a memory operation.
 *
 * `kind: "api"` is a user request authenticated at the gateway; `kind:
 * "operation"` is an agent acting under a run-bound workload token. Neither
 * variant carries caller-supplied tenant/owner/trust fields: those are derived
 * here from the verified identity and the trusted run record.
 */
export interface MemoryActor {
  kind: "api" | "operation";
  principal: string;
  userId: string;
  scopes: readonly string[];
  tenantId?: string;
  runId?: string;
  agent?: string;
  workload?: string;
  approvedActions?: readonly string[];
  approvedTargets?: readonly string[];
}

export interface WriteMemoryInput {
  content: string;
  sourceType: WritableMemorySource;
  sourceId: string;
  scope: MemoryScope;
  key?: string;
  tags?: readonly string[];
  runId?: string;
  conversationId?: string;
  ttlSeconds?: number;
}

export interface UpdateMemoryInput {
  content?: string;
  key?: string | null;
  tags?: readonly string[];
  ttlSeconds?: number;
  expectedVersion?: number;
}

export interface SearchMemoryInput {
  scope?: MemoryScope;
  runId?: string;
  key?: string;
  q?: string;
  limit?: number;
}

/** Bounded memory view returned by search (context minimization). */
export interface MemorySearchView {
  memoryId: string;
  scope: MemoryScope;
  collection: string;
  memoryType: MemoryType;
  status: MemoryStatus;
  key?: string;
  content: string;
  truncated: boolean;
  trust: MemoryTrust;
  authoritative: false;
  conflict: boolean;
  provenance: MemoryProvenance;
  integrity: MemoryIntegrity;
  injection?: MemoryInjectionSummary;
  expiresAt?: string;
  tsCreated: string;
  tsUpdated: string;
}

export interface MemorySearchResult {
  memories: readonly MemorySearchView[];
  truncated: boolean;
}

export interface IngestDocumentInput {
  source: string;
  content: string;
  contentType: string;
  title?: string;
  runId?: string;
  metadata?: Record<string, unknown>;
}

export interface IngestDocumentResult {
  docId: string;
  chunkCount: number;
  deduped: boolean;
}

export interface SearchDocumentsInput {
  query: string;
  limit?: number;
}

export interface DocumentProvenance {
  source: string;
  title: string;
  contentHash: string;
  ownerUserId?: string;
  tenantId?: string;
}

/** Retrieved documents are always untrusted context with provenance. */
export interface RetrievedDocumentMemory {
  docId: string;
  score: number;
  trust: "untrusted";
  provenance: DocumentProvenance;
}

export interface SearchDocumentsResult {
  documents: readonly RetrievedDocumentMemory[];
  denied: number;
}

export interface MemoryServiceDeps {
  /** Memory-owned persistence; never exposed to agents. */
  stores: MemoryStores;
  runs: RunsRepository;
  authz: AuthorizationProvider;
  audit: AuditProvider;
  embedding: EmbeddingProvider;
  /** Caller-visible deadline for each memory operation (cooperative). */
  timeoutMs?: number;
}

/** Upper bound on retrieved chunks; code-owned, never model-selected. */
export const MAX_DOCUMENT_RETRIEVAL_LIMIT = 50;

const DOCUMENT_METADATA_MAX_KEYS = 32;
const DOCUMENT_METADATA_MAX_KEY_CHARS = 64;
const DOCUMENT_METADATA_MAX_VALUE_CHARS = 1024;
const RESERVED_DOCUMENT_METADATA_KEYS: ReadonlySet<string> = new Set(["trust", "provenance", "injection"]);

const WRITE_MEMORY_KEYS: ReadonlySet<string> = new Set([
  "content",
  "sourceType",
  "sourceId",
  "scope",
  "key",
  "tags",
  "runId",
  "conversationId",
  "ttlSeconds",
]);
const UPDATE_MEMORY_KEYS: ReadonlySet<string> = new Set([
  "content",
  "key",
  "tags",
  "ttlSeconds",
  "expectedVersion",
]);
const SEARCH_MEMORY_KEYS: ReadonlySet<string> = new Set(["scope", "runId", "key", "q", "limit"]);
const INGEST_DOCUMENT_KEYS: ReadonlySet<string> = new Set([
  "source",
  "content",
  "contentType",
  "title",
  "runId",
  "metadata",
]);

/** Reject unknown fields so a caller cannot smuggle security metadata. */
function assertKnownKeys(input: object, allowed: ReadonlySet<string>, label: string): void {
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) {
      throw new ValidationError(`unknown ${label} field '${key}'`);
    }
  }
}

type MemoryOperation = "search" | "read" | "insert" | "update" | "delete";

interface AuthTarget {
  memoryId?: string;
  /** Object id for document operations (knowledge:read/index, knowledge.search). */
  requestedObject?: string;
  ownerUserId: string;
  tenantId?: string;
  runId?: string;
}

function injectionOf(result: DetectionResult): MemoryInjectionSummary {
  return {
    suspicious: result.suspicious,
    score: result.score,
    categories: result.signals.map((signal) => signal.category),
  };
}

function tierFor(sourceType: WritableMemorySource): UntrustedTier {
  switch (sourceType) {
    case "user":
      return "user-request";
    case "external_document":
      return "external";
    case "tool_output":
      return "tool-output";
    case "agent_output":
      return "agent-output";
  }
}

function normalizeTags(tags: readonly string[]): readonly string[] {
  if (tags.length > MEMORY_LIMITS.maxTags) {
    throw new ValidationError(`at most ${MEMORY_LIMITS.maxTags} memory tags are allowed`);
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of tags) {
    const tag = raw.trim();
    if (tag.length === 0) throw new ValidationError("memory tags cannot be empty");
    if (tag.length > MEMORY_LIMITS.maxTagChars) throw new ValidationError("memory tag is too long");
    if (seen.has(tag)) continue;
    seen.add(tag);
    out.push(tag);
  }
  return out;
}

function normalizeKey(key: string | undefined): string | undefined {
  if (key === undefined) return undefined;
  const trimmed = key.trim();
  if (trimmed.length === 0 || trimmed.length > MEMORY_LIMITS.maxKeyChars) {
    throw new ValidationError("invalid memory key");
  }
  return trimmed;
}

/**
 * Caller metadata is untrusted and namespaced away from authoritative fields.
 * Only bounded scalar values survive; `trust`/`provenance`/`injection` are
 * reserved for the service and can never be supplied.
 */
function sanitizeDocumentMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> {
  if (metadata === undefined) return {};
  const out: Record<string, unknown> = {};
  let kept = 0;
  for (const [key, value] of Object.entries(metadata)) {
    if (kept >= DOCUMENT_METADATA_MAX_KEYS) break;
    if (RESERVED_DOCUMENT_METADATA_KEYS.has(key)) continue;
    if (key.length === 0 || key.length > DOCUMENT_METADATA_MAX_KEY_CHARS) continue;
    if (typeof value === "string" && value.length <= DOCUMENT_METADATA_MAX_VALUE_CHARS) {
      out[key] = value;
      kept += 1;
    } else if (typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
      kept += 1;
    }
  }
  return out;
}

/**
 * The single application path for durable memory.
 *
 * Security properties:
 * - every operation is authorized through the existing `AuthorizationProvider`
 *   (OPA) before any storage access;
 * - owner/tenant/run/agent isolation is derived from verified identity and the
 *   trusted run record, never from caller-supplied fields;
 * - stored memory is always untrusted data and never authoritative, so it
 *   cannot become a system instruction or expand permissions;
 * - suspicious content is retained but flagged and audited, never silently
 *   promoted;
 * - reads are bounded and snippets are capped (context minimization);
 * - TTLs are clamped per source type and query results exclude expired rows.
 */
export class MemoryService {
  private readonly memories: MemoriesRepository;
  private readonly documents: MemoryStores["documents"];
  private readonly knowledge: MemoryStores["knowledge"];
  private readonly runs: RunsRepository;
  private readonly authz: AuthorizationProvider;
  private readonly audit: AuditProvider;
  private readonly embedding: EmbeddingProvider;
  private readonly timeoutMs: number;

  constructor(deps: MemoryServiceDeps) {
    this.memories = deps.stores.memories;
    this.documents = deps.stores.documents;
    this.knowledge = deps.stores.knowledge;
    this.runs = deps.runs;
    this.authz = deps.authz;
    this.audit = deps.audit;
    this.embedding = deps.embedding;
    this.timeoutMs = deps.timeoutMs ?? DEFAULT_MEMORY_TIMEOUT_MS;
  }

  /**
   * Bound each public operation. The deadline rejects the caller and aborts
   * the cooperative signal, but storage/driver work that ignores the signal may
   * finish later; Mongo/Qdrant clients already have their own 3s timeouts.
   */
  private async bounded<T>(operation: string, work: () => Promise<T>): Promise<T> {
    return withDeadline(async () => work(), {
      timeoutMs: this.timeoutMs,
      label: `memory.${operation}`,
    });
  }

  async write(actor: MemoryActor, input: WriteMemoryInput): Promise<MemoryRecord> {
    return this.bounded("write", () => this.writeImpl(actor, input));
  }

  private async writeImpl(actor: MemoryActor, input: WriteMemoryInput): Promise<MemoryRecord> {
    this.assertActor(actor);
    assertKnownKeys(input, WRITE_MEMORY_KEYS, "memory write");
    if (typeof input.content !== "string" || typeof input.sourceId !== "string") {
      throw new ValidationError("invalid memory content or source id");
    }
    if (input.tags !== undefined && !Array.isArray(input.tags)) {
      throw new ValidationError("memory tags must be an array");
    }
    if (!isWritableMemorySource(input.sourceType)) {
      throw new ValidationError("memory source type is not writable");
    }
    const scope = input.scope;
    this.assertScope(actor, scope);

    const resolved = await this.resolveWriteScope(actor, scope, input.runId);
    const collection = memoryCollectionFor(input.sourceType);
    const key = normalizeKey(input.key);
    const tags = input.tags !== undefined ? normalizeTags(input.tags) : [];
    if (input.content.trim().length === 0) {
      throw new ValidationError("memory content cannot be empty");
    }
    if (input.sourceId.trim().length === 0) {
      throw new ValidationError("memory source id cannot be empty");
    }
    const content = limitMemoryContent(redactSensitiveMemoryContent(input.content));
    const contentHash = stableHash(content);

    const inspection = await inspectUntrustedContent(this.audit, {
      tier: tierFor(input.sourceType),
      source: `memory:${input.sourceType}:${input.sourceId.slice(0, MEMORY_LIMITS.maxSourceIdChars)}`,
      content,
      agent: actor.agent ?? (actor.kind === "api" ? "gateway" : "unknown"),
      ...(resolved.runId !== undefined ? { runId: resolved.runId } : {}),
      principal: actor.userId,
    });

    const previousRaw =
      key !== undefined
        ? await this.memories.findLatestByKey({
            ownerUserId: resolved.ownerUserId,
            ...(resolved.tenantId !== undefined ? { tenantId: resolved.tenantId } : {}),
            scope,
            collection,
            key,
            ...(scope === "run" && resolved.runId !== undefined ? { runId: resolved.runId } : {}),
            ...(scope === "agent" && actor.agent !== undefined ? { agent: actor.agent } : {}),
          })
        : null;
    // Expired lineage never counts as the current value (TTL will remove it).
    const previous = previousRaw !== null && !isMemoryExpired(previousRaw) ? previousRaw : null;

    // Idempotent re-write of the same value: do not create a duplicate row.
    if (previous !== null && previous.contentHash === contentHash && previous.scope === scope) {
      return previous;
    }

    const now = new Date().toISOString();
    const ttl = retentionSecondsFor(input.sourceType, input.ttlSeconds);
    const conflict = previous !== null;
    const record: MemoryRecord = {
      memoryId: newId(),
      scope,
      collection,
      memoryType: memoryTypeFor(input.sourceType),
      status: memoryStatusFor(conflict),
      ...(key !== undefined ? { key } : {}),
      content,
      contentHash,
      // Stored memory is always untrusted, regardless of who supplied it.
      trust: derivedMemoryTrust(input.sourceType),
      authoritative: false,
      ownerUserId: resolved.ownerUserId,
      ...(resolved.tenantId !== undefined ? { tenantId: resolved.tenantId } : {}),
      ...(resolved.runId !== undefined ? { runId: resolved.runId } : {}),
      ...(scope === "agent" && actor.agent !== undefined ? { agent: actor.agent } : {}),
      tags,
      // A different value under the same logical key is a conflict: retain the
      // lineage instead of silently overwriting the earlier memory.
      conflict,
      provenance: {
        sourceType: input.sourceType,
        sourceId: input.sourceId.slice(0, MEMORY_LIMITS.maxSourceIdChars),
        createdBy: actor.kind === "api" ? actor.userId : (actor.agent ?? actor.userId),
        ...(input.conversationId !== undefined
          ? { conversationId: input.conversationId.slice(0, MEMORY_LIMITS.maxConversationIdChars) }
          : {}),
      },
      integrity: {
        version: previous !== null ? previous.integrity.version + 1 : 1,
        ...(previous !== null
          ? { previousVersion: previous.integrity.version, supersedes: previous.memoryId }
          : {}),
      },
      injection: injectionOf(inspection.result),
      expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
      tsCreated: now,
      tsUpdated: now,
    };

    await this.authorize(
      actor,
      "insert",
      {
        ownerUserId: record.ownerUserId,
        ...(record.tenantId !== undefined ? { tenantId: record.tenantId } : {}),
        ...(record.runId !== undefined ? { runId: record.runId } : {}),
      },
      record.tenantId,
    );

    const stored = await this.memories.insert(record);
    await this.auditRecord("memory.write", actor, stored, { conflict: stored.conflict });
    return stored;
  }

  /**
   * Ingest a knowledge document. API-only: agents may index documents they can
   * already access, but only the authenticated gateway admits new content.
   */
  async ingestDocument(actor: MemoryActor, input: IngestDocumentInput): Promise<IngestDocumentResult> {
    return this.bounded("ingestDocument", () => this.ingestDocumentImpl(actor, input));
  }

  private async ingestDocumentImpl(actor: MemoryActor, input: IngestDocumentInput): Promise<IngestDocumentResult> {
    this.assertActor(actor);
    assertKnownKeys(input, INGEST_DOCUMENT_KEYS, "document ingest");
    if (typeof input.content !== "string" || typeof input.source !== "string") {
      throw new ValidationError("invalid document content or source");
    }
    if (actor.kind !== "api") {
      throw new AuthorizationDeniedError("document ingestion is only available to the authenticated API");
    }
    if (input.content.trim().length === 0) {
      throw new ValidationError("document content cannot be empty");
    }

    let tenantId: string | undefined;
    if (input.runId !== undefined) {
      const run = await this.resolveRun(actor, input.runId);
      tenantId = run.tenantId;
    }

    await this.authorizeAction(
      actor,
      "knowledge:write",
      {
        ownerUserId: actor.userId,
        ...(tenantId !== undefined ? { tenantId } : {}),
        ...(input.runId !== undefined ? { runId: input.runId } : {}),
      },
      tenantId ?? actor.tenantId,
    );

    const inspection = await inspectUntrustedContent(this.audit, {
      tier: "external",
      source: `knowledge.ingest:${input.source}`,
      content: input.content,
      agent: "gateway",
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      principal: actor.userId,
    });

    const contentHash = stableHash(input.content);
    const existing = await this.documents.getByContentHash(contentHash);
    if (existing !== null) {
      // Do not disclose another owner's or tenant's doc id. The content itself
      // is not returned and remains protected by per-document authorization.
      const sameOwner = existing.ownerUserId === undefined || existing.ownerUserId === actor.userId;
      const sameTenant = (existing.tenantId ?? "") === (tenantId ?? "");
      return {
        docId: sameOwner && sameTenant ? existing.docId : "",
        chunkCount: existing.chunkCount,
        deduped: true,
      };
    }

    const chunks = chunkText(input.content);
    const vectors = await this.embedding.embed(chunks.map((chunk) => chunk.text));
    const docId = newId();
    const title = input.title ?? input.source;
    await this.knowledge.upsertChunks({
      docId,
      title,
      source: input.source,
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      ownerUserId: actor.userId,
      ...(tenantId !== undefined ? { tenantId } : {}),
      chunks: chunks.map((chunk) => ({ index: chunk.index, contentHash: chunk.contentHash })),
      vectors,
    });

    await this.documents.create({
      docId,
      source: input.source,
      title,
      contentType: input.contentType,
      contentHash,
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      ownerUserId: actor.userId,
      ...(tenantId !== undefined ? { tenantId } : {}),
      metadata: {
        ...sanitizeDocumentMetadata(input.metadata),
        trust: "untrusted",
        provenance: {
          source: input.source,
          ...(input.runId !== undefined ? { runId: input.runId } : {}),
          ownerUserId: actor.userId,
          ...(tenantId !== undefined ? { tenantId } : {}),
        },
        injection: injectionOf(inspection.result),
      },
    });
    await this.documents.markIndexed(docId, chunks.length);

    await this.audit.emit({
      type: "knowledge.ingest",
      ts: new Date().toISOString(),
      traceId: docId,
      principal: actor.userId,
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      data: {
        doc_id: docId,
        chunk_count: chunks.length,
        source: input.source,
        trust: "untrusted",
        suspicious: inspection.result.suspicious,
        ...(tenantId !== undefined ? { tenant_id: tenantId } : {}),
      },
    });

    return { docId, chunkCount: chunks.length, deduped: false };
  }

  /**
   * Secure RAG retrieval. The service selects the collection, applies the
   * server-side owner/tenant filter, authorizes every candidate document with
   * the existing policy, and returns untrusted data with provenance.
   */
  async searchDocuments(actor: MemoryActor, input: SearchDocumentsInput): Promise<SearchDocumentsResult> {
    return this.bounded("searchDocuments", () => this.searchDocumentsImpl(actor, input));
  }

  private async searchDocumentsImpl(actor: MemoryActor, input: SearchDocumentsInput): Promise<SearchDocumentsResult> {
    this.assertActor(actor);
    const requested = input.limit ?? 10;
    const limit = Math.min(Math.max(1, Math.trunc(requested)), MAX_DOCUMENT_RETRIEVAL_LIMIT);
    const action = actor.kind === "api" ? "knowledge:read" : "knowledge.search";

    await this.authorizeAction(
      actor,
      action,
      {
        ownerUserId: actor.userId,
        ...(actor.tenantId !== undefined ? { tenantId: actor.tenantId } : {}),
        ...(actor.runId !== undefined ? { runId: actor.runId } : {}),
      },
      actor.tenantId,
    );

    const inspection = await inspectUntrustedContent(this.audit, {
      tier: "user-request",
      source: "knowledge.query",
      content: input.query,
      agent: actor.agent ?? (actor.kind === "api" ? "gateway" : "knowledge"),
      ...(actor.runId !== undefined ? { runId: actor.runId } : {}),
      principal: actor.userId,
    });

    const vectors = await this.embedding.embed([input.query]);
    const queryVector = vectors[0];
    if (queryVector === undefined || queryVector.length === 0) {
      await this.auditRetrieval(actor, inspection.result.suspicious, [], 0);
      return { documents: [], denied: 0 };
    }

    const hits = await this.knowledge.search(queryVector, limit, {
      ownerUserId: actor.userId,
      includeUnowned: true,
      ...(actor.tenantId !== undefined ? { tenantId: actor.tenantId } : {}),
    });

    const documents: RetrievedDocumentMemory[] = [];
    let denied = 0;
    for (const hit of hits) {
      const doc = await this.documents.get(hit.docId);
      if (doc === null) continue;
      const allowed = await authorizeDocumentAccess({
        authz: this.authz,
        kind: actor.kind,
        action,
        user: actor.userId,
        requestedObject: hit.docId,
        resourceOwner: doc.ownerUserId ?? "",
        resourceTenantId: doc.tenantId ?? "",
        ...(actor.tenantId !== undefined ? { tenantId: actor.tenantId } : {}),
        ...(actor.kind === "api" ? { scopes: actor.scopes } : {}),
      });
      if (!allowed) {
        denied += 1;
        continue;
      }
      documents.push({
        docId: hit.docId,
        score: hit.score,
        trust: "untrusted",
        provenance: {
          source: doc.source,
          title: doc.title,
          contentHash: doc.contentHash,
          ...(doc.ownerUserId !== undefined ? { ownerUserId: doc.ownerUserId } : {}),
          ...(doc.tenantId !== undefined ? { tenantId: doc.tenantId } : {}),
        },
      });
    }

    await this.auditRetrieval(actor, inspection.result.suspicious, documents, denied);
    return { documents, denied };
  }

  /**
   * Mark explicit documents as indexed for an agent operation. Each document is
   * independently authorized; unlike ingestion this does not admit new content.
   */
  async indexDocuments(actor: MemoryActor, docIds: readonly string[]): Promise<{ indexed: readonly string[] }> {
    return this.bounded("indexDocuments", () => this.indexDocumentsImpl(actor, docIds));
  }

  private async indexDocumentsImpl(actor: MemoryActor, docIds: readonly string[]): Promise<{ indexed: readonly string[] }> {
    this.assertActor(actor);
    if (actor.kind !== "operation") {
      throw new AuthorizationDeniedError("document indexing is only available to an agent operation");
    }
    if (docIds.length === 0 || docIds.length > 100) {
      throw new ValidationError("invalid document index request");
    }

    const indexed: string[] = [];
    for (const docId of docIds) {
      const doc = await this.documents.get(docId);
      if (doc === null) continue;
      await this.authorizeAction(
        actor,
        "knowledge.index",
        {
          requestedObject: docId,
          ownerUserId: doc.ownerUserId ?? actor.userId,
          ...(doc.tenantId !== undefined ? { tenantId: doc.tenantId } : {}),
          ...(actor.runId !== undefined ? { runId: actor.runId } : {}),
        },
        actor.tenantId ?? doc.tenantId,
      );
      await this.documents.markIndexed(docId, doc.chunkCount);
      indexed.push(docId);
    }

    await this.audit.emit({
      type: "knowledge.index",
      ts: new Date().toISOString(),
      traceId: newId(),
      principal: actor.userId,
      ...(actor.runId !== undefined ? { runId: actor.runId } : {}),
      data: { requested: docIds.length, indexed: indexed.length },
    });
    return { indexed };
  }

  private async auditRetrieval(
    actor: MemoryActor,
    querySuspicious: boolean,
    documents: readonly RetrievedDocumentMemory[],
    denied: number,
  ): Promise<void> {
    await this.audit.emit({
      type: "knowledge.retrieval",
      ts: new Date().toISOString(),
      traceId: actor.runId ?? "knowledge-retrieval",
      principal: actor.userId,
      ...(actor.runId !== undefined ? { runId: actor.runId } : {}),
      data: {
        trust: "untrusted",
        query_source: "knowledge.query",
        query_suspicious: querySuspicious,
        returned: documents.length,
        denied,
        doc_ids: documents.map((document) => document.docId),
      },
    });
  }

  async get(actor: MemoryActor, memoryId: string): Promise<MemoryRecord> {
    return this.bounded("get", () => this.getImpl(actor, memoryId));
  }

  private async getImpl(actor: MemoryActor, memoryId: string): Promise<MemoryRecord> {
    this.assertActor(actor);
    const record = await this.memories.get(memoryId);
    if (record === null) throw new NotFoundError("memory not found");
    const tenant = await this.resolveRecordAccess(actor, record);
    await this.assertNotExpired(actor, record);
    await this.authorize(actor, "read", this.targetOf(record), tenant);
    await this.auditRecord("memory.read", actor, record, {});
    return record;
  }

  async search(actor: MemoryActor, input: SearchMemoryInput = {}): Promise<MemorySearchResult> {
    return this.bounded("search", () => this.searchImpl(actor, input));
  }

  private async searchImpl(actor: MemoryActor, input: SearchMemoryInput = {}): Promise<MemorySearchResult> {
    this.assertActor(actor);
    assertKnownKeys(input, SEARCH_MEMORY_KEYS, "memory search");
    const requested = input.limit ?? MEMORY_LIMITS.defaultResults;
    const limit = Math.min(Math.max(1, Math.trunc(requested)), MEMORY_LIMITS.maxResults);

    const baseScopes = this.scopesFor(actor);
    let scopes: MemoryScope[];
    if (input.scope !== undefined) {
      if (!baseScopes.includes(input.scope)) {
        throw new AuthorizationDeniedError(`memory scope '${input.scope}' is not available to this caller`);
      }
      scopes = [input.scope];
    } else {
      // Context minimization: API searches default to user notes; agents
      // default to their own user/run memory. Broader scopes require an
      // explicit, still-authorized request.
      scopes = actor.kind === "api" ? ["user"] : baseScopes.filter((s) => s === "user" || s === "run");
    }

    let runId = actor.runId;
    let tenantId = actor.tenantId;
    if (input.scope === "run") {
      const requestedRun = input.runId ?? actor.runId;
      if (requestedRun === undefined || requestedRun === "") {
        throw new ValidationError("run_id is required to search run-scoped memory");
      }
      const run = await this.resolveRun(actor, requestedRun);
      runId = run.runId;
      if (run.tenantId !== undefined) tenantId = run.tenantId;
    }
    if (scopes.includes("run") && (runId === undefined || runId === "")) {
      scopes = scopes.filter((scope) => scope !== "run");
    }
    if (scopes.includes("tenant") && (tenantId === undefined || tenantId === "")) {
      throw new AuthorizationDeniedError("tenant-scoped memory requires a tenant identity");
    }
    if (scopes.includes("agent") && (actor.agent === undefined || actor.agent === "")) {
      scopes = scopes.filter((scope) => scope !== "agent");
    }
    if (scopes.length === 0) return { memories: [], truncated: false };

    await this.authorize(
      actor,
      "search",
      {
        ownerUserId: actor.userId,
        ...(tenantId !== undefined ? { tenantId } : {}),
        ...(runId !== undefined ? { runId } : {}),
      },
      tenantId,
    );

    const q = input.q !== undefined ? input.q.slice(0, MEMORY_LIMITS.maxQueryChars) : undefined;
    const key = input.key !== undefined ? normalizeKey(input.key) : undefined;
    const records = await this.memories.search({
      ownerUserId: actor.userId,
      ...(tenantId !== undefined ? { tenantId } : {}),
      scopes,
      ...(runId !== undefined && runId !== "" ? { runId } : {}),
      ...(scopes.includes("agent") && actor.agent !== undefined ? { agent: actor.agent } : {}),
      ...(key !== undefined ? { key } : {}),
      ...(q !== undefined && q !== "" ? { q } : {}),
      limit: limit + 1,
    });

    // Defense in depth: re-check ownership/tenant/scope/expiry in code even
    // though the repository query already applied the same predicates.
    const now = Date.now();
    const visible = records.filter(
      (record) =>
        record.ownerUserId === actor.userId &&
        scopes.includes(record.scope) &&
        !isMemoryExpired(record, now) &&
        (tenantId !== undefined && tenantId !== ""
          ? record.tenantId === tenantId
          : record.tenantId === undefined || record.tenantId === ""),
    );
    const truncated = visible.length > limit;
    const memories = visible.slice(0, limit).map((record) => this.toSearchView(record));

    await this.audit.emit({
      type: "memory.search",
      ts: new Date().toISOString(),
      traceId: newId(),
      principal: actor.userId,
      ...(runId !== undefined ? { runId } : {}),
      data: {
        memory_id: "",
        scope: input.scope ?? (actor.kind === "api" ? "user" : "user,run"),
        collection: "",
        source_type: "",
        trust: "untrusted",
        conflict: false,
        suspicious: false,
        returned: memories.length,
        truncated,
      },
    });

    return { memories, truncated };
  }

  async update(actor: MemoryActor, memoryId: string, input: UpdateMemoryInput): Promise<MemoryRecord> {
    return this.bounded("update", () => this.updateImpl(actor, memoryId, input));
  }

  private async updateImpl(actor: MemoryActor, memoryId: string, input: UpdateMemoryInput): Promise<MemoryRecord> {
    this.assertActor(actor);
    assertKnownKeys(input, UPDATE_MEMORY_KEYS, "memory update");
    const record = await this.memories.get(memoryId);
    if (record === null) throw new NotFoundError("memory not found");
    const tenant = await this.resolveRecordAccess(actor, record);
    await this.assertNotExpired(actor, record);

    if (!isWritableMemorySource(record.provenance.sourceType)) {
      throw new ValidationError("memory source type is not writable");
    }
    if (
      input.content === undefined &&
      input.key === undefined &&
      input.tags === undefined &&
      input.ttlSeconds === undefined
    ) {
      throw new ValidationError("no memory changes were supplied");
    }
    if (input.expectedVersion !== undefined && input.expectedVersion !== record.integrity.version) {
      throw new AppError("conflict", "memory was modified by another request", 409);
    }

    if (input.content !== undefined && input.content.trim().length === 0) {
      throw new ValidationError("memory content cannot be empty");
    }
    const content =
      input.content !== undefined ? limitMemoryContent(redactSensitiveMemoryContent(input.content)) : record.content;
    const contentHash = stableHash(content);
    const key = input.key !== undefined && input.key !== null ? normalizeKey(input.key) : input.key;
    const inspection =
      input.content !== undefined
        ? await inspectUntrustedContent(this.audit, {
            tier: tierFor(record.provenance.sourceType),
            source: `memory:${record.provenance.sourceType}:${record.provenance.sourceId.slice(
              0,
              MEMORY_LIMITS.maxSourceIdChars,
            )}`,
            content,
            agent: actor.agent ?? (actor.kind === "api" ? "gateway" : "unknown"),
            ...(record.runId !== undefined ? { runId: record.runId } : {}),
            principal: actor.userId,
          })
        : undefined;

    const patch: MemoryUpdatePatch = {
      ...(input.content !== undefined ? { content, contentHash } : {}),
      ...(key !== undefined ? { key } : {}),
      ...(input.tags !== undefined ? { tags: normalizeTags(input.tags) } : {}),
      ...(inspection !== undefined ? { injection: injectionOf(inspection.result) } : {}),
      ...(input.ttlSeconds !== undefined
        ? { expiresAt: new Date(Date.now() + retentionSecondsFor(record.provenance.sourceType, input.ttlSeconds) * 1000).toISOString() }
        : {}),
      version: record.integrity.version + 1,
      previousVersion: record.integrity.version,
    };

    await this.authorize(actor, "update", this.targetOf(record), tenant);
    const updated = await this.memories.update(memoryId, this.isolationOf(record), patch);
    if (updated === null) {
      // The update filter pins the previous version, so a null result is
      // either concurrent modification or deletion. Distinguish the two.
      const still = await this.memories.get(memoryId);
      if (still === null) throw new NotFoundError("memory not found");
      throw new AppError("conflict", "memory was modified concurrently", 409);
    }
    await this.auditRecord("memory.update", actor, updated, {});
    return updated;
  }

  async remove(actor: MemoryActor, memoryId: string): Promise<boolean> {
    return this.bounded("remove", () => this.removeImpl(actor, memoryId));
  }

  private async removeImpl(actor: MemoryActor, memoryId: string): Promise<boolean> {
    this.assertActor(actor);
    const record = await this.memories.get(memoryId);
    if (record === null) throw new NotFoundError("memory not found");
    const tenant = await this.resolveRecordAccess(actor, record);
    await this.authorize(actor, "delete", this.targetOf(record), tenant);
    const deleted = await this.memories.remove(memoryId, this.isolationOf(record));
    if (deleted) {
      await this.auditRecord("memory.delete", actor, record, {});
    }
    return deleted;
  }

  private assertActor(actor: MemoryActor): void {
    if (actor.userId === "") {
      throw new AuthorizationDeniedError("memory access requires an authenticated user");
    }
  }

  /**
   * Operation callers must hold the action in the verified run grant. The OPA
   * policy independently checks ownership/run/tenant; this is the least
   * privilege check on the action itself.
   */
  private assertOperationGrant(actor: MemoryActor, action: string): void {
    if (actor.kind !== "operation") return;
    if (!(actor.approvedActions ?? []).includes(action)) {
      throw new AuthorizationDeniedError(`operation '${action}' is not granted to this caller`);
    }
  }

  private scopesFor(actor: MemoryActor): MemoryScope[] {
    const scopes: MemoryScope[] = ["user"];
    // API callers may address run-scoped memory only through an owned run,
    // which `resolveRun` verifies. Operation callers are bound to their run.
    if (actor.kind === "api") scopes.push("run");
    if (actor.kind === "operation" && actor.runId !== undefined && actor.runId !== "") scopes.push("run");
    if (actor.kind === "operation" && actor.agent !== undefined && actor.agent !== "") scopes.push("agent");
    if (actor.tenantId !== undefined && actor.tenantId !== "") scopes.push("tenant");
    return scopes;
  }

  private assertScope(actor: MemoryActor, scope: MemoryScope): void {
    if (!this.scopesFor(actor).includes(scope)) {
      throw new AuthorizationDeniedError(`memory scope '${scope}' is not available to this caller`);
    }
  }

  private async resolveWriteScope(
    actor: MemoryActor,
    scope: MemoryScope,
    requestedRunId: string | undefined,
  ): Promise<{ ownerUserId: string; tenantId?: string; runId?: string }> {
    if (scope === "run") {
      const runId = requestedRunId ?? actor.runId;
      if (runId === undefined || runId === "") {
        throw new ValidationError("run_id is required for run-scoped memory");
      }
      const run = await this.resolveRun(actor, runId);
      const tenantId = run.tenantId ?? actor.tenantId;
      return {
        ownerUserId: run.userId ?? actor.userId,
        ...(tenantId !== undefined ? { tenantId } : {}),
        runId: run.runId,
      };
    }
    if (scope === "tenant") {
      if (actor.tenantId === undefined || actor.tenantId === "") {
        throw new AuthorizationDeniedError("tenant-scoped memory requires a tenant identity");
      }
      return { ownerUserId: actor.userId, tenantId: actor.tenantId };
    }
    if (scope === "agent") {
      if (actor.agent === undefined || actor.agent === "") {
        throw new AuthorizationDeniedError("agent-scoped memory requires an agent identity");
      }
      return {
        ownerUserId: actor.userId,
        ...(actor.tenantId !== undefined ? { tenantId: actor.tenantId } : {}),
        ...(actor.runId !== undefined ? { runId: actor.runId } : {}),
      };
    }
    return {
      ownerUserId: actor.userId,
      ...(actor.tenantId !== undefined ? { tenantId: actor.tenantId } : {}),
    };
  }

  private async resolveRun(actor: MemoryActor, runId: string): Promise<RunRecord> {
    const run = await this.runs.get(runId);
    if (run === null) throw new NotFoundError("run not found");
    if (run.userId !== undefined && run.userId !== actor.userId) {
      throw new AuthorizationDeniedError("run is not owned by the caller");
    }
    if (actor.tenantId !== undefined && actor.tenantId !== "" && run.tenantId !== undefined && run.tenantId !== actor.tenantId) {
      throw new AuthorizationDeniedError("run tenant does not match the caller");
    }
    return run;
  }

  /**
   * Code-level isolation check plus tenant resolution for a stored record.
   * The OPA policy independently requires owner/tenant match.
   */
  private async resolveRecordAccess(actor: MemoryActor, record: MemoryRecord): Promise<string | undefined> {
    if (record.ownerUserId !== actor.userId) {
      throw new AuthorizationDeniedError("memory is not owned by the caller");
    }
    if (!this.scopesFor(actor).includes(record.scope)) {
      throw new AuthorizationDeniedError(`memory scope '${record.scope}' is not available to this caller`);
    }
    let tenantId = actor.tenantId;
    if (record.scope === "run") {
      if (record.runId === undefined || record.runId === "") {
        throw new AuthorizationDeniedError("run-scoped memory has no run binding");
      }
      if (actor.kind === "operation" && actor.runId !== record.runId) {
        throw new AuthorizationDeniedError("memory belongs to a different run");
      }
      if (actor.kind === "api") {
        const run = await this.runs.get(record.runId);
        if (run === null) throw new AuthorizationDeniedError("memory run no longer exists");
        if (run.userId !== undefined && run.userId !== actor.userId) {
          throw new AuthorizationDeniedError("memory run is not owned by the caller");
        }
        if (tenantId === undefined && run.tenantId !== undefined) tenantId = run.tenantId;
      }
    }
    if (record.scope === "agent" && actor.agent !== undefined && record.agent !== actor.agent) {
      throw new AuthorizationDeniedError("memory belongs to a different agent");
    }
    if (record.tenantId !== undefined && record.tenantId !== "") {
      if (tenantId !== record.tenantId) {
        throw new AuthorizationDeniedError("memory tenant does not match the caller");
      }
    } else if (tenantId !== undefined && tenantId !== "") {
      throw new AuthorizationDeniedError("caller tenant cannot access tenant-less memory");
    }
    return tenantId;
  }

  private async assertNotExpired(actor: MemoryActor, record: MemoryRecord): Promise<void> {
    if (!isMemoryExpired(record)) return;
    // Expiry cleanup is performed by the TTL index. Do not delete here: an
    // unauthenticated caller must not cause a store mutation.
    await this.auditRecord("memory.expired", actor, record, {});
    throw new NotFoundError("memory not found");
  }

  private async authorize(
    actor: MemoryActor,
    operation: MemoryOperation,
    target: AuthTarget,
    effectiveTenantId?: string,
  ): Promise<void> {
    const action = actor.kind === "api" ? `memory:${operation}` : `memory.${operation}`;
    await this.authorizeAction(actor, action, target, effectiveTenantId);
  }

  /** Build and evaluate an OPA decision for any memory-owned action. */
  private async authorizeAction(
    actor: MemoryActor,
    action: string,
    target: AuthTarget,
    effectiveTenantId?: string,
  ): Promise<void> {
    this.assertOperationGrant(actor, action);
    const resource: AuthzResource = {
      kind: actor.kind,
      ...(actor.kind === "api"
        ? { principal: actor.principal, scopes: actor.scopes }
        : {
            workload: actor.workload ?? actor.agent ?? "",
            agent: actor.agent ?? "",
            runId: actor.runId ?? "",
            approvedTargets: actor.approvedTargets ?? [],
            approvedActions: actor.approvedActions ?? [],
            requestedRunId: target.runId ?? actor.runId ?? "",
          }),
      user: actor.userId,
      requestedAction: action,
      ...(target.memoryId !== undefined ? { requestedObject: target.memoryId } : {}),
      ...(target.requestedObject !== undefined ? { requestedObject: target.requestedObject } : {}),
      resourceOwner: target.ownerUserId,
      resourceTenantId: target.tenantId ?? "",
      ...(effectiveTenantId !== undefined ? { tenantId: effectiveTenantId } : {}),
    };

    const decision = await this.authz.authorize(action, resource);
    if (!decision.allowed) {
      throw new AuthorizationDeniedError(decision.reason ?? `operation '${action}' is not authorized`);
    }
  }

  private targetOf(record: MemoryRecord): AuthTarget {
    return {
      memoryId: record.memoryId,
      ownerUserId: record.ownerUserId,
      ...(record.tenantId !== undefined ? { tenantId: record.tenantId } : {}),
      ...(record.runId !== undefined ? { runId: record.runId } : {}),
    };
  }

  private isolationOf(record: MemoryRecord): MemoryIsolation {
    return {
      ownerUserId: record.ownerUserId,
      ...(record.tenantId !== undefined ? { tenantId: record.tenantId } : {}),
      scopes: [record.scope],
      ...(record.runId !== undefined ? { runId: record.runId } : {}),
      ...(record.agent !== undefined ? { agent: record.agent } : {}),
    };
  }

  private toSearchView(record: MemoryRecord): MemorySearchView {
    const snippet = memorySnippet(record.content);
    return {
      memoryId: record.memoryId,
      scope: record.scope,
      collection: record.collection,
      memoryType: record.memoryType,
      status: record.status,
      ...(record.key !== undefined ? { key: record.key } : {}),
      content: snippet.content,
      truncated: snippet.truncated,
      trust: record.trust,
      authoritative: false,
      conflict: record.conflict,
      provenance: record.provenance,
      integrity: record.integrity,
      ...(record.injection !== undefined ? { injection: record.injection } : {}),
      ...(record.expiresAt !== undefined ? { expiresAt: record.expiresAt } : {}),
      tsCreated: record.tsCreated,
      tsUpdated: record.tsUpdated,
    };
  }

  private async auditRecord(
    type: string,
    actor: MemoryActor,
    record: MemoryRecord,
    extra: Record<string, unknown>,
  ): Promise<void> {
    await this.audit.emit({
      type,
      ts: new Date().toISOString(),
      traceId: record.memoryId,
      principal: actor.userId,
      ...(record.runId !== undefined ? { runId: record.runId } : {}),
      data: {
        memory_id: record.memoryId,
        scope: record.scope,
        collection: record.collection,
        memory_type: record.memoryType,
        status: record.status,
        source_type: record.provenance.sourceType,
        trust: record.trust,
        conflict: record.conflict,
        suspicious: record.injection?.suspicious ?? false,
        ...extra,
      },
    });
  }
}

export function createMemoryService(deps: MemoryServiceDeps): MemoryService {
  return new MemoryService(deps);
}
