import type { Collection, Db, Filter } from "mongodb";
import { ValidationError } from "../../core/errors.js";
import {
  MEMORY_LIMITS,
  type MemoryInjectionSummary,
  type MemoryRecord,
  type MemoryScope,
} from "../../core/memory.js";
function isoNow(): string {
  return new Date().toISOString();
}

/**
 * Isolation predicate that every memory query must carry. The repository
 * refuses to run an unbounded query: a caller cannot read memory without an
 * owner, and cannot read run/agent-scoped memory without the matching run or
 * agent. Authorization itself is enforced one layer up in `MemoryService`;
 * this is the structural "no alternate path" guard.
 */
export interface MemoryIsolation {
  ownerUserId: string;
  tenantId?: string;
  scopes: readonly MemoryScope[];
  runId?: string;
  agent?: string;
}

export interface MemoryQuery extends MemoryIsolation {
  collection?: string;
  key?: string;
  q?: string;
  limit: number;
}

export interface MemoryUpdatePatch {
  content?: string;
  contentHash?: string;
  /** `null` removes the logical key. */
  key?: string | null;
  tags?: readonly string[];
  conflict?: boolean;
  injection?: MemoryInjectionSummary;
  /** `null` removes the expiry. */
  expiresAt?: string | null;
  version: number;
  previousVersion?: number;
}

export interface MemoriesRepository {
  insert(record: MemoryRecord): Promise<MemoryRecord>;
  get(memoryId: string): Promise<MemoryRecord | null>;
  findLatestByKey(input: {
    ownerUserId: string;
    tenantId?: string;
    scope: MemoryScope;
    collection: string;
    key: string;
    runId?: string;
    agent?: string;
  }): Promise<MemoryRecord | null>;
  update(memoryId: string, isolation: MemoryIsolation, patch: MemoryUpdatePatch): Promise<MemoryRecord | null>;
  remove(memoryId: string, isolation: MemoryIsolation): Promise<boolean>;
  search(query: MemoryQuery): Promise<readonly MemoryRecord[]>;
}

type MongoMemoryDoc = {
  _id: string;
  memoryId: string;
  scope: string;
  collection: string;
  key?: string;
  content: string;
  contentHash: string;
  trust: string;
  authoritative: boolean;
  ownerUserId: string;
  tenantId?: string;
  runId?: string;
  agent?: string;
  tags: string[];
  conflict: boolean;
  provenance: {
    sourceType: string;
    sourceId: string;
    createdBy: string;
    conversationId?: string;
  };
  integrity: {
    version: number;
    previousVersion?: number;
    supersedes?: string;
  };
  injection?: {
    suspicious: boolean;
    score: number;
    categories: string[];
  };
  expiresAt?: string;
  /** Date form used by the MongoDB TTL index; never returned to callers. */
  expiresAtDate?: Date;
  tsCreated: string;
  tsUpdated: string;
};

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function tenantClause(tenantId: string | undefined): Filter<MongoMemoryDoc> {
  if (tenantId !== undefined && tenantId !== "") return { tenantId };
  return { $or: [{ tenantId: { $exists: false } }, { tenantId: "" }] };
}

function expiryClause(now: string): Filter<MongoMemoryDoc> {
  return {
    $or: [{ expiresAt: { $exists: false } }, { expiresAt: "" }, { expiresAt: { $gt: now } }],
  };
}

function assertIsolation(isolation: MemoryIsolation): void {
  if (isolation.ownerUserId === "") {
    throw new ValidationError("memory queries require an owner");
  }
  if (isolation.scopes.length === 0) {
    throw new ValidationError("memory queries require at least one scope");
  }
  if (isolation.scopes.includes("run") && (isolation.runId === undefined || isolation.runId === "")) {
    throw new ValidationError("run-scoped memory queries require a run id");
  }
  if (isolation.scopes.includes("agent") && (isolation.agent === undefined || isolation.agent === "")) {
    throw new ValidationError("agent-scoped memory queries require an agent");
  }
}

function isolationFilters(
  isolation: MemoryIsolation,
  now: string,
  includeExpiry = true,
): Filter<MongoMemoryDoc>[] {
  assertIsolation(isolation);
  const filters: Filter<MongoMemoryDoc>[] = [
    { ownerUserId: isolation.ownerUserId },
    { scope: { $in: [...isolation.scopes] } },
    tenantClause(isolation.tenantId),
  ];
  // Reads/updates must never touch expired memory. Deletion intentionally omits
  // this clause so an expired row can still be removed.
  if (includeExpiry) filters.push(expiryClause(now));
  if (isolation.scopes.includes("run") && isolation.runId !== undefined && isolation.runId !== "") {
    filters.push({ $or: [{ scope: { $ne: "run" } }, { runId: isolation.runId }] });
  }
  if (isolation.scopes.includes("agent") && isolation.agent !== undefined && isolation.agent !== "") {
    filters.push({ $or: [{ scope: { $ne: "agent" } }, { agent: isolation.agent }] });
  }
  return filters;
}

class MongoMemoriesRepository implements MemoriesRepository {
  private readonly collection: Collection<MongoMemoryDoc>;

  constructor(db: Db) {
    this.collection = db.collection<MongoMemoryDoc>("memories");
  }

  async insert(record: MemoryRecord): Promise<MemoryRecord> {
    const doc: MongoMemoryDoc = {
      _id: record.memoryId,
      memoryId: record.memoryId,
      scope: record.scope,
      collection: record.collection,
      ...(record.key !== undefined ? { key: record.key } : {}),
      content: record.content,
      contentHash: record.contentHash,
      trust: record.trust,
      authoritative: false,
      ownerUserId: record.ownerUserId,
      ...(record.tenantId !== undefined ? { tenantId: record.tenantId } : {}),
      ...(record.runId !== undefined ? { runId: record.runId } : {}),
      ...(record.agent !== undefined ? { agent: record.agent } : {}),
      tags: [...record.tags],
      conflict: record.conflict,
      provenance: { ...record.provenance },
      integrity: { ...record.integrity },
      ...(record.injection !== undefined
        ? {
            injection: {
              suspicious: record.injection.suspicious,
              score: record.injection.score,
              categories: [...record.injection.categories],
            },
          }
        : {}),
      ...(record.expiresAt !== undefined
        ? { expiresAt: record.expiresAt, expiresAtDate: new Date(record.expiresAt) }
        : {}),
      tsCreated: record.tsCreated,
      tsUpdated: record.tsUpdated,
    };
    await this.collection.insertOne(doc);
    return this.toRecord(doc);
  }

  async get(memoryId: string): Promise<MemoryRecord | null> {
    const doc = await this.collection.findOne({ _id: memoryId });
    return doc ? this.toRecord(doc) : null;
  }

  async findLatestByKey(input: {
    ownerUserId: string;
    tenantId?: string;
    scope: MemoryScope;
    collection: string;
    key: string;
    runId?: string;
    agent?: string;
  }): Promise<MemoryRecord | null> {
    const doc = await this.collection
      .find({
        ownerUserId: input.ownerUserId,
        ...tenantClause(input.tenantId),
        scope: input.scope,
        collection: input.collection,
        key: input.key,
        ...(input.runId !== undefined && input.runId !== "" ? { runId: input.runId } : {}),
        ...(input.agent !== undefined && input.agent !== "" ? { agent: input.agent } : {}),
      })
      .sort({ "integrity.version": -1 })
      .limit(1)
      .next();
    return doc ? this.toRecord(doc) : null;
  }

  async update(
    memoryId: string,
    isolation: MemoryIsolation,
    patch: MemoryUpdatePatch,
  ): Promise<MemoryRecord | null> {
    const now = isoNow();
    const set: Record<string, unknown> = {
      "integrity.version": patch.version,
      tsUpdated: now,
    };
    if (patch.previousVersion !== undefined) set["integrity.previousVersion"] = patch.previousVersion;
    if (patch.content !== undefined) set.content = patch.content;
    if (patch.contentHash !== undefined) set.contentHash = patch.contentHash;
    if (patch.tags !== undefined) set.tags = [...patch.tags];
    if (patch.conflict !== undefined) set.conflict = patch.conflict;
    if (patch.injection !== undefined) {
      set.injection = {
        suspicious: patch.injection.suspicious,
        score: patch.injection.score,
        categories: [...patch.injection.categories],
      };
    }
    if (patch.expiresAt !== undefined && patch.expiresAt !== null) {
      set.expiresAt = patch.expiresAt;
      set.expiresAtDate = new Date(patch.expiresAt);
    }

    const unset: Record<string, ""> = {};
    if (patch.key === null) unset.key = "";
    if (patch.expiresAt === null) {
      unset.expiresAt = "";
      unset.expiresAtDate = "";
    }

    const filter: Filter<MongoMemoryDoc> = {
      $and: [
        { _id: memoryId },
        ...isolationFilters(isolation, now),
        ...(patch.previousVersion !== undefined ? [{ "integrity.version": patch.previousVersion }] : []),
      ],
    };
    const update: Record<string, unknown> = { $set: set };
    if (Object.keys(unset).length > 0) update.$unset = unset;

    const doc = await this.collection.findOneAndUpdate(filter, update, {
      returnDocument: "after",
      includeResultMetadata: false,
    });
    return doc ? this.toRecord(doc) : null;
  }

  async remove(memoryId: string, isolation: MemoryIsolation): Promise<boolean> {
    const filter: Filter<MongoMemoryDoc> = {
      $and: [{ _id: memoryId }, ...isolationFilters(isolation, isoNow(), false)],
    };
    const result = await this.collection.deleteOne(filter);
    return result.deletedCount === 1;
  }

  async search(query: MemoryQuery): Promise<readonly MemoryRecord[]> {
    const filters = isolationFilters(query, isoNow());
    if (query.collection !== undefined) filters.push({ collection: query.collection });
    if (query.key !== undefined) filters.push({ key: query.key });
    if (query.q !== undefined && query.q !== "") {
      const bounded = query.q.slice(0, MEMORY_LIMITS.maxQueryChars);
      filters.push({ content: { $regex: escapeRegex(bounded), $options: "i" } });
    }
    const limit = Math.min(Math.max(query.limit, 1), MEMORY_LIMITS.maxResults);
    const docs = await this.collection
      .find({ $and: filters })
      .sort({ tsUpdated: -1 })
      .limit(limit)
      .maxTimeMS(1000)
      .toArray();
    return docs.map((doc) => this.toRecord(doc));
  }

  private toRecord(doc: MongoMemoryDoc): MemoryRecord {
    const key = doc.key as string | undefined;
    const tenantId = doc.tenantId as string | undefined;
    const runId = doc.runId as string | undefined;
    const agent = doc.agent as string | undefined;
    const previousVersion = doc.integrity.previousVersion as number | undefined;
    const supersedes = doc.integrity.supersedes as string | undefined;
    const injection = doc.injection as MongoMemoryDoc["injection"];
    const expiresAt = doc.expiresAt as string | undefined;
    const conversationId = doc.provenance.conversationId as string | undefined;
    return {
      memoryId: doc.memoryId,
      scope: doc.scope as MemoryScope,
      collection: doc.collection,
      ...(key !== undefined ? { key } : {}),
      content: doc.content,
      contentHash: doc.contentHash,
      trust: doc.trust as MemoryRecord["trust"],
      authoritative: false,
      ownerUserId: doc.ownerUserId,
      ...(tenantId !== undefined ? { tenantId } : {}),
      ...(runId !== undefined ? { runId } : {}),
      ...(agent !== undefined ? { agent } : {}),
      tags: [...doc.tags],
      conflict: doc.conflict,
      provenance: {
        sourceType: doc.provenance.sourceType as MemoryRecord["provenance"]["sourceType"],
        sourceId: doc.provenance.sourceId,
        createdBy: doc.provenance.createdBy,
        ...(conversationId !== undefined ? { conversationId } : {}),
      },
      integrity: {
        version: doc.integrity.version,
        ...(previousVersion !== undefined ? { previousVersion } : {}),
        ...(supersedes !== undefined ? { supersedes } : {}),
      },
      ...(injection !== undefined
        ? {
            injection: {
              suspicious: injection.suspicious,
              score: injection.score,
              categories: [...injection.categories],
            },
          }
        : {}),
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      tsCreated: doc.tsCreated,
      tsUpdated: doc.tsUpdated,
    };
  }
}

export function createMemoriesRepository(db: Db): MemoriesRepository {
  return new MongoMemoriesRepository(db);
}

export async function ensureMemoryIndexes(db: Db): Promise<void> {
  await Promise.all([
    db.collection("memories").createIndex({ ownerUserId: 1, scope: 1, tsUpdated: -1 }),
    db
      .collection("memories")
      .createIndex({ ownerUserId: 1, tenantId: 1, scope: 1, collection: 1, key: 1, "integrity.version": -1 }),
    // Lifecycle: MongoDB removes expired memory. Query-time expiry filtering is
    // still applied so a delayed TTL sweep cannot leak stale memory.
    db.collection("memories").createIndex({ expiresAtDate: 1 }, { expireAfterSeconds: 0 }),
  ]);
}
