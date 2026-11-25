import type { Schemas } from "@qdrant/js-client-rest";
import { ValidationError } from "../core/errors.js";
import type { QdrantStore } from "./qdrant.js";
import {
  vectorPointId,
  type KnowledgeVectorStore,
  type UpsertChunksInput,
  type VectorHit,
  type VectorSearchFilter,
} from "./knowledge-contract.js";

const COLLECTION = "knowledge";
/** Hard server-side cap; retrieval layers apply their own smaller bounds. */
const MAX_SEARCH_LIMIT = 100;

/**
 * Translate the closed, typed filter into Qdrant conditions. Callers cannot
 * inject raw Qdrant filters or select a collection: the collection name is a
 * module constant and only owner/tenant fields are translated here.
 */
function buildVectorFilter(filter: VectorSearchFilter | undefined): Schemas["Filter"] | undefined {
  if (filter === undefined) return undefined;

  const must: Schemas["Condition"][] = [];
  // Tenant: exact match when known; otherwise only tenant-less documents.
  if (filter.tenantId !== undefined && filter.tenantId !== "") {
    must.push({ key: "tenant_id", match: { value: filter.tenantId } });
  } else {
    must.push({ is_empty: { key: "tenant_id" } });
  }

  const should: Schemas["Condition"][] = [];
  if (filter.ownerUserId !== undefined && filter.ownerUserId !== "") {
    should.push({ key: "owner_user_id", match: { value: filter.ownerUserId } });
    if (filter.includeUnowned === true) {
      should.push({ is_empty: { key: "owner_user_id" } });
    }
  } else {
    // Without an identity, only global (owner-less) documents are eligible.
    must.push({ is_empty: { key: "owner_user_id" } });
  }

  const out: Schemas["Filter"] = { must };
  if (should.length > 0) out.should = should;
  return out;
}

export class QdrantKnowledgeVectorStore implements KnowledgeVectorStore {
  private payloadIndexesReady = false;

  constructor(private readonly store: QdrantStore) {}

  private async ensureCollection(size: number): Promise<void> {
    const client = this.store.getClient();
    const { exists } = await client.collectionExists(COLLECTION);
    if (!exists) {
      await client.createCollection(COLLECTION, { vectors: { size, distance: "Cosine" } });
    }
    await this.ensurePayloadIndexes();
  }

  /**
   * Payload indexes make the security filters efficient. They are an
   * optimization only: filters are always sent with the query, so a missing or
   * failed index cannot widen the result set.
   */
  private async ensurePayloadIndexes(): Promise<void> {
    if (this.payloadIndexesReady) return;
    const client = this.store.getClient();
    for (const field_name of ["owner_user_id", "tenant_id"]) {
      try {
        await client.createPayloadIndex(COLLECTION, { field_name, field_schema: "keyword" });
      } catch {
        // Index already exists (or the server does not support the call).
      }
    }
    this.payloadIndexesReady = true;
  }

  async upsertChunks(input: UpsertChunksInput): Promise<void> {
    if (input.chunks.length !== input.vectors.length) {
      throw new ValidationError("chunk and vector counts must match");
    }
    if (input.vectors.length === 0) return;

    await this.ensureCollection(input.vectors[0]!.length);

    const client = this.store.getClient();
    const points = input.chunks.map((chunk, i) => ({
      id: vectorPointId(input.docId, chunk.index),
      vector: [...input.vectors[i]!],
      payload: {
        doc_id: input.docId,
        chunk_index: chunk.index,
        content_hash: chunk.contentHash,
        source: input.source,
        title: input.title,
        ...(input.runId ? { run_id: input.runId } : {}),
        ...(input.ownerUserId ? { owner_user_id: input.ownerUserId } : {}),
        ...(input.tenantId ? { tenant_id: input.tenantId } : {}),
      },
    }));

    await client.upsert(COLLECTION, { points });
  }

  async search(
    queryVector: readonly number[],
    limit: number,
    filter?: VectorSearchFilter,
  ): Promise<readonly VectorHit[]> {
    const client = this.store.getClient();
    const { exists } = await client.collectionExists(COLLECTION);
    if (!exists) return [];

    const bounded = Math.min(Math.max(1, Math.trunc(limit)), MAX_SEARCH_LIMIT);
    const qdrantFilter = buildVectorFilter(filter);
    const result = await client.query(COLLECTION, {
      query: [...queryVector],
      limit: bounded,
      with_payload: true,
      ...(qdrantFilter !== undefined ? { filter: qdrantFilter } : {}),
    });
    return result.points.map((point) => ({
      docId: point.payload?.doc_id as string,
      score: point.score ?? 0,
    }));
  }
}
