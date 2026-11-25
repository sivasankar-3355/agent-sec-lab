import { stableHash } from "../core/ids.js";

export interface VectorChunkIndex {
  index: number;
  contentHash: string;
}

export interface UpsertChunksInput {
  docId: string;
  title: string;
  source: string;
  runId?: string;
  /** Server-derived document owner (never caller-selected). */
  ownerUserId?: string;
  /** Server-derived tenant (never caller-selected). */
  tenantId?: string;
  chunks: readonly VectorChunkIndex[];
  vectors: readonly (readonly number[])[];
}

/**
 * Server-side vector filter. It is a closed, typed structure: callers cannot
 * supply arbitrary payload filters or collection names, and the Qdrant adapter
 * only translates these fields into conditions.
 */
export interface VectorSearchFilter {
  /** Restrict to this owner (plus unowned/global documents when allowed). */
  ownerUserId?: string;
  /** Allow owner-less documents in addition to `ownerUserId`. */
  includeUnowned?: boolean;
  /**
   * Restrict to this tenant. When omitted, the adapter restricts to documents
   * that have no tenant claim, so a caller without a tenant cannot retrieve
   * tenant-scoped content even before the per-document authorization check.
   */
  tenantId?: string;
}

export interface VectorHit {
  docId: string;
  score: number;
}

export interface KnowledgeVectorStore {
  upsertChunks(input: UpsertChunksInput): Promise<void>;
  search(
    queryVector: readonly number[],
    limit: number,
    filter?: VectorSearchFilter,
  ): Promise<readonly VectorHit[]>;
}

export function vectorPointId(docId: string, chunkIndex: number): string {
  return stableHash(`${docId}:${chunkIndex}`);
}
