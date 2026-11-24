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
  chunks: readonly VectorChunkIndex[];
  vectors: readonly (readonly number[])[];
}

export interface VectorHit {
  docId: string;
  score: number;
}

export interface KnowledgeVectorStore {
  upsertChunks(input: UpsertChunksInput): Promise<void>;
  search(queryVector: readonly number[], limit: number): Promise<readonly VectorHit[]>;
}

export function vectorPointId(docId: string, chunkIndex: number): string {
  return stableHash(`${docId}:${chunkIndex}`);
}