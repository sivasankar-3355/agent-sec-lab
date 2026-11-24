import { ValidationError } from "../core/errors.js";
import type { QdrantStore } from "./qdrant.js";
import { vectorPointId, type KnowledgeVectorStore, type UpsertChunksInput, type VectorHit } from "./knowledge-contract.js";

const COLLECTION = "knowledge";

export class QdrantKnowledgeVectorStore implements KnowledgeVectorStore {
  constructor(private readonly store: QdrantStore) {}

  private async ensureCollection(size: number): Promise<void> {
    const client = this.store.getClient();
    const { exists } = await client.collectionExists(COLLECTION);
    if (!exists) {
      await client.createCollection(COLLECTION, { vectors: { size, distance: "Cosine" } });
    }
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
      },
    }));

    await client.upsert(COLLECTION, { points });
  }

  async search(queryVector: readonly number[], limit: number): Promise<readonly VectorHit[]> {
    const client = this.store.getClient();
    const { exists } = await client.collectionExists(COLLECTION);
    if (!exists) return [];

    const result = await client.query(COLLECTION, { query: [...queryVector], limit, with_payload: true });
    return result.points.map((point) => ({
      docId: point.payload?.doc_id as string,
      score: point.score ?? 0,
    }));
  }
}