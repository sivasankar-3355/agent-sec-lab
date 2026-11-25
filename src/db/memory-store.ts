import type { MongoStore } from "./mongo.js";
import type { QdrantStore } from "./qdrant.js";
import type { DocumentsRepository } from "./repositories/contracts.js";
import { createDocumentsRepository } from "./repositories/mongo.js";
import { createMemoriesRepository, type MemoriesRepository } from "./repositories/memory.js";
import { QdrantKnowledgeVectorStore } from "./knowledge.js";
import type { KnowledgeVectorStore } from "./knowledge-contract.js";

/**
 * All persistence owned by the centralized Memory Service.
 *
 * This is the only wiring point for memory-related MongoDB collections and the
 * Qdrant knowledge collection. Agents never receive this object; they only see
 * `MemoryService`. Keeping the concrete stores here (rather than in
 * `Repositories`) removes the alternate repository path.
 */
export interface MemoryStores {
  memories: MemoriesRepository;
  documents: DocumentsRepository;
  knowledge: KnowledgeVectorStore;
}

export function createMemoryStores(mongo: MongoStore, qdrant: QdrantStore): MemoryStores {
  const db = mongo.db();
  return {
    memories: createMemoriesRepository(db),
    documents: createDocumentsRepository(db),
    knowledge: new QdrantKnowledgeVectorStore(qdrant),
  };
}
