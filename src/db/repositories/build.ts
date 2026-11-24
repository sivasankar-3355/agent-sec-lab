import type { MongoStore } from "../mongo.js";
import type { QdrantStore } from "../qdrant.js";
import { createMongoRepositories, ensureMongoSchema } from "./mongo.js";
import { QdrantKnowledgeVectorStore } from "../knowledge.js";
import type { KnowledgeVectorStore } from "../knowledge-contract.js";
import type { DocumentsRepository, FindingsRepository, ReportsRepository, RunsRepository, TasksRepository } from "./contracts.js";

export interface Repositories {
  runs: RunsRepository;
  tasks: TasksRepository;
  findings: FindingsRepository;
  reports: ReportsRepository;
  documents: DocumentsRepository;
  knowledge: KnowledgeVectorStore;
}

export async function createRepositories(mongo: MongoStore, qdrant: QdrantStore): Promise<Repositories> {
  const db = mongo.db();
  await ensureMongoSchema(db);

  const base = createMongoRepositories(db);
  return {
    runs: base.runs,
    tasks: base.tasks,
    findings: base.findings,
    reports: base.reports,
    documents: base.documents,
    knowledge: new QdrantKnowledgeVectorStore(qdrant),
  };
}