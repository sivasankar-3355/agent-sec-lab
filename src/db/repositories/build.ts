import type { MongoStore } from "../mongo.js";
import { createMongoRepositories, ensureMongoSchema } from "./mongo.js";
import type {
  FindingsRepository,
  ReportsRepository,
  RunsRepository,
  TasksRepository,
  UsersRepository,
} from "./contracts.js";

/**
 * Operational repositories available to agents and the gateway.
 *
 * Memory-related stores (`memories`, `documents`, the Qdrant knowledge
 * collection) are deliberately absent: they are constructed only by
 * `createMemoryStores` and owned privately by `MemoryService`. This makes
 * `ctx.repos.documents` / `ctx.repos.knowledge` a compile error, so there is no
 * alternate repository path to memory.
 */
export interface Repositories {
  runs: RunsRepository;
  users: UsersRepository;
  tasks: TasksRepository;
  findings: FindingsRepository;
  reports: ReportsRepository;
}

export async function createRepositories(mongo: MongoStore): Promise<Repositories> {
  const db = mongo.db();
  await ensureMongoSchema(db);

  const base = createMongoRepositories(db);
  return {
    runs: base.runs,
    users: base.users,
    tasks: base.tasks,
    findings: base.findings,
    reports: base.reports,
  };
}
