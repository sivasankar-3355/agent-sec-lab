import express from "express";
import { loadConfig } from "../core/config.js";
import { createLogger } from "../core/logger.js";
import { buildSecurityProviders } from "../security/build.js";
import { connectStores, disconnectStores } from "../api/deps.js";
import { createRepositories } from "../db/repositories/build.js";
import { createMemoryStores } from "../db/memory-store.js";
import { createA2ARouter } from "../a2a/server.js";
import { BaseWorkerHandler, type WorkerExecutor } from "./base.js";
import { createMemoryService } from "./memory.js";
import type { AgentKind, TaskKind } from "../a2a/schema.js";
import { a2aAudience } from "../security/audience.js";

export async function bootWorker(
  agent: AgentKind,
  acceptedKinds: readonly TaskKind[],
  executor: WorkerExecutor,
): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  const stores = await connectStores(config, log);
  const repos = await createRepositories(stores.mongo!);
  const security = buildSecurityProviders(config, log);
  const memory = createMemoryService({
    stores: createMemoryStores(stores.mongo!, stores.qdrant!),
    runs: repos.runs,
    authz: security.authz,
    audit: security.audit,
    embedding: security.embedding,
  });

  const handler = new BaseWorkerHandler(
    agent,
    executor,
    {
      log,
      audit: security.audit,
      repos,
      security,
      memory,
    },
    acceptedKinds,
  );

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "256kb" }));
  app.use(
    createA2ARouter(handler, {
      log,
      authn: security.authn,
      authz: security.authz,
      audit: security.audit,
      agent,
      audience: a2aAudience(agent),
    }),
  );

  const server = app.listen(config.AGENT_PORT, config.AGENT_HOST, () => {
    log.info({ host: config.AGENT_HOST, port: config.AGENT_PORT, agent }, "worker a2a listening");
  });

  const shutdown = (signal: string): void => {
    log.info({ signal, agent }, "worker shutting down");
    server.close(async () => {
      await disconnectStores(stores, log);
      process.exit(0);
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}