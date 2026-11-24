import express from "express";
import { loadConfig } from "../core/config.js";
import { createLogger } from "../core/logger.js";
import { createContainer } from "../security/container.js";
import { connectStores, disconnectStores } from "../api/deps.js";
import { createRepositories } from "../db/repositories/build.js";
import { createRedisCoordinator } from "../db/coordinator.js";
import { createA2ARouter } from "../a2a/server.js";
import { A2AClient } from "../a2a/client.js";
import { AgentClientsBroker } from "../agents/orchestrator/broker.js";
import { OrchestratorHandler } from "../agents/orchestrator/handler.js";

const A2A_SCOPES = ["a2a:tasks/read", "a2a:tasks/write", "a2a:message/send"] as const;

async function start(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  const stores = await connectStores(config, log);
  const repos = await createRepositories(stores.mongo!, stores.qdrant!);
  const container = createContainer(config, log);
  const coordinator = createRedisCoordinator(stores.redis!);

  let agentToken: string | undefined;
  try {
    agentToken = await container.security.authn.createToken("orchestrator", A2A_SCOPES);
  } catch (err) {
    log.warn({ err }, "agent token unavailable; A2A outbound links fail closed");
  }

  const childClients = (base: string | undefined): A2AClient | undefined => {
    if (!base || agentToken === undefined) return undefined;
    return new A2AClient(base, { token: agentToken });
  };

  const handler = new OrchestratorHandler({
    log,
    audit: container.security.audit,
    repos,
    coordinator,
    children: new AgentClientsBroker({
      ...(childClients(config.RECON_A2A_URL) ? { recon: childClients(config.RECON_A2A_URL)! } : {}),
      ...(childClients(config.KNOWLEDGE_A2A_URL) ? { knowledge: childClients(config.KNOWLEDGE_A2A_URL)! } : {}),
      ...(childClients(config.REPORT_A2A_URL) ? { report: childClients(config.REPORT_A2A_URL)! } : {}),
    }),
  });

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "256kb" }));
  app.use(
    createA2ARouter(handler, {
      log,
      authn: container.security.authn,
      authz: container.security.authz,
      audit: container.security.audit,
    }),
  );

  const server = app.listen(config.AGENT_PORT, config.AGENT_HOST, () => {
    log.info({ host: config.AGENT_HOST, port: config.AGENT_PORT }, "orchestrator a2a listening");
  });

  const shutdown = (signal: string): void => {
    log.info({ signal }, "orchestrator shutting down");
    server.close(async () => {
      await disconnectStores(stores, log);
      process.exit(0);
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

start().catch((err) => {
  const fallback = createLogger("error");
  fallback.error({ err }, "failed to start orchestrator");
  process.exit(1);
});