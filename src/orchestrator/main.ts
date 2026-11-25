import express from "express";
import { loadConfig } from "../core/config.js";
import { createLogger } from "../core/logger.js";
import { buildSecurityProviders } from "../security/build.js";
import { connectStores, disconnectStores } from "../api/deps.js";
import { createRepositories } from "../db/repositories/build.js";
import { createRedisCoordinator } from "../db/coordinator.js";
import { createA2ARouter } from "../a2a/server.js";
import { STSClient } from "../a2a/sts.js";
import { AgentClientsBroker } from "../agents/orchestrator/broker.js";
import { OrchestratorHandler } from "../agents/orchestrator/handler.js";
import { A2A_SCOPES, INTERNAL_EXCHANGE_SCOPE, a2aAudience } from "../security/audience.js";

async function start(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  const stores = await connectStores(config, log);
  const repos = await createRepositories(stores.mongo!, stores.qdrant!);
  const security = buildSecurityProviders(config, log);
  const coordinator = createRedisCoordinator(stores.redis!);

  // The orchestrator NEVER holds the signing key and NEVER mints tokens.
  // Its workload token must come from the dedicated STS: either via the
  // bootstrap-secret token-issue endpoint, or (EKS) workload identity.
  let workloadToken: string | undefined;
  try {
    if (config.STS_URL.length > 0) {
      let bootstrap: string;
      try {
        const secret = await security.secrets.get("WORKLOAD_BOOTSTRAP");
        bootstrap = secret.value;
      } catch (err) {
        throw new Error(`no WORKLOAD_BOOTSTRAP secret available: ${err instanceof Error ? err.message : "unknown"}`);
      }
      const stsBootstrap = new STSClient(config.STS_URL, { bootstrapSecret: bootstrap });
      workloadToken = await stsBootstrap.issue("orchestrator", [INTERNAL_EXCHANGE_SCOPE, ...A2A_SCOPES]);
      log.info("orchestrator workload token issued by STS");
    }
  } catch (err) {
    log.warn({ err }, "orchestrator workload token unavailable; child delegation fails closed");
  }

  const exchange = config.STS_URL.length > 0 && workloadToken !== undefined
    ? new STSClient(config.STS_URL, { workloadToken })
    : undefined;

  const handler = new OrchestratorHandler({
    log,
    audit: security.audit,
    authz: security.authz,
    repos,
    coordinator,
    children: new AgentClientsBroker({
      ...(config.RECON_A2A_URL.length > 0 ? { recon: { base: config.RECON_A2A_URL } } : {}),
      ...(config.KNOWLEDGE_A2A_URL.length > 0 ? { knowledge: { base: config.KNOWLEDGE_A2A_URL } } : {}),
      ...(config.REPORT_A2A_URL.length > 0 ? { report: { base: config.REPORT_A2A_URL } } : {}),
    }),
    ...(exchange !== undefined ? { exchange } : {}),
  });

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "256kb" }));
  app.use(
    createA2ARouter(handler, {
      log,
      authn: security.authn,
      authz: security.authz,
      audit: security.audit,
      agent: "orchestrator",
      audience: a2aAudience("orchestrator"),
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