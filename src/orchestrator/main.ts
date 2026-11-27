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
import { RunGovernor } from "../core/resilience/index.js";
import { RedisRunBudgetStore } from "../db/run-budget-store.js";

async function start(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  const stores = await connectStores(config, log);
  const repos = await createRepositories(stores.mongo!);
  const security = buildSecurityProviders(config, log);
  const coordinator = createRedisCoordinator(stores.redis!);
  // Run budgets are shared with every worker through the existing Redis store.
  const governor = new RunGovernor({ store: new RedisRunBudgetStore(stores.redis!) });

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
    governor,
    children: new AgentClientsBroker(
      {
        ...(config.RECON_A2A_URL.length > 0 ? { recon: { base: config.RECON_A2A_URL } } : {}),
        ...(config.KNOWLEDGE_A2A_URL.length > 0 ? { knowledge: { base: config.KNOWLEDGE_A2A_URL } } : {}),
        ...(config.REPORT_A2A_URL.length > 0 ? { report: { base: config.REPORT_A2A_URL } } : {}),
      },
      {
        timeoutMs: config.A2A_CALL_TIMEOUT_MS,
        circuit: {
          failureThreshold: config.CIRCUIT_FAILURE_THRESHOLD,
          recoveryIntervalMs: config.CIRCUIT_RECOVERY_INTERVAL_MS,
          halfOpenMaxCalls: config.CIRCUIT_HALF_OPEN_MAX_CALLS,
        },
        onCircuitStateChange: (agent, from, to) => {
          log.warn({ agent, from, to }, "child agent circuit state changed");
          void security.audit.emit({
            type: "resilience.circuit.state",
            ts: new Date().toISOString(),
            traceId: `a2a:${agent}`,
            data: { peer: `a2a:${agent}`, from, to },
          });
        },
      },
    ),
    ...(exchange !== undefined ? { exchange } : {}),
    options: {
      retry: {
        maxAttempts: config.A2A_RETRY_MAX_ATTEMPTS,
        baseDelayMs: config.A2A_RETRY_BASE_DELAY_MS,
        maxDelayMs: config.A2A_RETRY_MAX_DELAY_MS,
      },
      pollIntervalMs: 250,
      pollMaxAttempts: Math.max(1, Math.ceil(config.AGENT_TASK_TIMEOUT_MS / 250) + 20),
    },
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
      requestTimeoutMs: config.A2A_REQUEST_TIMEOUT_MS,
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