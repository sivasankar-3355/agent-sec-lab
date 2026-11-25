import { loadConfig } from "../core/config.js";
import { createLogger } from "../core/logger.js";
import { buildSecurityProviders } from "../security/build.js";
import { STSClient } from "../a2a/sts.js";
import { INTERNAL_MINT_SCOPE } from "../security/audience.js";
import type { RunTokenMinter } from "../security/protocols.js";
import { createApp } from "./app.js";
import { buildRuntime, disconnectStores } from "./deps.js";
import { createMemoriesRepository } from "../db/repositories/memory.js";
import { createMemoryService } from "../agents/memory.js";

/**
 * The gateway authenticates to the STS with its workload identity and receives
 * a short-lived gateway workload token used only to mint run tokens. It never
 * holds the STS private key and never signs workload tokens itself.
 */
async function gatewaySTSClient(
  config: ReturnType<typeof loadConfig>,
  security: ReturnType<typeof buildSecurityProviders>,
  log: ReturnType<typeof createLogger>,
): Promise<RunTokenMinter | undefined> {
  if (config.STS_URL.length === 0) return undefined;
  try {
    const secret = await security.secrets.get("WORKLOAD_BOOTSTRAP");
    const bootstrap = new STSClient(config.STS_URL, { bootstrapSecret: secret.value });
    const workloadToken = await bootstrap.issue("gateway", [INTERNAL_MINT_SCOPE]);
    return new STSClient(config.STS_URL, { workloadToken });
  } catch (err) {
    // Fail closed: without an STS client no run token can be minted, so run
    // dispatch will not occur.
    log.warn({ err }, "STS client unavailable; run dispatch will fail closed without run tokens");
    return undefined;
  }
}

async function start(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  const runtime = await buildRuntime(config, log);
  const security = buildSecurityProviders(config, log);
  const sts = await gatewaySTSClient(config, security, log);

  const memory = createMemoryService({
    repo: createMemoriesRepository(runtime.stores.mongo!.db()),
    runs: runtime.repos.runs,
    authz: security.authz,
    audit: security.audit,
  });

  const app = createApp({
    log,
    security,
    stores: runtime.stores,
    repos: runtime.repos,
    memory,
    ...(config.ORCHESTRATOR_A2A_URL.length > 0 ? { orchestrator: { base: config.ORCHESTRATOR_A2A_URL } } : {}),
    ...(sts !== undefined ? { sts } : {}),
  });

  const server = app.listen(config.HTTP_PORT, config.HTTP_HOST, () => {
    log.info({ host: config.HTTP_HOST, port: config.HTTP_PORT }, "api listening");
  });

  const shutdown = (signal: string): void => {
    log.info({ signal }, "shutting down");
    server.close(async () => {
      await disconnectStores(runtime.stores, log);
      process.exit(0);
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

start().catch((err) => {
  const fallback = createLogger("error");
  fallback.error({ err }, "failed to start");
  process.exit(1);
});
