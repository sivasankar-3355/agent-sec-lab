import { loadConfig } from "../core/config.js";
import { createLogger } from "../core/logger.js";
import { createContainer } from "../security/container.js";
import { createApp } from "./app.js";
import { buildRuntime, disconnectStores } from "./deps.js";

async function start(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  const runtime = await buildRuntime(config, log);
  const container = createContainer(config, log);

  const app = createApp({
    log,
    security: container.security,
    stores: runtime.stores,
    repos: runtime.repos,
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
