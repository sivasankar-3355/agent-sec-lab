import { loadConfig } from "../core/config.js";
import { createLogger } from "../core/logger.js";
import { buildSecurityProviders } from "../security/build.js";
import { MongoStore } from "../db/mongo.js";
import { QdrantStore } from "../db/qdrant.js";
import { createRepositories } from "../db/repositories/build.js";
import { createSTSApp } from "./app.js";

async function start(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.LOG_LEVEL);

  // The STS needs MongoDB read access to validate the trusted run record.
  const mongo = new MongoStore(config.MONGODB_URI, config.MONGODB_DB);
  await mongo.connect();
  const qdrant = new QdrantStore(config.QDRANT_URL);
  const repos = await createRepositories(mongo, qdrant);

  // STS_PRIVATE_KEY + STS_PUBLIC_KEY(S) must be configured; otherwise the
  // tokenIssuer is absent and every mint/exchange endpoint fails closed.
  const security = buildSecurityProviders(config, log);

  const app = createSTSApp({ log, security, stores: { mongo }, repos });
  const server = app.listen(config.STS_PORT, config.STS_HOST, () => {
    log.info({ host: config.STS_HOST, port: config.STS_PORT }, "sts listening");
  });

  const shutdown = (signal: string): void => {
    log.info({ signal }, "sts shutting down");
    server.close(async () => {
      await mongo.close();
      process.exit(0);
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

start().catch((err) => {
  const fallback = createLogger("error");
  fallback.error({ err }, "failed to start sts");
  process.exit(1);
});
