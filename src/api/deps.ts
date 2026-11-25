import type { Logger } from "pino";
import type { Config } from "../core/config.js";
import { MongoStore } from "../db/mongo.js";
import { QdrantStore } from "../db/qdrant.js";
import { RedisStore } from "../db/redis.js";
import { createRepositories, type Repositories } from "../db/repositories/build.js";

export interface Stores {
  mongo?: MongoStore;
  qdrant?: QdrantStore;
  redis?: RedisStore;
}

export interface Runtime {
  config: Config;
  log: Logger;
  stores: Stores;
  repos: Repositories;
}

export async function connectStores(config: Config, log: Logger): Promise<Stores> {
  const mongo = new MongoStore(config.MONGODB_URI, config.MONGODB_DB);
  const qdrant = new QdrantStore(config.QDRANT_URL);
  const redis = new RedisStore(config.REDIS_URL);

  await mongo.connect();
  await redis.connect();

  log.info("connected to mongodb and redis");
  return { mongo, qdrant, redis };
}

export async function buildRuntime(config: Config, log: Logger): Promise<Runtime> {
  const stores = await connectStores(config, log);
  const repos = await createRepositories(stores.mongo!);
  return { config, log, stores, repos };
}

export async function disconnectStores(stores: Stores, log: Logger): Promise<void> {
  await Promise.allSettled([
    stores.mongo?.close?.() ?? Promise.resolve(),
    stores.redis?.close?.() ?? Promise.resolve(),
  ]);
  log.info("disconnected stores");
}
