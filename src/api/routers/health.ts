import { Router } from "express";
import type { MongoStore } from "../../db/mongo.js";
import type { QdrantStore } from "../../db/qdrant.js";
import type { RedisStore } from "../../db/redis.js";

export interface HealthStores {
  mongo?: MongoStore;
  qdrant?: QdrantStore;
  redis?: RedisStore;
}

export function createHealthRouter(stores: HealthStores): Router {
  const router = Router();

  router.get("/healthz", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  router.get("/readyz", async (_req, res) => {
    const checks: Record<string, boolean> = {};

    const ping = async (name: string, fn: () => Promise<boolean>): Promise<void> => {
      checks[name] = await fn();
    };

    await Promise.all([
      stores.mongo ? ping("mongo", () => stores.mongo!.ping()) : Promise.resolve((checks["mongo"] = false)),
      stores.qdrant ? ping("qdrant", () => stores.qdrant!.ping()) : Promise.resolve((checks["qdrant"] = false)),
      stores.redis ? ping("redis", () => stores.redis!.ping()) : Promise.resolve((checks["redis"] = false)),
    ]);

    const ready = Object.values(checks).every(Boolean);
    res.status(ready ? 200 : 503).json({ ready, checks });
  });

  return router;
}
