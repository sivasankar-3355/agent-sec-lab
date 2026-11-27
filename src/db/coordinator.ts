import { A2AError } from "../core/errors.js";
import type { RedisStore } from "./redis.js";

export interface Coordinator {
  acquireLock(key: string, ttlMs?: number): Promise<boolean>;
  /** Extend a held lock; returns false if the lock is no longer held. */
  extendLock(key: string, ttlMs?: number): Promise<boolean>;
  releaseLock(key: string): Promise<void>;
  ensureSeen(key: string, ttlMs?: number): Promise<boolean>;
}

export function lockKeyFor(runId: string): string {
  return `lock:run:${runId}`;
}

export function seenKeyFor(runId: string, taskId: string): string {
  return `seen:${runId}:${taskId}`;
}

function seconds(ttlMs: number): number {
  return Math.max(1, Math.ceil(ttlMs / 1000));
}

export function createRedisCoordinator(redis: RedisStore): Coordinator {
  const client = redis.getClient();

  const setOnce = async (key: string, ttlMs: number): Promise<boolean> => {
    try {
      const reply = await client.set(key, "1", "EX", seconds(ttlMs), "NX");
      return reply === "OK";
    } catch {
      throw new A2AError("coordination control (Redis) unavailable", 503);
    }
  };

  return {
    async acquireLock(key, ttlMs = 30_000): Promise<boolean> {
      return setOnce(key, ttlMs);
    },
    async extendLock(key, ttlMs = 30_000): Promise<boolean> {
      try {
        return (await client.pexpire(key, seconds(ttlMs) * 1000)) === 1;
      } catch {
        throw new A2AError("coordination control (Redis) unavailable", 503);
      }
    },
    async releaseLock(key): Promise<void> {
      await client.del(key);
    },
    async ensureSeen(key, ttlMs = 24 * 60 * 60 * 1000): Promise<boolean> {
      return setOnce(key, ttlMs);
    },
  };
}