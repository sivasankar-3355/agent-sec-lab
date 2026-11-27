import type { BudgetBucket, RunBudgetStore } from "../core/resilience/budget.js";
import { BudgetExceededError } from "../core/resilience/errors.js";
import type { RedisStore } from "./redis.js";

/**
 * Redis-backed run budget counters shared by every agent process. Redis is
 * already an application dependency (locks/idempotency); no new store or
 * deployment change is introduced.
 *
 * If Redis is unavailable the governor fails closed (the execution is refused)
 * rather than running without a budget. Refunds are best-effort because the
 * original refusal already limits the caller.
 */
const INCREMENT_SCRIPT = `
local v = redis.call('INCRBY', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return v
`;

const DECREMENT_SCRIPT = `
local v = redis.call('DECRBY', KEYS[1], ARGV[1])
if v < 0 then
  redis.call('SET', KEYS[1], 0)
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return 0
end
return v
`;

export class RedisRunBudgetStore implements RunBudgetStore {
  constructor(private readonly redis: RedisStore) {}

  private key(runId: string, bucket: BudgetBucket): string {
    return `budget:${runId}:${bucket}`;
  }

  async increment(runId: string, bucket: BudgetBucket, amount: number, ttlMs: number): Promise<number> {
    const key = this.key(runId, bucket);
    try {
      const client = this.redis.getClient();
      const value = await client.eval(
        INCREMENT_SCRIPT,
        1,
        key,
        amount,
        Math.max(1, Math.trunc(ttlMs)),
      );
      return Number(value);
    } catch {
      throw new BudgetExceededError(
        "run budget store (Redis) unavailable; execution refused",
        "budget_store_unavailable",
        503,
      );
    }
  }

  async decrement(
    runId: string,
    bucket: BudgetBucket,
    amount: number,
    ttlMs = 60_000,
  ): Promise<void> {
    const key = this.key(runId, bucket);
    try {
      const client = this.redis.getClient();
      // Keep the key (even at zero) until its TTL so a concurrent increment is
      // not deleted by this refund. The Lua script also prevents a refund after
      // expiry from creating a negative counter.
      await client.eval(
        DECREMENT_SCRIPT,
        1,
        key,
        amount,
        Math.max(1, Math.trunc(ttlMs)),
      );
    } catch {
      // Best-effort refund; the original refusal remains authoritative.
    }
  }
}
