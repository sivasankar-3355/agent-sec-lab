import type { RunRecord } from "../domain.js";
import { BudgetExceededError } from "./errors.js";

export type BudgetBucket =
  | "agentCalls"
  | "toolCalls"
  | "retries"
  | "llmCalls"
  | "agentConcurrency";

export interface RunBudget {
  readonly maxAgentCalls: number;
  readonly maxToolCalls: number;
  readonly maxDurationMs: number;
  readonly maxConcurrentAgentTasks: number;
  readonly maxRetries: number;
  readonly maxLlmCalls: number;
}

export const RUN_BUDGET_DEFAULTS: RunBudget = {
  maxAgentCalls: 50,
  maxToolCalls: 100,
  maxDurationMs: 30 * 60 * 1000,
  maxConcurrentAgentTasks: 4,
  maxRetries: 5,
  maxLlmCalls: 10,
};

/**
 * Absolute code-owned ceilings. A run record may ask for a lower budget, but
 * never a higher one than these. Agents have no path to write the run record.
 */
export const RUN_BUDGET_HARD_LIMITS: RunBudget = {
  maxAgentCalls: 500,
  maxToolCalls: 2_000,
  maxDurationMs: 24 * 60 * 60 * 1000,
  maxConcurrentAgentTasks: 16,
  maxRetries: 50,
  maxLlmCalls: 100,
};

function configuredInteger(value: unknown, fallback: number, hardMax: number, minimum = 1): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const integer = Math.trunc(value);
  return Math.min(hardMax, Math.max(minimum, integer));
}

function budgetConfigOf(run: RunRecord): Record<string, unknown> | undefined {
  const raw = run.config["budget"];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  return raw as Record<string, unknown>;
}

/**
 * Derive the run budget from the trusted run record. `run.config.budget` may
 * lower a budget; every value is clamped to the code-owned hard limit. Missing
 * or invalid values fall back to defaults. The task body and model output have
 * no influence here.
 */
export function resolveRunBudget(run: RunRecord): RunBudget {
  const config = budgetConfigOf(run);
  if (config === undefined) return { ...RUN_BUDGET_DEFAULTS };
  return {
    maxAgentCalls: configuredInteger(
      config["maxAgentCalls"],
      RUN_BUDGET_DEFAULTS.maxAgentCalls,
      RUN_BUDGET_HARD_LIMITS.maxAgentCalls,
    ),
    maxToolCalls: configuredInteger(
      config["maxToolCalls"],
      RUN_BUDGET_DEFAULTS.maxToolCalls,
      RUN_BUDGET_HARD_LIMITS.maxToolCalls,
    ),
    maxDurationMs: configuredInteger(
      config["maxDurationMs"],
      RUN_BUDGET_DEFAULTS.maxDurationMs,
      RUN_BUDGET_HARD_LIMITS.maxDurationMs,
      1_000,
    ),
    maxConcurrentAgentTasks: configuredInteger(
      config["maxConcurrentAgentTasks"],
      RUN_BUDGET_DEFAULTS.maxConcurrentAgentTasks,
      RUN_BUDGET_HARD_LIMITS.maxConcurrentAgentTasks,
    ),
    maxRetries: configuredInteger(
      config["maxRetries"],
      RUN_BUDGET_DEFAULTS.maxRetries,
      RUN_BUDGET_HARD_LIMITS.maxRetries,
      0,
    ),
    maxLlmCalls: configuredInteger(
      config["maxLlmCalls"],
      RUN_BUDGET_DEFAULTS.maxLlmCalls,
      RUN_BUDGET_HARD_LIMITS.maxLlmCalls,
      0,
    ),
  };
}

/** Run start time from the trusted timeline, falling back to creation time. */
export function runStartedAt(run: RunRecord): number {
  const started = run.timeline.find((entry) => entry.state === "STARTED");
  const parsed = Date.parse(started?.ts ?? run.tsCreated);
  return Number.isFinite(parsed) ? parsed : Date.now();
}

export function runDeadline(run: RunRecord, budget: RunBudget = resolveRunBudget(run)): number {
  return runStartedAt(run) + budget.maxDurationMs;
}

/**
 * Atomic counter store for run budgets. The Redis implementation makes the
 * budget shared across agent processes; the in-memory implementation is
 * process-local (tests/embedded use).
 */
export interface RunBudgetStore {
  increment(runId: string, bucket: BudgetBucket, amount: number, ttlMs: number): Promise<number>;
  decrement(runId: string, bucket: BudgetBucket, amount: number, ttlMs?: number): Promise<void>;
}

interface InMemoryCounter {
  value: number;
  expiresAt: number;
}

export class InMemoryRunBudgetStore implements RunBudgetStore {
  private readonly counters = new Map<string, InMemoryCounter>();
  private readonly now: () => number;

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? (() => Date.now());
  }

  async increment(runId: string, bucket: BudgetBucket, amount: number, ttlMs: number): Promise<number> {
    const key = `${runId}:${bucket}`;
    const now = this.now();
    const existing = this.counters.get(key);
    const value = existing !== undefined && existing.expiresAt > now ? existing.value + amount : amount;
    this.counters.set(key, { value, expiresAt: now + ttlMs });
    return value;
  }

  async decrement(
    runId: string,
    bucket: BudgetBucket,
    amount: number,
    _ttlMs?: number,
  ): Promise<void> {
    const key = `${runId}:${bucket}`;
    const existing = this.counters.get(key);
    if (existing === undefined) return;
    const value = Math.max(0, existing.value - amount);
    if (value === 0) this.counters.delete(key);
    else this.counters.set(key, { ...existing, value });
  }
}

function limitFor(budget: RunBudget, bucket: BudgetBucket): number {
  switch (bucket) {
    case "agentCalls":
      return budget.maxAgentCalls;
    case "toolCalls":
      return budget.maxToolCalls;
    case "retries":
      return budget.maxRetries;
    case "llmCalls":
      return budget.maxLlmCalls;
    case "agentConcurrency":
      return budget.maxConcurrentAgentTasks;
  }
}

function budgetTtlMs(budget: RunBudget): number {
  return Math.min(
    RUN_BUDGET_HARD_LIMITS.maxDurationMs + 60_000,
    Math.max(60_000, budget.maxDurationMs + 60_000),
  );
}

export interface RunGovernorOptions {
  store?: RunBudgetStore;
  now?: () => number;
}

/**
 * Enforces run-scoped resilience budgets. Every consumer passes the trusted run
 * record; budgets are derived here and can never be raised by task input. A
 * counter-store error fails closed by propagating the error to the caller.
 */
export class RunGovernor {
  private readonly store: RunBudgetStore;
  private readonly now: () => number;

  constructor(options: RunGovernorOptions = {}) {
    this.store = options.store ?? new InMemoryRunBudgetStore();
    this.now = options.now ?? (() => Date.now());
  }

  budgetFor(run: RunRecord): RunBudget {
    return resolveRunBudget(run);
  }

  remainingMs(run: RunRecord, budget: RunBudget = this.budgetFor(run)): number {
    return runDeadline(run, budget) - this.now();
  }

  assertWithinDuration(run: RunRecord, budget: RunBudget = this.budgetFor(run)): void {
    if (this.remainingMs(run, budget) <= 0) {
      throw new BudgetExceededError(
        `run '${run.runId}' exceeded its maximum execution duration`,
        "run_deadline_exceeded",
        504,
      );
    }
  }

  async consume(
    run: RunRecord,
    bucket: BudgetBucket,
    amount = 1,
    budget: RunBudget = this.budgetFor(run),
  ): Promise<void> {
    const limit = limitFor(budget, bucket);
    const value = await this.store.increment(run.runId, bucket, amount, budgetTtlMs(budget));
    if (!Number.isFinite(value)) {
      await this.store.decrement(run.runId, bucket, amount, budgetTtlMs(budget)).catch(() => {});
      throw new BudgetExceededError(
        "run budget store returned an invalid counter; execution refused",
        "budget_store_unavailable",
        503,
      );
    }
    if (value > limit) {
      // Refund the refused increment so one refusal does not poison the
      // counter for later legitimate work.
      await this.store.decrement(run.runId, bucket, amount, budgetTtlMs(budget)).catch(() => {});
      throw new BudgetExceededError(
        `run '${run.runId}' ${bucket} budget exceeded (limit ${limit})`,
        bucket === "retries" ? "run_retry_budget_exceeded" : "run_budget_exceeded",
        429,
      );
    }
  }

  async consumeAgentCall(run: RunRecord): Promise<void> {
    this.assertWithinDuration(run);
    await this.consume(run, "agentCalls");
  }

  async consumeToolCall(run: RunRecord): Promise<void> {
    this.assertWithinDuration(run);
    await this.consume(run, "toolCalls");
  }

  async consumeRetry(run: RunRecord): Promise<void> {
    this.assertWithinDuration(run);
    await this.consume(run, "retries");
  }

  async consumeLlmCall(run: RunRecord, budget: RunBudget = this.budgetFor(run)): Promise<void> {
    this.assertWithinDuration(run, budget);
    await this.consume(run, "llmCalls", 1, budget);
  }

  /** Acquire one run-scoped agent-task slot; returns the release function. */
  async acquireAgentSlot(run: RunRecord): Promise<() => Promise<void>> {
    this.assertWithinDuration(run);
    const budget = this.budgetFor(run);
    await this.consume(run, "agentConcurrency", 1, budget);
    return async (): Promise<void> => {
      await this.store
        .decrement(run.runId, "agentConcurrency", 1, budgetTtlMs(budget))
        .catch(() => {});
    };
  }
}
