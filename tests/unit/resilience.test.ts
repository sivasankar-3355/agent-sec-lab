import { describe, expect, it } from "vitest";
import { AppError } from "../../src/core/errors.js";
import type { RunRecord } from "../../src/core/domain.js";
import { withDeadline } from "../../src/core/resilience/abort.js";
import {
  CircuitBreaker,
  type CircuitState,
} from "../../src/core/resilience/circuit.js";
import {
  BudgetExceededError,
  CancelledError,
  CircuitOpenError,
  TimeoutError,
} from "../../src/core/resilience/errors.js";
import {
  backoffDelay,
  classifyError,
  isRetryable,
  retry,
} from "../../src/core/resilience/retry.js";
import {
  InMemoryRunBudgetStore,
  resolveRunBudget,
  RUN_BUDGET_HARD_LIMITS,
  RunGovernor,
} from "../../src/core/resilience/budget.js";
import { newId } from "../../src/core/ids.js";

function runRecord(overrides: Partial<RunRecord> = {}): RunRecord {
  const now = new Date().toISOString();
  return {
    runId: newId(),
    name: "resilience",
    scope: { targets: ["host-1"] },
    config: {},
    state: "STARTED",
    timeline: [{ state: "STARTED", ts: now }],
    tsCreated: now,
    tsUpdated: now,
    ...overrides,
  };
}

describe("Phase-6 circuit breaker", () => {
  it("transitions CLOSED -> OPEN -> HALF_OPEN -> CLOSED and limits probes", () => {
    let now = 1_000;
    const transitions: Array<[CircuitState, CircuitState]> = [];
    const breaker = new CircuitBreaker({
      name: "peer",
      failureThreshold: 2,
      recoveryIntervalMs: 100,
      halfOpenMaxCalls: 1,
      now: () => now,
      onStateChange: (from, to) => transitions.push([from, to]),
    });

    expect(breaker.state).toBe("CLOSED");
    expect(breaker.allowRequest()).toBe(true);
    breaker.recordFailure();
    expect(breaker.state).toBe("CLOSED");
    breaker.recordFailure();
    expect(breaker.state).toBe("OPEN");
    expect(breaker.allowRequest()).toBe(false);

    now += 100;
    expect(breaker.allowRequest()).toBe(true);
    expect(breaker.state).toBe("HALF_OPEN");
    // Only one probe is admitted.
    expect(breaker.allowRequest()).toBe(false);

    breaker.recordSuccess();
    expect(breaker.state).toBe("CLOSED");
    expect(transitions).toEqual([
      ["CLOSED", "OPEN"],
      ["OPEN", "HALF_OPEN"],
      ["HALF_OPEN", "CLOSED"],
    ]);
  });

  it("re-opens when a half-open probe fails", () => {
    let now = 0;
    const breaker = new CircuitBreaker({
      name: "peer",
      failureThreshold: 1,
      recoveryIntervalMs: 10,
      halfOpenMaxCalls: 1,
      now: () => now,
    });
    expect(breaker.allowRequest()).toBe(true);
    breaker.recordFailure();
    expect(breaker.state).toBe("OPEN");
    now += 10;
    expect(breaker.allowRequest()).toBe(true);
    expect(breaker.state).toBe("HALF_OPEN");
    breaker.recordFailure();
    expect(breaker.state).toBe("OPEN");
    expect(breaker.allowRequest()).toBe(false);
  });
});

describe("Phase-6 retry classification and backoff", () => {
  it("classifies permanent/auth/validation/budget/cancel failures as non-retryable", () => {
    expect(classifyError(new AppError("forbidden", "no", 403))).toBe("authorization");
    expect(classifyError(new AppError("unauthorized", "no", 401))).toBe("authorization");
    expect(classifyError(new AppError("validation_error", "no", 422))).toBe("validation");
    expect(classifyError(new AppError("not_found", "no", 404))).toBe("permanent");
    expect(classifyError(new AppError("tool_timeout", "no", 504))).toBe("transient");
    expect(classifyError(new TimeoutError("slow"))).toBe("timeout");
    expect(classifyError(new CancelledError("stop"))).toBe("cancelled");
    expect(classifyError(new CircuitOpenError("peer"))).toBe("circuit_open");
    expect(classifyError(new BudgetExceededError("budget"))).toBe("budget");
    expect(classifyError(new TypeError("fetch failed"))).toBe("transient");

    expect(isRetryable(new AppError("forbidden", "no", 403))).toBe(false);
    expect(isRetryable(new TimeoutError("slow"))).toBe(false);
    expect(isRetryable(new TimeoutError("slow"), { retryTimeouts: true })).toBe(true);
  });

  it("retries transient failures up to the bound and never retries authorization", async () => {
    let attempts = 0;
    const result = await retry(
      async () => {
        attempts += 1;
        if (attempts < 3) throw new AppError("upstream", "temporary", 503);
        return "ok";
      },
      { policy: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2, jitter: 0 } },
    );
    expect(result).toBe("ok");
    expect(attempts).toBe(3);

    let deniedAttempts = 0;
    await expect(
      retry(
        async () => {
          deniedAttempts += 1;
          throw new AppError("forbidden", "denied", 403);
        },
        { policy: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 2, jitter: 0 } },
      ),
    ).rejects.toMatchObject({ status: 403 });
    expect(deniedAttempts).toBe(1);
  });

  it("grows exponentially with bounded jitter", () => {
    const low = backoffDelay(3, { baseDelayMs: 100, maxDelayMs: 1_000, jitter: 0.5 }, () => 0);
    const high = backoffDelay(3, { baseDelayMs: 100, maxDelayMs: 1_000, jitter: 0.5 }, () => 1);
    expect(low).toBe(200);
    expect(high).toBe(400);
    expect(backoffDelay(20, { baseDelayMs: 100, maxDelayMs: 1_000, jitter: 0 }, () => 1)).toBe(1_000);
  });
});

describe("Phase-6 run budgets", () => {
  it("clamps configured budgets to code-owned hard ceilings and rewards lower values", () => {
    const hard = resolveRunBudget(
      runRecord({ config: { budget: { maxToolCalls: 999_999, maxAgentCalls: 999_999 } } }),
    );
    expect(hard.maxToolCalls).toBe(RUN_BUDGET_HARD_LIMITS.maxToolCalls);
    expect(hard.maxAgentCalls).toBe(RUN_BUDGET_HARD_LIMITS.maxAgentCalls);

    const lower = resolveRunBudget(
      runRecord({ config: { budget: { maxToolCalls: 3, maxRetries: 0, maxLlmCalls: 0 } } }),
    );
    expect(lower.maxToolCalls).toBe(3);
    expect(lower.maxRetries).toBe(0);
    expect(lower.maxLlmCalls).toBe(0);
  });

  it("enforces tool-call, retry and concurrency budgets", async () => {
    const run = runRecord({ config: { budget: { maxToolCalls: 2, maxRetries: 0, maxConcurrentAgentTasks: 1 } } });
    const governor = new RunGovernor({ store: new InMemoryRunBudgetStore() });

    await expect(governor.consumeToolCall(run)).resolves.toBeUndefined();
    await expect(governor.consumeToolCall(run)).resolves.toBeUndefined();
    await expect(governor.consumeToolCall(run)).rejects.toMatchObject({
      status: 429,
      code: "run_budget_exceeded",
    });
    await expect(governor.consumeRetry(run)).rejects.toMatchObject({
      status: 429,
      code: "run_retry_budget_exceeded",
    });

    const release = await governor.acquireAgentSlot(run);
    await expect(governor.acquireAgentSlot(run)).rejects.toMatchObject({
      status: 429,
      code: "run_budget_exceeded",
    });
    await release();
    const releaseAgain = await governor.acquireAgentSlot(run);
    await releaseAgain();
  });

  it("fails closed when the run duration deadline has passed", () => {
    let now = Date.parse("2026-01-01T00:00:10.000Z");
    const governor = new RunGovernor({
      store: new InMemoryRunBudgetStore({ now: () => now }),
      now: () => now,
    });
    const run = runRecord({
      tsCreated: "2026-01-01T00:00:00.000Z",
      timeline: [{ state: "STARTED", ts: "2026-01-01T00:00:00.000Z" }],
      config: { budget: { maxDurationMs: 1_000 } },
    });
    expect(() => governor.assertWithinDuration(run)).toThrow(/maximum execution duration/);
    now = Date.parse("2026-01-01T00:00:00.500Z");
    expect(() => governor.assertWithinDuration(run)).not.toThrow();
  });
});

describe("Phase-6 deadlines and cancellation", () => {
  it("rejects a slow operation with TimeoutError", async () => {
    await expect(
      withDeadline(
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 50));
          return "late";
        },
        { timeoutMs: 5, label: "test.slow" },
      ),
    ).rejects.toBeInstanceOf(TimeoutError);
  });

  it("propagates a parent cancellation as CancelledError", async () => {
    const controller = new AbortController();
    const running = withDeadline(
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 50));
        return "late";
      },
      { timeoutMs: 1_000, signal: controller.signal, label: "test.cancel" },
    );
    controller.abort(new CancelledError("stop"));
    await expect(running).rejects.toBeInstanceOf(CancelledError);
  });
});
