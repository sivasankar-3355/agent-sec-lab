import { A2AError, AppError } from "../errors.js";
import { sleep, throwIfAborted } from "./abort.js";
import { BudgetExceededError, CancelledError, CircuitOpenError, TimeoutError } from "./errors.js";

export type FailureClass =
  | "transient"
  | "timeout"
  | "permanent"
  | "authorization"
  | "validation"
  | "cancelled"
  | "budget"
  | "circuit_open";

export interface RetryPolicy {
  /** Total attempts, including the first. Values are clamped to 1..10. */
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Fraction of the exponential delay replaced by random jitter (0..1). */
  jitter: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 2,
  baseDelayMs: 100,
  maxDelayMs: 2_000,
  jitter: 0.2,
};

function isAbortError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    ((err as { name?: unknown }).name === "AbortError" ||
      (err as { code?: unknown }).code === "ABORT_ERR")
  );
}

/**
 * Classify a failure so retry decisions never amplify permanent, authorization,
 * validation, budget or cancellation failures.
 */
export function classifyError(err: unknown): FailureClass {
  if (err instanceof CancelledError) return "cancelled";
  if (err instanceof TimeoutError) return "timeout";
  if (err instanceof CircuitOpenError) return "circuit_open";
  if (err instanceof BudgetExceededError) return "budget";
  if (isAbortError(err)) return "cancelled";

  if (err instanceof A2AError) {
    // JSON-RPC errors default to a 5xx HTTP status even for method-level
    // authorization/validation failures. Inspect the code first so those are
    // never retried.
    const match = /^(-?\d+):/.exec(err.message);
    if (match !== null) {
      const code = Number.parseInt(match[1] ?? "", 10);
      if (code === -32001 || code === -32003) return "authorization";
      if (code === -32004 || code === -32600 || code === -32601 || code === -32602 || code === -32700) {
        return "permanent";
      }
      if (code === -32005) return "timeout";
      if (code === -32006) return "cancelled";
      if (code === -32000 || code === -32603) return "transient";
      // Unknown JSON-RPC method errors are not assumed safe to retry.
      return "permanent";
    }
  }

  if (err instanceof AppError) {
    if (err.status === 401 || err.status === 403) return "authorization";
    if (err.status === 409 || err.status === 404) return "permanent";
    if (err.status === 422 || err.status === 400) return "validation";
    if (err.status === 429) return "budget";
    if (err.status >= 500) return "transient";

    // Unknown application errors are not assumed safe to retry.
    return "permanent";
  }

  // Node's fetch raises TypeError/network errors for a dead peer or transport
  // failure. Retrying these is bounded by the caller's policy/budget.
  if (err instanceof TypeError) return "transient";
  return "permanent";
}

export function isRetryable(
  err: unknown,
  options: { retryTimeouts?: boolean } = {},
): boolean {
  const kind = classifyError(err);
  if (kind === "transient") return true;
  if (kind === "timeout") return options.retryTimeouts === true;
  return false;
}

/** Exponential delay with bounded jitter. `attempt` is 1-based. */
export function backoffDelay(
  attempt: number,
  policy: Pick<RetryPolicy, "baseDelayMs" | "maxDelayMs" | "jitter">,
  random: () => number = Math.random,
): number {
  const exponent = Math.max(0, attempt - 1);
  const ceiling = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** exponent);
  const jitterFraction = Math.min(1, Math.max(0, policy.jitter));
  // Keep at least half of the exponential delay so backoff actually grows.
  const floor = ceiling * (1 - jitterFraction);
  const delay = floor + random() * (ceiling - floor);
  return Math.max(0, Math.round(delay));
}

export interface RetryInfo {
  attempt: number;
  delayMs: number;
  error: unknown;
  classification: FailureClass;
}

export interface RetryOptions {
  policy?: Partial<RetryPolicy>;
  signal?: AbortSignal;
  shouldRetry?: (err: unknown) => boolean;
  /**
   * Called before sleeping. Throwing here (e.g. a retry-budget refusal) stops
   * the retry loop. This is also the place to audit the retry.
   */
  onRetry?: (info: RetryInfo) => void | Promise<void>;
}

/**
 * Single retry layer. Callers must not nest this around another automatic
 * retry (A2AClient does not retry by itself), to avoid retry amplification.
 */
export async function retry<T>(
  work: (attempt: number) => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const policy: RetryPolicy = {
    ...DEFAULT_RETRY_POLICY,
    ...(options.policy ?? {}),
  };
  const maxAttempts = Math.min(10, Math.max(1, Math.trunc(policy.maxAttempts)));
  let last: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    throwIfAborted(options.signal);
    try {
      return await work(attempt);
    } catch (err) {
      last = err;
      const classification = classifyError(err);
      const canRetry = options.shouldRetry !== undefined ? options.shouldRetry(err) : isRetryable(err);
      if (attempt >= maxAttempts || !canRetry) throw err;
      const delayMs = backoffDelay(attempt, policy);
      await options.onRetry?.({ attempt, delayMs, error: err, classification });
      await sleep(delayMs, options.signal);
    }
  }
  throw last;
}
