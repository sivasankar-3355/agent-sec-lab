import { CircuitOpenError } from "./errors.js";

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitSnapshot {
  name: string;
  state: CircuitState;
  failures: number;
  halfOpenInFlight: number;
  openedAt?: number;
  lastTransitionAt: number;
}

export interface CircuitBreakerOptions {
  name: string;
  /** Consecutive transient failures that open the circuit. */
  failureThreshold?: number;
  /** Time to wait in OPEN before probing HALF_OPEN. */
  recoveryIntervalMs?: number;
  /** Maximum concurrent probe requests admitted while HALF_OPEN. */
  halfOpenMaxCalls?: number;
  now?: () => number;
  onStateChange?: (from: CircuitState, to: CircuitState, snapshot: CircuitSnapshot) => void;
}

const DEFAULTS = {
  failureThreshold: 3,
  recoveryIntervalMs: 15_000,
  halfOpenMaxCalls: 1,
} as const;

/**
 * Per-peer circuit breaker for agent communication.
 *
 * CLOSED      normal operation; transient failures are counted.
 * OPEN        all requests are refused until the recovery interval elapses.
 * HALF_OPEN   a limited number of probes are admitted; one success closes the
 *             circuit, any failure re-opens it.
 *
 * Only transient communication failures should be recorded. Authorization,
 * validation, budget and cancellation failures must not trip the breaker.
 */
export class CircuitBreaker {
  readonly name: string;
  private readonly failureThreshold: number;
  private readonly recoveryIntervalMs: number;
  private readonly halfOpenMaxCalls: number;
  private readonly now: () => number;
  private readonly onStateChange:
    | ((from: CircuitState, to: CircuitState, snapshot: CircuitSnapshot) => void)
    | undefined;

  private current: CircuitState = "CLOSED";
  private failures = 0;
  private halfOpenInFlight = 0;
  private openedAt: number | undefined;
  private lastTransitionAt: number;

  constructor(options: CircuitBreakerOptions) {
    this.name = options.name;
    this.failureThreshold = Math.max(1, Math.trunc(options.failureThreshold ?? DEFAULTS.failureThreshold));
    this.recoveryIntervalMs = Math.max(1, Math.trunc(options.recoveryIntervalMs ?? DEFAULTS.recoveryIntervalMs));
    this.halfOpenMaxCalls = Math.max(1, Math.trunc(options.halfOpenMaxCalls ?? DEFAULTS.halfOpenMaxCalls));
    this.now = options.now ?? (() => Date.now());
    this.onStateChange = options.onStateChange;
    this.lastTransitionAt = this.now();
  }

  get state(): CircuitState {
    this.maybeTransitionToHalfOpen();
    return this.current;
  }

  /**
   * Admit or refuse a request. In HALF_OPEN this consumes one probe slot; the
   * eventual `recordSuccess`/`recordFailure` must be called for that request.
   */
  allowRequest(): boolean {
    this.maybeTransitionToHalfOpen();
    if (this.current === "OPEN") return false;
    if (this.current === "HALF_OPEN") {
      if (this.halfOpenInFlight >= this.halfOpenMaxCalls) return false;
      this.halfOpenInFlight += 1;
    }
    return true;
  }

  /** Throw `CircuitOpenError` when a request is refused. */
  assertRequestAllowed(): void {
    if (!this.allowRequest()) throw new CircuitOpenError(this.name);
  }

  recordSuccess(): void {
    if (this.current === "HALF_OPEN") {
      if (this.halfOpenInFlight > 0) this.halfOpenInFlight -= 1;
      if (this.halfOpenInFlight === 0) {
        this.failures = 0;
        this.transition("CLOSED");
      }
      return;
    }
    if (this.current === "CLOSED") this.failures = 0;
  }

  recordFailure(): void {
    if (this.current === "HALF_OPEN") {
      if (this.halfOpenInFlight > 0) this.halfOpenInFlight -= 1;
      this.trip();
      return;
    }
    if (this.current === "CLOSED") {
      this.failures += 1;
      if (this.failures >= this.failureThreshold) this.trip();
    }
  }

  snapshot(): CircuitSnapshot {
    this.maybeTransitionToHalfOpen();
    return {
      name: this.name,
      state: this.current,
      failures: this.failures,
      halfOpenInFlight: this.halfOpenInFlight,
      ...(this.openedAt !== undefined ? { openedAt: this.openedAt } : {}),
      lastTransitionAt: this.lastTransitionAt,
    };
  }

  private maybeTransitionToHalfOpen(): void {
    if (this.current !== "OPEN" || this.openedAt === undefined) return;
    if (this.now() - this.openedAt >= this.recoveryIntervalMs) {
      this.halfOpenInFlight = 0;
      this.transition("HALF_OPEN");
    }
  }

  private trip(): void {
    this.openedAt = this.now();
    this.halfOpenInFlight = 0;
    this.transition("OPEN");
  }

  private transition(to: CircuitState): void {
    if (this.current === to) return;
    const from = this.current;
    this.current = to;
    this.lastTransitionAt = this.now();
    if (to === "CLOSED") this.openedAt = undefined;
    try {
      this.onStateChange?.(from, to, this.snapshot());
    } catch {
      // Observability callbacks must not affect breaker behavior.
    }
  }
}
