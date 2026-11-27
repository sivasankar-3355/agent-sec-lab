import { AppError } from "../errors.js";

/** A bounded operation exceeded its deadline. */
export class TimeoutError extends AppError {
  constructor(message = "operation timed out") {
    super("timeout", message, 504);
  }
}

/** A caller/task/run cancellation was observed. */
export class CancelledError extends AppError {
  constructor(message = "operation was cancelled") {
    super("cancelled", message, 499);
  }
}

/** An agent-communication circuit breaker refused a request. */
export class CircuitOpenError extends AppError {
  constructor(name: string) {
    super("circuit_open", `circuit '${name}' is open; request refused`, 503);
  }
}

/**
 * A trusted run budget/deadline was exhausted. `code` and `status` are
 * injectable so callers can distinguish a rate/budget refusal (429) from a
 * run deadline (504) or an unavailable budget store (503).
 */
export class BudgetExceededError extends AppError {
  constructor(message: string, code = "run_budget_exceeded", status = 429) {
    super(code, message, status);
  }
}
