import type { AppError } from "../errors.js";
import { CancelledError, TimeoutError } from "./errors.js";

export type AbortKind = "timeout" | "cancelled";

/** Internal abort metadata; never constructed from caller input. */
export class AbortReason {
  constructor(
    readonly kind: AbortKind,
    readonly label: string,
  ) {}
}

/**
 * Convert an aborted signal into the application error that matches why it was
 * aborted. Unknown abort reasons fail closed as a cancellation (not a success).
 */
export function abortError(signal: AbortSignal): AppError {
  const reason = signal.reason as unknown;
  if (reason instanceof TimeoutError) return reason;
  if (reason instanceof CancelledError) return reason;
  if (reason instanceof AbortReason) {
    return reason.kind === "timeout"
      ? new TimeoutError(reason.label.length > 0 ? reason.label : "operation timed out")
      : new CancelledError(reason.label.length > 0 ? reason.label : "operation was cancelled");
  }
  return new CancelledError("operation was cancelled");
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal !== undefined && signal.aborted) throw abortError(signal);
}

/** A promise that rejects as soon as `signal` aborts. */
export function abortPromise(signal: AbortSignal): Promise<never> {
  return new Promise<never>((_resolve, reject) => {
    if (signal.aborted) {
      reject(abortError(signal));
      return;
    }
    signal.addEventListener("abort", () => reject(abortError(signal)), { once: true });
  });
}

/** Abortable sleep used by polling and backoff. */
export async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) {
    throwIfAborted(signal);
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    timer.unref?.();
    const onAbort = (): void => {
      cleanup();
      reject(abortError(signal!));
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    if (signal !== undefined) {
      if (signal.aborted) {
        cleanup();
        reject(abortError(signal));
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

export interface DeadlineOptions {
  timeoutMs?: number;
  /** Parent cancellation signal, e.g. the run/task abort signal. */
  signal?: AbortSignal;
  label?: string;
}

/**
 * Run `work` with a bounded deadline and an optional parent cancellation
 * signal. The provided signal is aborted on either condition, so cooperative
 * downstream work can stop. Rejections are always `TimeoutError` or
 * `CancelledError` when the deadline/parent won the race.
 *
 * This is a cooperative deadline: code that ignores the signal may continue in
 * the background. It prevents the caller from being blocked indefinitely, not
 * a runaway OS process (that is a sandbox concern).
 */
export async function withDeadline<T>(
  work: (signal: AbortSignal) => Promise<T>,
  options: DeadlineOptions = {},
): Promise<T> {
  const label = options.label ?? "operation";
  const controller = new AbortController();
  let timedOut = false;
  let parentAborted = false;

  const onParentAbort = (): void => {
    parentAborted = true;
    controller.abort(options.signal?.reason ?? new AbortReason("cancelled", `${label} cancelled`));
  };

  if (options.signal !== undefined) {
    if (options.signal.aborted) {
      onParentAbort();
    } else {
      options.signal.addEventListener("abort", onParentAbort, { once: true });
    }
  }

  let timer: NodeJS.Timeout | undefined;
  if (options.timeoutMs !== undefined && Number.isFinite(options.timeoutMs)) {
    if (options.timeoutMs <= 0) {
      timedOut = true;
      controller.abort(new AbortReason("timeout", `${label} timed out`));
    } else {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort(new AbortReason("timeout", `${label} timed out`));
      }, options.timeoutMs);
      timer.unref?.();
    }
  }

  const workPromise = work(controller.signal);
  // If the deadline wins, the work promise may still settle later.
  workPromise.catch(() => {});

  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = (): void => reject(abortError(controller.signal));
    if (controller.signal.aborted) {
      onAbort();
      return;
    }
    controller.signal.addEventListener("abort", onAbort, { once: true });
  });

  try {
    return await Promise.race([workPromise, aborted]);
  } catch (err) {
    if (controller.signal.aborted) {
      if (timedOut) throw new TimeoutError(`${label} timed out`);
      if (parentAborted || options.signal?.aborted === true) {
        throw abortError(options.signal!);
      }
      throw abortError(controller.signal);
    }
    throw err;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    options.signal?.removeEventListener("abort", onParentAbort);
    if (onAbort !== undefined) controller.signal.removeEventListener("abort", onAbort);
  }
}
