import type { RunState } from "../../core/domain.js";
import { AppError } from "../../core/errors.js";

const TRANSITIONS: ReadonlyMap<RunState, readonly RunState[]> = new Map<RunState, readonly RunState[]>([
  ["CREATED", ["STARTED", "FAILED", "CANCELLED"]],
  ["STARTED", ["RECON", "FAILED", "CANCELLED"]],
  ["RECON", ["KNOWLEDGE", "FAILED", "CANCELLED"]],
  ["KNOWLEDGE", ["REPORT", "FAILED", "CANCELLED"]],
  ["REPORT", ["COMPLETED", "FAILED", "CANCELLED"]],
]);

export { TRANSITIONS };

export function canTransition(from: RunState, to: RunState): boolean {
  return (TRANSITIONS.get(from) ?? []).includes(to);
}

export function assertTransition(from: RunState, to: RunState): void {
  if (!canTransition(from, to)) {
    throw new AppError("invalid_run_state", `invalid run state transition: ${from} -> ${to}`, 409);
  }
}