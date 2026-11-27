import type { RunRecord } from "../../core/domain.js";
import type { RunBudget } from "../../core/resilience/index.js";
import type { Decision, ResolvedTarget } from "../protocols.js";
import type { ToolActor, ToolLimits } from "./types.js";

/**
 * A fully authorized and validated tool execution request.
 *
 * This object contains only trusted state: the actor comes from
 * `VerifiedContext`, the run comes from the trusted run repository, the target
 * comes from the broker's canonicalization/DNS checks, and the arguments have
 * already passed the registered schema. It never contains a model-supplied
 * operation, executable, shell string or permission.
 *
 * There is deliberately no `command`, `shell`, `executable` or `handler`
 * field. A future process executor must select a fixed executable from a
 * code-owned allowlist and pass an argument array with `shell: false`.
 */
export interface ToolExecutionRequest {
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly target?: ResolvedTarget;
  readonly signal: AbortSignal;
  readonly actor: ToolActor;
  readonly run: RunRecord;
  readonly decision: Decision;
  readonly limits: ToolLimits;
  /** Trusted run budget resolved by the broker from the run record. */
  readonly budget: RunBudget;
}

/**
 * Pluggable execution backend. Authorization, argument validation and target
 * validation stay in the broker; this interface owns only execution.
 *
 * Phase 5 ships a controlled in-process `LocalToolExecutor`. Phase 7 can add a
 * sandboxed executor without changing the broker or policy logic.
 */
export interface ToolExecutor {
  readonly kind: "local" | "sandbox";
  /** Whether this executor has a code-owned operation for the tool. */
  supports(tool: string): boolean;
  execute(request: ToolExecutionRequest): Promise<unknown>;
}
