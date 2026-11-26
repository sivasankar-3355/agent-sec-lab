import type { ZodTypeAny } from "zod";
import type { RunRecord } from "../../core/domain.js";
import type { Decision, ResolvedTarget } from "../protocols.js";

/**
 * Risk classification used for audit and for deciding how strict the tool gate
 * must be. It is code-owned; callers and models can never set it.
 */
export type ToolRisk = "low" | "medium" | "high";

/** Code-owned execution limits. Callers cannot raise these per call. */
export interface ToolLimits {
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly maxConcurrency: number;
  readonly rateLimit: {
    readonly maxCalls: number;
    readonly windowMs: number;
  };
}

export type ToolTargetKind = "host" | "url" | "host-or-url";

/**
 * Declares which argument carries the target and how it must be validated.
 * The target value is never authorization evidence by itself: it is checked
 * against the trusted run record and the signed run grant.
 */
export interface ToolTargetRule {
  readonly field: string;
  readonly kind: ToolTargetKind;
  /** Resolve hostnames and reject private/reserved addresses (default true). */
  readonly resolve: boolean;
  /**
   * Allow private/loopback/link-local addresses. Code-owned and false by
   * default; no current tool opts in.
   */
  readonly allowPrivate?: boolean;
}

/**
 * A code-owned tool definition. `schema` must be a strict object schema;
 * unknown arguments are rejected by zod before the handler runs.
 */
export interface ToolSpec<S extends ZodTypeAny = ZodTypeAny> {
  readonly name: string;
  readonly description: string;
  readonly schema: S;
  /** Agents that may ever invoke this tool. Unknown agents fail closed. */
  readonly allowedAgents: readonly string[];
  /** Existing OPA operation action that must be granted on the run token. */
  readonly requiredAction: string;
  readonly risk: ToolRisk;
  readonly limits: ToolLimits;
  readonly target?: ToolTargetRule;
  /** Optional argument field that must match the signed run id. */
  readonly runIdField?: string;
  /** Structural validation for application-owned output. */
  readonly outputSchema?: ZodTypeAny;
}

/**
 * The verified caller identity for a tool call. Every field is derived from
 * the verified A2A context (`VerifiedContext`) or from the trusted run record;
 * none of it is supplied by the model or the task body.
 */
export interface ToolActor {
  agent: string;
  workload: string;
  userId: string;
  runId: string;
  taskId: string;
  tenantId?: string;
  scopes: readonly string[];
  approvedActions: readonly string[];
  approvedTargets: readonly string[];
  audience: readonly string[];
  caller: string;
}

export interface ToolRequest {
  /** Code-selected tool identifier; never parsed from model output. */
  readonly name: string;
  readonly args: unknown;
}

/** Trusted inputs handed to a tool handler after every gate has passed. */
export interface ToolCallContext<A> {
  readonly args: A;
  readonly actor: ToolActor;
  readonly run: RunRecord;
  readonly target?: ResolvedTarget;
  readonly signal: AbortSignal;
  readonly decision: Decision;
}

export interface ToolProvenance {
  tool: string;
  agent: string;
  runId: string;
  taskId: string;
  target?: string;
}

/**
 * Tool output is always untrusted data with provenance. It is never an
 * instruction and it never carries authority.
 */
export interface ToolResult<T = unknown> {
  readonly tool: string;
  readonly trust: "untrusted";
  readonly authoritative: false;
  readonly provenance: ToolProvenance;
  readonly data: T;
  readonly bytes: number;
  readonly durationMs: number;
}

export interface TargetResolver {
  /** Resolve a hostname to all A/AAAA addresses. Must fail (throw) on error. */
  resolve(hostname: string): Promise<readonly string[]>;
}
