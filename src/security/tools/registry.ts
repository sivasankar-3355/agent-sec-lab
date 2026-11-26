import type { ZodTypeAny, output } from "zod";
import { AppError } from "../../core/errors.js";
import type { Decision, VerifiedContext } from "../protocols.js";
import type { ToolSpec } from "./types.js";

export function defineTool<S extends ZodTypeAny>(spec: ToolSpec<S>): ToolSpec<S> {
  return spec;
}

const TOOL_NAME = /^[a-z][a-z0-9._-]{1,127}$/;
const AGENT_NAME = /^[a-z][a-z0-9-]{0,63}$/;

function assertLimits(spec: ToolSpec): void {
  const { timeoutMs, maxOutputBytes, maxConcurrency, rateLimit } = spec.limits;
  const valid =
    Number.isInteger(timeoutMs) &&
    timeoutMs >= 1 &&
    timeoutMs <= 300_000 &&
    Number.isInteger(maxOutputBytes) &&
    maxOutputBytes >= 1 &&
    maxOutputBytes <= 1_048_576 &&
    Number.isInteger(maxConcurrency) &&
    maxConcurrency >= 1 &&
    maxConcurrency <= 64 &&
    Number.isInteger(rateLimit.maxCalls) &&
    rateLimit.maxCalls >= 1 &&
    rateLimit.maxCalls <= 10_000 &&
    Number.isInteger(rateLimit.windowMs) &&
    rateLimit.windowMs >= 1 &&
    rateLimit.windowMs <= 3_600_000;
  if (!valid) throw new Error(`tool '${spec.name}' has invalid execution limits`);
}

function assertSpec(spec: ToolSpec): void {
  if (!TOOL_NAME.test(spec.name)) throw new Error(`invalid tool name '${spec.name}'`);
  if (spec.description.trim().length === 0) throw new Error(`tool '${spec.name}' has no description`);
  if (spec.allowedAgents.length === 0) throw new Error(`tool '${spec.name}' has no allowed agents`);
  for (const agent of spec.allowedAgents) {
    if (!AGENT_NAME.test(agent)) throw new Error(`tool '${spec.name}' has an invalid agent '${agent}'`);
  }
  if (spec.requiredAction.trim().length === 0) throw new Error(`tool '${spec.name}' has no required action`);
  if (spec.target !== undefined) {
    if (spec.target.field.trim().length === 0) throw new Error(`tool '${spec.name}' has an invalid target field`);
    // Every target rule must resolve hostnames so private/reserved addresses
    // are checked before execution. Opting out requires a code review.
    if (!spec.target.resolve) throw new Error(`tool '${spec.name}' must resolve host targets`);
  }
  assertLimits(spec);
}

/**
 * Trusted, immutable allowlist of code-owned tools. Registration is closed
 * before any worker starts; an unknown or non-permitted tool fails closed.
 */
export class ToolRegistry {
  private readonly tools = new Map<string, ToolSpec>();
  private sealed = false;

  register(spec: ToolSpec): void {
    if (this.sealed) throw new Error("tool registry is sealed");
    assertSpec(spec);
    if (this.tools.has(spec.name)) throw new Error(`duplicate tool registration: ${spec.name}`);
    Object.freeze(spec.allowedAgents);
    Object.freeze(spec.limits.rateLimit);
    Object.freeze(spec.limits);
    if (spec.target !== undefined) Object.freeze(spec.target);
    Object.freeze(spec);
    this.tools.set(spec.name, spec);
  }

  /** Close the registry so no tool can be added after boot. */
  seal(): void {
    this.sealed = true;
  }

  get isSealed(): boolean {
    return this.sealed;
  }

  get(name: string): ToolSpec {
    const spec = this.tools.get(name);
    if (spec === undefined) {
      throw new AppError("tool_not_registered", `tool '${name}' is not registered`, 403);
    }
    return spec;
  }

  /** Per-agent allowlist. A tool name alone is never permission. */
  requireForAgent(name: string, agent: string): ToolSpec {
    const spec = this.get(name);
    if (!spec.allowedAgents.includes(agent)) {
      throw new AppError(
        "tool_not_permitted",
        `agent '${agent}' is not permitted to invoke tool '${name}'`,
        403,
      );
    }
    return spec;
  }

  listForAgent(agent: string): readonly ToolSpec[] {
    return [...this.tools.values()].filter((spec) => spec.allowedAgents.includes(agent));
  }

  list(): readonly ToolSpec[] {
    return [...this.tools.values()];
  }
}

export interface ToolAuthorization {
  /** Verified, signed run grant for this call (absent in unauthenticated dev paths). */
  grant?: VerifiedContext;
  /** Decision returned by the existing authorization layer for `requiredAction`. */
  decision?: Decision;
}

function argumentObject(data: unknown): Record<string, unknown> {
  return typeof data === "object" && data !== null && !Array.isArray(data)
    ? (data as Record<string, unknown>)
    : {};
}

/**
 * Legacy pure validation helper retained for compatibility. New execution paths
 * must use `ToolBroker.execute`, which additionally enforces the per-agent
 * allowlist, trusted run scope, DNS/IP checks, limits and output handling.
 */
export function validateToolCall<S extends ZodTypeAny>(
  spec: ToolSpec<S>,
  raw: unknown,
  authorization: ToolAuthorization = {},
): output<S> {
  const parsed = spec.schema.safeParse(raw);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
    throw new AppError("validation_error", `invalid arguments for tool '${spec.name}': ${detail}`, 422);
  }

  const grant = authorization.grant;
  if (grant !== undefined) {
    if (!grant.permittedActions.includes(spec.requiredAction)) {
      throw new AppError(
        "forbidden",
        `tool '${spec.name}' requires action '${spec.requiredAction}' which is not in the run grant`,
        403,
      );
    }
    const args = argumentObject(parsed.data);
    const targetField = spec.target?.field;
    if (targetField !== undefined) {
      const target = args[targetField];
      if (typeof target === "string" && !grant.scopeTargets.includes(target)) {
        throw new AppError(
          "forbidden",
          `tool '${spec.name}' target '${target}' is outside the approved scope`,
          403,
        );
      }
    }
    if (spec.runIdField !== undefined) {
      const runId = args[spec.runIdField];
      if (typeof runId === "string" && runId !== "" && runId !== grant.runId) {
        throw new AppError("forbidden", `tool '${spec.name}' run '${runId}' is outside the authorized run`, 403);
      }
    }
  }

  if (spec.risk === "high" && authorization.decision === undefined && grant !== undefined) {
    throw new AppError("forbidden", `tool '${spec.name}' requires an explicit authorization decision`, 403);
  }
  if (authorization.decision !== undefined && !authorization.decision.allowed) {
    throw new AppError(
      "forbidden",
      authorization.decision.reason ?? `tool '${spec.name}' was not authorized`,
      403,
    );
  }

  return parsed.data;
}
