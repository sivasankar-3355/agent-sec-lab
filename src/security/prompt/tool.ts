import type { ZodTypeAny, output } from "zod";
import { AppError } from "../../core/errors.js";
import type { Decision, VerifiedContext } from "../protocols.js";

export type ToolSensitivity = "low" | "medium" | "high";

/**
 * A code-owned tool definition. Descriptions are trusted (they live in source
 * code); argument schemas are strict (`z.object({...}).strict()`), so
 * model-generated or caller-supplied extra fields are rejected.
 */
export interface ToolSpec<S extends ZodTypeAny = ZodTypeAny> {
  readonly name: string;
  readonly description: string;
  readonly schema: S;
  /** Existing authorization action that must be granted before invocation. */
  readonly requiredAction: string;
  readonly sensitivity: ToolSensitivity;
  /** Optional argument field that must be within the signed target scope. */
  readonly targetField?: string;
  /** Optional argument field that must match the signed run id. */
  readonly runIdField?: string;
}

export function defineTool<S extends ZodTypeAny>(spec: ToolSpec<S>): ToolSpec<S> {
  return spec;
}

/** Allowlist of tools an agent may invoke; unknown names fail closed. */
export class ToolRegistry {
  private readonly tools = new Map<string, ToolSpec>();

  register(spec: ToolSpec): void {
    if (this.tools.has(spec.name)) {
      throw new Error(`duplicate tool registration: ${spec.name}`);
    }
    this.tools.set(spec.name, spec);
  }

  get(name: string): ToolSpec {
    const spec = this.tools.get(name);
    if (spec === undefined) {
      throw new AppError("tool_not_registered", `tool '${name}' is not registered for this agent`, 403);
    }
    return spec;
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
 * Validate a tool call independently of any prompt:
 *  1. the tool must be registered (caller decides the tool, never the model),
 *  2. arguments must match the strict schema,
 *  3. the required action must be present in the signed run grant,
 *  4. target/run arguments must stay inside the signed grant,
 *  5. a denied authorization decision (or a missing one for a high-sensitivity
 *     tool) rejects the call.
 *
 * This performs no authorization of its own; it *requires* the existing
 * authorization decision, so prompt content cannot manufacture permission.
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
    if (spec.targetField !== undefined) {
      const target = args[spec.targetField];
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

  if (spec.sensitivity === "high" && authorization.decision === undefined && grant !== undefined) {
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
