import { AppError } from "../core/errors.js";
import type { VerifiedContext } from "../security/protocols.js";
import type { ToolActor } from "../security/tools/index.js";
import { workloadOfCaller } from "./authz.js";

/** The task fields that must be bound to a verified A2A context. */
export interface VerifiedTaskInput {
  runId: string;
  taskId: string;
  authz?: VerifiedContext;
}

/**
 * Build the tool actor from verified state only. A missing, unbound or
 * unverified context fails closed: no tool executes for an anonymous caller or
 * for a context whose run id does not match the task.
 */
export function toolActorOf(agent: string, task: VerifiedTaskInput): ToolActor {
  const authz = task.authz;
  if (authz === undefined) {
    throw new AppError("forbidden", "tool execution requires a verified run context", 403);
  }
  if (authz.runId === "" || authz.runId !== task.runId) {
    throw new AppError(
      "forbidden",
      `tool run '${task.runId}' is outside authorized run '${authz.runId}'`,
      403,
    );
  }
  if (authz.userId === "") {
    throw new AppError("forbidden", "tool execution requires an authenticated user", 403);
  }
  if (authz.agent !== "" && authz.agent !== `a2a:${agent}`) {
    throw new AppError("forbidden", "verified agent binding does not match the executor", 403);
  }
  const workload = workloadOfCaller(authz.caller);
  if (workload === "") {
    throw new AppError("forbidden", "tool execution requires a verified workload identity", 403);
  }
  return {
    agent,
    workload,
    userId: authz.userId,
    runId: authz.runId,
    taskId: task.taskId,
    ...(authz.tenantId !== undefined ? { tenantId: authz.tenantId } : {}),
    scopes: [...authz.scopes],
    approvedActions: [...authz.permittedActions],
    approvedTargets: [...authz.scopeTargets],
    audience: [...authz.audience],
    caller: authz.caller,
  };
}
