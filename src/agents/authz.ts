import { AppError } from "../core/errors.js";
import type { AuthorizationProvider, AuthzResource, Decision } from "../security/protocols.js";

/** Extract the workload name from a verified caller ("workload:recon" -> "recon"). */
export function workloadOfCaller(caller: string | undefined): string {
  if (caller === undefined || caller.length === 0) return "";
  if (caller.startsWith("workload:")) return caller.slice("workload:".length);
  return caller;
}

/**
 * Agent-side PEP: independently ask the central OPA decision engine whether an
 * operation is authorized. Throws 403 on default-deny. This is defense in
 * depth on top of the A2A method admission performed by the A2A server.
 */
export async function assertAuthorized(
  authz: AuthorizationProvider,
  action: string,
  resource: AuthzResource,
): Promise<Decision> {
  const decision = await authz.authorize(action, resource);
  if (!decision.allowed) {
    throw new AppError("forbidden", decision.reason ?? `operation '${action}' is not authorized`, 403, [
      decision.rule ?? "denied-by-policy",
    ]);
  }
  return decision;
}

export interface DocumentAccessQuery {
  authz: AuthorizationProvider;
  /** Policy kind used at the call site ("operation" for agents, "api" in the gateway). */
  kind: "operation" | "api";
  action: string;
  user: string;
  requestedObject: string;
  resourceOwner?: string;
  resourceTenantId?: string;
  tenantId?: string;
  scopes?: readonly string[];
}

/** ABAC: is this specific document accessible to `user` (owner, tenant)? */
export async function authorizeDocumentAccess(query: DocumentAccessQuery): Promise<boolean> {
  const decision = await query.authz.authorize(query.action, {
    kind: query.kind,
    agent: "knowledge",
    ...(query.kind === "operation" ? { workload: "orchestrator" } : {}),
    ...(query.user !== "" ? { user: query.user } : {}),
    requestedAction: query.action,
    requestedObject: query.requestedObject,
    resourceOwner: query.resourceOwner ?? "",
    resourceTenantId: query.resourceTenantId ?? "",
    ...(query.tenantId !== undefined ? { tenantId: query.tenantId } : {}),
    ...(query.scopes !== undefined ? { scopes: query.scopes } : {}),
  });
  return decision.allowed;
}
