import { randomUUID } from "node:crypto";
import type { AuthzResource } from "../protocols.js";
import type { AuthorizationAttributes, AuthorizationInput, PolicyKind } from "./types.js";

function strs(value: readonly string[] | undefined): string[] {
  return (value ?? []).filter((v): v is string => typeof v === "string");
}

function str(value: string | undefined): string {
  return typeof value === "string" ? value : "";
}

/** Derive the policy kind from the action name when not supplied at the PEP. */
export function deriveKind(action: string, hint?: PolicyKind): PolicyKind {
  if (hint !== undefined) return hint;
  if (action.startsWith("a2a:")) return "a2a";
  if (action.includes(":")) return "api";
  return "operation";
}

function workloadFromPrincipal(principal: string | undefined): string {
  if (principal === undefined) return "";
  if (principal.startsWith("workload:")) return principal.slice("workload:".length);
  return "";
}

/**
 * Build the OPA authorization input document from a PEP call. Only attributes
 * the PEP gathered from *verified* state (token claims, trusted repos) are
 * placed in the `approved*` / `resource*` fields; every `requested*` field is
 * attacker-influenced intent and is checked against them by policy. Missing
 * attributes normalize to "" / [] so the policy's default-deny applies.
 */
export function buildAuthorizationInput(
  action: string,
  resource: AuthzResource,
  options: { policyVersion: string; sourceLabel?: string; decisionId?: string },
): AuthorizationInput {
  const kind = deriveKind(action, resource.kind);
  const workload =
    resource.workload !== undefined
      ? resource.workload
      : kind === "api"
        ? "gateway"
        : workloadFromPrincipal(resource.principal);
  const user = str(resource.user !== undefined ? resource.user : (resource.principal ?? ""));

  const attributes: AuthorizationAttributes = {
    action: kind === "a2a" && action.startsWith("a2a:") ? action.slice("a2a:".length) : action,
    workload,
    agent: str(resource.agent),
    user,
    runId: str(resource.runId),
    approvedTargets: strs(resource.approvedTargets),
    approvedActions: strs(resource.approvedActions),
    requestedAction: str(resource.requestedAction),
    requestedTool: str(resource.requestedTool),
    requestedTarget: str(resource.requestedTarget),
    requestedRunId: str(resource.requestedRunId),
    requestedDocIds: strs(resource.requestedDocIds),
    requestedObject: str(resource.requestedObject),
    resourceOwner: str(resource.resourceOwner),
    resourceTenantId: str(resource.resourceTenantId),
    tenantId: str(resource.tenantId),
    scopes: strs(resource.scopes),
  };

  const input: AuthorizationInput = {
    kind,
    version: options.policyVersion,
    attributes,
    context: {
      decisionId: options.decisionId ?? randomUUID(),
      source: options.sourceLabel ?? "signed-token",
      policy: options.policyVersion,
    },
  };
  return input;
}
