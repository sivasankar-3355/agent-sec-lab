import type { AuditProvider, AuthzResource } from "../protocols.js";

export type PolicyKind = "api" | "a2a" | "operation";

export interface PolicyDecision {
  allowed: boolean;
  rule?: string;
  reason?: string;
}

export interface AuthorizationAttributes {
  action: string;
  workload: string;
  agent: string;
  user: string;
  runId: string;
  approvedTargets: string[];
  approvedActions: string[];
  requestedAction: string;
  requestedTool: string;
  requestedTarget: string;
  requestedRunId: string;
  requestedDocIds: string[];
  requestedObject: string;
  resourceOwner: string;
  resourceTenantId: string;
  tenantId: string;
  scopes: string[];
}

export interface AuthorizationInput {
  kind: PolicyKind;
  version: string;
  attributes: AuthorizationAttributes;
  context: {
    decisionId: string;
    source: string;
    policy: string;
  };
}

/** Central policy decision interface consumed by the PEPs. */
export interface PolicyEngine {
  readonly policyVersion: string;
  /** Fail-closed contract: throws on any evaluation error. */
  evaluate(input: AuthorizationInput): Promise<PolicyDecision>;
}

export interface PolicyEngineOptions {
  /** Full Rego source for the embedded engine. */
  policySource?: string;
  /** Remote OPA base URL (e.g. http://opa:8181). */
  opaUrl?: string;
  /** OPA data path (default: agentseclab/authz). */
  opaPath?: string;
  policyVersion?: string;
  timeoutMs?: number;
}

export interface ProviderFactoryOptions {
  audit?: AuditProvider;
  policyVersion?: string;
  sourceLabel?: string;
}

export type { AuthzResource };
