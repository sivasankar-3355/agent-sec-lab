import type { AgentKind } from "../a2a/schema.js";

/** The A2A audience name for a service (per-hop token recipient). */
export function a2aAudience(agent: AgentKind): string {
  return `a2a:${agent}`;
}

export const A2A_SCOPES: readonly string[] = [
  "a2a:tasks/send",
  "a2a:tasks/get",
  "a2a:tasks/cancel",
  "a2a:message/send",
];

export const INTERNAL_EXCHANGE_SCOPE = "internal:token-exchange";
export const INTERNAL_ISSUE_SCOPE = "internal:token-issue";
/** Gateway workload scope required to mint a run-bound token from the STS. */
export const INTERNAL_MINT_SCOPE = "internal:token-mint";

/** Domain operations granted on a run token. */
export const RUN_ACTIONS: readonly string[] = ["run.start", "recon.run", "knowledge.search", "report.generate"];

/** Scopes granted to an authenticated user by default (Phase 1; no IdP yet). */
export const USER_SCOPES: readonly string[] = [
  "runs:create",
  "runs:read",
  "knowledge:read",
  "knowledge:write",
  "memory:search",
  "memory:read",
  "memory:insert",
  "memory:update",
  "memory:delete",
];

/** Which child audiences an orchestrator may exchange run credits for. */
export const ALLOWED_CHILD_AUDIENCES: readonly string[] = ["a2a:recon", "a2a:knowledge", "a2a:report"];

/** Domain actions a child audience may be granted. */
export const ACTIONS_BY_AUDIENCE: Record<string, readonly string[]> = {
  "a2a:recon": ["recon.run"],
  "a2a:knowledge": ["knowledge.search", "knowledge.index"],
  "a2a:report": ["report.generate"],
};

export const STS_EXCHANGE_PATH = "/api/v1/internal/token-exchange";
export const STS_ISSUE_PATH = "/api/v1/internal/token-issue";
export const STS_MINT_PATH = "/api/v1/internal/token-mint";