import { RegoEngine } from "./rego.js";
import type { AuthorizationInput, PolicyDecision, PolicyEngine, PolicyEngineOptions } from "./types.js";

/**
 * Embedded Rego engine: evaluates the checked-in policy bundle in-process.
 * Used for local dev and tests; behaves exactly like OPA for the restricted
 * subset (see rego.ts). Fail-closed: any parse/evaluation problem surfaces as
 * an error that callers turn into a denial.
 */
export class EmbeddedRegoPolicyEngine implements PolicyEngine {
  readonly policyVersion: string;
  private readonly engine: RegoEngine;

  constructor(options: { policySource: string; policyVersion?: string }) {
    this.engine = new RegoEngine(options.policySource);
    const declared = this.engine.constant("version");
    this.policyVersion = typeof declared === "string" && declared.length > 0 ? declared : (options.policyVersion ?? "dev");
  }

  async evaluate(input: AuthorizationInput): Promise<PolicyDecision> {
    const allowed = this.engine.evaluate(input as unknown as Record<string, unknown>);
    return {
      allowed,
      ...(allowed
        ? { rule: "agentseclab.authz.allow" }
        : { reason: "denied by policy (default-deny)" }),
    };
  }
}

/**
 * Remote OPA engine: posts the authorization input document to OPA's Data API
 * (`POST /v1/data/agentseclab/authz`) and reads `result.allow`. This is the
 * production path when `OPA_URL` is set.
 */
export class OpaHttpPolicyEngine implements PolicyEngine {
  readonly policyVersion: string;
  private readonly base: string;
  private readonly path: string;
  private readonly timeoutMs: number;

  constructor(options: { opaUrl: string; opaPath?: string; policyVersion?: string; timeoutMs?: number }) {
    this.base = options.opaUrl.replace(/\/+$/, "");
    this.path = (options.opaPath ?? "agentseclab/authz").replace(/^\/+/, "");
    this.policyVersion = options.policyVersion ?? "remote";
    this.timeoutMs = options.timeoutMs ?? 3000;
  }

  async evaluate(input: AuthorizationInput): Promise<PolicyDecision> {
    const response = await fetch(`${this.base}/v1/data/${this.path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) throw new Error(`OPA returned ${response.status}`);
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new Error("OPA returned malformed JSON");
    }
    const result = (body as { result?: { allow?: unknown } | undefined }).result;
    if (result === undefined) throw new Error("OPA returned no decision");
    const allowed = result.allow === true;
    if (allowed) return { allowed, rule: `opa:${this.path}.allow` };
    return { allowed: false, reason: "denied by OPA" };
  }
}

/** Engine that is never usable; every request fails closed. */
export class UnavailablePolicyEngine implements PolicyEngine {
  readonly policyVersion = "unavailable";
  readonly reason: string;

  constructor(reason: string) {
    this.reason = reason;
  }

  async evaluate(_input: AuthorizationInput): Promise<PolicyDecision> {
    throw new Error(`policy engine unavailable: ${this.reason}`);
  }
}

/** Build an engine from options: remote OPA wins, otherwise embedded. */
export function createPolicyEngine(options: PolicyEngineOptions): PolicyEngine {
  const version = options.policyVersion ?? "dev";
  if (options.opaUrl !== undefined && options.opaUrl.trim().length > 0) {
    return new OpaHttpPolicyEngine({ ...options, opaUrl: options.opaUrl });
  }
  if (options.policySource === undefined || options.policySource.trim().length === 0) {
    throw new Error("no policy source and no OPA URL configured");
  }
  return new EmbeddedRegoPolicyEngine({ policySource: options.policySource, policyVersion: version });
}
