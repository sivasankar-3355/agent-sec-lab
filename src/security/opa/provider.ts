import type { Logger } from "pino";
import type { AuditProvider, AuthorizationProvider, AuthzResource, Decision } from "../protocols.js";
import { buildAuthorizationInput } from "./input.js";
import { createPolicyEngine, UnavailablePolicyEngine } from "./engine.js";
import { DEFAULT_POLICY_DIR, DEFAULT_POLICY_VERSION, loadPolicyBundle } from "./policies.js";
import type { PolicyEngine, PolicyEngineOptions, ProviderFactoryOptions } from "./types.js";

export interface OpaAuthorizationProviderOptions extends PolicyEngineOptions, ProviderFactoryOptions {
  log: Logger;
  /** Directory that holds versioned policy bundles (default: policies). */
  policyDir?: string;
}

/**
 * Policy Enforcement Point (PEP): implements `AuthorizationProvider` on top
 * of the central OPA policy decision engine.
 *
 * Security properties:
 * - default deny: `allow` must be explicitly true; the Rego `default allow :=
 *   false` guarantees it.
 * - fail closed: any engine/parse/transport error becomes a denial, never an
 *   allow.
 * - signed context only: `approved*`/`resource*` attributes are supplied by
 *   the PEP from verified state (token claims / trusted repos); request-body
 *   fields only ever appear in `requested*` and are bounded by policy.
 * - every decision is recorded on the audit log.
 */
export class OpaAuthorizationProvider implements AuthorizationProvider {
  private readonly engine: PolicyEngine;
  private readonly audit: AuditProvider | undefined;
  private readonly log: Logger;

  constructor(engine: PolicyEngine, audit: AuditProvider | undefined, log: Logger) {
    this.engine = engine;
    this.audit = audit;
    this.log = log;
  }

  get policyVersion(): string {
    return this.engine.policyVersion;
  }

  async authorize(action: string, resource: AuthzResource): Promise<Decision> {
    const input = buildAuthorizationInput(action, resource, { policyVersion: this.engine.policyVersion });

    let decision: { allowed: boolean; rule?: string; reason?: string };
    try {
      decision = await this.engine.evaluate(input);
    } catch (err) {
      const reason = err instanceof Error ? err.message : "unknown engine error";
      this.log.warn({ err, action }, "authorization engine failed; denying (fail-closed)");
      decision = { allowed: false, reason: `authorization engine unavailable: ${reason}` };
    }

    const attrs = input.attributes;
    void this.audit?.emit({
      type: "authz.decision",
      ts: new Date().toISOString(),
      traceId: input.context.decisionId,
      ...(resource.principal !== undefined ? { principal: resource.principal } : {}),
      ...(attrs.runId !== "" ? { runId: attrs.runId } : {}),
      data: {
        decision: decision.allowed ? "allow" : "deny",
        policy: input.context.policy,
        kind: input.kind,
        action: attrs.action,
        workload: attrs.workload,
        agent: attrs.agent,
        user: attrs.user,
        rule: decision.rule ?? null,
        reason: decision.reason ?? null,
      },
    });

    const result: Decision = { allowed: decision.allowed };
    if (decision.reason !== undefined) result.reason = decision.reason;
    if (decision.rule !== undefined) result.rule = decision.rule;
    return result;
  }
}

/**
 * Build the authorization provider for a process. Remote OPA (OPA_URL) is used
 * when configured; otherwise the embedded Rego engine evaluates the versioned
 * bundle. Fail-closed on any initialization error.
 */
export function createOpaAuthorizationProvider(options: OpaAuthorizationProviderOptions): AuthorizationProvider {
  const version = options.policyVersion ?? DEFAULT_POLICY_VERSION;
  let engine: PolicyEngine;
  try {
    let source = options.policySource;
    if (source === undefined || source.length === 0) {
      source = loadPolicyBundle(options.policyDir ?? DEFAULT_POLICY_DIR, version).source;
    }
    engine = createPolicyEngine({ ...options, policySource: source });
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown";
    options.log.warn({ err }, `OPA initialization failed; authorization fails closed (${reason})`);
    engine = new UnavailablePolicyEngine(reason);
  }
  return new OpaAuthorizationProvider(engine, options.audit, options.log);
}
