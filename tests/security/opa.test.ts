import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { createLogger } from "../../src/core/logger.js";
import type { AuthzResource } from "../../src/security/protocols.js";
import {
  DEFAULT_POLICY_DIR,
  DEFAULT_POLICY_VERSION,
  loadPolicyBundle,
} from "../../src/security/opa/policies.js";
import { EmbeddedRegoPolicyEngine, OpaHttpPolicyEngine } from "../../src/security/opa/engine.js";
import { createOpaAuthorizationProvider } from "../../src/security/opa/provider.js";
import { buildAuthorizationInput } from "../../src/security/opa/input.js";
import { TestAuditProvider } from "../helpers/testkit.js";

const log = createLogger("silent", false);
const bundle = loadPolicyBundle(DEFAULT_POLICY_DIR, DEFAULT_POLICY_VERSION);

function provider(audit?: TestAuditProvider) {
  return createOpaAuthorizationProvider({
    log,
    policySource: bundle.source,
    policyVersion: DEFAULT_POLICY_VERSION,
    ...(audit !== undefined ? { audit } : {}),
  });
}

describe("OPA policy engine + bundle", () => {
  it("reports the versioned policy bundle", () => {
    const engine = new EmbeddedRegoPolicyEngine({ policySource: bundle.source });
    expect(engine.policyVersion).toBe("1.0.0");
  });

  it("defaults to deny for anything not explicitly allowed", async () => {
    const p = provider();
    const d = await p.authorize("a2a:tasks/send", { kind: "a2a" });
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/policy|deny/i);
  });

  it("allows legitimate orchestrator -> child dispatch within the run grant", async () => {
    const p = provider();
    const base: AuthzResource = {
      kind: "a2a",
      workload: "orchestrator",
      agent: "recon",
      user: "user:alice",
      runId: "run-1",
      approvedTargets: ["host-1"],
      approvedActions: ["recon.run"],
      requestedAction: "recon.run",
      requestedTarget: "host-1",
      requestedRunId: "run-1",
    };
    expect((await p.authorize("a2a:tasks/send", base)).allowed).toBe(true);
    expect((await p.authorize("a2a:tasks/send", { ...base, requestedTarget: "evil.test" })).allowed).toBe(false);
    expect((await p.authorize("a2a:tasks/send", { ...base, workload: "recon" })).allowed).toBe(false);
  });

  it("allows API actions only when the user token carries the scope", async () => {
    const p = provider();
    const base: AuthzResource = { kind: "api", user: "user:alice" };
    expect((await p.authorize("runs:create", { ...base, scopes: ["runs:create"] })).allowed).toBe(true);
    expect((await p.authorize("runs:create", { ...base, scopes: [] })).allowed).toBe(false);
    expect(
      (await p.authorize("runs:read", { ...base, scopes: ["runs:read"], resourceOwner: "user:mallory" })).allowed,
    ).toBe(false);
  });

  it("enforces report run ownership and tenant isolation", async () => {
    const p = provider();
    const report: AuthzResource = {
      kind: "operation",
      workload: "orchestrator",
      agent: "report",
      user: "user:alice",
      runId: "run-1",
      requestedAction: "report.generate",
      requestedRunId: "run-1",
      resourceOwner: "user:alice",
    };
    expect((await p.authorize("report.generate", report)).allowed).toBe(true);
    expect((await p.authorize("report.generate", { ...report, resourceOwner: "user:bob" })).allowed).toBe(false);
    expect(
      (await p.authorize("report.generate", { ...report, tenantId: "t1", resourceTenantId: "t2" })).allowed,
    ).toBe(false);
  });

  it("fails closed when the OPA engine is unavailable", async () => {
    const p = createOpaAuthorizationProvider({ log, policyDir: "/definitely/not/a/real/dir", policyVersion: "1" });
    const d = await p.authorize("a2a:tasks/send", {
      kind: "a2a",
      workload: "orchestrator",
      agent: "recon",
      runId: "run-1",
      approvedTargets: ["host-1"],
      approvedActions: ["recon.run"],
      requestedAction: "recon.run",
      requestedTarget: "host-1",
    });
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/unavailable/i);
  });

  it("records allow and deny decisions on the audit log", async () => {
    const audit = new TestAuditProvider();
    const p = provider(audit);
    await p.authorize("runs:create", { kind: "api", user: "user:alice", scopes: ["runs:create"] });
    await p.authorize("runs:create", { kind: "api", user: "user:alice", scopes: [] });

    const decisions = audit.events.filter((e) => e.type === "authz.decision");
    expect(decisions).toHaveLength(2);
    expect(decisions.map((d) => d.data?.decision)).toEqual(["allow", "deny"]);
    expect(decisions[0]!.data?.policy).toBe("1.0.0");
    expect(decisions[0]!.data?.action).toBe("runs:create");
  });

  it("builds policy input from PEP attributes only (untrusted intent stays bounded)", () => {
    const input = buildAuthorizationInput(
      "recon.run",
      {
        kind: "operation",
        workload: "orchestrator",
        agent: "recon",
        user: "user:alice",
        approvedTargets: ["good.test"],
        requestedTarget: "evil.test",
      },
      { policyVersion: "1.0.0" },
    );
    expect(input.kind).toBe("operation");
    expect(input.attributes.approvedTargets).toEqual(["good.test"]);
    expect(input.attributes.requestedTarget).toBe("evil.test");
  });

  it("evaluates decisions through a remote OPA data API", async () => {
    const server = createServer((req, res) => {
      if (req.method === "POST" && req.url === "/v1/data/agentseclab/authz") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ result: { allow: true } }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as AddressInfo).port;
    try {
      const engine = new OpaHttpPolicyEngine({ opaUrl: `http://127.0.0.1:${port}` });
      const decision = await engine.evaluate(
        buildAuthorizationInput("a2a:initialize", { principal: "workload:orchestrator" }, { policyVersion: "remote" }),
      );
      expect(decision.allowed).toBe(true);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
