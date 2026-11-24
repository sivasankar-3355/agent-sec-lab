import request from "supertest";
import { describe, expect, it } from "vitest";
import { createSTSApp } from "../../src/sts/app.js";
import { createLogger } from "../../src/core/logger.js";
import { encodeJwt } from "../../src/security/jwt.js";
import { FakeRepositories, TestSecretProvider, makeTestIdentity, testSecurity } from "../helpers/testkit.js";
import {
  A2A_SCOPES,
  INTERNAL_EXCHANGE_SCOPE,
  INTERNAL_MINT_SCOPE,
  RUN_ACTIONS,
} from "../../src/security/audience.js";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";

const log = createLogger("silent", false);
const identity = makeTestIdentity();

function stsApp(overrides: Partial<FailClosedSecurityProviders> = {}) {
  const security = testSecurity(log, { authn: identity.verifier, tokenIssuer: identity.issuer, ...overrides });
  const repos = new FakeRepositories();
  return { app: createSTSApp({ log, security, stores: {}, repos }), repos };
}

async function mintRunToken(runId: string) {
  return identity.issuer.mintRunToken({
    userId: "user:alice",
    runId,
    targets: ["good.test"],
    actions: [...RUN_ACTIONS],
    correlationId: "cid",
  });
}

function gatewayWorkload(scopes: readonly string[] = [INTERNAL_MINT_SCOPE]): Promise<string> {
  return identity.workloadToken("gateway", scopes);
}

async function createRun(repos: FakeRepositories, targets: string[] = ["good.test"], userId = "user:alice") {
  return repos.runs.create({ name: "r", scope: { targets }, ...(userId.length > 0 ? { userId } : {}) });
}

describe("STS token-mint (gateway -> run-bound workload token)", () => {
  it("mints a run token derived from the trusted run record", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos, ["good.test", "other.test"]);
    const workloadToken = await gatewayWorkload();

    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runId: run.runId, targets: ["other.test", "good.test"], actions: [...RUN_ACTIONS], correlationId: "cid-1" });
    expect(res.status).toBe(200);
    const token = res.body.token as string;
    const verdict = await identity.verifier.verifyToken(token, { audience: "a2a:orchestrator" });
    expect(verdict.valid).toBe(true);
    const ctx = verdict.context;
    expect(ctx?.userId).toBe("user:alice");
    expect(ctx?.runId).toBe(run.runId);
    expect(ctx?.caller).toBe("workload:gateway");
    expect(ctx?.scopeTargets).toEqual(["good.test", "other.test"]);
    expect(ctx?.permittedActions).toEqual([...RUN_ACTIONS]);
  });

  it("rejects a workload token without the token-mint scope", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const weak = await identity.workloadToken("gateway", ["a2a:tasks/send"]);
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${weak}`)
      .send({ runId: run.runId, targets: ["good.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(403);
  });

  it("rejects an invalid gateway workload identity (non-gateway caller)", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const orchestratorToken = await identity.workloadToken("orchestrator", [INTERNAL_MINT_SCOPE]);
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${orchestratorToken}`)
      .send({ runId: run.runId, targets: ["good.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(403);
  });

  it("rejects an unauthenticated mint request", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .send({ runId: run.runId, targets: ["good.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(401);
  });

  it("rejects targets that do not match the run's approved scope (no permission expansion)", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos, ["good.test"]);
    const workloadToken = await gatewayWorkload();
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runId: run.runId, targets: ["evil.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(403);
  });

  it("rejects actions beyond the allowed run grant", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const workloadToken = await gatewayWorkload();
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runId: run.runId, targets: ["good.test"], actions: ["sudo.run"], correlationId: "c" });
    expect(res.status).toBe(403);
  });

  it("rejects mint for an unknown run", async () => {
    const { app } = stsApp();
    const workloadToken = await gatewayWorkload();
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runId: "0195aabb-ccdd-eeff-0011-223344556677", targets: ["good.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(404);
  });

  it("rejects mint for a run that is not bound to an authenticated user", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos, ["good.test"], "");
    const workloadToken = await gatewayWorkload();
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runId: run.runId, targets: ["good.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(403);
  });

  it("rejects mint for a failed run", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    await repos.runs.setState(run.runId, "FAILED");
    const workloadToken = await gatewayWorkload();
    const res = await request(app)
      .post("/api/v1/internal/token-mint")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runId: run.runId, targets: ["good.test"], actions: ["recon.run"], correlationId: "c" });
    expect(res.status).toBe(403);
  });
});

describe("STS token-exchange (orchestrator delegation)", () => {
  it("issues a recon-scoped child token for a legit orchestrator", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const runToken = await mintRunToken(run.runId);
    const workloadToken = await identity.workloadToken("orchestrator", [INTERNAL_EXCHANGE_SCOPE, ...A2A_SCOPES]);

    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runToken, audience: "a2a:recon", actions: ["recon.run"] });
    expect(res.status).toBe(200);
    const child = res.body.token as string;
    const verdict = await identity.verifier.verifyToken(child, { audience: "a2a:recon" });
    expect(verdict.valid).toBe(true);
    expect(verdict.context?.userId).toBe("user:alice");
    expect(verdict.context?.caller).toBe("workload:orchestrator");
    expect(verdict.context?.permittedActions).toEqual(["recon.run"]);
    expect(verdict.context?.scopeTargets).toEqual(["good.test"]);
  });

  it("rejects a workload token without the exchange scope", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const runToken = await mintRunToken(run.runId);
    const weak = await identity.workloadToken("orchestrator", ["a2a:tasks/send"]);
    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${weak}`)
      .send({ runToken, audience: "a2a:recon", actions: ["recon.run"] });
    expect(res.status).toBe(403);
  });

  it("rejects a non-orchestrator workload presenting a run token", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const runToken = await mintRunToken(run.runId);
    const reportWorkload = await identity.workloadToken("report", [INTERNAL_EXCHANGE_SCOPE]);
    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${reportWorkload}`)
      .send({ runToken, audience: "a2a:recon", actions: ["recon.run"] });
    expect(res.status).toBe(403);
  });

  it("rejects actions beyond the audience's allowed set", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    const runToken = await mintRunToken(run.runId);
    const workloadToken = await identity.workloadToken("orchestrator", [INTERNAL_EXCHANGE_SCOPE]);
    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runToken, audience: "a2a:recon", actions: ["report.generate"] });
    expect(res.status).toBe(403);
  });

  it("rejects exchange for an unknown run", async () => {
    const { app } = stsApp();
    const runToken = await mintRunToken("0195aabb-ccdd-eeff-0011-223344556677");
    const workloadToken = await identity.workloadToken("orchestrator", [INTERNAL_EXCHANGE_SCOPE]);
    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runToken, audience: "a2a:recon", actions: ["recon.run"] });
    expect(res.status).toBe(404);
  });

  it("rejects exchange for a failed run", async () => {
    const { app, repos } = stsApp();
    const run = await createRun(repos);
    await repos.runs.setState(run.runId, "FAILED");
    const runToken = await mintRunToken(run.runId);
    const workloadToken = await identity.workloadToken("orchestrator", [INTERNAL_EXCHANGE_SCOPE]);
    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runToken, audience: "a2a:recon", actions: ["recon.run"] });
    expect(res.status).toBe(403);
  });

  it("rejects an expired run token", async () => {
    const { app } = stsApp();
    const now = Math.floor(Date.now() / 1000);
    const expired = encodeJwt(
      {
        kind: "run",
        sub: "user:alice",
        actor: "workload:gateway",
        aud: ["a2a:orchestrator"],
        reg: { runId: newId(), targets: ["good.test"], actions: ["recon.run"], correlationId: "c" },
        scopes: [...A2A_SCOPES],
        iss: "agent-sec-lab-test",
        iat: now - 120,
        exp: now - 60,
        jti: "expired-jti",
      },
      identity.privateKey,
      "test-key",
    );
    const workloadToken = await identity.workloadToken("orchestrator", [INTERNAL_EXCHANGE_SCOPE]);
    const res = await request(app)
      .post("/api/v1/internal/token-exchange")
      .set("Authorization", `Bearer ${workloadToken}`)
      .send({ runToken: expired, audience: "a2a:recon", actions: ["recon.run"] });
    expect(res.status).toBe(403);
  });
});

describe("STS token-issue (workload bootstrap)", () => {
  it("issues a workload token for the orchestrator with a valid bootstrap secret", async () => {
    const { app } = stsApp({ secrets: new TestSecretProvider({ WORKLOAD_BOOTSTRAP: "boot-secret-1" }) });
    const res = await request(app)
      .post("/api/v1/internal/token-issue")
      .set("x-bootstrap", "boot-secret-1")
      .send({ workload: "orchestrator", scopes: [INTERNAL_EXCHANGE_SCOPE, ...A2A_SCOPES] });
    expect(res.status).toBe(200);
    const token = res.body.token as string;
    const verdict = await identity.verifier.verifyToken(token);
    expect(verdict.valid).toBe(true);
    expect(verdict.principal).toBe("workload:orchestrator");
    expect(verdict.context?.caller).toBe("workload:orchestrator");
    expect(verdict.context?.scopes).toContain(INTERNAL_EXCHANGE_SCOPE);
  });

  it("rejects an invalid bootstrap secret", async () => {
    const { app } = stsApp({ secrets: new TestSecretProvider({ WORKLOAD_BOOTSTRAP: "boot-secret-1" }) });
    const res = await request(app)
      .post("/api/v1/internal/token-issue")
      .set("x-bootstrap", "wrong-secret")
      .send({ workload: "orchestrator", scopes: [] });
    expect(res.status).toBe(401);
  });

  it("fails closed when the bootstrap secret provider is not configured", async () => {
    const { app } = stsApp();
    const res = await request(app)
      .post("/api/v1/internal/token-issue")
      .set("x-bootstrap", "anything")
      .send({ workload: "orchestrator", scopes: [] });
    expect(res.status).toBe(500);
  });
});

function newId(): string {
  return "0195aabb-ccdd-eeff-0011-223344556677";
}
