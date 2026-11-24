import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createApp } from "../../src/api/app.js";
import { createA2ARouter } from "../../src/a2a/server.js";
import { BaseWorkerHandler } from "../../src/agents/base.js";
import { ReconExecutor, reconAcceptedKinds } from "../../src/agents/recon/handler.js";
import { createLogger } from "../../src/core/logger.js";
import { loadConfig } from "../../src/core/config.js";
import { buildSecurityProviders } from "../../src/security/build.js";
import { decodeJwt } from "../../src/security/jwt.js";
import { a2aAudience } from "../../src/security/audience.js";
import { FakeRepositories, makeTestIdentity, testSecurity } from "../helpers/testkit.js";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";

const log = createLogger("silent", false);
const identity = makeTestIdentity();

function gatewayApp(overrides: Partial<FailClosedSecurityProviders> = {}) {
  const security = testSecurity(log, { userAuth: identity.userAuth, ...overrides });
  const repos = new FakeRepositories();
  return { app: createApp({ log, security, stores: {}, repos }), repos };
}

async function registeredToken(email = "alice@example.test"): Promise<string> {
  const { app } = gatewayApp();
  await request(app)
    .post("/api/v1/auth/register")
    .send({ email, password: "correct-horse-battery" });
  const login = await request(app).post("/api/v1/auth/login").send({ email, password: "correct-horse-battery" });
  return login.body.token as string;
}

describe("user authentication (HS256, gateway)", () => {
  it("registers a user and logs in with a valid HS256 user JWT", async () => {
    const { app, repos } = gatewayApp();
    const registered = await request(app)
      .post("/api/v1/auth/register")
      .send({ email: "Alice@Example.TEST", password: "correct-horse-battery" });
    expect(registered.status).toBe(201);
    expect(registered.body.user_id).toMatch(/^user:/);
    expect(repos.users.users).toHaveLength(1);
    expect(repos.users.users[0]!.email).toBe("alice@example.test");
    expect(repos.users.users[0]!.passwordHash).not.toBe("correct-horse-battery");

    const login = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "alice@example.test", password: "correct-horse-battery" });
    expect(login.status).toBe(200);
    const token = login.body.token as string;

    const decoded = decodeJwt(token);
    if (!("claims" in decoded)) {
      expect.fail("expected a valid JWT payload");
      return;
    }
    const header = decodeHeader(token);
    expect(header.alg).toBe("HS256");
    const claims = decoded.claims as Record<string, unknown>;
    expect(claims.iss).toBe("agent-sec-lab-user");
    expect(claims.aud).toEqual(["api-gateway"]);
    expect(String(claims.sub)).toMatch(/^user:/);
    expect(typeof claims.exp).toBe("number");
    expect(typeof claims.iat).toBe("number");
    expect((claims.exp as number) - (claims.iat as number)).toBeGreaterThan(0);
  });

  it("mints tokens whose subject matches /me and scopes are preserved", async () => {
    const { app } = gatewayApp();
    const token = await registeredToken();
    const res = await request(app).get("/api/v1/me").set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.userId).toMatch(/^user:/);
    expect(res.body.scopes).toContain("runs:create");
    expect(res.body.principal).toBe(res.body.userId);
  });

  it("rejects login with invalid credentials", async () => {
    const { app } = gatewayApp();
    await request(app)
      .post("/api/v1/auth/register")
      .send({ email: "bob@example.test", password: "correct-horse-battery" });
    const wrongPassword = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "bob@example.test", password: "not-the-password" });
    expect(wrongPassword.status).toBe(401);
    const unknownEmail = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "nobody@example.test", password: "anything" });
    expect(unknownEmail.status).toBe(401);
  });

  it("rejects an invalid user JWT", async () => {
    const { app } = gatewayApp();
    const garbage = await request(app).get("/api/v1/me").set("Authorization", "Bearer not.a.jwt");
    expect(garbage.status).toBe(401);
    const missing = await request(app).get("/api/v1/me");
    expect(missing.status).toBe(401);
  });

  it("register is idempotent-rejecting and password rules are enforced", async () => {
    const { app } = gatewayApp();
    const body = { email: "carol@example.test", password: "correct-horse-battery" };
    await request(app).post("/api/v1/auth/register").send(body);
    const dup = await request(app).post("/api/v1/auth/register").send(body);
    expect(dup.status).toBe(409);
    const weak = await request(app)
      .post("/api/v1/auth/register")
      .send({ email: "dave@example.test", password: "short" });
    expect(weak.status).toBe(422);
  });
});

describe("cross-service token substitution", () => {
  function reconA2A(): express.Application {
    const security = testSecurity(log, { authn: identity.verifier });
    const app = express();
    app.use(express.json());
    app.use(
      createA2ARouter(
        new BaseWorkerHandler("recon", new ReconExecutor(), {
          log,
          audit: security.audit,
          repos: new FakeRepositories(),
          security,
        }, reconAcceptedKinds),
        { log, authn: identity.verifier, authz: security.authz, audit: security.audit, agent: "recon", audience: a2aAudience("recon") },
      ),
    );
    return app;
  }

  it("rejects a user JWT presented as a workload token (agent A2A)", async () => {
    const app = reconA2A();
    const userToken = await identity.userToken();
    const res = await request(app)
      .post("/a2a")
      .set("Authorization", `Bearer ${userToken}`)
      .send({ jsonrpc: "2.0", id: "x", method: "tasks/get", params: { id: "some-task" } });
    expect(res.status).toBe(401);
  });

  it("rejects a workload JWT presented as a user token (gateway API)", async () => {
    const { app } = gatewayApp();
    const runToken = await identity.issuer.mintRunToken({
      userId: "user:alice",
      runId: "0195aabb-0000-7000-8000-000000000000",
      targets: ["host-a"],
      actions: ["recon.run"],
      correlationId: "c",
    });
    const res = await request(app).get("/api/v1/me").set("Authorization", `Bearer ${runToken}`);
    expect(res.status).toBe(401);
  });
});

describe("key separation", () => {
  it("the gateway build can verify users but cannot sign workload tokens", async () => {
    const { publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const config = loadConfig({
      NODE_ENV: "test",
      USER_JWT_SECRET: "user-only-secret",
      STS_PUBLIC_KEYS: JSON.stringify({ "sts": publicKey }),
      STS_PUBLIC_KEY: publicKey,
    });
    const security = buildSecurityProviders(config, log);
    expect(security.userAuth).toBeDefined();
    expect(security.tokenIssuer).toBeUndefined();
    expect(security.authn).toBeDefined();
    await expect(security.userAuth!.mintUserToken("user:x", [])).resolves.toMatch(/\./);
    // The gateway verifier must reject tokens signed with a workload key.
    const workload = await identity.issuer.mintWorkloadToken("orchestrator", []);
    // userAuth is a verifier-only (+user mint) provider: it cannot produce a
    // workload token, and its verifier never accepts an asymmetric token.
    expect((await security.userAuth!.verifyToken(workload)).valid).toBe(false);
  });

  it("the STS build holds the issuer but never user auth", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const config = loadConfig({
      NODE_ENV: "test",
      STS_PRIVATE_KEY: privateKey,
      STS_PUBLIC_KEY: publicKey,
    });
    const security = buildSecurityProviders(config, log);
    expect(security.tokenIssuer).toBeDefined();
    expect(security.userAuth).toBeUndefined();
    const token = await security.tokenIssuer!.mintWorkloadToken("orchestrator", []);
    const verdict = await security.authn.verifyToken(token);
    expect(verdict.valid).toBe(true);
    // HS256 user tokens are not accepted by the workload verifier (allowlist).
    const userToken = await identity.userAuth.mintUserToken("user:alice", []);
    expect((await security.authn.verifyToken(userToken)).valid).toBe(false);
  });

  it("fails closed entirely when no key material is configured", async () => {
    const security = buildSecurityProviders(loadConfig({ NODE_ENV: "test" }), log);
    expect(security.userAuth).toBeUndefined();
    expect(security.tokenIssuer).toBeUndefined();
    expect((await security.authn.verifyToken("anything")).valid).toBe(false);
  });
});

function decodeHeader(token: string): { alg: string } {
  const decoded = decodeJwt(token);
  return "claims" in decoded ? decoded.header : { alg: "unknown" };
}
