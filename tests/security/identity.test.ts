import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { encodeJwt, b64url } from "../../src/security/jwt.js";
import { JwtTokenService, JwtVerifier } from "../../src/security/jwt-issuer.js";
import { makeTestIdentity } from "../helpers/testkit.js";

function b64urlDecode(input: string): Record<string, unknown> {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as Record<string, unknown>;
}

describe("Phase-0 JWT identity", () => {
  it("round-trips a run token with the full grant", async () => {
    const identity = makeTestIdentity();
    const token = await identity.issuer.mintRunToken({
      userId: "user:alice",
      tenantId: "tenant-1",
      runId: "0195-run-0001",
      targets: ["host-a"],
      actions: ["run.start", "recon.run"],
      correlationId: "0195-cid-0001",
      scopes: ["a2a:tasks/send"],
    });
    const verdict = await identity.verifier.verifyToken(token, { audience: "a2a:orchestrator" });
    expect(verdict.valid).toBe(true);
    const ctx = verdict.context;
    expect(ctx?.userId).toBe("user:alice");
    expect(ctx?.tenantId).toBe("tenant-1");
    expect(ctx?.runId).toBe("0195-run-0001");
    expect(ctx?.scopeTargets).toEqual(["host-a"]);
    expect(ctx?.permittedActions).toEqual(["run.start", "recon.run"]);
    expect(ctx?.correlationId).toBe("0195-cid-0001");
    expect(ctx?.nonce.length).toBeGreaterThan(0);
    expect(ctx?.caller).toBe("workload:gateway");
  });

  it("binds user context to the callsite and never trusts body fields", async () => {
    const identity = makeTestIdentity();
    const token = await identity.issuer.mintRunToken({
      userId: "user:alice",
      runId: "0195-run-0002",
      targets: ["host-a"],
      actions: ["recon.run"],
      correlationId: "cid",
    });
    const forged = token;
    const [header, payload] = forged.split(".");
    const claims = b64urlDecode(payload);
    claims.reg = { ...(claims.reg as Record<string, unknown>), targets: ["attacker.example"] };
    const tampered = `${header}.${b64url(JSON.stringify(claims))}.${forged.split(".")[2]!}`;
    const verdict = await identity.verifier.verifyToken(tampered, { audience: "a2a:orchestrator" });
    expect(verdict.valid).toBe(false);
  });

  it("rejects a token whose audience does not include the receiver", async () => {
    const identity = makeTestIdentity();
    const token = await identity.issuer.exchangeRunToken(
      await identity.issuer.mintRunToken({
        userId: "user:alice",
        runId: "r",
        targets: ["host-a"],
        actions: ["recon.run"],
        correlationId: "cid",
      }),
      { audience: "a2a:recon", actions: ["recon.run"], actor: "workload:orchestrator" },
    );
    expect((await identity.verifier.verifyToken(token, { audience: "a2a:recon" })).valid).toBe(true);
    expect((await identity.verifier.verifyToken(token, { audience: "a2a:knowledge" })).valid).toBe(false);
    expect((await identity.verifier.verifyToken(token, { audience: "a2a:report" })).valid).toBe(false);
  });

  it("narrows child tokens: fresh jti, per-hop audience, restricted actions, delegation chain", async () => {
    const identity = makeTestIdentity();
    const runToken = await identity.issuer.mintRunToken({
      userId: "user:alice",
      runId: "r",
      targets: ["host-a"],
      actions: ["run.start", "recon.run", "knowledge.search", "report.generate"],
      correlationId: "cid",
    });
    const child = await identity.issuer.exchangeRunToken(runToken, {
      audience: "a2a:recon",
      actions: ["recon.run"],
      actor: "workload:orchestrator",
    });
    const verdict = await identity.verifier.verifyToken(child, { audience: "a2a:recon" });
    expect(verdict.valid).toBe(true);
    expect(verdict.context?.caller).toBe("workload:orchestrator");
    expect(verdict.context?.userId).toBe("user:alice");
    expect(verdict.context?.permittedActions).toEqual(["recon.run"]);
    expect(verdict.context?.scopeTargets).toEqual(["host-a"]);
    // child token differs from the run token (fresh jti => replay of old child rejected)
    const [runPayload, childPayload] = [runToken, child].map((t) => b64urlDecode(t.split(".")[1]!));
    expect(childPayload.jti).not.toBe(runPayload.jti);
    expect(childPayload.prev).toBe(runPayload.jti);
  });

  it("rejects expired tokens and future-issued tokens", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const keyId = "exp-key";
    const verifier = new JwtVerifier({
      issuer: "agent-sec-lab-test",
      keyId,
      signingKeyPem: privateKey,
      publicKeys: new Map([[keyId, publicKey]]),
      workloadTtlSec: 300,
      runTtlSec: 1800,
      childTtlSec: 600,
    });
    const now = Math.floor(Date.now() / 1000);
    const expired = encodeJwt(
      { kind: "run", sub: "user:x", aud: ["a2a:recon"], iat: now - 90, exp: now - 30, jti: "x", iss: "agent-sec-lab-test", reg: { runId: "r", targets: [], actions: [], correlationId: "c" } },
      privateKey,
      keyId,
    );
    const future = encodeJwt(
      { kind: "run", sub: "user:x", aud: ["a2a:recon"], iat: now + 120, exp: now + 600, jti: "y", iss: "agent-sec-lab-test", reg: { runId: "r", targets: [], actions: [], correlationId: "c" } },
      privateKey,
      keyId,
    );
    expect((await verifier.verifyToken(expired, { audience: "a2a:recon" })).valid).toBe(false);
    expect((await verifier.verifyToken(future, { audience: "a2a:recon" })).valid).toBe(false);
  });

  it("rejects tokens signed by an unknown key id", async () => {
    const identity = makeTestIdentity();
    const token = await identity.issuer.mintRunToken({
      userId: "user",
      runId: "r",
      targets: ["a"],
      actions: ["recon.run"],
      correlationId: "c",
    });
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const other = new JwtTokenService({
      issuer: "agent-sec-lab-test",
      keyId: "other-key",
      signingKeyPem: privateKey,
      publicKeys: new Map(),
      workloadTtlSec: 300,
      runTtlSec: 1800,
      childTtlSec: 600,
    });
    const foreign = await other.mintRunToken({ userId: "user", runId: "r", targets: ["a"], actions: ["recon.run"], correlationId: "c" });
    expect((await identity.verifier.verifyToken(foreign, { audience: "a2a:orchestrator" })).valid).toBe(false);
    void token;
  });
});