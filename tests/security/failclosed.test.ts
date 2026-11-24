import { describe, expect, it } from "vitest";
import { createLogger } from "../../src/core/logger.js";
import { failClosedProviders } from "../../src/security/defaults.js";

describe("M4 fail-closed matrix", () => {
  const security = failClosedProviders(createLogger("silent", false));

  it("authorization denies by default", async () => {
    const decision = await security.authz.authorize("anything", {});
    expect(decision.allowed).toBe(false);
  });

  it("authentication rejects tokens by default", async () => {
    const verdict = await security.authn.verifyToken("some-token");
    expect(verdict.valid).toBe(false);
  });

  it("policy emits a violation by default", async () => {
    const violations = await security.policy.evaluate("target", "action", []);
    expect(violations.length).toBeGreaterThan(0);
  });

  it("network policy denies egress by default", async () => {
    const decision = await security.network.assertEgress("https://example.test");
    expect(decision.allowed).toBe(false);
  });

  it("sandbox is unavailable by default", async () => {
    await expect(security.sandbox.run({ name: "step", input: {} })).rejects.toThrow();
  });

  it("embedding is unavailable by default", async () => {
    await expect(security.embedding.embed(["text"])).rejects.toThrow();
  });

  it("model is unavailable by default", async () => {
    await expect(security.model.complete("prompt", {})).rejects.toThrow();
  });

  it("secrets are unavailable by default", async () => {
    await expect(security.secrets.get("worker_key")).rejects.toThrow();
  });

  it("crypto never verifies and cannot sign by default", async () => {
    const signature = { algorithm: "x", value: "y" };
    expect(await security.crypto.verify(Buffer.from("data"), signature, "report")).toBe(false);
    await expect(security.crypto.sign(Buffer.from("data"))).rejects.toThrow();
  });
});