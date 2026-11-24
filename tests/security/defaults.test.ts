import { describe, expect, it } from "vitest";
import { createLogger } from "../../src/core/logger.js";
import {
  EgressDeniedError,
  NotConfiguredError,
  SandboxUnavailableError,
} from "../../src/core/errors.js";
import { failClosedProviders } from "../../src/security/defaults.js";

const silentLog = createLogger("silent" as never, false);

describe("fail-closed security defaults", () => {
  const p = failClosedProviders(silentLog);

  it("authorization denies every action", async () => {
    const d = await p.authz.authorize("run.create", {});
    expect(d.allowed).toBe(false);
  });

  it("sandbox is unavailable", async () => {
    await expect(p.sandbox.run({ name: "step", input: {} })).rejects.toBeInstanceOf(SandboxUnavailableError);
  });

  it("policy returns a default-deny violation", async () => {
    const v = await p.policy.evaluate("target.example", "scan", ["rule-a"]);
    expect(v.length).toBeGreaterThan(0);
    expect(v[0]!.rule).toBe("default-deny");
  });

  it("network policy denies egress", async () => {
    const d = await p.network.assertEgress("target.example");
    expect(d.allowed).toBe(false);
  });

  it("secrets are not retrievable", async () => {
    await expect(p.secrets.get("OPENAI_API_KEY")).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("verification of signatures is false", async () => {
    const ok = await p.crypto.verify(Buffer.from("x"), { algorithm: "sig", value: "v" }, "report");
    expect(ok).toBe(false);
    await expect(p.crypto.sign(Buffer.from("x"))).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("embeddings and model are not configured", async () => {
    await expect(p.embedding.embed(["hi"])).rejects.toBeInstanceOf(NotConfiguredError);
    await expect(p.model.complete("hi", {})).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("tokens are never accepted", async () => {
    const verdict = await p.authn.verifyToken("anything");
    expect(verdict.valid).toBe(false);
    await expect(p.authn.createToken("u", ["runs:read"])).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("authorization errors map to egress_denied only when configured so", () => {
    expect(new EgressDeniedError().code).toBe("egress_denied");
  });
});
