import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/core/config.js";

describe("loadConfig", () => {
  it("applies safe defaults", () => {
    const config = loadConfig({});
    expect(config.NODE_ENV).toBe("development");
    expect(config.HTTP_HOST).toBe("127.0.0.1");
    expect(config.HTTP_PORT).toBe(3000);
    expect(config.MONGODB_DB).toBe("agentseclab");
    expect(config.A2A_CALL_TIMEOUT_MS).toBe(5_000);
    expect(config.AGENT_TASK_TIMEOUT_MS).toBe(120_000);
    expect(config.CIRCUIT_FAILURE_THRESHOLD).toBe(3);
    expect(config.CIRCUIT_HALF_OPEN_MAX_CALLS).toBe(1);
    expect(config.MEMORY_TIMEOUT_MS).toBe(30_000);
  });

  it("reads provided values", () => {
    const config = loadConfig({ HTTP_PORT: "8080", LOG_LEVEL: "debug" });
    expect(config.HTTP_PORT).toBe(8080);
    expect(config.LOG_LEVEL).toBe("debug");
  });

  it("rejects invalid values", () => {
    expect(() => loadConfig({ HTTP_PORT: "not-a-number" })).toThrow(/invalid environment configuration/);
    expect(() => loadConfig({ LOG_LEVEL: "loud" })).toThrow(/invalid environment configuration/);
    expect(() => loadConfig({ CIRCUIT_FAILURE_THRESHOLD: "0" })).toThrow(/invalid environment configuration/);
  });
});
