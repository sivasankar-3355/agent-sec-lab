import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/core/config.js";

describe("loadConfig", () => {
  it("applies safe defaults", () => {
    const config = loadConfig({});
    expect(config.NODE_ENV).toBe("development");
    expect(config.HTTP_HOST).toBe("127.0.0.1");
    expect(config.HTTP_PORT).toBe(3000);
    expect(config.MONGODB_DB).toBe("agentseclab");
  });

  it("reads provided values", () => {
    const config = loadConfig({ HTTP_PORT: "8080", LOG_LEVEL: "debug" });
    expect(config.HTTP_PORT).toBe(8080);
    expect(config.LOG_LEVEL).toBe("debug");
  });

  it("rejects invalid values", () => {
    expect(() => loadConfig({ HTTP_PORT: "not-a-number" })).toThrow(/invalid environment configuration/);
    expect(() => loadConfig({ LOG_LEVEL: "loud" })).toThrow(/invalid environment configuration/);
  });
});
