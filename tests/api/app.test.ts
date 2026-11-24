import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { loadConfig } from "../../src/core/config.js";
import { createLogger } from "../../src/core/logger.js";
import { createContainer } from "../../src/security/container.js";
import { FakeRepositories } from "../helpers/testkit.js";

const log = createLogger("silent", false);
const container = createContainer(loadConfig({ NODE_ENV: "test" }), log);

const app = createApp({
  log,
  security: container.security,
  stores: {},
  repos: new FakeRepositories(),
});

describe("api boundary", () => {
  it("healthz is open and ok", async () => {
    const res = await request(app).get("/healthz");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
  });

  it("readyz is not ready without stores", async () => {
    const res = await request(app).get("/readyz");
    expect(res.status).toBe(503);
    expect(res.body.ready).toBe(false);
  });

  it("rejects unauthenticated access to protected routes", async () => {
    const res = await request(app).get("/api/v1/me");
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("unauthorized");
    expect(typeof res.headers["x-request-id"]).toBe("string");
  });

  it("rejects requests with any token under fail-closed authn", async () => {
    const res = await request(app).get("/api/v1/me").set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x");
    expect(res.status).toBe(401);
  });

  it("404s unknown routes with consistent error shape", async () => {
    const res = await request(app).get("/nope");
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe("not_found");
  });
});
