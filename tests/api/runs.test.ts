import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { createLogger } from "../../src/core/logger.js";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";
import { DenyAllAuthorizationProvider, FakeRepositories, testSecurity } from "../helpers/testkit.js";

const log = createLogger("silent", false);
const bearer = "Bearer test-token";

function makeApp(securityOverrides?: Partial<FailClosedSecurityProviders>) {
  const security = testSecurity(log, securityOverrides);
  const repos = new FakeRepositories();
  return { app: createApp({ log, security, stores: {}, repos }), repos };
}

describe("runs api", () => {
  it("creates a run and reports its status", async () => {
    const { app, repos } = makeApp();

    const create = await request(app)
      .post("/api/v1/runs")
      .set("Authorization", bearer)
      .send({ name: "initial recon", scope: { targets: ["10.0.0.5"] } });

    expect(create.status).toBe(202);
    expect(typeof create.body.run_id).toBe("string");
    expect(create.body.state).toBe("CREATED");

    const status = await request(app).get(`/api/v1/runs/${create.body.run_id}`).set("Authorization", bearer);
    expect(status.status).toBe(200);
    expect(status.body.state).toBe("CREATED");
    expect(status.body.timeline.length).toBe(1);
    expect(status.body.task_summary).toMatchObject({ total: 0, succeeded: 0 });
    expect(repos.runs.created.length).toBe(1);
  });

  it("rejects invalid run bodies", async () => {
    const { app } = makeApp();
    const res = await request(app)
      .post("/api/v1/runs")
      .set("Authorization", bearer)
      .send({ name: "" });
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe("validation_error");
  });

  it("returns 404 for unknown runs", async () => {
    const { app } = makeApp();
    const res = await request(app).get("/api/v1/runs/00000000-0000-7000-8000-000000000000").set("Authorization", bearer);
    expect(res.status).toBe(404);
  });

  it("returns empty findings and 404 report for a fresh run", async () => {
    const { app } = makeApp();
    const create = await request(app).post("/api/v1/runs").set("Authorization", bearer).send({
      name: "r",
      scope: { targets: ["example.test"] },
    });

    const findings = await request(app).get(`/api/v1/runs/${create.body.run_id}/findings`).set("Authorization", bearer);
    expect(findings.status).toBe(200);
    expect(findings.body.findings).toEqual([]);

    const report = await request(app).get(`/api/v1/runs/${create.body.run_id}/report`).set("Authorization", bearer);
    expect(report.status).toBe(404);
  });

  it("denies run creation when authorization is denied", async () => {
    const { app } = makeApp({ authz: new DenyAllAuthorizationProvider() });
    const res = await request(app)
      .post("/api/v1/runs")
      .set("Authorization", bearer)
      .send({ name: "nope", scope: { targets: ["x.test"] } });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("forbidden");
  });
});