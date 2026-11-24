import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { createA2ARouter } from "../../src/a2a/server.js";
import { A2AClient } from "../../src/a2a/client.js";
import { OrchestratorHandler } from "../../src/agents/orchestrator/handler.js";
import { createLogger } from "../../src/core/logger.js";
import { newId } from "../../src/core/ids.js";
import {
  DenyAllAuthorizationProvider,
  FakeChildBroker,
  FakeCoordinator,
  FakeRepositories,
  testSecurity,
} from "../helpers/testkit.js";

const log = createLogger("silent", false);
const security = testSecurity(log);

const sharedRepos = new FakeRepositories();
const sharedCoordinator = new FakeCoordinator();
const sharedBroker = new FakeChildBroker({
  "recon.run": { status: "completed", result: { findings: ["f-1"] } },
  "knowledge.search": { status: "completed", result: { hits: [] } },
  "report.generate": { status: "completed", result: { reportId: "r-1" } },
});

let server: Server;
let baseUrl: string;
let orchestrator: OrchestratorHandler;

beforeAll(async () => {
  orchestrator = new OrchestratorHandler({
    log,
    audit: security.audit,
    repos: sharedRepos,
    coordinator: sharedCoordinator,
    children: sharedBroker,
    options: { pollIntervalMs: 5, pollMaxAttempts: 5 },
  });
  const app = express();
  app.use(express.json());
  app.use(createA2ARouter(orchestrator, { log, authn: security.authn, authz: security.authz, audit: security.audit }));
  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  const port = typeof address === "string" ? Number.parseInt(address.split(":").pop() ?? "0", 10) : (address as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});

describe("orchestrator A2A server", () => {
  it("rejects unauthenticated JSON-RPC calls", async () => {
    const app = express();
    const handler = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos: new FakeRepositories(),
      coordinator: new FakeCoordinator(),
      children: new FakeChildBroker(),
    });
    app.use(express.json());
    app.use(createA2ARouter(handler, { log, authn: security.authn, authz: security.authz, audit: security.audit }));

    const res = await request(app).post("/a2a").send({
      jsonrpc: "2.0",
      id: "x-1",
      method: "tasks/get",
      params: { id: newId() },
    });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe(-32001);
  });

  it("denies calls under deny-by-default authorization", async () => {
    const denySecurity = testSecurity(log, { authz: new DenyAllAuthorizationProvider() });
    const app = express();
    const handler = new OrchestratorHandler({
      log,
      audit: denySecurity.audit,
      repos: new FakeRepositories(),
      coordinator: new FakeCoordinator(),
      children: new FakeChildBroker(),
    });
    app.use(express.json());
    app.use(createA2ARouter(handler, { log, authn: denySecurity.authn, authz: denySecurity.authz, audit: denySecurity.audit }));

    const res = await request(app)
      .post("/a2a")
      .set("Authorization", "Bearer test-token")
      .send({ jsonrpc: "2.0", id: "x-2", method: "initialize", params: {} });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe(-32003);
  });

  it("serves the agent card", async () => {
    const res = await request(baseUrl).get("/agent-card");
    expect(res.status).toBe(200);
    expect(res.body.agentId).toBe("orchestrator");
  });
});

describe("orchestrator e2e skeleton", () => {
  it("drives a run to completion over HTTP A2A", async () => {
    const client = new A2AClient(baseUrl, { token: "test-token" });
    const api = createApp({
      log,
      security,
      stores: {},
      repos: sharedRepos,
      orchestrator: client,
    });

    const res = await request(api)
      .post("/api/v1/runs")
      .set("Authorization", "Bearer test-token")
      .send({ name: "demo", scope: { targets: ["host-a"] }, config: { recon: {} } });
    expect(res.status).toBe(202);
    const runId = res.body.run_id as string;

    await orchestrator.drain();

    const status = await request(api)
      .get(`/api/v1/runs/${runId}`)
      .set("Authorization", "Bearer test-token");
    expect(status.status).toBe(200);
    expect(status.body.state).toBe("COMPLETED");

    const tasks = await sharedRepos.tasks.listByRun(runId);
    expect(tasks.some((t) => t.kind === "recon.run" && t.status === "SUCCEEDED")).toBe(true);
    expect(tasks.some((t) => t.kind === "knowledge.search" && t.status === "SUCCEEDED")).toBe(true);
    expect(tasks.some((t) => t.kind === "report.generate" && t.status === "SUCCEEDED")).toBe(true);
    expect(tasks.some((t) => t.kind === "run.start" && t.status === "SUCCEEDED")).toBe(true);
  });

  it("marks the run failed when a child task fails", async () => {
    const repos = new FakeRepositories();
    const coordinator = new FakeCoordinator();
    const broker = new FakeChildBroker({
      "recon.run": { status: "failed", error: "recon blew up" },
    });
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator,
      children: broker,
      options: { pollIntervalMs: 5, pollMaxAttempts: 5 },
    });

    const run = await repos.runs.create({ name: "fail", scope: { targets: ["host-b"] } });
    const sent = await orchestrator.taskSend({
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-b"] } },
    });
    expect(["submitted", "working"]).toContain(sent.task.status);
    await orchestrator.drain();

    const after = await repos.runs.get(run.runId);
    expect(after?.state).toBe("FAILED");
    const root = await repos.tasks.get(sent.task.taskId);
    expect(root?.status).toBe("FAILED");
    expect(root?.error).toContain("recon blew up");
  });

  it("keeps a run CREATED when no orchestrator link is wired", async () => {
    const repos = new FakeRepositories();
    const api = createApp({ log, security, stores: {}, repos });

    const res = await request(api)
      .post("/api/v1/runs")
      .set("Authorization", "Bearer test-token")
      .send({ name: "unwired", scope: { targets: ["host-c"] } });
    expect(res.status).toBe(202);
    expect(res.body.state).toBe("CREATED");

    const run = await repos.runs.get(res.body.run_id as string);
    expect(run?.state).toBe("CREATED");
  });

  it("cancels a run on host-initiated task cancel", async () => {
    const repos = new FakeRepositories();
    const coordinator = new FakeCoordinator();
    const broker = new FakeChildBroker({ "recon.run": { status: "working" } });
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator,
      children: broker,
      options: { pollIntervalMs: 10, pollMaxAttempts: 200 },
    });

    const run = await repos.runs.create({ name: "cancel", scope: { targets: ["host-d"] } });
    const taskId = newId();
    const sent = await orchestrator.taskSend({
      taskId,
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-d"] } },
    });
    expect(["submitted", "working"]).toContain(sent.task.status);

    const cancelled = await orchestrator.taskCancel(taskId);
    expect(cancelled.task.status).toBe("canceled");
    await orchestrator.drain();

    const after = await repos.runs.get(run.runId);
    expect(after?.state).toBe("CANCELLED");
    const root = await repos.tasks.get(taskId);
    expect(root?.status).toBe("CANCELLED");
  });

  it("returns a not-found error for an unknown task", async () => {
    const repos = new FakeRepositories();
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: new FakeChildBroker(),
    });
    await expect(
      orchestrator.taskGet(newId()),
    ).rejects.toMatchObject({ code: "not_found" });
  });
});