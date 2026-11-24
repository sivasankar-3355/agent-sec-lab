import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { createA2ARouter } from "../../src/a2a/server.js";
import { A2AClient } from "../../src/a2a/client.js";
import { OrchestratorHandler } from "../../src/agents/orchestrator/handler.js";
import { AgentClientsBroker } from "../../src/agents/orchestrator/broker.js";
import { BaseWorkerHandler } from "../../src/agents/base.js";
import { ReconExecutor, reconAcceptedKinds } from "../../src/agents/recon/handler.js";
import { KnowledgeExecutor, knowledgeAcceptedKinds } from "../../src/agents/knowledge/handler.js";
import { ReportExecutor, reportAcceptedKinds } from "../../src/agents/report/handler.js";
import { createLogger } from "../../src/core/logger.js";
import {
  FakeRepositories,
  FakeCoordinator,
  TestCryptoProvider,
  TestModelProvider,
  TestNetworkProvider,
  TestPolicyProvider,
  TestSandboxProvider,
  testSecurity,
} from "../helpers/testkit.js";
import type { Logger } from "pino";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";
import type { A2AHandler } from "../../src/a2a/handler.js";

const log = createLogger("silent", false);

function workerSecurity(): FailClosedSecurityProviders {
  return testSecurity(log, {
    policy: new TestPolicyProvider(),
    network: new TestNetworkProvider(),
    sandbox: new TestSandboxProvider(),
    model: new TestModelProvider(),
    crypto: new TestCryptoProvider(),
  });
}

const apps = {
  recon: workerSecurity(),
  knowledge: workerSecurity(),
  report: workerSecurity(),
  orchestrator: workerSecurity(),
};
const repos = new FakeRepositories();
const coordinator = new FakeCoordinator();

let orchestrator: OrchestratorHandler;
let orchestratorUrl: string;
const servers: Server[] = [];

async function boot(handler: A2AHandler, security: FailClosedSecurityProviders): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createA2ARouter(handler, { log, authn: security.authn, authz: security.authz, audit: security.audit }));
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  const port = typeof address === "string" ? Number.parseInt(address.split(":").pop() ?? "0", 10) : (address as AddressInfo).port;
  return `http://127.0.0.1:${port}`;
}

const workerCtx = (security: FailClosedSecurityProviders, logRef: Logger) => ({
  log: logRef,
  audit: security.audit,
  repos,
  security,
});

beforeAll(async () => {
  const reconUrl = await boot(
    new BaseWorkerHandler("recon", new ReconExecutor(), workerCtx(apps.recon, log), reconAcceptedKinds),
    apps.recon,
  );
  const knowledgeUrl = await boot(
    new BaseWorkerHandler("knowledge", new KnowledgeExecutor(), workerCtx(apps.knowledge, log), knowledgeAcceptedKinds),
    apps.knowledge,
  );
  const reportUrl = await boot(
    new BaseWorkerHandler("report", new ReportExecutor(), workerCtx(apps.report, log), reportAcceptedKinds),
    apps.report,
  );

  orchestrator = new OrchestratorHandler({
    log,
    audit: apps.orchestrator.audit,
    repos,
    coordinator,
    children: new AgentClientsBroker({
      recon: new A2AClient(reconUrl, { token: "test-token" }),
      knowledge: new A2AClient(knowledgeUrl, { token: "test-token" }),
      report: new A2AClient(reportUrl, { token: "test-token" }),
    }),
    options: { pollIntervalMs: 5, pollMaxAttempts: 20 },
  });
  orchestratorUrl = await boot(orchestrator, apps.orchestrator);
});

afterAll(async () => {
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe("M3 full pipeline e2e", () => {
  it("runs recon -> knowledge -> report to completion over real HTTP A2A", async () => {
    const orchClient = new A2AClient(orchestratorUrl, { token: "test-token" });
    const api = createApp({
      log,
      security: apps.orchestrator,
      stores: {},
      repos,
      orchestrator: orchClient,
    });

    const res = await request(api)
      .post("/api/v1/runs")
      .set("Authorization", "Bearer test-token")
      .send({ name: "pipeline", scope: { targets: ["host-1"] } });
    expect(res.status).toBe(202);
    const runId = res.body.run_id as string;

    await orchestrator.drain();

    const status = await request(api)
      .get(`/api/v1/runs/${runId}`)
      .set("Authorization", "Bearer test-token");
    expect(status.status).toBe(200);
    expect(status.body.state).toBe("COMPLETED");

    const tasks = await repos.tasks.listByRun(runId);
    expect(tasks.some((t) => t.kind === "recon.run" && t.status === "SUCCEEDED")).toBe(true);
    expect(tasks.some((t) => t.kind === "knowledge.search" && t.status === "SUCCEEDED")).toBe(true);
    expect(tasks.some((t) => t.kind === "report.generate" && t.status === "SUCCEEDED")).toBe(true);

    const findings = await repos.findings.listByRun(runId, {});
    expect(findings.length).toBe(1);
    expect(findings[0]!.agent).toBe("recon");

    const report = await repos.reports.getLatest(runId);
    expect(report).not.toBeNull();
    expect(report!.status).toBe("ready");
    expect(report!.signature?.length).toBeGreaterThan(0);
    expect(report!.content).toContain("# Reconnaissance Report");
  });
});