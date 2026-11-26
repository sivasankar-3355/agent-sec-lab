import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import type { Application } from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { createSTSApp } from "../../src/sts/app.js";
import { createA2ARouter } from "../../src/a2a/server.js";
import { OrchestratorHandler } from "../../src/agents/orchestrator/handler.js";
import { AgentClientsBroker, type TokenExchanger } from "../../src/agents/orchestrator/broker.js";
import { BaseWorkerHandler } from "../../src/agents/base.js";
import { ReconExecutor, reconAcceptedKinds } from "../../src/agents/recon/handler.js";
import { KnowledgeExecutor, knowledgeAcceptedKinds } from "../../src/agents/knowledge/handler.js";
import { ReportExecutor, reportAcceptedKinds } from "../../src/agents/report/handler.js";
import { createLogger } from "../../src/core/logger.js";
import { STSClient } from "../../src/a2a/sts.js";
import {
  FakeRepositories,
  FakeCoordinator,
  FakeMemoryStores,
  makeMemoryService,
  makeTestIdentity,
  makeToolBroker,
  TestSecretProvider,
  opaSecurity,
  testSecurity,
} from "../helpers/testkit.js";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";
import type { A2AHandler } from "../../src/a2a/handler.js";
import {
  A2A_SCOPES,
  INTERNAL_EXCHANGE_SCOPE,
  INTERNAL_MINT_SCOPE,
  a2aAudience,
} from "../../src/security/audience.js";

const log = createLogger("silent", false);
const identity = makeTestIdentity();
const BOOTSTRAP = "boot-secret-e2e";

function gatewaySecurity(): FailClosedSecurityProviders {
  // User auth (HS256) + real OPA authorization for the gateway API.
  return opaSecurity(log, { authn: identity.verifier, overrides: { userAuth: identity.userAuth } });
}

function workerSecurity(): FailClosedSecurityProviders {
  // Real OPA authorization; every other control is a test double.
  return opaSecurity(log, { authn: identity.verifier });
}

const apps = {
  recon: workerSecurity(),
  knowledge: workerSecurity(),
  report: workerSecurity(),
  orchestrator: workerSecurity(),
};
const repos = new FakeRepositories();
const memoryStores = new FakeMemoryStores();
const coordinator = new FakeCoordinator();

let orchestrator: OrchestratorHandler;
let orchestratorUrl: string;
let stsUrl: string;
const servers: Server[] = [];
const exchanged: Array<{ runToken: string; audience: string; actions: string[] }> = [];
let stsExchange: TokenExchanger;

async function bootServer(app: Application): Promise<string> {
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  const port = typeof address === "string" ? Number.parseInt(address.split(":").pop() ?? "0", 10) : (address as AddressInfo).port;
  return `http://127.0.0.1:${port}`;
}

async function bootAgent(handler: A2AHandler, security: FailClosedSecurityProviders, agent: string): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(
    createA2ARouter(handler, {
      log,
      authn: security.authn,
      authz: security.authz,
      audit: security.audit,
      agent,
      audience: a2aAudience(agent),
    }),
  );
  return bootServer(app);
}

const workerCtx = (security: FailClosedSecurityProviders) => ({
  log,
  audit: security.audit,
  repos,
  security,
  memory: makeMemoryService(security, repos.runs, memoryStores),
  tools: makeToolBroker(security, repos),
});

beforeAll(async () => {
  const reconUrl = await bootAgent(
    new BaseWorkerHandler("recon", new ReconExecutor(), workerCtx(apps.recon), reconAcceptedKinds),
    apps.recon,
    "recon",
  );
  const knowledgeUrl = await bootAgent(
    new BaseWorkerHandler("knowledge", new KnowledgeExecutor(), workerCtx(apps.knowledge), knowledgeAcceptedKinds),
    apps.knowledge,
    "knowledge",
  );
  const reportUrl = await bootAgent(
    new BaseWorkerHandler("report", new ReportExecutor(), workerCtx(apps.report), reportAcceptedKinds),
    apps.report,
    "report",
  );

  // Dedicated STS service, sharing the same (real) repositories: the run
  // record created by the gateway is the trusted source for token minting.
  const stsSecurity = testSecurity(log, {
    authn: identity.verifier,
    tokenIssuer: identity.issuer,
    secrets: new TestSecretProvider({ WORKLOAD_BOOTSTRAP: BOOTSTRAP }),
  });
  stsUrl = await bootServer(createSTSApp({ log, security: stsSecurity, stores: {}, repos }));

  const orchestratorClient = new STSClient(stsUrl, { bootstrapSecret: BOOTSTRAP });
  const orchestratorWorkload = await orchestratorClient.issue("orchestrator", [
    INTERNAL_EXCHANGE_SCOPE,
    ...A2A_SCOPES,
  ]);
  const stsExchangeClient = new STSClient(stsUrl, { workloadToken: orchestratorWorkload });
  stsExchange = {
    async exchange(runToken, req) {
      exchanged.push({ runToken, audience: req.audience, actions: [...req.actions] });
      return stsExchangeClient.exchange(runToken, req);
    },
  };

  orchestrator = new OrchestratorHandler({
    log,
    audit: apps.orchestrator.audit,
    authz: apps.orchestrator.authz,
    repos,
    coordinator,
    children: new AgentClientsBroker({
      recon: { base: reconUrl },
      knowledge: { base: knowledgeUrl },
      report: { base: reportUrl },
    }),
    exchange: stsExchange,
    options: { pollIntervalMs: 5, pollMaxAttempts: 20 },
  });
  orchestratorUrl = await bootAgent(orchestrator, apps.orchestrator, "orchestrator");
});

afterAll(async () => {
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe("Phase-1 delegated identity e2e (user -> gateway -> STS -> agents)", () => {
  it("runs recon -> knowledge -> report with STS-minted per-hop JWTs over real HTTP", async () => {
    const userToken = await identity.userToken();

    // The gateway authenticates to the STS (bootstrap) purely to mint run tokens.
    const bootstrap = new STSClient(stsUrl, { bootstrapSecret: BOOTSTRAP });
    const gatewayWorkload = await bootstrap.issue("gateway", [INTERNAL_MINT_SCOPE]);
    const stsMinter = new STSClient(stsUrl, { workloadToken: gatewayWorkload });

    const api = createApp({
      log,
      security: gatewaySecurity(),
      stores: {},
      repos,
      orchestrator: { base: orchestratorUrl },
      sts: stsMinter,
    });

    const res = await request(api)
      .post("/api/v1/runs")
      .set("Authorization", `Bearer ${userToken}`)
      .send({ name: "delegated pipeline", scope: { targets: ["host-1"] } });
    expect(res.status).toBe(202);
    const runId = res.body.run_id as string;
    expect(repos.runs.created[0]!.userId).toBe("user:alice");

    await orchestrator.drain();

    const status = await request(api)
      .get(`/api/v1/runs/${runId}`)
      .set("Authorization", `Bearer ${userToken}`);
    expect(status.status).toBe(200);
    expect(status.body.state).toBe("COMPLETED");

    const tasks = await repos.tasks.listByRun(runId);
    expect(tasks.some((t) => t.kind === "run.start" && t.status === "SUCCEEDED")).toBe(true);
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

  it("delegates with per-hop audience narrowing and action narrowing", async () => {
    const audiences = exchanged.map((e) => e.audience).sort();
    expect(audiences).toEqual(["a2a:knowledge", "a2a:recon", "a2a:report"]);
    const byAudience = new Map(exchanged.map((e) => [e.audience, e.actions]));
    expect(byAudience.get("a2a:recon")).toEqual(["recon.run"]);
    expect(byAudience.get("a2a:knowledge")).toEqual(["knowledge.search"]);
    expect(byAudience.get("a2a:report")).toEqual(["report.generate"]);
  });
});
