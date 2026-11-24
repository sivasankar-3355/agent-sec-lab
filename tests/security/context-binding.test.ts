import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createA2ARouter } from "../../src/a2a/server.js";
import { BaseWorkerHandler } from "../../src/agents/base.js";
import { ReconExecutor, reconAcceptedKinds } from "../../src/agents/recon/handler.js";
import { OrchestratorHandler } from "../../src/agents/orchestrator/handler.js";
import { createLogger } from "../../src/core/logger.js";
import { newId } from "../../src/core/ids.js";
import { b64url } from "../../src/security/jwt.js";
import {
  FakeChildBroker,
  FakeCoordinator,
  FakeRepositories,
  makeTestIdentity,
  TestNetworkProvider,
  TestPolicyProvider,
  TestSandboxProvider,
  testSecurity,
} from "../helpers/testkit.js";
import { a2aAudience } from "../../src/security/audience.js";
import type { CallContext } from "../../src/a2a/handler.js";

const log = createLogger("silent", false);
const identity = makeTestIdentity();

let recon: BaseWorkerHandler;
let baseUrl: string;
const servers: Server[] = [];

function withAuthn(verifier: typeof identity.verifier) {
  return testSecurity(log, {
    authn: verifier,
    policy: new TestPolicyProvider(),
    network: new TestNetworkProvider(),
    sandbox: new TestSandboxProvider(),
  });
}

async function runTokenFor(targets: string[], actions: string[]): Promise<string> {
  const run = await identity.issuer.mintRunToken({
    userId: "user:alice",
    runId: "0195aabb-0000-7000-8000-000000000000",
    targets,
    actions: ["run.start", ...actions],
    correlationId: "0195-cid-a",
    scopes: ["a2a:tasks/send", "a2a:tasks/get", "a2a:tasks/cancel"],
  });
  return identity.issuer.exchangeRunToken(run, {
    audience: "a2a:recon",
    actions,
    actor: "workload:orchestrator",
  });
}

beforeAll(async () => {
  const security = withAuthn(identity.verifier);
  recon = new BaseWorkerHandler(
    "recon",
    new ReconExecutor(),
    { log, audit: security.audit, repos: new FakeRepositories(), security },
    reconAcceptedKinds,
  );
  const app = express();
  app.use(express.json());
  app.use(
    createA2ARouter(recon, {
      log,
      authn: security.authn,
      authz: security.authz,
      audit: security.audit,
      agent: "recon",
      audience: a2aAudience("recon"),
    }),
  );
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  const port = typeof address === "string" ? Number.parseInt(address.split(":").pop() ?? "0", 10) : (address as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function taskSend(token: string, task: Record<string, unknown>) {
  return request(baseUrl).post("/a2a").set("Authorization", `Bearer ${token}`).send({
    jsonrpc: "2.0",
    id: newId(),
    method: "tasks/send",
    params: { task },
  });
}

async function sentTask(token: string, target: string, runId = "0195aabb-0000-7000-8000-000000000000"): Promise<{ taskId: string }> {
  const res = await taskSend(token, {
    taskId: newId(),
    runId,
    kind: "recon.run",
    input: { target },
  });
  expect(res.status).toBe(200);
  return { taskId: res.body.result.task.taskId as string };
}

describe("Phase-0 workload authorization binding", () => {
  it("accepts a recon task inside the approved scope", async () => {
    const token = await runTokenFor(["good.test"], ["recon.run"]);
    const { taskId } = await sentTask(token, "good.test");
    const res = await request(baseUrl)
      .post("/a2a")
      .set("Authorization", `Bearer ${token}`)
      .send({ jsonrpc: "2.0", id: newId(), method: "tasks/get", params: { id: taskId } });
    expect(res.status).toBe(200);
    expect(res.body.result.task.status).toBe("completed");
  });

  it("rejects a recon target outside the approved scope", async () => {
    const token = await runTokenFor(["good.test"], ["recon.run"]);
    const res = await taskSend(token, {
      taskId: newId(),
      runId: "0195aabb-0000-7000-8000-000000000000",
      kind: "recon.run",
      input: { target: "evil.test" },
    });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe(-32003);
  });

  it("rejects a task bound to a different run than the token", async () => {
    const token = await runTokenFor(["good.test"], ["recon.run"]);
    const res = await taskSend(token, {
      taskId: newId(),
      runId: "0195aabb-0000-7000-8000-0000000000ff",
      kind: "recon.run",
      input: { target: "good.test" },
    });
    expect(res.status).toBe(403);
  });

  it("rejects a task kind the run did not grant", async () => {
    const token = await runTokenFor(["good.test"], ["recon.run"]);
    const res = await taskSend(token, {
      taskId: newId(),
      runId: "0195aabb-0000-7000-8000-000000000000",
      kind: "knowledge.search",
      input: { query: "x" },
    });
    expect(res.status).toBe(200);
    expect(res.body.error.code).toBe(-32000);
  });

  it("rejects a token whose audience names a different agent (impersonation)", async () => {
    const run = await identity.issuer.mintRunToken({
      userId: "user:alice",
      runId: "0195aabb-0000-7000-8000-000000000001",
      targets: ["good.test"],
      actions: ["knowledge.search"],
      correlationId: "cid",
    });
    const knowledgeToken = await identity.issuer.exchangeRunToken(run, {
      audience: "a2a:knowledge",
      actions: ["knowledge.search"],
      actor: "workload:orchestrator",
    });
    const res = await taskSend(knowledgeToken, {
      taskId: newId(),
      runId: "0195aabb-0000-7000-8000-000000000001",
      kind: "recon.run",
      input: { target: "good.test" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects a workload token with a tampered payload (invalid signature)", async () => {
    const token = await runTokenFor(["good.test"], ["recon.run"]);
    const parts = token.split(".");
    const claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Record<string, unknown>;
    claims.reg = { ...(claims.reg as Record<string, unknown>), targets: ["attacker.test"] };
    const payload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
    const tampered = `${parts[0]!}.${payload}.${parts[2]!}`;

    const res = await taskSend(tampered, {
      taskId: newId(),
      runId: "0195aabb-0000-7000-8000-000000000000",
      kind: "recon.run",
      input: { target: "good.test" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects an unsigned (alg=none) token at the agent boundary", async () => {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "none", kid: "test-key", typ: "JWT" };
    const claims = {
      iss: "agent-sec-lab-test",
      sub: "user:alice",
      aud: ["a2a:recon"],
      iat: now,
      exp: now + 600,
      jti: "unsigned-jti",
      reg: { runId: "0195aabb-0000-7000-8000-000000000000", targets: ["good.test"], actions: ["recon.run"], correlationId: "c" },
    };
    const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}.`;

    const res = await taskSend(unsigned, {
      taskId: newId(),
      runId: "0195aabb-0000-7000-8000-000000000000",
      kind: "recon.run",
      input: { target: "good.test" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects tasks/get for a run outside the token scope", async () => {
    const token = await runTokenFor(["good.test"], ["recon.run"]);
    const { taskId } = await sentTask(token, "good.test");
    const other = await runTokenFor(["other.test"], ["recon.run"]);
    const res = await request(baseUrl)
      .post("/a2a")
      .set("Authorization", `Bearer ${other}`)
      .send({ jsonrpc: "2.0", id: newId(), method: "tasks/get", params: { id: taskId } });
    expect(res.status).toBe(403);
  });

  it("orchestrator rejects a replayed run token (jti nonce)", async () => {
    const repos = new FakeRepositories();
    const coordinator = new FakeCoordinator();
    const orchestrator = new OrchestratorHandler({
      log,
      audit: testSecurity(log).audit,
      repos,
      coordinator,
      children: new FakeChildBroker(),
    });
    const run = await repos.runs.create({ name: "r", scope: { targets: ["good.test"] }, userId: "user:alice" });
    const runToken = await identity.issuer.mintRunToken({
      userId: "user:alice",
      runId: run.runId,
      targets: ["good.test"],
      actions: ["run.start", "recon.run"],
      correlationId: "cid",
    });
    const verdict = await identity.verifier.verifyToken(runToken, { audience: "a2a:orchestrator" });
    const verified = verdict.context!;
    verified.agent = "a2a:orchestrator";
    const ctx: CallContext = { verified, token: runToken };

    const task = {
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["good.test"] } },
    };
    await orchestrator.taskSend(task, ctx);
    await expect(orchestrator.taskSend(task, ctx)).rejects.toMatchObject({ status: 403 });
    await orchestrator.drain();
  });
});