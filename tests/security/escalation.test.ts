import express, { type Application } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createA2ARouter } from "../../src/a2a/server.js";
import { BaseWorkerHandler, type WorkerContext } from "../../src/agents/base.js";
import { ReconExecutor, reconAcceptedKinds } from "../../src/agents/recon/handler.js";
import { KnowledgeExecutor, knowledgeAcceptedKinds } from "../../src/agents/knowledge/handler.js";
import { ReportExecutor, reportAcceptedKinds } from "../../src/agents/report/handler.js";
import { createLogger } from "../../src/core/logger.js";
import { newId } from "../../src/core/ids.js";
import { encodeJwt } from "../../src/security/jwt.js";
import type { VerifiedContext } from "../../src/security/protocols.js";
import {
  A2A_SCOPES,
  RUN_ACTIONS,
  a2aAudience,
} from "../../src/security/audience.js";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";
import {
  FakeMemoryStores,
  FakeRepositories,
  TestAuditProvider,
  makeMemoryService,
  makeTestIdentity,
  makeToolBroker,
  opaSecurity,
} from "../helpers/testkit.js";

const log = createLogger("silent", false);
const identity = makeTestIdentity();

type WorkerAgent = "recon" | "knowledge" | "report";

function security(policyDir?: string, audit?: TestAuditProvider): FailClosedSecurityProviders {
  return opaSecurity(log, {
    authn: identity.verifier,
    ...(policyDir !== undefined ? { policyDir } : {}),
    ...(audit !== undefined ? { audit } : {}),
  });
}

function workerApp(
  agent: WorkerAgent,
  sec: FailClosedSecurityProviders,
  repos: FakeRepositories,
  stores: FakeMemoryStores = new FakeMemoryStores(),
): Application {
  const ctx: WorkerContext = {
    log,
    audit: sec.audit,
    repos,
    security: sec,
    memory: makeMemoryService(sec, repos.runs, stores),
    tools: makeToolBroker(sec, repos),
  };
  const handler =
    agent === "recon"
      ? new BaseWorkerHandler("recon", new ReconExecutor(), ctx, reconAcceptedKinds)
      : agent === "knowledge"
        ? new BaseWorkerHandler("knowledge", new KnowledgeExecutor(), ctx, knowledgeAcceptedKinds)
        : new BaseWorkerHandler("report", new ReportExecutor(), ctx, reportAcceptedKinds);

  const app = express();
  app.use(express.json());
  app.use(
    createA2ARouter(handler, {
      log,
      authn: sec.authn,
      authz: sec.authz,
      audit: sec.audit,
      agent,
      audience: a2aAudience(agent),
    }),
  );
  return app;
}

interface GrantOptions {
  runId: string;
  audience: string;
  /** Actions granted on the run token (defaults to the full run grant). */
  runActions?: string[];
  /** Actions carried by the delegated child token. */
  actions: string[];
  targets: string[];
  user?: string;
  tenantId?: string;
  actor?: string;
}

async function childGrant(options: GrantOptions): Promise<{ token: string; context: VerifiedContext }> {
  const runToken = await identity.issuer.mintRunToken({
    userId: options.user ?? "user:alice",
    runId: options.runId,
    targets: options.targets,
    actions: options.runActions ?? [...RUN_ACTIONS],
    correlationId: "cid",
    ...(options.tenantId !== undefined ? { tenantId: options.tenantId } : {}),
  });
  const child = await identity.issuer.exchangeRunToken(runToken, {
    audience: options.audience,
    actions: options.actions,
    actor: options.actor ?? "workload:orchestrator",
  });
  const verdict = await identity.verifier.verifyToken(child, { audience: options.audience });
  if (verdict.context === undefined) throw new Error("test token did not verify");
  return { token: child, context: verdict.context };
}

function sendTask(app: Application, token: string, task: Record<string, unknown>) {
  return request(app)
    .post("/a2a")
    .set("Authorization", `Bearer ${token}`)
    .send({ jsonrpc: "2.0", id: newId(), method: "tasks/send", params: { task } });
}

describe("Phase-2 privilege escalation scenarios", () => {
  it("S1: denies a compromised orchestrator invoking an unauthorized tool", async () => {
    const repos = new FakeRepositories();
    const sec = security();
    const app = workerApp("recon", sec, repos);
    const runId = newId();
    const { token } = await childGrant({ runId, audience: "a2a:recon", actions: ["recon.run"], targets: ["host-1"] });

    // Recon's grant is recon.run only; the orchestrator asks for a report tool.
    const res = await sendTask(app, token, {
      taskId: newId(),
      runId,
      kind: "report.generate",
      input: { reportKind: "overview" },
    });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe(-32003);
  });

  it("S2: denies recon targeting outside the approved scope (A2A + executor)", async () => {
    const repos = new FakeRepositories();
    const sec = security();
    const app = workerApp("recon", sec, repos);
    const run = await repos.runs.create({ name: "r", scope: { targets: ["host-1"] }, userId: "user:alice" });
    const runId = run.runId;
    const grant = await childGrant({ runId, audience: "a2a:recon", actions: ["recon.run"], targets: ["host-1"] });

    const viaA2A = await sendTask(app, grant.token, {
      taskId: newId(),
      runId,
      kind: "recon.run",
      input: { target: "evil.test" },
    });
    expect(viaA2A.status).toBe(403);

    // The agent's own executor PEP denies even without the A2A layer.
    const executor = new ReconExecutor();
    await expect(
      executor.execute(
        { log, audit: sec.audit, repos, security: sec, tools: makeToolBroker(sec, repos) },
        {
          taskId: newId(),
          runId,
          kind: "recon.run",
          input: { target: "evil.test" },
          authz: grant.context,
        },
      ),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("S3: denies knowledge indexing another tenant's document", async () => {
    const repos = new FakeRepositories();
    const stores = new FakeMemoryStores();
    const sec = security();
    const doc = await stores.documents.create({
      docId: newId(),
      source: "s",
      title: "t",
      contentType: "text/plain",
      contentHash: "hash-t2",
      ownerUserId: "user:bob",
      tenantId: "tenant-2",
      metadata: {},
    });
    const run = await repos.runs.create({
      name: "r",
      scope: { targets: ["host-1"] },
      userId: "user:alice",
      tenantId: "tenant-1",
    });
    const runId = run.runId;
    const grant = await childGrant({
      runId,
      audience: "a2a:knowledge",
      actions: ["knowledge.index"],
      targets: ["host-1"],
      tenantId: "tenant-1",
    });

    await expect(
      new KnowledgeExecutor().execute(
        {
          log,
          audit: sec.audit,
          repos,
          security: sec,
          memory: makeMemoryService(sec, repos.runs, stores),
          tools: makeToolBroker(sec, repos),
        },
        {
          taskId: newId(),
          runId,
          kind: "knowledge.index",
          input: { docIds: [doc.docId] },
          authz: grant.context,
        },
      ),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("S4: denies report on another user's run", async () => {
    const repos = new FakeRepositories();
    const sec = security();
    const run = await repos.runs.create({ name: "bob-run", scope: { targets: ["host-9"] }, userId: "user:bob" });
    const grant = await childGrant({
      runId: run.runId,
      audience: "a2a:report",
      actions: ["report.generate"],
      targets: ["host-9"],
      user: "user:alice",
    });

    await expect(
      new ReportExecutor().execute(
        { log, audit: sec.audit, repos, security: sec, tools: makeToolBroker(sec, repos) },
        {
          taskId: newId(),
          runId: run.runId,
          kind: "report.generate",
          input: { reportKind: "overview" },
          authz: grant.context,
        },
      ),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("S5: cannot widen its authorization context via request fields or tampering", async () => {
    // (a) a spoofed body field does not change the verified run grant.
    const repos = new FakeRepositories();
    const sec = security();
    const run = await repos.runs.create({ name: "r", scope: { targets: ["host-1"] }, userId: "user:alice" });
    const runId = run.runId;
    const grant = await childGrant({ runId, audience: "a2a:recon", actions: ["recon.run"], targets: ["host-1"] });

    await expect(
      new ReconExecutor().execute(
        { log, audit: sec.audit, repos, security: sec, tools: makeToolBroker(sec, repos) },
        {
          taskId: newId(),
          runId,
          kind: "recon.run",
          input: { target: "evil.test", approvedTargets: ["evil.test"] },
          authz: grant.context,
        },
      ),
    ).rejects.toMatchObject({ status: 403 });

    // (b) a tampered token is rejected before any policy runs.
    const app = workerApp("recon", sec, repos);
    const [header, payload, signature] = grant.token.split(".");
    const claims = JSON.parse(Buffer.from(payload!, "base64url").toString("utf8")) as Record<string, unknown>;
    const reg = claims.reg as Record<string, unknown>;
    claims.reg = { ...reg, targets: ["evil.test"] };
    const tampered = `${header}.${Buffer.from(JSON.stringify(claims), "utf8").toString("base64url")}.${signature}`;
    const res = await sendTask(app, tampered, {
      taskId: newId(),
      runId,
      kind: "recon.run",
      input: { target: "evil.test" },
    });
    expect(res.status).toBe(401);
  });

  it("S6: denies an agent invoking another agent's privileged operation", async () => {
    const repos = new FakeRepositories();
    const sec = security();
    const app = workerApp("knowledge", sec, repos);
    const runId = newId();
    // Simulate a bypass where a knowledge-audience token is minted for the
    // recon workload: the policy still refuses non-orchestrator senders.
    const { token } = await childGrant({
      runId,
      audience: "a2a:knowledge",
      actions: ["knowledge.index"],
      targets: ["host-1"],
      actor: "workload:recon",
    });
    const res = await sendTask(app, token, {
      taskId: newId(),
      runId,
      kind: "knowledge.index",
      input: { docIds: [newId()] },
    });
    expect(res.status).toBe(403);
  });

  it("S7: fails closed when OPA is unavailable", async () => {
    const repos = new FakeRepositories();
    const sec = security("/definitely/not/a/real/policy/dir");
    const app = workerApp("recon", sec, repos);
    const runId = newId();
    const { token } = await childGrant({ runId, audience: "a2a:recon", actions: ["recon.run"], targets: ["host-1"] });

    const res = await sendTask(app, token, {
      taskId: newId(),
      runId,
      kind: "recon.run",
      input: { target: "host-1" },
    });
    expect(res.status).toBe(403);
  });

  it("S8: denies a run-bound method when the authorization attributes are missing", async () => {
    const repos = new FakeRepositories();
    const sec = security();
    const app = workerApp("recon", sec, repos);

    // A workload identity token valid for this audience carries no run grant /
    // approved scope, so run-bound attributes are missing.
    const now = Math.floor(Date.now() / 1000);
    const workloadToken = encodeJwt(
      {
        kind: "workload",
        iss: "agent-sec-lab-test",
        sub: "workload:orchestrator",
        actor: "workload:orchestrator",
        aud: ["a2a:recon"],
        iat: now,
        exp: now + 300,
        jti: "s8-jti",
        scopes: [...A2A_SCOPES],
      },
      identity.privateKey,
      "test-key",
    );
    const res = await sendTask(app, workloadToken, {
      taskId: newId(),
      runId: newId(),
      kind: "recon.run",
      input: { target: "host-1" },
    });
    expect(res.status).toBe(403);
  });

  it("allows the legitimate in-scope operation (control) and audits the decision", async () => {
    const repos = new FakeRepositories();
    const audit = new TestAuditProvider();
    const sec = security(undefined, audit);
    const app = workerApp("recon", sec, repos);
    const run = await repos.runs.create({ name: "r", scope: { targets: ["host-1"] }, userId: "user:alice" });
    const runId = run.runId;
    const { token } = await childGrant({ runId, audience: "a2a:recon", actions: ["recon.run"], targets: ["host-1"] });

    const res = await sendTask(app, token, {
      taskId: newId(),
      runId,
      kind: "recon.run",
      input: { target: "host-1" },
    });
    expect(res.status).toBe(200);

    const decisions = audit.events.filter((e) => e.type === "authz.decision");
    expect(decisions.some((e) => e.data?.decision === "allow")).toBe(true);
  });
});
