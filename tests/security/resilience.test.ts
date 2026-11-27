import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createA2ARouter } from "../../src/a2a/server.js";
import { createAgentCard } from "../../src/a2a/agentCard.js";
import type { A2AHandler } from "../../src/a2a/handler.js";
import type { A2ATask, TaskInit } from "../../src/a2a/schema.js";
import { AppError, A2AError } from "../../src/core/errors.js";
import { newId } from "../../src/core/ids.js";
import { createLogger } from "../../src/core/logger.js";
import type { WorkerExecutor } from "../../src/agents/base.js";
import { BaseWorkerHandler } from "../../src/agents/base.js";
import {
  AgentClientsBroker,
  type ChildTaskBroker,
} from "../../src/agents/orchestrator/broker.js";
import { OrchestratorHandler } from "../../src/agents/orchestrator/handler.js";
import type { MemoryActor, MemoryService } from "../../src/agents/memory.js";
import {
  FakeChildBroker,
  FakeCoordinator,
  FakeMemoryStores,
  FakeRepositories,
  makeMemoryService,
  makeToolBroker,
  testSecurity,
} from "../helpers/testkit.js";

const log = createLogger("silent", false);
const security = testSecurity(log);

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error("waitFor timeout");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function taskBase(task: TaskInit): A2ATask {
  return {
    taskId: task.taskId,
    runId: task.runId,
    ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
    kind: task.kind,
    input: task.input,
    status: "submitted",
  };
}

/** Fails selected recon targets and completes everything else. */
class PartialReconBroker implements ChildTaskBroker {
  readonly submitted: TaskInit[] = [];
  readonly cancelled: string[] = [];

  constructor(
    private readonly failingTargets: ReadonlySet<string>,
    private readonly failureMessage = "recon failed for target",
  ) {}

  async submit(task: TaskInit): Promise<A2ATask> {
    this.submitted.push(task);
    return taskBase(task);
  }

  async poll(taskId: string): Promise<A2ATask> {
    const task = this.submitted.find((candidate) => candidate.taskId === taskId);
    if (task === undefined) {
      return { taskId, runId: taskId, kind: "recon.run", input: {}, status: "failed", error: "unknown task" };
    }
    const base = taskBase(task);
    if (task.kind === "recon.run" && this.failingTargets.has(String(task.input.target))) {
      return { ...base, status: "failed", error: this.failureMessage };
    }
    const result =
      task.kind === "recon.run"
        ? { findings: ["finding-1"] }
        : task.kind === "knowledge.search"
          ? { hits: [] }
          : { reportId: "report-1" };
    return {
      ...base,
      status: "completed",
      artifact: { artifactId: "result", text: JSON.stringify(result) },
    };
  }

  async cancel(taskId: string): Promise<A2ATask> {
    this.cancelled.push(taskId);
    const task = this.submitted.find((candidate) => candidate.taskId === taskId);
    if (task === undefined) {
      return { taskId, runId: taskId, kind: "recon.run", input: {}, status: "canceled" };
    }
    return { ...taskBase(task), status: "canceled" };
  }
}

/** Fails the first N transaction submissions with a configured error. */
class FlakyBroker implements ChildTaskBroker {
  readonly submitted: TaskInit[] = [];
  private failures = 0;

  constructor(
    private readonly error: unknown,
    private readonly failTimes: number,
  ) {}

  async submit(task: TaskInit): Promise<A2ATask> {
    this.submitted.push(task);
    if (this.failures < this.failTimes) {
      this.failures += 1;
      throw this.error;
    }
    return taskBase(task);
  }

  async poll(taskId: string): Promise<A2ATask> {
    const task = this.submitted.find((candidate) => candidate.taskId === taskId);
    if (task === undefined) {
      return { taskId, runId: taskId, kind: "recon.run", input: {}, status: "failed", error: "unknown task" };
    }
    const result =
      task.kind === "recon.run"
        ? { findings: [] }
        : task.kind === "knowledge.search"
          ? { hits: [] }
          : { reportId: "report-1" };
    return {
      ...taskBase(task),
      status: "completed",
      artifact: { artifactId: "result", text: JSON.stringify(result) },
    };
  }

  async cancel(taskId: string): Promise<A2ATask> {
    const task = this.submitted.find((candidate) => candidate.taskId === taskId);
    return task === undefined
      ? { taskId, runId: taskId, kind: "recon.run", input: {}, status: "canceled" }
      : { ...taskBase(task), status: "canceled" };
  }
}

describe("Phase-6 orchestrator resilience", () => {
  it("propagates host cancellation to the active child task", async () => {
    const repos = new FakeRepositories();
    const broker = new FakeChildBroker({ "recon.run": { status: "working" } });
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: broker,
      options: { pollIntervalMs: 5, pollMaxAttempts: 200 },
    });
    const run = await repos.runs.create({ name: "cancel", scope: { targets: ["host-1"] } });
    const sent = await orchestrator.taskSend({
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-1"] } },
    });

    await waitFor(() => broker.submitted.length === 1);
    await waitFor(() => broker.polls.length > 0);
    const childTaskId = broker.submitted[0]!.taskId;
    await orchestrator.taskCancel(sent.task.taskId);
    await orchestrator.drain();

    expect(broker.cancelled).toContain(childTaskId);
    expect((await repos.tasks.get(childTaskId))?.status).toBe("CANCELLED");
    expect((await repos.runs.get(run.runId))?.state).toBe("CANCELLED");
    expect((await repos.tasks.get(sent.task.taskId))?.status).toBe("CANCELLED");
  });

  it("isolates one failed recon target and completes with partial results", async () => {
    const repos = new FakeRepositories();
    const broker = new PartialReconBroker(new Set(["bad-host"]));
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: broker,
      options: { pollIntervalMs: 1, pollMaxAttempts: 20 },
    });
    const run = await repos.runs.create({
      name: "partial",
      scope: { targets: ["bad-host", "good-host"] },
    });
    const sent = await orchestrator.taskSend({
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["bad-host", "good-host"] } },
    });
    await orchestrator.drain();

    expect((await repos.runs.get(run.runId))?.state).toBe("COMPLETED");
    expect((await repos.tasks.get(sent.task.taskId))?.status).toBe("SUCCEEDED");
    const rootOutput = (await repos.tasks.get(sent.task.taskId))?.output as {
      partial?: boolean;
      failures?: unknown[];
    };
    expect(rootOutput.partial).toBe(true);
    expect(rootOutput.failures?.length).toBe(1);

    const tasks = await repos.tasks.listByRun(run.runId);
    expect(tasks.filter((task) => task.kind === "recon.run" && task.status === "FAILED")).toHaveLength(1);
    expect(tasks.filter((task) => task.kind === "recon.run" && task.status === "SUCCEEDED")).toHaveLength(1);
    expect(tasks.some((task) => task.kind === "knowledge.search" && task.status === "SUCCEEDED")).toBe(true);
    expect(tasks.some((task) => task.kind === "report.generate" && task.status === "SUCCEEDED")).toBe(true);
  });

  it("fails the run when every recon target fails and skips dependent work", async () => {
    const repos = new FakeRepositories();
    const broker = new PartialReconBroker(new Set(["bad-1", "bad-2"]));
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: broker,
      options: { pollIntervalMs: 1, pollMaxAttempts: 20 },
    });
    const run = await repos.runs.create({
      name: "all-recon-fail",
      scope: { targets: ["bad-1", "bad-2"] },
    });
    const sent = await orchestrator.taskSend({
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["bad-1", "bad-2"] } },
    });
    await orchestrator.drain();

    expect((await repos.runs.get(run.runId))?.state).toBe("FAILED");
    expect((await repos.tasks.get(sent.task.taskId))?.error).toContain("dependency_failed");
    // Knowledge search is independent and may still have run, but the
    // dependent report must not execute without a successful recon.
    expect(broker.submitted.some((task) => task.kind === "report.generate")).toBe(false);
  });

  it("stops immediately when a child reports a shared run-budget failure", async () => {
    const repos = new FakeRepositories();
    const broker = new PartialReconBroker(
      new Set(["host-1"]),
      "run_budget_exceeded: run tool budget exhausted",
    );
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: broker,
      options: { pollIntervalMs: 1, pollMaxAttempts: 20 },
    });
    const run = await repos.runs.create({ name: "shared-budget", scope: { targets: ["host-1"] } });
    const sent = await orchestrator.taskSend({
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-1"] } },
    });
    await orchestrator.drain();

    expect((await repos.runs.get(run.runId))?.state).toBe("FAILED");
    expect((await repos.tasks.get(sent.task.taskId))?.error).toContain("run_budget_exceeded");
    // No independent or dependent work after a global budget refusal.
    expect(broker.submitted).toHaveLength(1);
  });

  it("stops a run when the trusted agent-call budget is exhausted", async () => {
    const repos = new FakeRepositories();
    const broker = new FakeChildBroker({
      "recon.run": { status: "completed", result: { findings: [] } },
      "knowledge.search": { status: "completed", result: { hits: [] } },
      "report.generate": { status: "completed", result: { reportId: "r-1" } },
    });
    const orchestrator = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: broker,
      options: { pollIntervalMs: 1, pollMaxAttempts: 20 },
    });
    const run = await repos.runs.create({
      name: "budget",
      scope: { targets: ["host-1", "host-2"] },
      config: { budget: { maxAgentCalls: 1 } },
    });
    const sent = await orchestrator.taskSend({
      taskId: newId(),
      runId: run.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-1", "host-2"] } },
    });
    await orchestrator.drain();

    expect(broker.submitted).toHaveLength(1);
    expect((await repos.runs.get(run.runId))?.state).toBe("FAILED");
    expect((await repos.tasks.get(sent.task.taskId))?.error).toContain("run_budget_exceeded");
  });

  it("retries a transient child dispatch once and never retries authorization", async () => {
    const repos = new FakeRepositories();
    const retryingBroker = new FlakyBroker(new A2AError("temporary upstream failure", 503), 1);
    const retrying = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos,
      coordinator: new FakeCoordinator(),
      children: retryingBroker,
      options: {
        pollIntervalMs: 1,
        pollMaxAttempts: 20,
        retry: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 2, jitter: 0 },
      },
    });
    const retryRun = await repos.runs.create({ name: "retry", scope: { targets: ["host-1"] } });
    await retrying.taskSend({
      taskId: newId(),
      runId: retryRun.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-1"] } },
    });
    await retrying.drain();
    expect((await repos.runs.get(retryRun.runId))?.state).toBe("COMPLETED");
    expect(retryingBroker.submitted).toHaveLength(4); // retried recon + knowledge + report

    const deniedRepos = new FakeRepositories();
    const deniedBroker = new FlakyBroker(new AppError("forbidden", "denied", 403), 1);
    const denied = new OrchestratorHandler({
      log,
      audit: security.audit,
      repos: deniedRepos,
      coordinator: new FakeCoordinator(),
      children: deniedBroker,
      options: {
        pollIntervalMs: 1,
        pollMaxAttempts: 20,
        retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 2, jitter: 0 },
      },
    });
    const deniedRun = await deniedRepos.runs.create({ name: "denied", scope: { targets: ["host-1"] } });
    await denied.taskSend({
      taskId: newId(),
      runId: deniedRun.runId,
      kind: "run.start",
      input: { scope: { targets: ["host-1"] } },
    });
    await denied.drain();
    expect((await deniedRepos.runs.get(deniedRun.runId))?.state).toBe("FAILED");
    // Only the independent knowledge task may run after recon is denied; the
    // denied recon dispatch itself must not be retried.
    expect(deniedBroker.submitted.filter((task) => task.kind === "recon.run")).toHaveLength(1);
  });
});

describe("Phase-6 circuit breaker and timeouts", () => {
  let server: Server;
  let baseUrl: string;
  let hits = 0;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.post("/a2a", (_req, res) => {
      hits += 1;
      res.status(500).json({ error: "unavailable" });
    });
    server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    const port =
      typeof address === "string"
        ? Number.parseInt(address.split(":").pop() ?? "0", 10)
        : (address as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("opens the peer circuit and refuses further requests without hitting the peer", async () => {
    const broker = new AgentClientsBroker(
      { recon: { base: baseUrl } },
      {
        timeoutMs: 1_000,
        circuit: { failureThreshold: 1, recoveryIntervalMs: 60_000, halfOpenMaxCalls: 1 },
      },
    );
    const task: TaskInit = {
      taskId: newId(),
      runId: newId(),
      kind: "recon.run",
      input: { target: "host-1" },
    };

    await expect(broker.submit(task, "test-token")).rejects.toMatchObject({ status: 500 });
    await expect(
      broker.submit({ ...task, taskId: newId() }, "test-token"),
    ).rejects.toMatchObject({ status: 503, code: "circuit_open" });
    expect(hits).toBe(1);
  });

  it("bounds a hung A2A handler with a structured JSON-RPC timeout", async () => {
    const handler = {
      agentCard: async () => createAgentCard("recon"),
      taskGet: async () => new Promise<never>(() => {}),
    } as unknown as A2AHandler;
    const app = express();
    app.use(express.json());
    app.use(
      createA2ARouter(handler, {
        log,
        authn: security.authn,
        authz: security.authz,
        audit: security.audit,
        requestTimeoutMs: 20,
      }),
    );

    const res = await request(app)
      .post("/a2a")
      .set("Authorization", "Bearer test-token")
      .send({
        jsonrpc: "2.0",
        id: "timeout-1",
        method: "tasks/get",
        params: { id: newId() },
      });
    expect(res.status).toBe(504);
    expect(res.body.error.code).toBe(-32005);
  });

  it("bounds a worker task and records a structured timeout failure", async () => {
    const repos = new FakeRepositories();
    const tools = makeToolBroker(security, repos);
    const executor: WorkerExecutor = {
      async execute() {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return {};
      },
    };
    const handler = new BaseWorkerHandler(
      "recon",
      executor,
      { log, audit: security.audit, tools },
      ["recon.run"],
      { taskTimeoutMs: 20, maxConcurrentTasks: 1 },
    );
    const sent = await handler.taskSend({
      taskId: newId(),
      runId: newId(),
      kind: "recon.run",
      input: { target: "host-1" },
    });
    await handler.drain();
    const after = await handler.taskGet(sent.task.taskId);
    expect(after.task.status).toBe("failed");
    expect(after.task.error).toContain("timeout");
  });

  it("rejects excess worker tasks instead of queueing without bound", async () => {
    const repos = new FakeRepositories();
    const tools = makeToolBroker(security, repos);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started!: () => void;
    const startedPromise = new Promise<void>((resolve) => {
      started = resolve;
    });
    const executor: WorkerExecutor = {
      async execute() {
        started();
        await gate;
        return {};
      },
    };
    const handler = new BaseWorkerHandler(
      "recon",
      executor,
      { log, audit: security.audit, tools },
      ["recon.run"],
      { taskTimeoutMs: 1_000, maxConcurrentTasks: 1 },
    );
    const first = await handler.taskSend({
      taskId: newId(),
      runId: newId(),
      kind: "recon.run",
      input: { target: "host-1" },
    });
    await startedPromise;
    const second = await handler.taskSend({
      taskId: newId(),
      runId: newId(),
      kind: "recon.run",
      input: { target: "host-2" },
    });
    expect(second.task.status).toBe("failed");
    expect(second.task.error).toContain("worker_capacity_exceeded");
    release();
    await handler.drain();
    expect((await handler.taskGet(first.task.taskId)).task.status).toBe("completed");
  });

  it("bounds a hung memory operation", async () => {
    const repos = new FakeRepositories();
    const slowSecurity = testSecurity(log, {
      embedding: {
        async embed(texts: readonly string[]) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return texts.map(() => [1]);
        },
      },
    });
    const service: MemoryService = makeMemoryService(
      slowSecurity,
      repos.runs,
      new FakeMemoryStores(),
      10,
    );
    const actor: MemoryActor = {
      kind: "api",
      principal: "user:alice",
      userId: "user:alice",
      scopes: ["knowledge:read"],
    };
    await expect(service.searchDocuments(actor, { query: "slow" })).rejects.toMatchObject({
      status: 504,
      code: "timeout",
    });
  });
});
