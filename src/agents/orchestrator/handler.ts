import type { Logger } from "pino";
import { A2AError, AppError, NotFoundError } from "../../core/errors.js";
import type { RunState, TaskRecord } from "../../core/domain.js";
import type { Repositories } from "../../db/repositories/build.js";
import { lockKeyFor, seenKeyFor, type Coordinator } from "../../db/coordinator.js";
import type { AuditProvider } from "../../security/protocols.js";
import { createAgentCard } from "../../a2a/agentCard.js";
import type { A2AHandler } from "../../a2a/handler.js";
import {
  A2A_PROTOCOL_VERSION,
  a2aStatusOf,
  artifactFor,
  parseArtifact,
  taskKindSchema,
  validateTaskInput,
  type A2AMessage,
  type A2ATask,
  type InitializeResult,
  type TaskInit,
  type TaskKind,
} from "../../a2a/schema.js";
import type { AgentCard } from "../../a2a/agentCard.js";
import { phaseFor, planRun } from "./workflows.js";
import type { ChildTaskBroker } from "./broker.js";
import { assertTransition } from "./state.js";

export interface OrchestratorOptions {
  pollIntervalMs: number;
  pollMaxAttempts: number;
  lockTtlMs: number;
  seenTtlMs: number;
}

export interface OrchestratorDeps {
  log: Logger;
  audit: AuditProvider;
  repos: Repositories;
  coordinator: Coordinator;
  children: ChildTaskBroker;
  options?: Partial<OrchestratorOptions>;
}

const DEFAULT_OPTIONS: OrchestratorOptions = {
  pollIntervalMs: 200,
  pollMaxAttempts: 25,
  lockTtlMs: 30_000,
  seenTtlMs: 24 * 60 * 60 * 1000,
};

export class OrchestratorHandler implements A2AHandler {
  private readonly log: Logger;
  private readonly audit: AuditProvider;
  private readonly repos: Repositories;
  private readonly coordinator: Coordinator;
  private readonly children: ChildTaskBroker;
  private readonly options: OrchestratorOptions;
  private readonly drives = new Map<string, Promise<void>>();

  constructor(deps: OrchestratorDeps) {
    this.log = deps.log;
    this.audit = deps.audit;
    this.repos = deps.repos;
    this.coordinator = deps.coordinator;
    this.children = deps.children;
    this.options = { ...DEFAULT_OPTIONS, ...(deps.options ?? {}) };
  }

  async agentCard(): Promise<AgentCard> {
    return createAgentCard("orchestrator");
  }

  async initialize(): Promise<InitializeResult> {
    return {
      protocolVersion: A2A_PROTOCOL_VERSION,
      agentId: "orchestrator",
      capabilities: { streaming: false, pushNotifications: false },
    };
  }

  async messageSend(message: A2AMessage): Promise<{ message: A2AMessage }> {
    const run = await this.repos.runs.get(message.runId);
    if (!run) throw new NotFoundError("run not found");
    return { message };
  }

  async taskSend(task: TaskInit): Promise<{ task: A2ATask }> {
    if (task.kind !== "run.start") {
      throw new AppError("unsupported_task_kind", `orchestrator only accepts run.start tasks, got '${task.kind}'`, 422);
    }
    validateTaskInput(task.kind, task.input);

    const existing = await this.repos.tasks.get(task.taskId);
    if (existing) {
      void this.audit.emit({
        type: "run.start.replayed",
        ts: new Date().toISOString(),
        traceId: task.taskId,
        runId: task.runId,
        taskId: task.taskId,
        data: { reason: "duplicate tasks/send with known taskId" },
      });
      return { task: this.toA2ATask(existing) };
    }

    const run = await this.repos.runs.get(task.runId);
    if (!run) throw new NotFoundError("run not found");

    const seen = await this.coordinator.ensureSeen(`a2a:start:${task.taskId}`);
    if (!seen) {
      const recorded = await this.repos.tasks.get(task.taskId);
      if (recorded) {
        void this.audit.emit({
          type: "run.start.duplicate",
          ts: new Date().toISOString(),
          traceId: task.taskId,
          runId: task.runId,
          taskId: task.taskId,
          data: { reason: "idempotency key already present" },
        });
        return { task: this.toA2ATask(recorded) };
      }
      throw new A2AError("run.start task was already seen", 409);
    }

    await this.repos.tasks.create({
      taskId: task.taskId,
      runId: task.runId,
      ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
      kind: task.kind,
      input: task.input,
      status: "PENDING",
      attempts: 1,
    });

    const drive = this.driveRun(task.runId, task.taskId);
    this.drives.set(task.runId, drive);
    const recorded = await this.repos.tasks.get(task.taskId);
    return { task: this.toA2ATask(recorded!) };
  }

  async taskGet(id: string): Promise<{ task: A2ATask }> {
    const record = await this.repos.tasks.get(id);
    if (!record) throw new NotFoundError("task not found");
    return { task: this.toA2ATask(record) };
  }

  async taskCancel(id: string): Promise<{ task: A2ATask }> {
    const record = await this.repos.tasks.get(id);
    if (!record) throw new NotFoundError("task not found");
    if (record.status === "SUCCEEDED" || record.status === "FAILED" || record.status === "CANCELLED") {
      return { task: this.toA2ATask(record) };
    }
    await this.repos.tasks.setStatus(id, "CANCELLED");
    const run = await this.repos.runs.get(record.runId);
    if (run && run.state !== "COMPLETED" && run.state !== "CANCELLED" && run.state !== "FAILED") {
      assertTransition(run.state, "CANCELLED");
      await this.repos.runs.setState(record.runId, "CANCELLED");
    }
    const updated = await this.repos.tasks.get(id);
    return { task: this.toA2ATask(updated!) };
  }

  async drain(): Promise<void> {
    await Promise.all([...this.drives.values()]);
  }

  private async driveRun(runId: string, rootTaskId: string): Promise<void> {
    const acquired = await this.coordinator.acquireLock(lockKeyFor(runId), this.options.lockTtlMs);
    if (!acquired) {
      this.log.warn({ runId }, "run lock not acquired; skipping drive");
      return;
    }
    await this.repos.tasks.setStatus(rootTaskId, "RUNNING");
    try {
      const run = await this.repos.runs.get(runId);
      if (!run) {
        await this.failRun(runId, rootTaskId, "run record missing");
        return;
      }
      assertTransition(run.state, "STARTED");
      await this.repos.runs.setState(runId, "STARTED");
      void this.audit.emit({
        type: "run.started",
        ts: new Date().toISOString(),
        traceId: rootTaskId,
        runId,
        taskId: rootTaskId,
      });

      const children = planRun(run, rootTaskId);
      let currentPhase: RunState = "STARTED";

      for (const child of children) {
        if (await this.isCancelled(rootTaskId)) {
          await this.repos.runs.setState(runId, "CANCELLED");
          return;
        }

        const phase = phaseFor(child.kind);
        if (phase !== currentPhase) {
          assertTransition(currentPhase, phase);
          await this.repos.runs.setState(runId, phase);
          currentPhase = phase;
        }

        await this.repos.tasks.create({
          taskId: child.taskId,
          runId,
          ...(child.parentTaskId !== undefined ? { parentTaskId: child.parentTaskId } : {}),
          kind: child.kind,
          input: child.input,
          status: "PENDING",
          attempts: 1,
        });
        await this.coordinator.ensureSeen(seenKeyFor(runId, child.taskId));

        const submitted = await this.children.submit(child);
        if (submitted.status === "failed" || submitted.status === "canceled") {
          await this.repos.tasks.setStatus(child.taskId, "FAILED", {
            ...(submitted.error !== undefined ? { error: submitted.error } : {}),
          });
          await this.failRun(runId, rootTaskId, submitted.error ?? "child task did not start");
          return;
        }
        await this.repos.tasks.setStatus(child.taskId, "RUNNING");

        const final = await this.pollChild(child.taskId);
        if (final.status === "failed") {
          await this.repos.tasks.setStatus(child.taskId, "FAILED", {
            ...(final.error !== undefined ? { error: final.error } : {}),
          });
          await this.failRun(runId, rootTaskId, final.error ?? "child task failed");
          return;
        }
        if (final.status === "canceled") {
          await this.repos.tasks.setStatus(child.taskId, "CANCELLED");
          await this.repos.runs.setState(runId, "CANCELLED");
          void this.audit.emit({
            type: "run.cancelled",
            ts: new Date().toISOString(),
            traceId: rootTaskId,
            runId,
            taskId: rootTaskId,
            data: { reason: "child task reported canceled" },
          });
          return;
        }
        if (final.artifact === undefined) {
          await this.failRun(runId, rootTaskId, "child task completed without an artifact");
          return;
        }
        const output = parseArtifact<Record<string, unknown>>(final.artifact);
        await this.repos.tasks.setStatus(child.taskId, "SUCCEEDED", { output });
      }

      if (await this.isCancelled(rootTaskId)) {
        await this.repos.runs.setState(runId, "CANCELLED");
        return;
      }
      assertTransition(currentPhase, "COMPLETED");
      await this.repos.runs.setState(runId, "COMPLETED");
      await this.repos.tasks.setStatus(rootTaskId, "SUCCEEDED", { output: { runId } });
      void this.audit.emit({
        type: "run.completed",
        ts: new Date().toISOString(),
        traceId: rootTaskId,
        runId,
        taskId: rootTaskId,
      });
      this.log.info({ runId }, "run completed");
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown error";
      this.log.error({ err, runId }, "run drive failed");
      await this.failRun(runId, rootTaskId, message);
    } finally {
      await this.coordinator.releaseLock(lockKeyFor(runId));
      this.drives.delete(runId);
    }
  }

  private async pollChild(taskId: string): Promise<A2ATask> {
    for (let attempt = 0; attempt < this.options.pollMaxAttempts; attempt++) {
      const task = await this.children.poll(taskId);
      if (task.status === "completed" || task.status === "failed" || task.status === "canceled") return task;
      await sleep(this.options.pollIntervalMs);
    }
    const last = await this.children.poll(taskId);
    if (last.status === "completed" || last.status === "failed" || last.status === "canceled") return last;
    return {
      taskId: last.taskId,
      runId: last.runId,
      ...(last.parentTaskId !== undefined ? { parentTaskId: last.parentTaskId } : {}),
      kind: last.kind,
      input: last.input,
      status: "failed",
      error: "poll timeout: child task did not complete",
    };
  }

  private async isCancelled(rootTaskId: string): Promise<boolean> {
    const record = await this.repos.tasks.get(rootTaskId);
    return record?.status === "CANCELLED";
  }

  private async failRun(runId: string, rootTaskId: string, message: string): Promise<void> {
    const root = await this.repos.tasks.get(rootTaskId);
    if (root && (root.status === "CANCELLED" || root.status === "SUCCEEDED")) return;
    const run = await this.repos.runs.get(runId);
    if (run && run.state !== "COMPLETED" && run.state !== "CANCELLED" && run.state !== "FAILED") {
      assertTransition(run.state, "FAILED");
      await this.repos.runs.setState(runId, "FAILED");
    }
    await this.repos.tasks.setStatus(rootTaskId, "FAILED", { error: message });
    void this.audit.emit({
      type: "run.failed",
      ts: new Date().toISOString(),
      traceId: rootTaskId,
      runId,
      taskId: rootTaskId,
      data: { error: message },
    });
    this.log.warn({ runId, message }, "run failed");
  }

  private toA2ATask(record: TaskRecord): A2ATask {
    const status = a2aStatusOf(record.status);
    const task: A2ATask = {
      taskId: record.taskId,
      runId: record.runId,
      ...(record.parentTaskId !== undefined ? { parentTaskId: record.parentTaskId } : {}),
      kind: this.parseKind(record.kind),
      status,
      input: record.input,
    };
    if (record.output !== undefined) task.artifact = artifactFor(record.output);
    if (record.error !== undefined) task.error = record.error;
    return task;
  }

  private parseKind(kind: string): TaskKind {
    const parsed = taskKindSchema.safeParse(kind);
    return (parsed.success ? parsed.data : "run.start") as TaskKind;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}