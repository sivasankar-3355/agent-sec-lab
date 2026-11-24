import type { Logger } from "pino";
import { AppError, NotFoundError } from "../core/errors.js";
import type { Repositories } from "../db/repositories/build.js";
import type { AuditProvider, VerifiedContext } from "../security/protocols.js";
import type { SecurityProviders } from "../security/container.js";
import { createAgentCard } from "../a2a/agentCard.js";
import type { A2AHandler, CallContext } from "../a2a/handler.js";
import {
  A2A_PROTOCOL_VERSION,
  artifactFor,
  validateTaskInput,
  type A2AMessage,
  type A2ATask,
  type AgentKind,
  type A2AStatus,
  type InitializeResult,
  type TaskInit,
  type TaskKind,
} from "../a2a/schema.js";
import type { AgentCard } from "../a2a/agentCard.js";

export interface WorkerContext {
  log: Logger;
  audit: AuditProvider;
  repos: Repositories;
  security: SecurityProviders;
}

export interface WorkerExecuteInput {
  taskId: string;
  runId: string;
  kind: TaskKind;
  input: Record<string, unknown>;
  authz?: VerifiedContext;
}

export interface WorkerExecutor {
  execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>>;
}

interface MemoryTask {
  init: TaskInit;
  status: A2AStatus;
  artifact?: { artifactId: string; text: string };
  error?: string;
}

function assertRunBound(
  bound: VerifiedContext | undefined,
  task: { runId: string; kind: string; input?: Record<string, unknown> },
  method: string,
): void {
  if (bound === undefined || bound.runId === "") return;
  if (task.runId !== bound.runId) {
    throw new AppError("forbidden", `${method}: run '${task.runId}' outside authorized run '${bound.runId}'`, 403);
  }
  if (!bound.permittedActions.includes(task.kind)) {
    throw new AppError("forbidden", `${method}: kind '${task.kind}' not permitted for this run`, 403);
  }
  if (
    task.kind === "recon.run" &&
    typeof task.input?.target === "string" &&
    !bound.scopeTargets.includes(task.input.target)
  ) {
    throw new AppError(
      "forbidden",
      `${method}: target '${task.input.target}' is outside the approved scope [${bound.scopeTargets.join(", ")}]`,
      403,
    );
  }
}

export class BaseWorkerHandler implements A2AHandler {
  private readonly agent: AgentKind;
  private readonly executor: WorkerExecutor;
  private readonly ctx: WorkerContext;
  private readonly acceptedKinds: readonly TaskKind[];
  private readonly tasks = new Map<string, MemoryTask>();
  private readonly running = new Map<string, Promise<void>>();

  constructor(agent: AgentKind, executor: WorkerExecutor, ctx: WorkerContext, acceptedKinds: readonly TaskKind[]) {
    this.agent = agent;
    this.executor = executor;
    this.ctx = ctx;
    this.acceptedKinds = acceptedKinds;
  }

  async agentCard(): Promise<AgentCard> {
    return createAgentCard(this.agent);
  }

  async initialize(_params: { agentId?: string }): Promise<InitializeResult> {
    return {
      protocolVersion: A2A_PROTOCOL_VERSION,
      agentId: this.agent,
      capabilities: { streaming: false, pushNotifications: false },
    };
  }

  async messageSend(message: A2AMessage, ctx?: CallContext): Promise<{ message: A2AMessage }> {
    const bound = ctx?.verified;
    if (bound !== undefined && bound.runId !== "" && message.runId !== bound.runId) {
      throw new AppError("forbidden", `message run '${message.runId}' outside authorized run '${bound.runId}'`, 403);
    }
    return { message };
  }

  async taskSend(task: TaskInit, ctx?: CallContext): Promise<{ task: A2ATask }> {
    if (!this.acceptedKinds.includes(task.kind)) {
      throw new AppError(
        "unsupported_task_kind",
        `agent '${this.agent}' does not accept task kind '${task.kind}'`,
        422,
      );
    }
    validateTaskInput(task.kind, task.input);
    assertRunBound(ctx?.verified, task, "tasks/send");

    const existing = this.tasks.get(task.taskId);
    if (existing) return { task: this.toA2A(existing) };

    const record: MemoryTask = { init: task, status: "submitted" };
    this.tasks.set(task.taskId, record);
    this.running.set(task.taskId, this.run(task, ctx?.verified));
    return { task: this.toA2A(record) };
  }

  async taskGet(id: string, ctx?: CallContext): Promise<{ task: A2ATask }> {
    const record = this.tasks.get(id);
    if (!record) throw new NotFoundError("task not found");
    assertRunBound(ctx?.verified, record.init, "tasks/get");
    return { task: this.toA2A(record) };
  }

  async taskCancel(id: string, ctx?: CallContext): Promise<{ task: A2ATask }> {
    const record = this.tasks.get(id);
    if (!record) throw new NotFoundError("task not found");
    assertRunBound(ctx?.verified, record.init, "tasks/cancel");
    if (record.status === "completed" || record.status === "failed" || record.status === "canceled") {
      return { task: this.toA2A(record) };
    }
    record.status = "canceled";
    this.running.delete(id);
    void this.ctx.audit.emit({
      type: "task.cancelled",
      ts: new Date().toISOString(),
      traceId: id,
      runId: record.init.runId,
      taskId: record.init.taskId,
      data: { agent: this.agent },
    });
    return { task: this.toA2A(record) };
  }

  async drain(): Promise<void> {
    await Promise.all([...this.running.values()]);
  }

  private async run(task: TaskInit, authz?: VerifiedContext): Promise<void> {
    this.tasks.get(task.taskId)!.status = "working";
    void this.ctx.audit.emit({
      type: "task.started",
      ts: new Date().toISOString(),
      traceId: task.taskId,
      runId: task.runId,
      taskId: task.taskId,
      data: { agent: this.agent, kind: task.kind },
    });
    try {
      const output = await this.executor.execute(this.ctx, {
        taskId: task.taskId,
        runId: task.runId,
        kind: task.kind,
        input: task.input,
        ...(authz !== undefined ? { authz } : {}),
      });
      const record = this.tasks.get(task.taskId);
      if (!record || record.status === "canceled") return;
      record.status = "completed";
      record.artifact = artifactFor(output);
      void this.ctx.audit.emit({
        type: "task.completed",
        ts: new Date().toISOString(),
        traceId: task.taskId,
        runId: task.runId,
        taskId: task.taskId,
        data: { agent: this.agent, kind: task.kind },
      });
    } catch (err) {
      const record = this.tasks.get(task.taskId);
      if (!record || record.status === "canceled") return;
      record.status = "failed";
      record.error = err instanceof Error ? err.message : "unknown error";
      this.ctx.log.warn({ err, taskId: task.taskId }, "worker task failed");
      void this.ctx.audit.emit({
        type: "task.failed",
        ts: new Date().toISOString(),
        traceId: task.taskId,
        runId: task.runId,
        taskId: task.taskId,
        data: { agent: this.agent, kind: task.kind, error: record.error },
      });
    } finally {
      this.running.delete(task.taskId);
    }
  }

  private toA2A(record: MemoryTask): A2ATask {
    const task: A2ATask = {
      taskId: record.init.taskId,
      runId: record.init.runId,
      ...(record.init.parentTaskId !== undefined ? { parentTaskId: record.init.parentTaskId } : {}),
      kind: record.init.kind,
      status: record.status,
      input: record.init.input,
    };
    if (record.artifact !== undefined) task.artifact = record.artifact;
    if (record.error !== undefined) task.error = record.error;
    return task;
  }
}