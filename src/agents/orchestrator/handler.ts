import type { Logger } from "pino";
import { A2AError, AppError, NotFoundError } from "../../core/errors.js";
import type { RunRecord, RunState, TaskRecord } from "../../core/domain.js";
import type { Repositories } from "../../db/repositories/build.js";
import { lockKeyFor, seenKeyFor, type Coordinator } from "../../db/coordinator.js";
import type { AuditProvider, AuthorizationProvider, VerifiedContext } from "../../security/protocols.js";
import { sleep, throwIfAborted } from "../../core/resilience/abort.js";
import {
  BudgetExceededError,
  CancelledError,
  CircuitOpenError,
} from "../../core/resilience/errors.js";
import {
  DEFAULT_RETRY_POLICY,
  RunGovernor,
  isRetryable,
  retry,
  type RetryPolicy,
} from "../../core/resilience/index.js";
import { createAgentCard } from "../../a2a/agentCard.js";
import type { A2AHandler, CallContext } from "../../a2a/handler.js";
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
import { agentForKind, type ChildTaskBroker, type TokenExchanger } from "./broker.js";
import { assertTransition, canTransition } from "./state.js";
import { a2aAudience } from "../../security/audience.js";
import { assertAuthorized } from "../authz.js";
import { inspectUntrustedContent } from "../../security/prompt/index.js";

/** Upper bound on a child artifact before it is parsed as data. */
const MAX_CHILD_ARTIFACT_CHARS = 256 * 1024;

/** Structured failure text used in task records/audit: `<code>: <message>`. */
function errorText(err: unknown): string {
  if (err instanceof AppError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return `child_failed: ${err.message}`;
  return "child_failed: unknown error";
}

function errorCode(err: unknown): string {
  return err instanceof AppError ? err.code : "child_failed";
}

/** A child-reported error that means the whole run must stop, not isolate. */
function isGlobalFailure(message: string): boolean {
  return (
    message.includes("run_budget_exceeded") ||
    message.includes("run_retry_budget_exceeded") ||
    message.includes("run_deadline_exceeded") ||
    message.includes("budget_store_unavailable")
  );
}

export interface OrchestratorOptions {
  pollIntervalMs: number;
  pollMaxAttempts: number;
  lockTtlMs: number;
  seenTtlMs: number;
  /** Overrides for the single bounded retry layer (child submit/cancel). */
  retry?: Partial<RetryPolicy>;
}

export interface OrchestratorDeps {
  log: Logger;
  audit: AuditProvider;
  repos: Repositories;
  coordinator: Coordinator;
  children: ChildTaskBroker;
  exchange?: TokenExchanger;
  /** Authorization PEP: validates which agents/operations this orchestrator may invoke. */
  authz?: AuthorizationProvider;
  /** Shared run budget/deadline enforcer (Redis-backed in production). */
  governor?: RunGovernor;
  options?: Partial<OrchestratorOptions>;
}

const DEFAULT_OPTIONS: OrchestratorOptions = {
  // 250ms x 480 ~= 2 minutes, aligned with the default worker task deadline.
  // The run budget/deadline still bounds the total.
  pollIntervalMs: 250,
  pollMaxAttempts: 480,
  lockTtlMs: 30_000,
  seenTtlMs: 24 * 60 * 60 * 1000,
};

function assertRunBound(bound: VerifiedContext | undefined, runId: string, method: string): void {
  if (bound === undefined || bound.runId === "") return;
  if (runId !== bound.runId) {
    throw new AppError("forbidden", `${method}: run '${runId}' outside authorized run '${bound.runId}'`, 403);
  }
}

export class OrchestratorHandler implements A2AHandler {
  private readonly log: Logger;
  private readonly audit: AuditProvider;
  private readonly repos: Repositories;
  private readonly coordinator: Coordinator;
  private readonly children: ChildTaskBroker;
  private readonly exchange: TokenExchanger | undefined;
  private readonly authz: AuthorizationProvider | undefined;
  private readonly governor: RunGovernor;
  private readonly options: OrchestratorOptions;
  private readonly drives = new Map<string, Promise<void>>();
  private readonly runTokens = new Map<string, string>();
  private readonly runGrants = new Map<string, VerifiedContext>();
  private readonly runCancels = new Map<string, AbortController>();
  private readonly activeChildren = new Map<string, string>();

  constructor(deps: OrchestratorDeps) {
    this.log = deps.log;
    this.audit = deps.audit;
    this.repos = deps.repos;
    this.coordinator = deps.coordinator;
    this.children = deps.children;
    this.exchange = deps.exchange;
    this.authz = deps.authz;
    this.governor = deps.governor ?? new RunGovernor();
    this.options = { ...DEFAULT_OPTIONS, ...(deps.options ?? {}) };
  }

  async agentCard(): Promise<AgentCard> {
    return createAgentCard("orchestrator");
  }

  async initialize(_params: { agentId?: string }): Promise<InitializeResult> {
    return {
      protocolVersion: A2A_PROTOCOL_VERSION,
      agentId: "orchestrator",
      capabilities: { streaming: false, pushNotifications: false },
    };
  }

  async messageSend(message: A2AMessage, ctx?: CallContext): Promise<{ message: A2AMessage }> {
    assertRunBound(ctx?.verified, message.runId, "message/send");
    const run = await this.repos.runs.get(message.runId);
    if (!run) throw new NotFoundError("run not found");
    // Inbound agent messages are data, never instructions. Inspect/audit but
    // never feed them into a trusted instruction section or act on advice.
    await inspectUntrustedContent(this.audit, {
      tier: "agent-output",
      source: `agent-message:${message.agentId ?? "unknown"}`,
      content: message.text,
      agent: "orchestrator",
      runId: message.runId,
      taskId: message.taskId,
    });
    return { message };
  }

  async taskSend(task: TaskInit, ctx?: CallContext): Promise<{ task: A2ATask }> {
    if (task.kind !== "run.start") {
      throw new AppError("unsupported_task_kind", `orchestrator only accepts run.start tasks, got '${task.kind}'`, 422);
    }
    validateTaskInput(task.kind, task.input);

    const bound = ctx?.verified;
    if (bound !== undefined && bound.runId !== "") {
      assertRunBound(bound, task.runId, "tasks/send");
      if (!bound.permittedActions.includes("run.start")) {
        throw new AppError("forbidden", "run.start is not permitted by the presented run token", 403);
      }
      if (bound.nonce.length > 0) {
        const fresh = await this.coordinator.ensureSeen(`jti:${bound.nonce}`, 24 * 60 * 60 * 1000);
        if (!fresh) {
          throw new AppError("forbidden", "run token already used", 403);
        }
      }
    }

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
    if (run.state === "COMPLETED" || run.state === "CANCELLED" || run.state === "FAILED") {
      throw new A2AError(`run '${run.runId}' is ${run.state}; run.start refused`, 409);
    }

    // One driver per run. A duplicate run.start with a different taskId must
    // not overwrite the active drive promise or start a second task graph.
    if (this.drives.has(task.runId)) {
      void this.audit.emit({
        type: "run.start.rejected",
        ts: new Date().toISOString(),
        traceId: task.taskId,
        runId: task.runId,
        taskId: task.taskId,
        data: { reason: "run is already being driven" },
      });
      throw new A2AError("run is already being driven", 409);
    }

    const seen = await this.coordinator.ensureSeen(`a2a:start:${task.taskId}`, this.options.seenTtlMs);
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

    if (ctx?.token !== undefined && bound !== undefined && bound.runId !== "") {
      this.runTokens.set(task.runId, ctx.token);
    }
    if (bound !== undefined && bound.runId !== "") {
      this.runGrants.set(task.runId, bound);
    }

    const drive = this.driveRun(task.runId, task.taskId);
    this.drives.set(task.runId, drive);
    const recorded = await this.repos.tasks.get(task.taskId);
    return { task: this.toA2ATask(recorded!) };
  }

  async taskGet(id: string, ctx?: CallContext): Promise<{ task: A2ATask }> {
    const record = await this.repos.tasks.get(id);
    if (!record) throw new NotFoundError("task not found");
    assertRunBound(ctx?.verified, record.runId, "tasks/get");
    return { task: this.toA2ATask(record) };
  }

  async taskCancel(id: string, ctx?: CallContext): Promise<{ task: A2ATask }> {
    const record = await this.repos.tasks.get(id);
    if (!record) throw new NotFoundError("task not found");
    assertRunBound(ctx?.verified, record.runId, "tasks/cancel");
    if (record.status === "SUCCEEDED" || record.status === "FAILED" || record.status === "CANCELLED") {
      return { task: this.toA2ATask(record) };
    }
    await this.repos.tasks.setStatus(id, "CANCELLED");
    const run = await this.repos.runs.get(record.runId);
    if (run && run.state !== "COMPLETED" && run.state !== "CANCELLED" && run.state !== "FAILED") {
      if (canTransition(run.state, "CANCELLED")) {
        await this.repos.runs.setState(record.runId, "CANCELLED");
      }
    }

    // Propagate cancellation to the in-flight child agent and to the run's
    // polling loop. The child A2A cancel aborts the worker task controller,
    // which reaches the tool broker's abort signal.
    const controller = this.runCancels.get(record.runId);
    controller?.abort(new CancelledError(`run '${record.runId}' was cancelled by the host`));
    const activeChild = this.activeChildren.get(record.runId);
    if (activeChild !== undefined) {
      const childRecord = await this.repos.tasks.get(activeChild);
      if (
        childRecord !== null &&
        childRecord.status !== "SUCCEEDED" &&
        childRecord.status !== "FAILED" &&
        childRecord.status !== "CANCELLED"
      ) {
        await this.repos.tasks.setStatus(activeChild, "CANCELLED");
      }
      try {
        await this.children.cancel(activeChild, { signal: AbortSignal.timeout(2_000) });
      } catch (err) {
        this.log.warn({ err, runId: record.runId, taskId: activeChild }, "child cancel did not complete");
        void this.audit.emit({
          type: "run.cancel.propagation_failed",
          ts: new Date().toISOString(),
          traceId: id,
          runId: record.runId,
          taskId: activeChild,
          data: { reason: errorText(err) },
        });
      }
    }
    void this.audit.emit({
      type: "run.cancelled",
      ts: new Date().toISOString(),
      traceId: id,
      runId: record.runId,
      taskId: id,
      data: { reason: "host-initiated tasks/cancel" },
    });
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

    const controller = new AbortController();
    this.runCancels.set(runId, controller);
    const signal = controller.signal;
    // Keep the run lock alive for long but bounded runs. The TTL stays short so
    // a crashed orchestrator releases the run promptly.
    const heartbeat = setInterval(() => {
      void this.coordinator
        .extendLock(lockKeyFor(runId), this.options.lockTtlMs)
        .then((held) => {
          if (!held) this.log.warn({ runId }, "run lock lost during drive");
        })
        .catch((err: unknown) => this.log.warn({ err, runId }, "run lock heartbeat failed"));
    }, Math.max(250, Math.floor(this.options.lockTtlMs / 3)));
    heartbeat.unref?.();

    try {
      // Cancellation may have arrived before the async drive started. Never
      // overwrite a terminal root task with RUNNING.
      const currentRoot = await this.repos.tasks.get(rootTaskId);
      if (currentRoot?.status === "CANCELLED") {
        await this.cancelRun(runId, rootTaskId, "host cancelled before drive start");
        return;
      }
      if (currentRoot?.status === "FAILED" || currentRoot?.status === "SUCCEEDED") return;
      await this.repos.tasks.setStatus(rootTaskId, "RUNNING");

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
      const failures: Array<{ taskId: string; kind: TaskKind; code: string; message: string }> = [];
      let reconSucceeded = 0;
      let firstReconFailure: { taskId: string; kind: TaskKind; code: string; message: string } | undefined;

      for (const child of children) {
        throwIfAborted(signal);
        if (await this.isCancelled(rootTaskId)) {
          await this.cancelRun(runId, rootTaskId, "host cancelled the run");
          return;
        }

        // Report depends on at least one successful recon for a non-empty
        // scope. Recon targets are independent, so partial successes still let
        // the report proceed; total recon failure fails the run fast.
        if (
          child.kind === "report.generate" &&
          run.scope.targets.length > 0 &&
          reconSucceeded === 0
        ) {
          const reason = firstReconFailure?.message ?? "no recon task succeeded";
          await this.failRun(runId, rootTaskId, `dependency_failed: ${reason}`, "dependency_failed");
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
        await this.coordinator.ensureSeen(seenKeyFor(runId, child.taskId), this.options.seenTtlMs);

        // Run budgets are consumed before any new work. An exhausted
        // agent-call, deadline or concurrency budget stops the run.
        try {
          await this.governor.consumeAgentCall(run);
        } catch (err) {
          await this.repos.tasks.setStatus(child.taskId, "FAILED", { error: errorText(err) });
          await this.failRun(runId, rootTaskId, errorText(err), errorCode(err));
          return;
        }
        let releaseSlot: (() => Promise<void>) | undefined;
        try {
          releaseSlot = await this.governor.acquireAgentSlot(run);
        } catch (err) {
          await this.repos.tasks.setStatus(child.taskId, "FAILED", { error: errorText(err) });
          await this.failRun(runId, rootTaskId, errorText(err), errorCode(err));
          return;
        }

        try {
          if (this.authz !== undefined) {
            // Orchestrator PEP: the central OPA decides whether this orchestrator
            // may invoke this agent for this operation on this run.
            const grant = this.runGrants.get(runId);
            await assertAuthorized(this.authz, "a2a:tasks/send", {
              kind: "a2a",
              workload: "orchestrator",
              agent: agentForKind(child.kind),
              ...(grant !== undefined && grant.userId !== "" ? { user: grant.userId } : {}),
              runId,
              approvedTargets: run.scope.targets,
              approvedActions: grant?.permittedActions ?? [],
              requestedAction: child.kind,
              requestedRunId: runId,
              ...(child.kind === "recon.run" && typeof child.input.target === "string"
                ? { requestedTarget: child.input.target }
                : {}),
              ...(child.kind === "knowledge.index" && Array.isArray(child.input.docIds)
                ? { requestedDocIds: child.input.docIds as string[] }
                : {}),
              ...(grant !== undefined && grant.tenantId !== undefined ? { tenantId: grant.tenantId } : {}),
            });
          }
          const submitted = await this.retryChild(
            run,
            signal,
            `tasks/send:${child.kind}`,
            async () => {
              // Mint a fresh per-hop token per attempt; the child taskId is the
              // idempotency key, so a retry cannot create a second task.
              const childToken =
                this.exchange !== undefined && this.runTokens.has(runId)
                  ? await this.childToken(runId, child.kind)
                  : undefined;
              return this.children.submit(child, childToken, { signal });
            },
          );
          if (submitted.status === "failed" || submitted.status === "canceled") {
            const message = submitted.error ?? "child task did not start";
            await this.repos.tasks.setStatus(child.taskId, "FAILED", { error: message });
            const failure = {
              taskId: child.taskId,
              kind: child.kind,
              code: "child_dispatch_failed",
              message,
            };
            failures.push(failure);
            if (child.kind === "recon.run" && firstReconFailure === undefined) firstReconFailure = failure;
            if (child.kind === "report.generate") {
              await this.failRun(runId, rootTaskId, message, failure.code);
              return;
            }
            continue;
          }

          await this.repos.tasks.setStatus(child.taskId, "RUNNING");
          this.activeChildren.set(runId, child.taskId);
          let final: A2ATask;
          try {
            final = await this.pollChild(child.taskId, run, signal);
          } finally {
            this.activeChildren.delete(runId);
          }

          if (final.status === "canceled") {
            await this.repos.tasks.setStatus(child.taskId, "CANCELLED");
            if (signal.aborted || (await this.isCancelled(rootTaskId))) {
              await this.cancelRun(runId, rootTaskId, "child task reported canceled");
              return;
            }
            const failure = {
              taskId: child.taskId,
              kind: child.kind,
              code: "child_canceled",
              message: "child task was canceled",
            };
            failures.push(failure);
            if (child.kind === "recon.run" && firstReconFailure === undefined) firstReconFailure = failure;
            if (child.kind === "report.generate") {
              await this.failRun(runId, rootTaskId, failure.message, failure.code);
              return;
            }
            continue;
          }

          if (final.status === "failed" || final.artifact === undefined) {
            const message =
              final.status === "failed"
                ? final.error ?? "child task failed"
                : "child task completed without an artifact";
            await this.repos.tasks.setStatus(child.taskId, "FAILED", { error: message });
            if (final.status === "failed" && isGlobalFailure(message)) {
              // A shared run budget/deadline refusal is not isolated: no later
              // task can make progress under the same trusted limit.
              await this.failRun(runId, rootTaskId, message, "run_budget_exhausted");
              return;
            }
            const failure = {
              taskId: child.taskId,
              kind: child.kind,
              code: final.status === "failed" ? "child_failed" : "child_artifact_missing",
              message,
            };
            failures.push(failure);
            if (child.kind === "recon.run" && firstReconFailure === undefined) firstReconFailure = failure;
            if (child.kind === "report.generate") {
              await this.failRun(runId, rootTaskId, message, failure.code);
              return;
            }
            continue;
          }

          let output: Record<string, unknown>;
          try {
            output = await this.ingestChildOutput(final, child.kind, runId);
          } catch (err) {
            const failure = {
              taskId: child.taskId,
              kind: child.kind,
              code: "child_artifact_invalid",
              message: errorText(err),
            };
            await this.repos.tasks.setStatus(child.taskId, "FAILED", { error: failure.message });
            failures.push(failure);
            if (child.kind === "recon.run" && firstReconFailure === undefined) firstReconFailure = failure;
            if (child.kind === "report.generate") {
              await this.failRun(runId, rootTaskId, failure.message, failure.code);
              return;
            }
            continue;
          }

          await this.repos.tasks.setStatus(child.taskId, "SUCCEEDED", { output });
          if (child.kind === "recon.run") reconSucceeded += 1;
        } catch (err) {
          if (signal.aborted || err instanceof CancelledError) {
            // Host taskCancel already sent the child cancel; here we only need
            // to record the run result.
            await this.cancelRun(runId, rootTaskId, "run cancellation observed");
            return;
          }
          if (err instanceof BudgetExceededError) {
            // The run deadline/budget is global: stop the child that may still
            // be executing, then fail the run without starting more work.
            try {
              await this.children.cancel(child.taskId, { signal: AbortSignal.timeout(2_000) });
            } catch (cancelErr) {
              this.log.warn(
                { err: cancelErr, runId, taskId: child.taskId },
                "child cancel after run budget exhaustion did not complete",
              );
            }
            await this.failRun(runId, rootTaskId, errorText(err), err.code);
            return;
          }
          // One child failure must not crash unrelated agents. Recon targets
          // and knowledge search are independent; a report failure is final.
          const message = errorText(err);
          await this.repos.tasks.setStatus(child.taskId, "FAILED", { error: message });
          const failure = {
            taskId: child.taskId,
            kind: child.kind,
            code: errorCode(err),
            message,
          };
          failures.push(failure);
          if (child.kind === "recon.run" && firstReconFailure === undefined) firstReconFailure = failure;
          if (child.kind === "report.generate") {
            await this.failRun(runId, rootTaskId, message, failure.code);
            return;
          }
          this.log.warn({ err, runId, taskId: child.taskId }, "isolated child failure");
        } finally {
          await releaseSlot?.();
        }
      }

      if (await this.isCancelled(rootTaskId)) {
        await this.cancelRun(runId, rootTaskId, "host cancelled the run");
        return;
      }
      assertTransition(currentPhase, "COMPLETED");
      await this.repos.runs.setState(runId, "COMPLETED");
      const rootOutput = failures.length > 0 ? { runId, partial: true, failures } : { runId };
      await this.repos.tasks.setStatus(rootTaskId, "SUCCEEDED", { output: rootOutput });
      void this.audit.emit({
        type: failures.length > 0 ? "run.completed_partial" : "run.completed",
        ts: new Date().toISOString(),
        traceId: rootTaskId,
        runId,
        taskId: rootTaskId,
        ...(failures.length > 0 ? { data: { failed_tasks: failures.length } } : {}),
      });
      this.log.info({ runId, partialFailures: failures.length }, "run completed");
    } catch (err) {
      if (signal.aborted || err instanceof CancelledError) {
        await this.cancelRun(runId, rootTaskId, "run cancellation observed");
        return;
      }
      const message = errorText(err);
      this.log.error({ err, runId }, "run drive failed");
      await this.failRun(runId, rootTaskId, message, errorCode(err));
    } finally {
      clearInterval(heartbeat);
      await this.coordinator.releaseLock(lockKeyFor(runId));
      this.drives.delete(runId);
      this.runTokens.delete(runId);
      this.runGrants.delete(runId);
      this.runCancels.delete(runId);
      this.activeChildren.delete(runId);
    }
  }

  private async ingestChildOutput(task: A2ATask, kind: string, runId: string): Promise<Record<string, unknown>> {
    const artifact = task.artifact;
    if (artifact === undefined) throw new A2AError("child artifact missing");
    if (artifact.text.length > MAX_CHILD_ARTIFACT_CHARS) {
      throw new A2AError("child artifact exceeds the allowed size");
    }
    // Child output is untrusted data. It is inspected/audited and parsed as a
    // bounded JSON object; recommendations in it are never executed and never
    // affect authorization.
    await inspectUntrustedContent(this.audit, {
      tier: "agent-output",
      source: `agent:${agentForKind(kind)}`,
      content: artifact.text,
      agent: "orchestrator",
      runId,
      taskId: task.taskId,
    });
    let parsed: unknown;
    try {
      parsed = parseArtifact<unknown>(artifact);
    } catch {
      throw new A2AError("child artifact is not valid JSON");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new A2AError("child artifact must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  }

  private async childToken(runId: string, kind: string): Promise<string> {
    const runToken = this.runTokens.get(runId);
    if (runToken === undefined || this.exchange === undefined) {
      throw new A2AError(`no run token available to delegate children for run '${runId}'`, 503);
    }
    const agent = agentForKind(kind);
    const audience = a2aAudience(agent);
    const actions = [kind];
    return this.exchange.exchange(runToken, { audience, actions });
  }

  private async pollChild(taskId: string, run: RunRecord, signal: AbortSignal): Promise<A2ATask> {
    let lastError: unknown;
    for (let attempt = 0; attempt < this.options.pollMaxAttempts; attempt++) {
      throwIfAborted(signal);
      this.governor.assertWithinDuration(run);
      try {
        const task = await this.children.poll(taskId, { signal });
        if (task.status === "completed" || task.status === "failed" || task.status === "canceled") {
          return task;
        }
      } catch (err) {
        // A circuit refusal or permanent error must not be retried into a
        // storm; transient poll failures are absorbed by the bounded loop.
        if (err instanceof CircuitOpenError || !isRetryable(err, { retryTimeouts: true })) throw err;
        lastError = err;
        this.log.warn({ err, taskId }, "transient child poll failure");
      }
      await sleep(this.options.pollIntervalMs, signal);
    }

    this.governor.assertWithinDuration(run);
    let last: A2ATask | undefined;
    try {
      last = await this.children.poll(taskId, { signal });
    } catch (err) {
      if (err instanceof CircuitOpenError || !isRetryable(err, { retryTimeouts: true })) throw err;
      lastError = err;
    }
    if (
      last !== undefined &&
      (last.status === "completed" || last.status === "failed" || last.status === "canceled")
    ) {
      return last;
    }
    // Polling is exhausted while the child is still working. Ask it to stop so
    // a slow/orphaned task does not keep consuming resources after the
    // orchestrator has recorded a failed child.
    try {
      await this.children.cancel(taskId, { signal: AbortSignal.timeout(2_000) });
    } catch (err) {
      this.log.warn({ err, taskId }, "child cancel after poll exhaustion did not complete");
    }
    return {
      taskId: last?.taskId ?? taskId,
      runId: last?.runId ?? run.runId,
      ...(last?.parentTaskId !== undefined ? { parentTaskId: last.parentTaskId } : {}),
      kind: last?.kind ?? "recon.run",
      input: last?.input ?? {},
      status: "failed",
      error:
        lastError === undefined
          ? "poll_timeout: child task did not complete"
          : `poll_timeout: child task did not complete (last error: ${errorText(lastError)})`,
    };
  }

  /** Single retry layer for idempotent child A2A calls, charged to the run. */
  private async retryChild<T>(
    run: RunRecord,
    signal: AbortSignal,
    operation: string,
    work: () => Promise<T>,
  ): Promise<T> {
    return retry(work, {
      policy: { ...DEFAULT_RETRY_POLICY, ...(this.options.retry ?? {}) },
      signal,
      shouldRetry: (err) => isRetryable(err, { retryTimeouts: true }),
      onRetry: async (info) => {
        // A retry consumes a separate run budget; exhaustion stops the loop.
        await this.governor.consumeRetry(run);
        void this.audit.emit({
          type: "resilience.retry",
          ts: new Date().toISOString(),
          traceId: run.runId,
          runId: run.runId,
          data: {
            operation,
            attempt: info.attempt,
            delay_ms: info.delayMs,
            classification: info.classification,
          },
        });
        this.log.warn({ runId: run.runId, operation, attempt: info.attempt }, "retrying child A2A call");
      },
    });
  }

  private async isCancelled(rootTaskId: string): Promise<boolean> {
    const record = await this.repos.tasks.get(rootTaskId);
    return record?.status === "CANCELLED";
  }

  private async cancelRun(runId: string, rootTaskId: string, reason: string): Promise<void> {
    const root = await this.repos.tasks.get(rootTaskId);
    if (root && root.status !== "CANCELLED" && root.status !== "SUCCEEDED") {
      await this.repos.tasks.setStatus(rootTaskId, "CANCELLED");
    }
    const activeChildId = this.activeChildren.get(runId);
    if (activeChildId !== undefined) {
      const child = await this.repos.tasks.get(activeChildId);
      if (
        child !== null &&
        child.status !== "SUCCEEDED" &&
        child.status !== "FAILED" &&
        child.status !== "CANCELLED"
      ) {
        await this.repos.tasks.setStatus(activeChildId, "CANCELLED");
      }
    }
    const run = await this.repos.runs.get(runId);
    if (run && run.state !== "COMPLETED" && run.state !== "CANCELLED" && run.state !== "FAILED") {
      if (canTransition(run.state, "CANCELLED")) {
        await this.repos.runs.setState(runId, "CANCELLED");
      }
    }
    void this.audit.emit({
      type: "run.cancelled",
      ts: new Date().toISOString(),
      traceId: rootTaskId,
      runId,
      taskId: rootTaskId,
      data: { reason },
    });
  }

  private async failRun(
    runId: string,
    rootTaskId: string,
    message: string,
    code = "run_failed",
  ): Promise<void> {
    const root = await this.repos.tasks.get(rootTaskId);
    if (root && (root.status === "CANCELLED" || root.status === "SUCCEEDED")) return;
    const run = await this.repos.runs.get(runId);
    if (run && run.state !== "COMPLETED" && run.state !== "CANCELLED" && run.state !== "FAILED") {
      if (canTransition(run.state, "FAILED")) {
        await this.repos.runs.setState(runId, "FAILED");
      }
    }
    await this.repos.tasks.setStatus(rootTaskId, "FAILED", { error: message });
    void this.audit.emit({
      type: "run.failed",
      ts: new Date().toISOString(),
      traceId: rootTaskId,
      runId,
      taskId: rootTaskId,
      data: { code, error: message },
    });
    this.log.warn({ runId, code, message }, "run failed");
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