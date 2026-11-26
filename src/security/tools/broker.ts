import type { ZodTypeAny, output } from "zod";
import type { RunRecord } from "../../core/domain.js";
import { AppError, EgressDeniedError, ValidationError } from "../../core/errors.js";
import { inspectUntrustedContent } from "../prompt/audit.js";
import type {
  AuditProvider,
  AuthorizationProvider,
  AuthzResource,
  Decision,
  NetworkPolicyProvider,
  ResolvedTarget,
} from "../protocols.js";
import type { ToolRegistry } from "./registry.js";
import { assertOutputSize, outputBytes, redactSecrets } from "./output.js";
import {
  assertTargetInScope,
  DnsTargetResolver,
  parseToolTarget,
  resolveParsedTarget,
} from "./targets.js";
import type { ParsedToolTarget } from "./targets.js";
import type {
  TargetResolver,
  ToolActor,
  ToolCallContext,
  ToolRequest,
  ToolResult,
  ToolSpec,
  ToolTargetRule,
} from "./types.js";

/** Bound for prompt-injection inspection; the full output is still size-checked. */
const MAX_INSPECT_CHARS = 64 * 1024;

export interface ToolBrokerOptions {
  registry: ToolRegistry;
  authz: AuthorizationProvider;
  audit: AuditProvider;
  network: NetworkPolicyProvider;
  /** Trusted run lookup; must come from the operational `runs` repository. */
  resolveRun: (runId: string) => Promise<RunRecord | null>;
  resolver?: TargetResolver;
  now?: () => number;
}

class ToolAbortReason {
  constructor(readonly kind: "timeout" | "cancelled") {}
}

function abortError(signal: AbortSignal): AppError {
  if (signal.reason instanceof ToolAbortReason && signal.reason.kind === "timeout") {
    return new AppError("tool_timeout", "tool execution timed out", 504);
  }
  return new AppError("tool_cancelled", "tool execution was cancelled", 499);
}

function abortPromise(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    const onAbort = (): void => reject(abortError(signal));
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function assertSafeArgKeys(value: unknown): void {
  if (typeof value !== "object" || value === null) return;
  if (Array.isArray(value)) {
    for (const item of value) assertSafeArgKeys(item);
    return;
  }
  for (const key of Object.keys(value)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new ValidationError("tool arguments contain a reserved key");
    }
    assertSafeArgKeys((value as Record<string, unknown>)[key]);
  }
}

/**
 * Centralized in-process Tool Execution Layer (Tool Broker).
 *
 * Every agent tool call goes through `execute`, which is the single
 * enforcement point for:
 *  - the trusted registry and per-agent tool allowlist;
 *  - the verified workload identity and run binding;
 *  - the trusted run record's target scope and the signed grant;
 *  - target canonicalization, DNS resolution and private/reserved IP denial;
 *  - OPA authorization for the tool's required action;
 *  - argument schema validation and canonicalization;
 *  - rate, concurrency, timeout, cancellation and output-size limits;
 *  - output schema validation, provenance and prompt-injection inspection.
 *
 * It never parses a tool name or arguments from model output. Callers pass a
 * code-owned `ToolSpec` object; the broker verifies that it is the exact
 * registered definition before doing anything else.
 */
export class ToolBroker {
  private readonly registry: ToolRegistry;
  private readonly authz: AuthorizationProvider;
  private readonly audit: AuditProvider;
  private readonly network: NetworkPolicyProvider;
  private readonly resolveRun: (runId: string) => Promise<RunRecord | null>;
  private readonly resolver: TargetResolver;
  private readonly now: () => number;
  private readonly calls = new Map<string, number[]>();
  private readonly active = new Map<string, number>();

  constructor(options: ToolBrokerOptions) {
    if (!options.registry.isSealed) {
      throw new Error("tool registry must be sealed before the tool broker is created");
    }
    this.registry = options.registry;
    this.authz = options.authz;
    this.audit = options.audit;
    this.network = options.network;
    this.resolveRun = options.resolveRun;
    this.resolver = options.resolver ?? new DnsTargetResolver();
    this.now = options.now ?? (() => Date.now());
  }

  async execute<S extends ZodTypeAny, R>(
    spec: ToolSpec<S>,
    actor: ToolActor,
    request: ToolRequest,
    handler: (call: ToolCallContext<output<S>>) => Promise<R>,
    options: { signal?: AbortSignal } = {},
  ): Promise<ToolResult<R>> {
    const started = this.now();

    if (!this.isValidRequest(request)) {
      return this.deny(actor, "unknown", "invalid tool request", "validation_error", 422);
    }

    let registered: ToolSpec;
    try {
      registered = this.registry.requireForAgent(request.name, actor.agent);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, request.name, error.message, error.code, error.status);
    }
    if (registered !== spec) {
      return this.deny(
        actor,
        request.name,
        "tool definition does not match the registered definition",
        "tool_not_registered",
        403,
      );
    }

    try {
      this.assertActorBinding(actor, spec);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    const parsed = spec.schema.safeParse(request.args);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
      return this.deny(
        actor,
        spec.name,
        `invalid arguments for tool '${spec.name}': ${detail}`,
        "validation_error",
        422,
      );
    }

    try {
      assertSafeArgKeys(parsed.data);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    const run = await this.loadRun(actor, spec);
    try {
      this.assertRunBinding(actor, run);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    let args = parsed.data as output<S>;
    let parsedTarget: ParsedToolTarget | undefined;
    let targetRule: ToolTargetRule | undefined;
    let approvedTargets: readonly string[] = actor.approvedTargets;
    try {
      const prepared = this.prepareTarget(spec, actor, run, args);
      args = prepared.args;
      parsedTarget = prepared.parsedTarget;
      targetRule = prepared.targetRule;
      approvedTargets = prepared.approvedTargets;
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    let decision: Decision;
    try {
      decision = await this.authorize(spec, actor, run, args, parsedTarget?.canonical, approvedTargets);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    // Resolve and check the network target only after the OPA decision, so an
    // unauthorized request cannot trigger DNS lookups.
    let target: ResolvedTarget | undefined;
    if (parsedTarget !== undefined && targetRule !== undefined) {
      try {
        target = await resolveParsedTarget(parsedTarget, targetRule, this.resolver);
        await this.assertEgress(target);
      } catch (err) {
        const error = this.safeError(err);
        return this.deny(actor, spec.name, error.message, error.code, error.status);
      }
    }

    try {
      this.consumeRateLimit(actor, spec);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    let release: () => void;
    try {
      release = this.acquireConcurrency(actor, spec);
    } catch (err) {
      const error = this.safeError(err);
      return this.deny(actor, spec.name, error.message, error.code, error.status);
    }

    try {
      const result = await this.runWithLimits(
        spec,
        actor,
        run,
        args,
        target,
        decision,
        handler,
        options.signal,
      );

      const { text, bytes } = outputBytes(result);
      assertOutputSize(bytes, spec.limits.maxOutputBytes);
      if (spec.outputSchema !== undefined) {
        const outputCheck = spec.outputSchema.safeParse(result);
        if (!outputCheck.success) {
          throw new AppError("tool_output_invalid", "tool output did not match its registered schema", 502);
        }
      }

      const inspection = await inspectUntrustedContent(this.audit, {
        tier: "tool-output",
        source: `tool:${spec.name}`,
        content: text.slice(0, MAX_INSPECT_CHARS),
        agent: actor.agent,
        runId: actor.runId,
        taskId: actor.taskId,
        ...(actor.userId !== "" ? { principal: actor.userId } : {}),
      });

      const durationMs = this.now() - started;
      await this.audit.emit({
        type: "tool.execution.completed",
        ts: new Date().toISOString(),
        traceId: actor.taskId,
        runId: actor.runId,
        taskId: actor.taskId,
        ...(actor.userId !== "" ? { principal: actor.userId } : {}),
        data: {
          tool: spec.name,
          agent: actor.agent,
          risk: spec.risk,
          action: spec.requiredAction,
          decision_rule: decision.rule ?? null,
          target: target?.canonical ?? null,
          duration_ms: durationMs,
          output_bytes: bytes,
          suspicious: inspection.result.suspicious,
          categories: inspection.result.signals.map((signal) => signal.category),
        },
      });

      return {
        tool: spec.name,
        trust: "untrusted",
        authoritative: false,
        provenance: {
          tool: spec.name,
          agent: actor.agent,
          runId: actor.runId,
          taskId: actor.taskId,
          ...(target !== undefined ? { target: target.canonical } : {}),
        },
        data: result,
        bytes,
        durationMs,
      };
    } catch (err) {
      const error = this.safeError(err);
      await this.audit.emit({
        type: "tool.execution.failed",
        ts: new Date().toISOString(),
        traceId: actor.taskId,
        runId: actor.runId,
        taskId: actor.taskId,
        ...(actor.userId !== "" ? { principal: actor.userId } : {}),
        data: {
          tool: spec.name,
          agent: actor.agent,
          code: error.code,
          error_name: error.name,
          duration_ms: this.now() - started,
        },
      });
      throw error;
    } finally {
      release();
    }
  }

  private isValidRequest(request: ToolRequest): boolean {
    if (typeof request !== "object" || request === null || Array.isArray(request)) return false;
    if (!Object.prototype.hasOwnProperty.call(request, "name")) return false;
    if (Object.prototype.hasOwnProperty.call(request, "args") === false) return false;
    for (const key of Object.keys(request)) {
      if (key !== "name" && key !== "args") return false;
    }
    return typeof request.name === "string" && request.name.length > 0;
  }

  private assertActorBinding(actor: ToolActor, spec: ToolSpec): void {
    if (actor.agent === "" || !spec.allowedAgents.includes(actor.agent)) {
      throw new AppError("tool_not_permitted", `agent '${actor.agent}' may not invoke tool '${spec.name}'`, 403);
    }
    if (actor.runId === "" || actor.taskId === "" || actor.userId === "") {
      throw new AppError("forbidden", "tool execution requires a verified run, task and user", 403);
    }
    if (!actor.caller.startsWith("workload:") || actor.workload === "") {
      throw new AppError("forbidden", "tool execution requires a verified workload identity", 403);
    }
    if (!actor.audience.includes(`a2a:${actor.agent}`)) {
      throw new AppError("forbidden", "token audience does not match the receiving agent", 403);
    }
  }

  private async loadRun(actor: ToolActor, spec: ToolSpec): Promise<RunRecord> {
    let run: RunRecord | null;
    try {
      run = await this.resolveRun(actor.runId);
    } catch {
      return this.deny(actor, spec.name, "trusted run lookup failed", "tool_execution_failed", 503);
    }
    if (run === null || run === undefined) {
      return this.deny(actor, spec.name, "run not found or not authorized", "forbidden", 403);
    }
    return run;
  }

  private assertRunBinding(actor: ToolActor, run: RunRecord): void {
    if (run.runId !== actor.runId) {
      throw new AppError("forbidden", "tool run does not match the trusted run record", 403);
    }
    if (run.state === "COMPLETED" || run.state === "CANCELLED" || run.state === "FAILED") {
      throw new AppError("forbidden", `run '${run.runId}' is ${run.state}; tools cannot execute`, 403);
    }
    if (run.userId === undefined || run.userId === "" || run.userId !== actor.userId) {
      throw new AppError("forbidden", "tool run is not owned by the verified user", 403);
    }
    if ((run.tenantId ?? "") !== (actor.tenantId ?? "")) {
      throw new AppError("forbidden", "tool run tenant does not match the verified tenant", 403);
    }
  }

  private prepareTarget<S extends ZodTypeAny>(
    spec: ToolSpec<S>,
    actor: ToolActor,
    run: RunRecord,
    args: output<S>,
  ): {
    args: output<S>;
    parsedTarget?: ParsedToolTarget;
    targetRule?: ToolTargetRule;
    approvedTargets: readonly string[];
  } {
    const rule = spec.target;
    if (rule === undefined) return { args, approvedTargets: actor.approvedTargets };

    const raw = (args as Record<string, unknown>)[rule.field];
    if (typeof raw !== "string") {
      throw new ValidationError(`tool '${spec.name}' requires a string target`);
    }

    const parsed = parseToolTarget(raw, rule.kind);
    const approvedTargets = assertTargetInScope({
      canonical: parsed.canonical,
      kind: rule.kind,
      approvedTargets: actor.approvedTargets,
      runTargets: run.scope.targets,
    });

    return {
      args: { ...(args as Record<string, unknown>), [rule.field]: parsed.canonical } as output<S>,
      parsedTarget: parsed,
      targetRule: rule,
      approvedTargets,
    };
  }

  private async assertEgress(target: ResolvedTarget): Promise<void> {
    let decision: { allowed: boolean; reason?: string };
    try {
      decision = await this.network.assertEgress(target.canonical);
    } catch {
      throw new EgressDeniedError("egress policy evaluation failed");
    }
    if (!decision.allowed) {
      throw new EgressDeniedError(decision.reason ?? `egress to '${target.canonical}' denied`);
    }
  }

  private async authorize<S extends ZodTypeAny>(
    spec: ToolSpec<S>,
    actor: ToolActor,
    run: RunRecord,
    args: output<S>,
    requestedTarget: string | undefined,
    approvedTargets: readonly string[],
  ): Promise<Decision> {
    const docIds = (args as Record<string, unknown>).docIds;
    const resource: AuthzResource = {
      kind: "operation",
      workload: actor.workload,
      agent: actor.agent,
      user: actor.userId,
      runId: actor.runId,
      approvedTargets: [...approvedTargets],
      approvedActions: [...actor.approvedActions],
      requestedAction: spec.requiredAction,
      requestedTool: spec.name,
      requestedRunId: actor.runId,
      resourceOwner: run.userId ?? "",
      resourceTenantId: run.tenantId ?? "",
      tenantId: actor.tenantId ?? "",
      scopes: [...actor.scopes],
      ...(requestedTarget !== undefined ? { requestedTarget } : {}),
      ...(Array.isArray(docIds) && docIds.every((id): id is string => typeof id === "string")
        ? { requestedDocIds: docIds }
        : {}),
    };

    let decision: Decision;
    try {
      decision = await this.authz.authorize(spec.requiredAction, resource);
    } catch {
      throw new AppError("forbidden", "authorization engine unavailable", 403);
    }
    if (!decision.allowed) {
      throw new AppError(
        "forbidden",
        decision.reason ?? `tool '${spec.name}' is not authorized`,
        403,
        [decision.rule ?? "denied-by-policy"],
      );
    }
    return decision;
  }

  private consumeRateLimit(actor: ToolActor, spec: ToolSpec): void {
    const key = `${actor.agent}:${spec.name}`;
    const now = this.now();
    const windowStart = now - spec.limits.rateLimit.windowMs;
    const recent = (this.calls.get(key) ?? []).filter((ts) => ts > windowStart);
    if (recent.length >= spec.limits.rateLimit.maxCalls) {
      throw new AppError("tool_rate_limited", `tool '${spec.name}' rate limit exceeded`, 429);
    }
    recent.push(now);
    this.calls.set(key, recent);
  }

  private acquireConcurrency(actor: ToolActor, spec: ToolSpec): () => void {
    const key = `${actor.agent}:${spec.name}`;
    const active = this.active.get(key) ?? 0;
    if (active >= spec.limits.maxConcurrency) {
      throw new AppError("tool_concurrency_exceeded", `tool '${spec.name}' concurrency limit exceeded`, 429);
    }
    this.active.set(key, active + 1);
    return () => {
      const current = (this.active.get(key) ?? 1) - 1;
      if (current <= 0) this.active.delete(key);
      else this.active.set(key, current);
    };
  }

  private async runWithLimits<S extends ZodTypeAny, R>(
    spec: ToolSpec<S>,
    actor: ToolActor,
    run: RunRecord,
    args: output<S>,
    target: ResolvedTarget | undefined,
    decision: Decision,
    handler: (call: ToolCallContext<output<S>>) => Promise<R>,
    parentSignal: AbortSignal | undefined,
  ): Promise<R> {
    const controller = new AbortController();
    const onParentAbort = (): void => controller.abort(new ToolAbortReason("cancelled"));
    if (parentSignal !== undefined) {
      if (parentSignal.aborted) throw abortError(parentSignal);
      parentSignal.addEventListener("abort", onParentAbort, { once: true });
    }
    const timer = setTimeout(() => controller.abort(new ToolAbortReason("timeout")), spec.limits.timeoutMs);
    timer.unref();

    const call: ToolCallContext<output<S>> = {
      args,
      actor,
      run,
      signal: controller.signal,
      decision,
      ...(target !== undefined ? { target } : {}),
    };

    try {
      const work = handler(call);
      // If the timeout wins the race, the handler may still settle later; do not
      // let that become an unhandled rejection.
      work.catch(() => {});
      return await Promise.race([work, abortPromise(controller.signal)]);
    } catch (err) {
      if (controller.signal.aborted) throw abortError(controller.signal);
      throw err;
    } finally {
      clearTimeout(timer);
      parentSignal?.removeEventListener("abort", onParentAbort);
    }
  }

  private safeError(err: unknown): AppError {
    if (err instanceof AppError) {
      return new AppError(
        err.code,
        redactSecrets(err.message),
        err.status,
        err.causes.map((cause) => redactSecrets(cause)),
      );
    }
    return new AppError("tool_execution_failed", "tool execution failed", 502);
  }

  private async deny(
    actor: ToolActor,
    tool: string,
    reason: string,
    code = "forbidden",
    status = 403,
  ): Promise<never> {
    const safeReason = redactSecrets(reason);
    await this.audit.emit({
      type: "tool.execution.denied",
      ts: new Date().toISOString(),
      traceId: actor.taskId !== "" ? actor.taskId : tool,
      ...(actor.runId !== "" ? { runId: actor.runId } : {}),
      ...(actor.taskId !== "" ? { taskId: actor.taskId } : {}),
      ...(actor.userId !== "" ? { principal: actor.userId } : {}),
      data: {
        tool,
        agent: actor.agent,
        run_id: actor.runId,
        task_id: actor.taskId,
        code,
        reason: safeReason,
      },
    });
    throw new AppError(code, safeReason, status);
  }
}

/** Build a Tool Broker. The registry must already be sealed. */
export function createToolBroker(options: ToolBrokerOptions): ToolBroker {
  return new ToolBroker(options);
}
