import { AppError } from "../core/errors.js";
import type {
  AuditProvider,
  CryptoProvider,
  ModelProvider,
  PolicyProvider,
  ResolvedTarget,
  SandboxProvider,
  SandboxResult,
  SandboxStep,
} from "../security/protocols.js";
import type { ToolExecutionRequest, ToolExecutor } from "../security/tools/index.js";
import { isDisallowedIp } from "../security/tools/index.js";
import { BudgetExceededError, type RunGovernor } from "../core/resilience/index.js";
import type { Repositories } from "../db/repositories/build.js";
import type { MemoryService } from "./memory.js";
import type { ToolCatalog } from "./tool-catalog.js";
import type { OperationBudget, ToolOperationContext, ToolRuntime } from "./tool-operation.js";

export interface LocalToolExecutorDeps {
  audit: AuditProvider;
  policy: PolicyProvider;
  model: ModelProvider;
  crypto: CryptoProvider;
  repos: Repositories;
  sandbox: SandboxProvider;
  memory?: MemoryService;
  /** Shared run governor; the broker and operations consume the same budgets. */
  governor?: RunGovernor;
  llmTimeoutMs?: number;
}

/**
 * Controlled in-process executor for development. It runs the code-owned
 * operation selected from the sealed catalog and delegates external steps to
 * the configured sandbox provider.
 *
 * This is not OS-level isolation and does not spawn processes. A Phase 7
 * sandboxed executor can implement the same `ToolExecutor` interface without
 * changing broker authorization or argument validation.
 */
export class LocalToolExecutor implements ToolExecutor, ToolRuntime {
  readonly kind = "local" as const;

  constructor(
    private readonly catalog: ToolCatalog,
    private readonly deps: LocalToolExecutorDeps,
  ) {}

  supports(tool: string): boolean {
    try {
      this.catalog.get(tool);
      return true;
    } catch {
      return false;
    }
  }

  async execute(request: ToolExecutionRequest): Promise<unknown> {
    // Defense in depth: the broker already checked this, but the executor
    // refuses to run a tool outside the requesting agent's allowlist even if
    // it is invoked directly in-process.
    this.catalog.registry.requireForAgent(request.tool, request.actor.agent);
    const definition = this.catalog.get(request.tool);
    const runtime: ToolRuntime = {
      runStep: (step) => this.runStep(step, request.target),
    };
    const governor = this.deps.governor;
    const budget: OperationBudget = {
      budget: request.budget,
      llmTimeoutMs: this.deps.llmTimeoutMs ?? 30_000,
      remainingMs: () =>
        governor === undefined
          ? Number.POSITIVE_INFINITY
          : governor.remainingMs(request.run, request.budget),
      consumeLlm: async () => {
        if (governor === undefined) return false;
        try {
          await governor.consumeLlmCall(request.run, request.budget);
          return true;
        } catch (err) {
          if (err instanceof BudgetExceededError) {
            // A run deadline is global and must not be swallowed. An exhausted
            // or unavailable LLM-call budget instead degrades safely to the
            // deterministic path without model reasoning.
            if (err.code === "run_deadline_exceeded") throw err;
            return false;
          }
          throw err;
        }
      },
    };
    const context: ToolOperationContext = {
      request,
      audit: this.deps.audit,
      policy: this.deps.policy,
      model: this.deps.model,
      crypto: this.deps.crypto,
      repos: this.deps.repos,
      ...(this.deps.memory !== undefined ? { memory: this.deps.memory } : {}),
      runtime,
      budget,
    };
    return definition.operation(context);
  }

  /**
   * Re-check the pinned target envelope before dispatching an external step.
   * The broker already validated it; this is defense in depth at the executor
   * boundary. The sandbox adapter must connect only to `target.addresses` and
   * honor `constraints.maxRedirects`.
   *
   * When `expectedTarget` is supplied, the operation cannot substitute a
   * different (even public) target for the one the broker authorized.
   */
  async runStep(step: SandboxStep, expectedTarget?: ResolvedTarget): Promise<SandboxResult> {
    if (step.target === undefined) {
      throw new AppError("tool_target_denied", "sandbox step requires a pinned target", 403);
    }
    if (expectedTarget !== undefined) {
      if (
        step.target.canonical !== expectedTarget.canonical ||
        step.target.addresses.length !== expectedTarget.addresses.length ||
        step.target.addresses.some((address, index) => address !== expectedTarget.addresses[index])
      ) {
        throw new AppError("tool_target_denied", "sandbox step target does not match the authorized target", 403);
      }
    }
    if (step.constraints === undefined || step.constraints.maxRedirects !== 0) {
      throw new AppError("tool_target_denied", "sandbox step must forbid redirects", 403);
    }
    if (step.constraints.pinAddresses !== true) {
      throw new AppError("tool_target_denied", "sandbox step must pin the resolved addresses", 403);
    }
    for (const address of step.target.addresses) {
      if (!step.target.allowPrivate && isDisallowedIp(address)) {
        throw new AppError("tool_target_denied", "sandbox step target is no longer allowed", 403);
      }
    }
    return this.deps.sandbox.run(step);
  }
}
