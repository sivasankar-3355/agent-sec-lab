import type { Repositories } from "../db/repositories/build.js";
import type {
  AuditProvider,
  CryptoProvider,
  ModelProvider,
  PolicyProvider,
  SandboxResult,
  SandboxStep,
} from "../security/protocols.js";
import type { ToolExecutionRequest } from "../security/tools/index.js";
import type { RunBudget } from "../core/resilience/index.js";
import type { MemoryService } from "./memory.js";

/**
 * Narrow run-budget view for code-owned operations. `consumeLlm` returns false
 * when the configured LLM-call budget is exhausted, allowing a safe degraded
 * path (e.g. recon still returns the sandbox observation without a model note).
 */
export interface OperationBudget {
  readonly budget: RunBudget;
  readonly llmTimeoutMs: number;
  remainingMs(): number;
  consumeLlm(): Promise<boolean>;
}

/**
 * External-effect boundary available to a tool operation. The local executor
 * implements this by calling the configured `SandboxProvider`. A future
 * sandboxed executor can provide the same interface without changing the
 * operation's authorization or validation logic.
 */
export interface ToolRuntime {
  runStep(step: SandboxStep): Promise<SandboxResult>;
}

/**
 * Trusted context for a code-owned tool operation. It deliberately does not
 * expose raw DB clients, connection strings, sandbox/network providers or
 * unrestricted request data.
 */
export interface ToolOperationContext {
  readonly request: ToolExecutionRequest;
  readonly audit: AuditProvider;
  readonly policy: PolicyProvider;
  readonly model: ModelProvider;
  readonly crypto: CryptoProvider;
  readonly repos: Repositories;
  readonly memory?: MemoryService;
  readonly runtime: ToolRuntime;
  readonly budget: OperationBudget;
}

export type ToolOperation = (context: ToolOperationContext) => Promise<unknown>;
