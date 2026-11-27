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
import type { MemoryService } from "./memory.js";

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
}

export type ToolOperation = (context: ToolOperationContext) => Promise<unknown>;
