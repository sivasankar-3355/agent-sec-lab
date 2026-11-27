import { AppError } from "../core/errors.js";
import type { ToolRegistry, ToolSpec } from "../security/tools/index.js";
import type { ToolOperation } from "./tool-operation.js";
import {
  agentToolRegistry,
  knowledgeIndexTool,
  knowledgeSearchTool,
  reconSnapshotTool,
  reportGenerateTool,
} from "./tools.js";
import { reconSnapshotOperation } from "./recon/handler.js";
import { knowledgeIndexOperation, knowledgeSearchOperation } from "./knowledge/handler.js";
import { reportGenerateOperation } from "./report/handler.js";

export interface ToolDefinition {
  readonly spec: ToolSpec;
  readonly operation: ToolOperation;
}

/**
 * Sealed binding between the trusted tool specs and their code-owned
 * operations. The broker authorizes and validates against the registry; the
 * executor looks up the operation here. Agents never pass an operation or a
 * definition into `execute`, so a caller cannot substitute behavior.
 */
export class ToolCatalog {
  private readonly definitions = new Map<string, ToolDefinition>();
  private sealed = false;

  constructor(readonly registry: ToolRegistry) {
    if (!registry.isSealed) throw new Error("tool registry must be sealed before the catalog");
  }

  register(spec: ToolSpec, operation: ToolOperation): void {
    if (this.sealed) throw new Error("tool catalog is sealed");
    if (this.registry.get(spec.name) !== spec) {
      throw new Error(`tool '${spec.name}' operation is not bound to the registered spec`);
    }
    if (this.definitions.has(spec.name)) {
      throw new Error(`duplicate tool operation: ${spec.name}`);
    }
    this.definitions.set(spec.name, Object.freeze({ spec, operation }));
  }

  /** Ensure every registered tool has exactly one operation, then close. */
  seal(): void {
    for (const spec of this.registry.list()) {
      if (!this.definitions.has(spec.name)) {
        throw new Error(`tool '${spec.name}' has no registered operation`);
      }
    }
    this.sealed = true;
  }

  get isSealed(): boolean {
    return this.sealed;
  }

  get(name: string): ToolDefinition {
    const definition = this.definitions.get(name);
    if (definition === undefined) {
      throw new AppError("tool_not_registered", `tool '${name}' has no registered operation`, 403);
    }
    return definition;
  }

  list(): readonly ToolDefinition[] {
    return [...this.definitions.values()];
  }
}

export const agentToolCatalog = new ToolCatalog(agentToolRegistry);
agentToolCatalog.register(reconSnapshotTool, reconSnapshotOperation);
agentToolCatalog.register(knowledgeSearchTool, knowledgeSearchOperation);
agentToolCatalog.register(knowledgeIndexTool, knowledgeIndexOperation);
agentToolCatalog.register(reportGenerateTool, reportGenerateOperation);
agentToolCatalog.seal();
