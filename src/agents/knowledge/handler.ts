import { AppError, NotConfiguredError } from "../../core/errors.js";
import type { ToolActor } from "../../security/tools/index.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { knowledgeIndexTool, knowledgeSearchTool } from "../tools.js";
import type { ToolOperation, ToolOperationContext } from "../tool-operation.js";
import { toolActorOf } from "../tool-actor.js";
import type { MemoryActor, MemoryService } from "../memory.js";

export const knowledgeAcceptedKinds: readonly ["knowledge.search", "knowledge.index"] = [
  "knowledge.search",
  "knowledge.index",
];

function memoryOf(ctx: ToolOperationContext): MemoryService {
  if (ctx.memory === undefined) {
    throw new NotConfiguredError("memory service is not configured");
  }
  return ctx.memory;
}

/** Build the memory actor from the verified tool actor only. */
function memoryActorOf(actor: ToolActor): MemoryActor {
  return {
    kind: "operation",
    principal: actor.caller,
    userId: actor.userId,
    scopes: actor.scopes,
    ...(actor.tenantId !== undefined ? { tenantId: actor.tenantId } : {}),
    runId: actor.runId,
    agent: actor.agent,
    workload: actor.workload,
    approvedActions: actor.approvedActions,
    approvedTargets: actor.approvedTargets,
  };
}

export const knowledgeSearchOperation: ToolOperation = async (ctx) => {
  const args = ctx.request.args as { query: string };
  const retrieval = await memoryOf(ctx).searchDocuments(memoryActorOf(ctx.request.actor), {
    query: args.query,
    limit: 10,
  });
  return {
    hits: retrieval.documents.map((document) => ({
      docId: document.docId,
      score: document.score,
      trust: document.trust,
      provenance: document.provenance,
    })),
    denied: retrieval.denied,
  };
};

export const knowledgeIndexOperation: ToolOperation = async (ctx) => {
  const args = ctx.request.args as { docIds: string[] };
  const { indexed } = await memoryOf(ctx).indexDocuments(memoryActorOf(ctx.request.actor), args.docIds);
  return { indexed: [...indexed] };
};

export class KnowledgeExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    switch (task.kind) {
      case "knowledge.search": {
        const actor = toolActorOf("knowledge", task);
        // The code-owned operation is selected from the sealed catalog. All
        // Qdrant/Mongo access stays inside the Memory Service, which performs
        // its own owner/tenant filter and per-document authorization.
        const result = await ctx.tools.execute(
          actor,
          { name: knowledgeSearchTool.name, args: { query: task.input.query } },
          { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
        );
        return result.data as Record<string, unknown>;
      }
      case "knowledge.index": {
        const actor = toolActorOf("knowledge", task);
        const result = await ctx.tools.execute(
          actor,
          { name: knowledgeIndexTool.name, args: { docIds: task.input.docIds } },
          { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
        );
        return result.data as Record<string, unknown>;
      }
      default:
        throw new AppError("unsupported_task_kind", `knowledge worker does not accept '${task.kind}'`, 422);
    }
  }
}
