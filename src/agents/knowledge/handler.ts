import { AppError, NotConfiguredError } from "../../core/errors.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { workloadOfCaller } from "../authz.js";
import { knowledgeIndexTool, knowledgeSearchTool } from "../tools.js";
import { toolActorOf } from "../tool-actor.js";
import type { MemoryActor, MemoryService } from "../memory.js";

export const knowledgeAcceptedKinds: readonly ["knowledge.search", "knowledge.index"] = [
  "knowledge.search",
  "knowledge.index",
];

/** Build the memory actor from the verified run-token context only. */
function actorOf(task: WorkerExecuteInput): MemoryActor {
  const authz = task.authz;
  if (authz === undefined) {
    throw new NotConfiguredError("knowledge executor requires a verified authorization context");
  }
  return {
    kind: "operation",
    principal: authz.caller,
    userId: authz.userId,
    scopes: authz.scopes,
    ...(authz.tenantId !== undefined ? { tenantId: authz.tenantId } : {}),
    ...(authz.runId !== undefined ? { runId: authz.runId } : {}),
    agent: "knowledge",
    workload: workloadOfCaller(authz.caller),
    approvedActions: authz.permittedActions,
    approvedTargets: authz.scopeTargets,
  };
}

function memoryOf(ctx: WorkerContext): MemoryService {
  if (ctx.memory === undefined) {
    throw new NotConfiguredError("memory service is not configured");
  }
  return ctx.memory;
}

export class KnowledgeExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    switch (task.kind) {
      case "knowledge.search": {
        const actor = toolActorOf("knowledge", task);

        // The Tool Broker enforces the knowledge.search allowlist, verified
        // identity, run binding, strict query schema, OPA action grant and
        // rate/timeout limits. All Qdrant/Mongo document access then happens
        // inside the Memory Service with its own server-side owner/tenant
        // filter and per-document authorization.
        const result = await ctx.tools.execute(
          knowledgeSearchTool,
          actor,
          { name: knowledgeSearchTool.name, args: { query: task.input.query } },
          async (call) => {
            const retrieval = await memoryOf(ctx).searchDocuments(actorOf(task), {
              query: call.args.query,
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
          },
          { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
        );

        return result.data;
      }
      case "knowledge.index": {
        const actor = toolActorOf("knowledge", task);

        // The model never chooses which documents to index. Strict validation
        // happens in the broker; per-document ownership and tenant checks
        // happen inside the Memory Service.
        const result = await ctx.tools.execute(
          knowledgeIndexTool,
          actor,
          { name: knowledgeIndexTool.name, args: { docIds: task.input.docIds } },
          async (call) => {
            const { indexed } = await memoryOf(ctx).indexDocuments(actorOf(task), call.args.docIds);
            return { indexed: [...indexed] };
          },
          { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
        );

        return result.data;
      }
      default:
        throw new AppError("unsupported_task_kind", `knowledge worker does not accept '${task.kind}'`, 422);
    }
  }
}
