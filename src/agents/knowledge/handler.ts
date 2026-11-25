import { AppError, NotConfiguredError } from "../../core/errors.js";
import type { AuthzResource } from "../../security/protocols.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { assertAuthorized, workloadOfCaller } from "../authz.js";
import { knowledgeIndexTool, knowledgeSearchTool } from "../tools.js";
import { validateToolCall } from "../../security/prompt/index.js";
import type { MemoryActor, MemoryService } from "../memory.js";

export const knowledgeAcceptedKinds: readonly ["knowledge.search", "knowledge.index"] = [
  "knowledge.search",
  "knowledge.index",
];

function opBase(task: WorkerExecuteInput): AuthzResource {
  return {
    kind: "operation",
    workload: workloadOfCaller(task.authz?.caller),
    agent: "knowledge",
    runId: task.runId,
    approvedTargets: task.authz?.scopeTargets ?? [],
    approvedActions: task.authz?.permittedActions ?? [],
    ...(task.authz?.userId !== undefined && task.authz.userId !== "" ? { user: task.authz.userId } : {}),
    ...(task.authz?.tenantId !== undefined ? { tenantId: task.authz.tenantId } : {}),
  };
}

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
        const query = String(task.input.query);
        const actor = actorOf(task);

        // Independent PEP for the tool gate. The Memory Service performs its
        // own authorization for the retrieval; this decision only gates the
        // tool call.
        const authorization = await assertAuthorized(ctx.security.authz, "knowledge.search", {
          ...opBase(task),
          requestedAction: "knowledge.search",
          requestedTarget: query,
          ...(task.authz?.tenantId !== undefined ? { resourceTenantId: task.authz.tenantId } : {}),
        });

        const searchCall = validateToolCall(knowledgeSearchTool, { query }, {
          ...(task.authz !== undefined ? { grant: task.authz } : {}),
          decision: authorization,
        });

        // All Qdrant/Mongo document access happens inside the Memory Service:
        // server-side owner/tenant filter, per-document authorization,
        // provenance and untrusted tagging.
        const retrieval = await memoryOf(ctx).searchDocuments(actor, {
          query: searchCall.query,
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
      }
      case "knowledge.index": {
        const actor = actorOf(task);
        // Strict validation of the document set; the model never chooses which
        // documents to index.
        const indexCall = validateToolCall(
          knowledgeIndexTool,
          { docIds: (task.input.docIds as string[]) ?? [] },
          { ...(task.authz !== undefined ? { grant: task.authz } : {}) },
        );

        const { indexed } = await memoryOf(ctx).indexDocuments(actor, indexCall.docIds);
        return { indexed: [...indexed] };
      }
      default:
        throw new AppError("unsupported_task_kind", `knowledge worker does not accept '${task.kind}'`, 422);
    }
  }
}
