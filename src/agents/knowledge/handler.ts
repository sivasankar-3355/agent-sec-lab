import { AppError } from "../../core/errors.js";
import type { AuthzResource } from "../../security/protocols.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { assertAuthorized, workloadOfCaller } from "../authz.js";
import { knowledgeIndexTool, knowledgeSearchTool } from "../tools.js";
import { validateToolCall } from "../../security/prompt/index.js";
import { retrieveAuthorizedDocuments } from "./retrieval.js";

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

export class KnowledgeExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    switch (task.kind) {
      case "knowledge.search": {
        const query = String(task.input.query);
        const user = task.authz?.userId ?? "";

        const authorization =
          task.authz !== undefined
            ? await assertAuthorized(ctx.security.authz, "knowledge.search", {
                ...opBase(task),
                requestedAction: "knowledge.search",
                requestedTarget: query,
                // The un-scoped search is bounded to the actor's tenant;
                // individual documents are then checked against their real
                // tenant by the retrieval boundary below.
                ...(task.authz.tenantId !== undefined ? { resourceTenantId: task.authz.tenantId } : {}),
              })
            : undefined;

        // Independent tool gate: strict query schema + signed-grant bound.
        const searchCall = validateToolCall(knowledgeSearchTool, { query }, {
          ...(task.authz !== undefined ? { grant: task.authz } : {}),
          ...(authorization !== undefined ? { decision: authorization } : {}),
        });

        // Secure RAG boundary: authorized documents only, provenance retained,
        // results tagged as untrusted data.
        const retrieval = await retrieveAuthorizedDocuments({
          repos: ctx.repos,
          embedding: ctx.security.embedding,
          audit: ctx.audit,
          query: searchCall.query,
          limit: 10,
          user,
          ...(task.authz !== undefined ? { authz: ctx.security.authz } : {}),
          ...(task.authz?.tenantId !== undefined ? { tenantId: task.authz.tenantId } : {}),
          runId: task.runId,
          taskId: task.taskId,
          ...(task.authz !== undefined && task.authz.userId !== "" ? { principal: task.authz.userId } : {}),
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
        // Strict, independent validation of the document set selected by code
        // or by the caller; the model never chooses which documents to index.
        const indexCall = validateToolCall(
          knowledgeIndexTool,
          { docIds: (task.input.docIds as string[]) ?? [] },
          { ...(task.authz !== undefined ? { grant: task.authz } : {}) },
        );

        const indexed: string[] = [];
        for (const docId of indexCall.docIds) {
          const doc = await ctx.repos.documents.get(docId);
          if (!doc) continue;
          if (task.authz !== undefined) {
            // Independent PEP: this specific document must be accessible.
            await assertAuthorized(ctx.security.authz, "knowledge.index", {
              ...opBase(task),
              requestedAction: "knowledge.index",
              requestedObject: docId,
              resourceOwner: doc.ownerUserId ?? "",
              resourceTenantId: doc.tenantId ?? "",
            });
          }
          await ctx.repos.documents.markIndexed(docId, doc.chunkCount);
          indexed.push(docId);
        }
        return { indexed };
      }
      default:
        throw new AppError("unsupported_task_kind", `knowledge worker does not accept '${task.kind}'`, 422);
    }
  }
}
