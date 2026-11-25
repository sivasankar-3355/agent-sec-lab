import { AppError } from "../../core/errors.js";
import type { AuthzResource } from "../../security/protocols.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { assertAuthorized, authorizeDocumentAccess, workloadOfCaller } from "../authz.js";

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

        if (task.authz !== undefined) {
          await assertAuthorized(ctx.security.authz, "knowledge.search", {
            ...opBase(task),
            requestedAction: "knowledge.search",
            requestedTarget: query,
            // The un-scoped search is bounded to the actor's tenant; individual
            // documents are then checked against their real tenant below.
            ...(task.authz.tenantId !== undefined ? { resourceTenantId: task.authz.tenantId } : {}),
          });
        }

        const vectors = await ctx.security.embedding.embed([query]);
        const hits = await ctx.repos.knowledge.search(vectors[0]!, 10);

        // ABAC: only return documents the user owns (or global knowledge).
        const filtered: Array<{ docId: string; score: number }> = [];
        for (const hit of hits) {
          const doc = await ctx.repos.documents.get(hit.docId);
          if (!doc) continue;
          if (task.authz !== undefined) {
            const accessible = await authorizeDocumentAccess({
              authz: ctx.security.authz,
              kind: "operation",
              action: "knowledge.search",
              user,
              requestedObject: hit.docId,
              resourceOwner: doc.ownerUserId ?? "",
              resourceTenantId: doc.tenantId ?? "",
              ...(task.authz.tenantId !== undefined ? { tenantId: task.authz.tenantId } : {}),
            });
            if (!accessible) continue;
          }
          filtered.push({ docId: hit.docId, score: hit.score });
        }
        return { hits: filtered };
      }
      case "knowledge.index": {
        const docIds = (task.input.docIds as string[]) ?? [];
        const indexed: string[] = [];
        for (const docId of docIds) {
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
