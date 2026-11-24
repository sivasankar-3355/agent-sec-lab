import { AppError } from "../../core/errors.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";

export const knowledgeAcceptedKinds: readonly ["knowledge.search", "knowledge.index"] = [
  "knowledge.search",
  "knowledge.index",
];

export class KnowledgeExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    switch (task.kind) {
      case "knowledge.search": {
        const query = String(task.input.query);
        const vectors = await ctx.security.embedding.embed([query]);
        const hits = await ctx.repos.knowledge.search(vectors[0]!, 10);
        return { hits: hits.map((h) => ({ docId: h.docId, score: h.score })) };
      }
      case "knowledge.index": {
        const docIds = (task.input.docIds as string[]) ?? [];
        const indexed: string[] = [];
        for (const docId of docIds) {
          const doc = await ctx.repos.documents.get(docId);
          if (!doc) continue;
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