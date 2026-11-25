import { Router } from "express";
import { z } from "zod";
import type { RouterDeps } from "./contract.js";
import { parseBody, readMemoryActor, readUserId, requireAuthorized } from "./contract.js";
import { NotConfiguredError } from "../../core/errors.js";
import type { MemoryService } from "../../agents/memory.js";

const ingestSchema = z
  .object({
    source: z.string().trim().min(1).max(2048),
    content: z.string().min(1).max(2_000_000),
    content_type: z.string().trim().min(1).max(256).default("text/plain"),
    title: z.string().trim().min(1).max(200).optional(),
    run_id: z.string().uuid().optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const searchSchema = z
  .object({
    q: z.string().trim().min(1).max(2000),
    limit: z.coerce.number().int().min(1).max(50).default(10),
  })
  .strict();

function serviceOf(deps: RouterDeps): MemoryService {
  if (deps.memory === undefined) throw new NotConfiguredError("memory service is not configured");
  return deps.memory;
}

export function createKnowledgeRouter(deps: RouterDeps): Router {
  const router = Router();

  router.post("/knowledge/documents", async (req, res) => {
    const userId = readUserId(res);
    await requireAuthorized(deps.authz, "knowledge:write", res, { resourceOwner: userId });
    const body = parseBody(ingestSchema, req.body);

    // All admission, provenance, trust, embedding and storage happen inside the
    // Memory Service. The gateway never touches MongoDB or Qdrant directly.
    const result = await serviceOf(deps).ingestDocument(readMemoryActor(res), {
      source: body.source,
      content: body.content,
      contentType: body.content_type,
      ...(body.title !== undefined ? { title: body.title } : {}),
      ...(body.run_id !== undefined ? { runId: body.run_id } : {}),
      ...(body.metadata !== undefined ? { metadata: body.metadata } : {}),
    });

    deps.log.info({ docId: result.docId, chunkCount: result.chunkCount }, "document indexed");
    res.status(result.deduped ? 200 : 201).json({
      ...(result.docId !== "" ? { doc_id: result.docId } : {}),
      chunk_count: result.chunkCount,
      ...(result.deduped ? { deduped: true } : {}),
    });
  });

  router.get("/knowledge/search", async (req, res) => {
    const userId = readUserId(res);
    await requireAuthorized(deps.authz, "knowledge:read", res, { resourceOwner: userId });
    const query = parseBody(searchSchema, req.query);

    // Server-side owner/tenant filtering, per-document authorization and
    // untrusted provenance all happen in the Memory Service.
    const result = await serviceOf(deps).searchDocuments(readMemoryActor(res), {
      query: query.q,
      limit: query.limit,
    });

    res.status(200).json({
      hits: result.documents.map((document) => ({
        doc_id: document.docId,
        score: document.score,
        snippet: null,
        source: document.provenance.source,
        title: document.provenance.title,
        trust: document.trust,
      })),
      denied: result.denied,
    });
  });

  return router;
}
