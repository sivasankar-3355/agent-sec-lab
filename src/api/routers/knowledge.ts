import { Router } from "express";
import { z } from "zod";
import { chunkText } from "../../core/chunking.js";
import { stableHash } from "../../core/ids.js";
import { newId } from "../../core/ids.js";
import type { RouterDeps } from "./contract.js";
import { parseBody, readUserId, requireAuthorized } from "./contract.js";
import { readPrincipal } from "../auth.js";
import { authorizeDocumentAccess } from "../../agents/authz.js";

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

const searchSchema = z.object({
  q: z.string().trim().min(1).max(2000),
  limit: z.coerce.number().int().min(1).max(100).default(10),
}).strict();

export function createKnowledgeRouter(deps: RouterDeps): Router {
  const router = Router();

  router.post("/knowledge/documents", async (req, res) => {
    await requireAuthorized(deps.authz, "knowledge:write", res);
    const body = parseBody(ingestSchema, req.body);
    const userId = readUserId(res);

    const contentHash = stableHash(body.content);
    const existing = await deps.repos.documents.getByContentHash(contentHash);
    if (existing) {
      res.status(200).json({ doc_id: existing.docId, chunk_count: existing.chunkCount, deduped: true });
      return;
    }

    const chunks = chunkText(body.content);
    const vectors = await deps.embedding.embed(chunks.map((c) => c.text));

    const docId = newId();
    await deps.repos.knowledge.upsertChunks({
      docId,
      title: body.title ?? body.source,
      source: body.source,
      ...(body.run_id ? { runId: body.run_id } : {}),
      chunks: chunks.map((c) => ({ index: c.index, contentHash: c.contentHash })),
      vectors,
    });

    await deps.repos.documents.create({
      docId,
      source: body.source,
      title: body.title ?? body.source,
      contentType: body.content_type,
      contentHash,
      ...(body.run_id ? { runId: body.run_id } : {}),
      ...(userId.length > 0 ? { ownerUserId: userId } : {}),
      metadata: body.metadata ?? {},
    });
    await deps.repos.documents.markIndexed(docId, chunks.length);

    deps.log.info({ docId, chunkCount: chunks.length }, "document indexed");
    res.status(201).json({ doc_id: docId, chunk_count: chunks.length });
  });

  router.get("/knowledge/search", async (req, res) => {
    await requireAuthorized(deps.authz, "knowledge:read", res);
    const query = parseBody(searchSchema, req.query);

    const embedded = await deps.embedding.embed([query.q]);
    const hits = await deps.repos.knowledge.search(embedded[0]!, query.limit);

    // ABAC: only return documents the user owns (or global knowledge), so an
    // authenticated user cannot read another user's documents.
    const principal = readPrincipal(res);
    const userId = readUserId(res);
    const visible: Array<{ doc_id: string; score: number; snippet: null }> = [];
    for (const hit of hits) {
      const doc = await deps.repos.documents.get(hit.docId);
      if (!doc) continue;
      const allowed = await authorizeDocumentAccess({
        authz: deps.authz,
        kind: "api",
        action: "knowledge:read",
        user: userId,
        requestedObject: hit.docId,
        resourceOwner: doc.ownerUserId ?? "",
        resourceTenantId: doc.tenantId ?? "",
        scopes: principal?.scopes ?? [],
      });
      if (!allowed) continue;
      visible.push({ doc_id: hit.docId, score: hit.score, snippet: null });
    }

    res.status(200).json({ hits: visible });
  });

  return router;
}