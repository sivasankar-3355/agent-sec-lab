import { Router } from "express";
import { z } from "zod";
import { chunkText } from "../../core/chunking.js";
import { stableHash } from "../../core/ids.js";
import { newId } from "../../core/ids.js";
import type { RouterDeps } from "./contract.js";
import { parseBody, readUserId, requireAuthorized } from "./contract.js";
import { readPrincipal } from "../auth.js";
import { authorizeDocumentAccess } from "../../agents/authz.js";
import { inspectUntrustedContent } from "../../security/prompt/index.js";

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

    // Ingested content is untrusted. Detection is supplementary: the document
    // is stored as data with provenance/trust markers, never as instructions.
    const inspection = await inspectUntrustedContent(deps.audit, {
      tier: "external",
      source: `knowledge.ingest:${body.source}`,
      content: body.content,
      agent: "gateway",
      ...(body.run_id !== undefined ? { runId: body.run_id } : {}),
      ...(userId.length > 0 ? { principal: userId } : {}),
    });

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
      metadata: {
        ...(body.metadata ?? {}),
        trust: "untrusted",
        provenance: {
          source: body.source,
          ...(body.run_id !== undefined ? { runId: body.run_id } : {}),
          ...(userId.length > 0 ? { ownerUserId: userId } : {}),
        },
        injection: {
          suspicious: inspection.result.suspicious,
          score: inspection.result.score,
          categories: inspection.result.signals.map((signal) => signal.category),
        },
      },
    });
    await deps.repos.documents.markIndexed(docId, chunks.length);

    deps.log.info({ docId, chunkCount: chunks.length }, "document indexed");
    res.status(201).json({ doc_id: docId, chunk_count: chunks.length });
  });

  router.get("/knowledge/search", async (req, res) => {
    await requireAuthorized(deps.authz, "knowledge:read", res);
    const query = parseBody(searchSchema, req.query);
    const principal = readPrincipal(res);
    const userId = readUserId(res);

    // The query is user-supplied data; inspect/audit it and keep retrieval
    // bounded by the code-owned limit in the request schema.
    await inspectUntrustedContent(deps.audit, {
      tier: "user-request",
      source: "knowledge.search.query",
      content: query.q,
      agent: "gateway",
      ...(userId.length > 0 ? { principal: userId } : {}),
    });

    const embedded = await deps.embedding.embed([query.q]);
    const hits = await deps.repos.knowledge.search(embedded[0]!, query.limit);

    // ABAC: only return documents the user owns (or global knowledge), so an
    // authenticated user cannot read another user's documents.
    const visible: Array<{
      doc_id: string;
      score: number;
      snippet: null;
      source: string;
      title: string;
      trust: "untrusted";
    }> = [];
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
      // Preserve provenance and mark the retrieved content as untrusted data.
      visible.push({
        doc_id: hit.docId,
        score: hit.score,
        snippet: null,
        source: doc.source,
        title: doc.title,
        trust: "untrusted",
      });
    }

    res.status(200).json({ hits: visible });
  });

  return router;
}