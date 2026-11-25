import { Router } from "express";
import { z } from "zod";
import { NotConfiguredError } from "../../core/errors.js";
import {
  MEMORY_LIMITS,
  MEMORY_RETENTION_SECONDS,
  WRITABLE_MEMORY_SOURCES,
  type MemoryRecord,
} from "../../core/memory.js";
import type { MemorySearchView, MemoryService } from "../../agents/memory.js";
import type { RouterDeps } from "./contract.js";
import { parseBody, parseId, readMemoryActor, readUserId, requireAuthorized } from "./contract.js";

const sourceTypeSchema = z.enum(WRITABLE_MEMORY_SOURCES);
const apiScopeSchema = z.enum(["user", "run"]);

const writeSchema = z
  .object({
    content: z.string().min(1).max(MEMORY_LIMITS.maxContentChars),
    source_type: sourceTypeSchema,
    source_id: z.string().trim().min(1).max(MEMORY_LIMITS.maxSourceIdChars),
    scope: apiScopeSchema.default("user"),
    key: z.string().trim().min(1).max(MEMORY_LIMITS.maxKeyChars).optional(),
    tags: z
      .array(z.string().trim().min(1).max(MEMORY_LIMITS.maxTagChars))
      .max(MEMORY_LIMITS.maxTags)
      .optional(),
    run_id: z.string().uuid().optional(),
    conversation_id: z.string().trim().min(1).max(MEMORY_LIMITS.maxConversationIdChars).optional(),
    // Absolute ceiling; the service clamps per source type.
    ttl_seconds: z.number().int().min(MEMORY_LIMITS.minTtlSeconds).max(MEMORY_RETENTION_SECONDS.external_document).optional(),
  })
  .strict()
  .superRefine((body, ctx) => {
    if (body.scope === "run" && body.run_id === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "run_id is required for run-scoped memory", path: ["run_id"] });
    }
  });

const searchSchema = z
  .object({
    scope: apiScopeSchema.optional(),
    run_id: z.string().uuid().optional(),
    key: z.string().trim().min(1).max(MEMORY_LIMITS.maxKeyChars).optional(),
    q: z.string().trim().min(1).max(MEMORY_LIMITS.maxQueryChars).optional(),
    limit: z.coerce.number().int().min(1).max(MEMORY_LIMITS.maxResults).default(MEMORY_LIMITS.defaultResults),
  })
  .strict()
  .superRefine((body, ctx) => {
    if (body.scope === "run" && body.run_id === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "run_id is required to search run-scoped memory", path: ["run_id"] });
    }
  });

const updateSchema = z
  .object({
    content: z.string().min(1).max(MEMORY_LIMITS.maxContentChars).optional(),
    key: z.string().trim().min(1).max(MEMORY_LIMITS.maxKeyChars).nullable().optional(),
    tags: z
      .array(z.string().trim().min(1).max(MEMORY_LIMITS.maxTagChars))
      .max(MEMORY_LIMITS.maxTags)
      .optional(),
    ttl_seconds: z.number().int().min(MEMORY_LIMITS.minTtlSeconds).max(MEMORY_RETENTION_SECONDS.external_document).optional(),
    expected_version: z.number().int().min(1).optional(),
  })
  .strict()
  .refine(
    (body) =>
      body.content !== undefined ||
      body.key !== undefined ||
      body.tags !== undefined ||
      body.ttl_seconds !== undefined,
    { message: "no memory changes were supplied" },
  );

function serviceOf(deps: RouterDeps): MemoryService {
  if (deps.memory === undefined) throw new NotConfiguredError("memory store is not configured");
  return deps.memory;
}

function metadata(record: MemoryRecord): Record<string, unknown> {
  return {
    memory_id: record.memoryId,
    scope: record.scope,
    collection: record.collection,
    ...(record.key !== undefined ? { key: record.key } : {}),
    trust: record.trust,
    authoritative: record.authoritative,
    conflict: record.conflict,
    owner_user_id: record.ownerUserId,
    ...(record.tenantId !== undefined ? { tenant_id: record.tenantId } : {}),
    ...(record.runId !== undefined ? { run_id: record.runId } : {}),
    ...(record.agent !== undefined ? { agent: record.agent } : {}),
    tags: record.tags,
    provenance: record.provenance,
    integrity: record.integrity,
    ...(record.injection !== undefined ? { injection: record.injection } : {}),
    ...(record.expiresAt !== undefined ? { expires_at: record.expiresAt } : {}),
    created_at: record.tsCreated,
    updated_at: record.tsUpdated,
  };
}

function searchView(view: MemorySearchView): Record<string, unknown> {
  return {
    memory_id: view.memoryId,
    scope: view.scope,
    collection: view.collection,
    ...(view.key !== undefined ? { key: view.key } : {}),
    content: view.content,
    truncated: view.truncated,
    trust: view.trust,
    authoritative: view.authoritative,
    conflict: view.conflict,
    provenance: view.provenance,
    integrity: view.integrity,
    ...(view.injection !== undefined ? { injection: view.injection } : {}),
    ...(view.expiresAt !== undefined ? { expires_at: view.expiresAt } : {}),
    created_at: view.tsCreated,
    updated_at: view.tsUpdated,
  };
}

export function createMemoryRouter(deps: RouterDeps): Router {
  const router = Router();

  router.post("/memory", async (req, res) => {
    const userId = readUserId(res);
    await requireAuthorized(deps.authz, "memory:write", res, { resourceOwner: userId });
    const body = parseBody(writeSchema, req.body);
    const record = await serviceOf(deps).write(readMemoryActor(res), {
      content: body.content,
      sourceType: body.source_type,
      sourceId: body.source_id,
      scope: body.scope,
      ...(body.key !== undefined ? { key: body.key } : {}),
      ...(body.tags !== undefined ? { tags: body.tags } : {}),
      ...(body.run_id !== undefined ? { runId: body.run_id } : {}),
      ...(body.conversation_id !== undefined ? { conversationId: body.conversation_id } : {}),
      ...(body.ttl_seconds !== undefined ? { ttlSeconds: body.ttl_seconds } : {}),
    });
    res.status(201).json(metadata(record));
  });

  router.get("/memory", async (req, res) => {
    const userId = readUserId(res);
    await requireAuthorized(deps.authz, "memory:read", res, { resourceOwner: userId });
    const query = parseBody(searchSchema, req.query);
    const result = await serviceOf(deps).search(readMemoryActor(res), {
      ...(query.scope !== undefined ? { scope: query.scope } : {}),
      ...(query.run_id !== undefined ? { runId: query.run_id } : {}),
      ...(query.key !== undefined ? { key: query.key } : {}),
      ...(query.q !== undefined ? { q: query.q } : {}),
      limit: query.limit,
    });
    res.status(200).json({ memories: result.memories.map(searchView), truncated: result.truncated });
  });

  router.get("/memory/:memoryId", async (req, res) => {
    const userId = readUserId(res);
    const memoryId = parseId(req.params.memoryId, "memory");
    await requireAuthorized(deps.authz, "memory:read", res, { resourceOwner: userId });
    const record = await serviceOf(deps).get(readMemoryActor(res), memoryId);
    res.status(200).json({ ...metadata(record), content: record.content });
  });

  router.patch("/memory/:memoryId", async (req, res) => {
    const userId = readUserId(res);
    const memoryId = parseId(req.params.memoryId, "memory");
    await requireAuthorized(deps.authz, "memory:write", res, { resourceOwner: userId });
    const body = parseBody(updateSchema, req.body);
    const record = await serviceOf(deps).update(readMemoryActor(res), memoryId, {
      ...(body.content !== undefined ? { content: body.content } : {}),
      ...(body.key !== undefined ? { key: body.key } : {}),
      ...(body.tags !== undefined ? { tags: body.tags } : {}),
      ...(body.ttl_seconds !== undefined ? { ttlSeconds: body.ttl_seconds } : {}),
      ...(body.expected_version !== undefined ? { expectedVersion: body.expected_version } : {}),
    });
    res.status(200).json({ ...metadata(record), content: record.content });
  });

  router.delete("/memory/:memoryId", async (req, res) => {
    const userId = readUserId(res);
    const memoryId = parseId(req.params.memoryId, "memory");
    await requireAuthorized(deps.authz, "memory:write", res, { resourceOwner: userId });
    const deleted = await serviceOf(deps).remove(readMemoryActor(res), memoryId);
    res.status(200).json({ deleted });
  });

  return router;
}
