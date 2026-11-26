import { z } from "zod";
import { defineTool, ToolRegistry } from "../security/tools/index.js";

/**
 * Code-owned tool catalog. Tool descriptions, schemas, allowlists, risk
 * classifications and execution limits are trusted source code; any
 * description or schema obtained externally must be treated as untrusted and
 * never registered without review.
 *
 * The registry is sealed at module load. The Tool Broker verifies that a call
 * passes the exact spec object defined here, so a caller cannot substitute a
 * permissive definition with the same name.
 */

const knowledgeProvenanceSchema = z
  .object({
    source: z.string(),
    title: z.string(),
    contentHash: z.string(),
    ownerUserId: z.string().optional(),
    tenantId: z.string().optional(),
  })
  .strict();

const knowledgeHitSchema = z
  .object({
    docId: z.string().min(1),
    score: z.number(),
    trust: z.literal("untrusted"),
    provenance: knowledgeProvenanceSchema,
  })
  .strict();

export const knowledgeSearchOutputSchema = z
  .object({
    hits: z.array(knowledgeHitSchema),
    denied: z.number().int().nonnegative(),
  })
  .strict();

export const knowledgeIndexOutputSchema = z
  .object({
    indexed: z.array(z.string().min(1)),
  })
  .strict();

export const reportGenerateOutputSchema = z
  .object({
    reportId: z.string().min(1),
  })
  .strict();

export const reconSnapshotTool = defineTool({
  name: "recon.snapshot",
  description: "Collect reconnaissance observations for an approved target.",
  schema: z.object({ target: z.string().trim().min(1).max(2048) }).strict(),
  allowedAgents: ["recon"],
  requiredAction: "recon.run",
  risk: "medium",
  target: { field: "target", kind: "host-or-url", resolve: true },
  limits: {
    timeoutMs: 30_000,
    maxOutputBytes: 256 * 1024,
    maxConcurrency: 4,
    rateLimit: { maxCalls: 30, windowMs: 60_000 },
  },
  // The sandbox output shape is adapter-owned. The broker still bounds its
  // size, tags it untrusted and inspects it for injection; the prompt layer
  // places it in an UNTRUSTED_DATA envelope.
});

export const knowledgeSearchTool = defineTool({
  name: "knowledge.search",
  description: "Search indexed knowledge for documents the caller may read.",
  schema: z.object({ query: z.string().trim().min(1).max(2000) }).strict(),
  allowedAgents: ["knowledge"],
  requiredAction: "knowledge.search",
  risk: "low",
  limits: {
    timeoutMs: 10_000,
    maxOutputBytes: 256 * 1024,
    maxConcurrency: 8,
    rateLimit: { maxCalls: 60, windowMs: 60_000 },
  },
  outputSchema: knowledgeSearchOutputSchema,
});

export const knowledgeIndexTool = defineTool({
  name: "knowledge.index",
  description: "Mark explicitly supplied documents as indexed after access checks.",
  schema: z
    .object({ docIds: z.array(z.string().trim().min(1).max(128)).min(1).max(100) })
    .strict(),
  allowedAgents: ["knowledge"],
  requiredAction: "knowledge.index",
  risk: "medium",
  limits: {
    timeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    maxConcurrency: 4,
    rateLimit: { maxCalls: 30, windowMs: 60_000 },
  },
  outputSchema: knowledgeIndexOutputSchema,
});

export const reportGenerateTool = defineTool({
  name: "report.generate",
  description: "Render the run's findings into a signed report artifact.",
  schema: z.object({ reportKind: z.enum(["overview", "detailed"]).default("overview") }).strict(),
  allowedAgents: ["report"],
  requiredAction: "report.generate",
  risk: "medium",
  limits: {
    timeoutMs: 30_000,
    maxOutputBytes: 128 * 1024,
    maxConcurrency: 4,
    rateLimit: { maxCalls: 20, windowMs: 60_000 },
  },
  outputSchema: reportGenerateOutputSchema,
});

export const agentToolRegistry = new ToolRegistry();
agentToolRegistry.register(reconSnapshotTool);
agentToolRegistry.register(knowledgeSearchTool);
agentToolRegistry.register(knowledgeIndexTool);
agentToolRegistry.register(reportGenerateTool);
agentToolRegistry.seal();
