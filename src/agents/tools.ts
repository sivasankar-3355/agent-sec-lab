import { z } from "zod";
import { defineTool, ToolRegistry } from "../security/prompt/tool.js";

/**
 * Code-owned tool catalog. Tool descriptions are trusted source code; any
 * description or schema obtained externally must be treated as untrusted and
 * never registered without review.
 */

export const reconSnapshotTool = defineTool({
  name: "recon.snapshot",
  description: "Collect reconnaissance observations for an approved target.",
  schema: z.object({ target: z.string().trim().min(1).max(2048) }).strict(),
  requiredAction: "recon.run",
  sensitivity: "medium",
  targetField: "target",
});

export const knowledgeSearchTool = defineTool({
  name: "knowledge.search",
  description: "Search indexed knowledge for documents the caller may read.",
  schema: z.object({ query: z.string().trim().min(1).max(2000) }).strict(),
  requiredAction: "knowledge.search",
  sensitivity: "low",
});

export const knowledgeIndexTool = defineTool({
  name: "knowledge.index",
  description: "Mark explicitly supplied documents as indexed after access checks.",
  schema: z
    .object({ docIds: z.array(z.string().trim().min(1).max(128)).min(1).max(100) })
    .strict(),
  requiredAction: "knowledge.index",
  sensitivity: "medium",
});

export const reportGenerateTool = defineTool({
  name: "report.generate",
  description: "Render the run's findings into a signed report artifact.",
  schema: z.object({ reportKind: z.enum(["overview", "detailed"]).default("overview") }).strict(),
  requiredAction: "report.generate",
  sensitivity: "medium",
});

export const agentToolRegistry = new ToolRegistry();
agentToolRegistry.register(reconSnapshotTool);
agentToolRegistry.register(knowledgeSearchTool);
agentToolRegistry.register(knowledgeIndexTool);
agentToolRegistry.register(reportGenerateTool);
