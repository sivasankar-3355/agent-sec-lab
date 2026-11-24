import { z } from "zod";
import { ValidationError } from "../core/errors.js";
import type { TaskStatus } from "../core/domain.js";

export const A2A_PROTOCOL_VERSION = "0.3.0";

export type AgentKind = "orchestrator" | "recon" | "knowledge" | "report";
export type TaskKind = "run.start" | "recon.run" | "knowledge.index" | "knowledge.search" | "report.generate";
export type A2AStatus = "submitted" | "input-required" | "working" | "completed" | "failed" | "canceled";

export const agentKindSchema = z.enum(["orchestrator", "recon", "knowledge", "report"]);
export const taskKindSchema = z.enum(["run.start", "recon.run", "knowledge.index", "knowledge.search", "report.generate"]);
export const a2aStatusSchema = z.enum(["submitted", "input-required", "working", "completed", "failed", "canceled"]);

const scopeSchema = z.object({ targets: z.array(z.string().trim().min(1).max(2048)).min(1) }).strict();
const runStartInputSchema = z.object({
  scope: scopeSchema,
  config: z.record(z.string(), z.unknown()).optional(),
}).strict();
const reconRunInputSchema = z.object({
  target: z.string().trim().min(1).max(2048),
  rulesRef: z.string().trim().min(1).max(256).optional(),
}).strict();
const knowledgeIndexInputSchema = z
  .object({ docIds: z.array(z.string().trim().min(1).max(128)).min(1) })
  .strict();
const knowledgeSearchInputSchema = z.object({ query: z.string().trim().min(1).max(2000) }).strict();
const reportGenerateInputSchema = z.object({
  reportKind: z.enum(["overview", "detailed"]).default("overview"),
}).strict();

export const taskInputSchemas: Record<TaskKind, z.ZodType<Record<string, unknown>, z.ZodTypeDef, unknown>> = {
  "run.start": runStartInputSchema,
  "recon.run": reconRunInputSchema,
  "knowledge.index": knowledgeIndexInputSchema,
  "knowledge.search": knowledgeSearchInputSchema,
  "report.generate": reportGenerateInputSchema,
};

export function validateTaskInput(kind: TaskKind, raw: unknown): Record<string, unknown> {
  const schema = taskInputSchemas[kind];
  const result = schema.safeParse(raw);
  if (!result.success) {
    const detail = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new ValidationError(`invalid input for task '${kind}': ${detail}`);
  }
  return result.data;
}

export interface Artifact {
  artifactId: string;
  text: string;
}

export interface TaskInit {
  taskId: string;
  runId: string;
  parentTaskId?: string;
  kind: TaskKind;
  input: Record<string, unknown>;
}

export interface A2ATask extends TaskInit {
  status: A2AStatus;
  artifact?: Artifact;
  error?: string;
}

export interface A2AMessage {
  messageId: string;
  runId: string;
  taskId: string;
  parentTaskId?: string;
  agentId?: AgentKind;
  text: string;
  metadata?: Record<string, unknown>;
}

export interface InitializeResult {
  protocolVersion: string;
  agentId: AgentKind;
  capabilities: { streaming: boolean; pushNotifications: boolean };
}

const taskBaseSchema = z.object({
  taskId: z.string().uuid(),
  runId: z.string().uuid(),
  parentTaskId: z.string().uuid().optional(),
  kind: taskKindSchema,
  input: z.record(z.string(), z.unknown()),
}).strict();

export const taskInitSchema = z.object({ task: taskBaseSchema }).strict();

export const taskSchema = z
  .object({
    taskId: z.string().uuid(),
    runId: z.string().uuid(),
    parentTaskId: z.string().uuid().optional(),
    kind: taskKindSchema,
    status: a2aStatusSchema,
    input: z.record(z.string(), z.unknown()),
    artifact: z.object({ artifactId: z.string().min(1).max(128), text: z.string() }).strict().optional(),
    error: z.string().optional(),
  })
  .strict();

export const a2aMessageSchema = z
  .object({
    messageId: z.string().uuid(),
    runId: z.string().uuid(),
    taskId: z.string().uuid(),
    parentTaskId: z.string().uuid().optional(),
    agentId: agentKindSchema.optional(),
    text: z.string().min(1).max(16_384),
    metadata: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

export const initializeParamsSchema = z.object({ agentId: agentKindSchema.optional() }).strict();
export const initializeResultSchema = z
  .object({
    protocolVersion: z.literal(A2A_PROTOCOL_VERSION),
    agentId: agentKindSchema,
    capabilities: z.object({ streaming: z.boolean(), pushNotifications: z.boolean() }).strict(),
  })
  .strict();
export const messageSendParamsSchema = z.object({ message: a2aMessageSchema }).strict();
export const taskGetParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const taskCancelParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const jsonRpcRequestSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: z.string().min(1).max(64),
    method: z.string().min(1).max(128),
    params: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

export interface JsonRpcErrorBody {
  code: number;
  message: string;
  data?: unknown;
}

export const jsonRpcResponseSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string(), z.null()]),
    result: z.unknown().optional(),
    error: z.object({ code: z.number(), message: z.string().min(1), data: z.unknown().optional() }).strict().optional(),
  })
  .strict();

export const a2aMethods: readonly string[] = [
  "initialize",
  "agentCard",
  "message/send",
  "tasks/send",
  "tasks/get",
  "tasks/cancel",
];

export type A2AMethod = (typeof a2aMethods)[number];

export function a2aStatusOf(status: TaskStatus): A2AStatus {
  switch (status) {
    case "PENDING":
      return "submitted";
    case "ASSIGNED":
      return "input-required";
    case "RUNNING":
      return "working";
    case "SUCCEEDED":
      return "completed";
    case "FAILED":
      return "failed";
    case "CANCELLED":
      return "canceled";
  }
}

export function domainStatusOf(status: A2AStatus): TaskStatus {
  switch (status) {
    case "submitted":
      return "PENDING";
    case "input-required":
      return "ASSIGNED";
    case "working":
      return "RUNNING";
    case "completed":
      return "SUCCEEDED";
    case "failed":
      return "FAILED";
    case "canceled":
      return "CANCELLED";
  }
}

export function artifactFor(output: unknown): Artifact {
  return { artifactId: "result", text: JSON.stringify(output) };
}

export function artifactText(artifact: Artifact): string {
  return artifact.text;
}

export function parseArtifact<T>(artifact: Artifact): T {
  return JSON.parse(artifact.text) as T;
}