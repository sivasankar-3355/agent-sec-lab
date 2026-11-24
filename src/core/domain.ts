export type RunState =
  | "CREATED"
  | "STARTED"
  | "RECON"
  | "KNOWLEDGE"
  | "REPORT"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export type TaskStatus = "PENDING" | "ASSIGNED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "CANCELLED";

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type FindingStatus = "open" | "accepted" | "mitigated" | "verified" | "closed";

export type ReportStatus = "generating" | "ready" | "failed";

export type DocumentStatus = "pending" | "indexed" | "failed";

export interface TimelineEntry {
  state: RunState;
  ts: string;
}

export interface Scope {
  targets: readonly string[];
}

export interface RunCreateInput {
  name: string;
  scope: Scope;
  config?: Record<string, unknown>;
}

export interface RunRecord {
  runId: string;
  name: string;
  scope: Scope;
  config: Record<string, unknown>;
  state: RunState;
  timeline: readonly TimelineEntry[];
  tsCreated: string;
  tsUpdated: string;
}

export interface TaskRecord {
  taskId: string;
  runId: string;
  parentTaskId?: string;
  kind: string;
  input: Record<string, unknown>;
  status: TaskStatus;
  attempts: number;
  output?: unknown;
  error?: string;
  tsCreated: string;
  tsUpdated: string;
}

export interface FindingRecord {
  findingId: string;
  runId: string;
  taskId: string;
  agent: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence?: unknown;
  refs: readonly string[];
  tags: readonly string[];
  status: FindingStatus;
  hash: string;
  tsCreated: string;
  tsUpdated: string;
}

export interface ReportRecord {
  reportId: string;
  runId: string;
  status: ReportStatus;
  kind: string;
  summary: string;
  content: string;
  checksum: string;
  signature?: string;
  format: string;
  version: number;
  tsCreated: string;
  tsUpdated: string;
}

export interface DocumentRecord {
  docId: string;
  source: string;
  title: string;
  contentType: string;
  contentHash: string;
  chunkCount: number;
  status: DocumentStatus;
  runId?: string;
  metadata: Record<string, unknown>;
  tsCreated: string;
  tsUpdated: string;
}