import type {
  DocumentRecord,
  FindingRecord,
  FindingSeverity,
  FindingStatus,
  ReportRecord,
  ReportStatus,
  RunCreateInput,
  RunRecord,
  RunState,
  TaskRecord,
  TaskStatus,
  UserRecord,
} from "../../core/domain.js";

export interface UsersRepository {
  create(input: { userId: string; email: string; passwordHash: string; scopes: readonly string[] }): Promise<UserRecord>;
  getByEmail(email: string): Promise<UserRecord | null>;
  get(userId: string): Promise<UserRecord | null>;
}

export interface RunsRepository {
  create(input: RunCreateInput): Promise<RunRecord>;
  get(runId: string): Promise<RunRecord | null>;
  setState(runId: string, state: RunState, ts?: string): Promise<void>;
}

export interface TasksRepository {
  create(input: {
    taskId: string;
    runId: string;
    parentTaskId?: string;
    kind: string;
    input: Record<string, unknown>;
    status: "PENDING" | "ASSIGNED";
    attempts: number;
  }): Promise<TaskRecord>;
  get(taskId: string): Promise<TaskRecord | null>;
  setStatus(
    taskId: string,
    status: TaskStatus,
    detail?: { output?: unknown; error?: string },
  ): Promise<void>;
  listByRun(runId: string): Promise<readonly TaskRecord[]>;
}

export interface FindingsRepository {
  listByRun(runId: string, filter: { severity?: FindingSeverity; limit?: number }): Promise<readonly FindingRecord[]>;
  getByHash(hash: string): Promise<FindingRecord | null>;
  create(input: {
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
  }): Promise<FindingRecord>;
}

export interface ReportsRepository {
  getLatest(runId: string): Promise<ReportRecord | null>;
  create(input: {
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
  }): Promise<ReportRecord>;
}

export interface DocumentsRepository {
  get(docId: string): Promise<DocumentRecord | null>;
  getByContentHash(contentHash: string): Promise<DocumentRecord | null>;
  create(input: {
    docId: string;
    source: string;
    title: string;
    contentType: string;
    contentHash: string;
    runId?: string;
    ownerUserId?: string;
    tenantId?: string;
    metadata: Record<string, unknown>;
  }): Promise<DocumentRecord>;
  markIndexed(docId: string, chunkCount: number): Promise<void>;
}