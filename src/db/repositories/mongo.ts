import { MongoServerError, type Collection, type Db } from "mongodb";
import { newId } from "../../core/ids.js";
import type {
  DocumentRecord,
  FindingRecord,
  FindingSeverity,
  ReportRecord,
  RunCreateInput,
  RunRecord,
  RunState,
  TaskRecord,
} from "../../core/domain.js";
import type {
  DocumentsRepository,
  FindingsRepository,
  ReportsRepository,
  RunsRepository,
  TasksRepository,
} from "./contracts.js";

type MongoDoc = {
  _id: string;
  runId?: string;
  name?: string;
  scope?: { targets: string[] };
  config?: Record<string, unknown>;
  state?: string;
  status?: string;
  version?: number;
  timeline?: { state: string; ts: string }[];
  tsCreated?: string;
  tsUpdated?: string;
  taskId?: string;
  kind?: string;
  agent?: string;
  parentTaskId?: string;
  input?: Record<string, unknown>;
  output?: unknown;
  error?: string;
  attempts?: number;
  severity?: string;
  findingId?: string;
  title?: string;
  description?: string;
  evidence?: unknown;
  refs?: string[];
  tags?: string[];
  hash?: string;
  reportId?: string;
  summary?: string;
  content?: string;
  checksum?: string;
  signature?: string;
  format?: string;
  docId?: string;
  source?: string;
  contentType?: string;
  contentHash?: string;
  chunkCount?: number;
  metadata?: Record<string, unknown>;
};

type MongoDBFilter = { _id: string; runId: string; severity?: string };

function isoNow(): string {
  return new Date().toISOString();
}

class MongoRunsRepository implements RunsRepository {
  private readonly collection: Collection<MongoDoc>;

  constructor(db: Db) {
    this.collection = db.collection<MongoDoc>("runs");
  }

  async create(input: RunCreateInput): Promise<RunRecord> {
    const now = isoNow();
    const runId = newId();
    const doc: MongoDoc = {
      _id: runId,
      runId,
      name: input.name,
      scope: { targets: [...input.scope.targets] },
      config: input.config ?? {},
      state: "CREATED",
      timeline: [{ state: "CREATED", ts: now }],
      tsCreated: now,
      tsUpdated: now,
    };
    await this.collection.insertOne(doc);
    return this.toRecord(doc);
  }

  async get(runId: string): Promise<RunRecord | null> {
    const doc = await this.collection.findOne({ _id: runId });
    return doc ? this.toRecord(doc) : null;
  }

  async setState(runId: string, state: RunState, ts?: string): Promise<void> {
    const tsValue = ts ?? isoNow();
    await this.collection.updateOne(
      { _id: runId },
      { $set: { state, tsUpdated: tsValue }, $push: { timeline: { state, ts: tsValue } } },
    );
  }

  private toRecord(doc: MongoDoc): RunRecord {
    return {
      runId: doc.runId as string,
      name: doc.name as string,
      scope: doc.scope as { targets: readonly string[] },
      config: (doc.config ?? {}) as Record<string, unknown>,
      state: doc.state as RunState,
      timeline: (doc.timeline as readonly { state: RunState; ts: string }[]) ?? [],
      tsCreated: doc.tsCreated as string,
      tsUpdated: doc.tsUpdated as string,
    };
  }
}

class MongoTasksRepository implements TasksRepository {
  private readonly collection: Collection<MongoDoc>;

  constructor(db: Db) {
    this.collection = db.collection<MongoDoc>("tasks");
  }

  async create(input: {
    taskId: string;
    runId: string;
    parentTaskId?: string;
    kind: string;
    input: Record<string, unknown>;
    status: "PENDING" | "ASSIGNED";
    attempts: number;
  }): Promise<TaskRecord> {
    const now = isoNow();
    const doc: MongoDoc = {
      _id: input.taskId,
      taskId: input.taskId,
      runId: input.runId,
      ...(input.parentTaskId !== undefined ? { parentTaskId: input.parentTaskId } : {}),
      kind: input.kind,
      input: input.input,
      status: input.status,
      attempts: input.attempts,
      tsCreated: now,
      tsUpdated: now,
    };
    await this.collection.insertOne(doc);
    return this.toRecord(doc);
  }

  async get(taskId: string): Promise<TaskRecord | null> {
    const doc = await this.collection.findOne({ _id: taskId });
    return doc ? this.toRecord(doc) : null;
  }

  async setStatus(
    taskId: string,
    status: TaskRecord["status"],
    detail?: { output?: unknown; error?: string },
  ): Promise<void> {
    const $set: Record<string, unknown> = { status, tsUpdated: isoNow() };
    if (detail?.output !== undefined) $set.output = detail.output;
    if (detail?.error !== undefined) $set.error = detail.error;
    await this.collection.updateOne({ _id: taskId }, { $set });
  }

  async listByRun(runId: string): Promise<readonly TaskRecord[]> {
    const docs = await this.collection.find({ runId }).sort({ tsCreated: 1 }).toArray();
    return docs.map((doc) => this.toRecord(doc));
  }

  private toRecord(doc: MongoDoc): TaskRecord {
    return {
      taskId: doc.taskId as string,
      runId: doc.runId as string,
      ...(doc.parentTaskId !== undefined ? { parentTaskId: doc.parentTaskId as string } : {}),
      kind: doc.kind as string,
      input: (doc.input ?? {}) as Record<string, unknown>,
      status: doc.status as TaskRecord["status"],
      attempts: (doc.attempts ?? 1) as number,
      ...(doc.output !== undefined ? { output: doc.output as unknown } : {}),
      ...(doc.error !== undefined ? { error: doc.error as string } : {}),
      tsCreated: doc.tsCreated as string,
      tsUpdated: doc.tsUpdated as string,
    };
  }
}

class MongoFindingsRepository implements FindingsRepository {
  private readonly collection: Collection<MongoDoc>;

  constructor(db: Db) {
    this.collection = db.collection<MongoDoc>("findings");
  }

  async getByHash(hash: string): Promise<FindingRecord | null> {
    const doc = await this.collection.findOne({ hash });
    return doc ? this.toRecord(doc) : null;
  }

  async create(input: {
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
    status: FindingRecord["status"];
    hash: string;
  }): Promise<FindingRecord> {
    const now = isoNow();
    const doc: MongoDoc = {
      _id: input.findingId,
      findingId: input.findingId,
      runId: input.runId,
      taskId: input.taskId,
      agent: input.agent,
      severity: input.severity,
      title: input.title,
      description: input.description,
      ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
      refs: [...input.refs],
      tags: [...input.tags],
      status: input.status,
      hash: input.hash,
      tsCreated: now,
      tsUpdated: now,
    };
    try {
      await this.collection.insertOne(doc);
    } catch (err) {
      if (err instanceof MongoServerError && err.code === 11000) {
        const existing = await this.getByHash(input.hash);
        if (existing) return existing;
      }
      throw err;
    }
    return this.toRecord(doc);
  }

  async listByRun(runId: string, filter: { severity?: FindingSeverity; limit?: number }): Promise<readonly FindingRecord[]> {
    const query: MongoDBFilter = { _id: runId, runId };
    if (filter.severity) query.severity = filter.severity;
    const docs = await this.collection.find(query).sort({ tsCreated: -1 }).limit(filter.limit ?? 100).toArray();
    return docs.map((doc) => this.toRecord(doc));
  }

  private toRecord(doc: MongoDoc): FindingRecord {
    const evidence = doc.evidence as unknown | undefined;
    return {
      findingId: doc.findingId as string,
      runId: doc.runId as string,
      taskId: doc.taskId as string,
      agent: doc.agent as string,
      severity: doc.severity as FindingSeverity,
      title: doc.title as string,
      description: doc.description as string,
      ...(evidence !== undefined ? { evidence } : {}),
      refs: (doc.refs ?? []) as readonly string[],
      tags: (doc.tags ?? []) as readonly string[],
      status: doc.status as FindingRecord["status"],
      hash: doc.hash as string,
      tsCreated: doc.tsCreated as string,
      tsUpdated: doc.tsUpdated as string,
    };
  }
}

class MongoReportsRepository implements ReportsRepository {
  private readonly collection: Collection<MongoDoc>;

  constructor(db: Db) {
    this.collection = db.collection<MongoDoc>("reports");
  }

  async getLatest(runId: string): Promise<ReportRecord | null> {
    const docs = await this.collection.find({ runId }).sort({ version: -1 }).limit(1).toArray();
    if (docs.length === 0) return null;
    return this.toRecord(docs[0]!);
  }

  async create(input: {
    reportId: string;
    runId: string;
    status: ReportRecord["status"];
    kind: string;
    summary: string;
    content: string;
    checksum: string;
    signature?: string;
    format: string;
    version: number;
  }): Promise<ReportRecord> {
    const now = isoNow();
    const doc: MongoDoc = {
      _id: input.reportId,
      reportId: input.reportId,
      runId: input.runId,
      status: input.status,
      kind: input.kind,
      summary: input.summary,
      content: input.content,
      checksum: input.checksum,
      ...(input.signature !== undefined ? { signature: input.signature } : {}),
      format: input.format,
      version: input.version,
      tsCreated: now,
      tsUpdated: now,
    };
    await this.collection.insertOne(doc);
    return this.toRecord(doc);
  }

  private toRecord(doc: MongoDoc): ReportRecord {
    const signature = doc.signature as string | undefined;
    return {
      reportId: doc.reportId as string,
      runId: doc.runId as string,
      status: doc.status as ReportRecord["status"],
      kind: doc.kind as string,
      summary: doc.summary as string,
      content: doc.content as string,
      checksum: doc.checksum as string,
      ...(signature !== undefined ? { signature } : {}),
      format: doc.format as string,
      version: doc.version as number,
      tsCreated: doc.tsCreated as string,
      tsUpdated: doc.tsUpdated as string,
    };
  }
}

class MongoDocumentsRepository implements DocumentsRepository {
  private readonly collection: Collection<MongoDoc>;

  constructor(db: Db) {
    this.collection = db.collection<MongoDoc>("documents");
  }

  async get(docId: string): Promise<DocumentRecord | null> {
    const doc = await this.collection.findOne({ _id: docId });
    return doc ? this.toRecord(doc) : null;
  }

  async getByContentHash(contentHash: string): Promise<DocumentRecord | null> {
    const doc = await this.collection.findOne({ contentHash });
    return doc ? this.toRecord(doc) : null;
  }

  async create(input: {
    docId: string;
    source: string;
    title: string;
    contentType: string;
    contentHash: string;
    runId?: string;
    metadata: Record<string, unknown>;
  }): Promise<DocumentRecord> {
    const now = isoNow();
    const doc: MongoDoc = {
      _id: input.docId,
      docId: input.docId,
      source: input.source,
      title: input.title,
      contentType: input.contentType,
      contentHash: input.contentHash,
      chunkCount: 0,
      status: "pending",
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      metadata: input.metadata,
      tsCreated: now,
      tsUpdated: now,
    };
    await this.collection.insertOne(doc);
    return this.toRecord(doc);
  }

  async markIndexed(docId: string, chunkCount: number): Promise<void> {
    await this.collection.updateOne({ _id: docId }, { $set: { status: "indexed", chunkCount, tsUpdated: isoNow() } });
  }

  private toRecord(doc: MongoDoc): DocumentRecord {
    const runId = doc.runId as string | undefined;
    return {
      docId: doc.docId as string,
      source: doc.source as string,
      title: doc.title as string,
      contentType: doc.contentType as string,
      contentHash: doc.contentHash as string,
      chunkCount: (doc.chunkCount ?? 0) as number,
      status: doc.status as DocumentRecord["status"],
      ...(runId !== undefined ? { runId } : {}),
      metadata: (doc.metadata ?? {}) as Record<string, unknown>,
      tsCreated: doc.tsCreated as string,
      tsUpdated: doc.tsUpdated as string,
    };
  }
}

export function createMongoRepositories(db: Db): {
  runs: RunsRepository;
  tasks: TasksRepository;
  findings: FindingsRepository;
  reports: ReportsRepository;
  documents: DocumentsRepository;
} {
  return {
    runs: new MongoRunsRepository(db),
    tasks: new MongoTasksRepository(db),
    findings: new MongoFindingsRepository(db),
    reports: new MongoReportsRepository(db),
    documents: new MongoDocumentsRepository(db),
  };
}

export async function ensureMongoSchema(db: Db): Promise<void> {
  await Promise.all([
    db.collection("runs").createIndex({ state: 1 }),
    db.collection("runs").createIndex({ tsCreated: -1 }),
    db.collection("tasks").createIndex({ runId: 1, status: 1 }),
    db.collection("findings").createIndex({ runId: 1, severity: 1 }),
    db.collection("findings").createIndex({ runId: 1, status: 1 }),
    db.collection("findings").createIndex({ hash: 1 }, { unique: true }),
    db.collection("reports").createIndex({ runId: 1, version: -1 }, { unique: true }),
    db.collection("documents").createIndex({ contentHash: 1 }, { unique: true }),
    db.collection("audit").createIndex({ ts: 1 }),
  ]);
}