import type { Logger } from "pino";
import type {
  DocumentRecord,
  FindingRecord,
  FindingSeverity,
  ReportRecord,
  RunCreateInput,
  RunRecord,
  RunState,
  TaskRecord,
  TaskStatus,
  UserRecord,
} from "../../src/core/domain.js";
import type {
  DocumentsRepository,
  FindingsRepository,
  ReportsRepository,
  RunsRepository,
  TasksRepository,
  UsersRepository,
} from "../../src/db/repositories/contracts.js";
import type { KnowledgeVectorStore, VectorHit, UpsertChunksInput, VectorSearchFilter } from "../../src/db/knowledge-contract.js";
import type {
  MemoriesRepository,
  MemoryIsolation,
  MemoryQuery,
  MemoryUpdatePatch,
} from "../../src/db/repositories/memory.js";
import type { MemoryRecord } from "../../src/core/memory.js";
import type { Coordinator } from "../../src/db/coordinator.js";
import type { ChildTaskBroker } from "../../src/agents/orchestrator/broker.js";
import type { A2ATask, A2AStatus, TaskInit } from "../../src/a2a/schema.js";
import { newId } from "../../src/core/ids.js";
import type { Repositories } from "../../src/db/repositories/build.js";
import type {
  AuditEvent,
  AuthTokenProvider,
  AuthorizationProvider,
  CryptoProvider,
  Decision,
  EmbeddingProvider,
  ModelProvider,
  NetworkPolicyProvider,
  PolicyProvider,
  SandboxProvider,
  SecretProvider,
  Signature,
  TokenVerdict,
} from "../../src/security/protocols.js";
import { failClosedProviders, type FailClosedSecurityProviders } from "../../src/security/defaults.js";
import { JwtTokenService, JwtVerifier } from "../../src/security/jwt-issuer.js";
import { UserAuthService } from "../../src/security/user-jwt.js";
import { USER_SCOPES } from "../../src/security/audience.js";
import { createOpaAuthorizationProvider } from "../../src/security/opa/provider.js";
import { DEFAULT_POLICY_DIR, DEFAULT_POLICY_VERSION } from "../../src/security/opa/policies.js";

import { generateKeyPairSync } from "node:crypto";

export interface TestIdentity {
  /** Workload issuer (STS-side, RS256 private key). */
  issuer: JwtTokenService;
  /** Workload verifier (agents, public key only). */
  verifier: JwtVerifier;
  /** User authentication (gateway-side, HS256 dedicated secret). */
  userAuth: UserAuthService;
  /** RSA private key used by the test issuer (for crafting edge-case tokens). */
  privateKey: string;
  /** RSA public key that verifies the test issuer's tokens. */
  publicKey: string;
  /** HS256 user JWT for `user:alice`. */
  userToken(): Promise<string>;
  /** RS256 workload identity token. */
  workloadToken(workload: string, scopes: readonly string[]): Promise<string>;
}

export function makeTestIdentity(): TestIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const workloadOptions = {
    issuer: "agent-sec-lab-test",
    keyId: "test-key",
    signingKeyPem: privateKey,
    publicKeys: new Map([[ "test-key", publicKey ]]),
    workloadTtlSec: 300,
    runTtlSec: 1800,
    childTtlSec: 600,
  };
  const issuer = new JwtTokenService(workloadOptions);
  const verifier = new JwtVerifier(workloadOptions);
  const userAuth = new UserAuthService({
    secret: "test-user-secret-0123456789abcdef0123456789abcdef",
    issuer: "agent-sec-lab-user",
    audience: "api-gateway",
    ttlSec: 1800,
  });
  return {
    issuer,
    verifier,
    userAuth,
    privateKey,
    publicKey,
    async userToken() {
      return userAuth.mintUserToken("user:alice", [...USER_SCOPES]);
    },
    async workloadToken(workload, scopes) {
      return issuer.mintWorkloadToken(workload, scopes);
    },
  };
}

export function isoNow(): string {
  return new Date().toISOString();
}

export function hashVector(text: string, dim = 16): number[] {
  let h = 0x811c9dc5;
  for (const ch of text) {
    h ^= ch.codePointAt(0)!;
    h = Math.imul(h, 0x01000193);
  }
  const vector = new Array<number>(dim).fill(0);
  for (let i = 0; i < dim; i++) {
    vector[i] = ((h >> ((i % 4) * 8)) & 0xff) / 255;
  }
  const norm = Math.sqrt(vector.reduce((s, v) => s + v * v, 0)) || 1;
  return vector.map((v) => v / norm);
}

class TestAuthTokenProvider implements AuthTokenProvider {
  async createToken(_principal: string, _scopes: readonly string[]): Promise<string> {
    return "test-token";
  }

  async verifyToken(token: string): Promise<TokenVerdict> {
    if (token === "test-token") {
      return {
        valid: true,
        principal: "tester",
        scopes: ["runs:read", "runs:write", "knowledge:read", "knowledge:write", "memory:read", "memory:write"],
      };
    }
    return { valid: false, reason: "invalid token" };
  }
}

class AllowAllAuthorizationProvider implements AuthorizationProvider {
  async authorize(): Promise<Decision> {
    return { allowed: true };
  }
}

export class DenyAllAuthorizationProvider implements AuthorizationProvider {
  async authorize(): Promise<Decision> {
    return { allowed: false, reason: "denied for test" };
  }
}

export class TestPolicyProvider implements PolicyProvider {
  async evaluate(_target: string, _action: string, _ruleRefs: readonly string[]): Promise<readonly { rule: string; reason: string }[]> {
    return [];
  }
}

export class TestNetworkProvider implements NetworkPolicyProvider {
  async assertEgress(_target: string): Promise<{ allowed: boolean; reason?: string }> {
    return { allowed: true };
  }
}

export class TestSandboxProvider implements SandboxProvider {
  async run(step: { name: string; input: unknown }): Promise<{ ok: boolean; output: unknown }> {
    return { ok: true, output: { step: step.name } };
  }
}

export class TestModelProvider implements ModelProvider {
  async complete(prompt: string, _context: Record<string, unknown>): Promise<{ text: string }> {
    return { text: `summary from model for: ${prompt.slice(0, 40)}` };
  }
}

export class TestCryptoProvider implements CryptoProvider {
  async sign(data: Buffer): Promise<Signature> {
    let hash = 0x811c9dc5;
    for (const byte of data) {
      hash ^= byte;
      hash = Math.imul(hash, 0x01000193);
    }
    return { algorithm: "test-hash", value: hash.toString(16) };
  }

  async verify(_data: Buffer, _signature: Signature, _purpose: string): Promise<boolean> {
    return true;
  }
}

export class TestSecretProvider implements SecretProvider {
  constructor(private readonly secrets: Record<string, string>) {}

  async get(name: string): Promise<{ name: string; value: string }> {
    const value = this.secrets[name];
    if (value === undefined) {
      throw new Error(`secret '${name}' not found in test`);
    }
    return { name, value };
  }
}

export class TestEmbeddingProvider implements EmbeddingProvider {
  async embed(texts: readonly string[]): Promise<number[][]> {
    return texts.map((t) => hashVector(t));
  }
}

export function testSecurity(log: Logger, overrides?: Partial<FailClosedSecurityProviders>): FailClosedSecurityProviders {
  const base = failClosedProviders(log);
  return {
    ...base,
    authn: new TestAuthTokenProvider(),
    authz: new AllowAllAuthorizationProvider(),
    embedding: new TestEmbeddingProvider(),
    ...overrides,
  };
}

/** Captures audit events for assertions. */
export class TestAuditProvider {
  readonly events: AuditEvent[] = [];

  async emit(event: AuditEvent): Promise<void> {
    this.events.push(event);
  }
}

/**
 * Security providers wired to the real OPA authorization engine (embedded
 * Rego bundle). Use for policy-aware tests; every other control stays its
 * test double (allow-all policy/network/sandbox + working model/crypto).
 */
export function opaSecurity(
  log: Logger,
  options: {
    policyDir?: string;
    policyVersion?: string;
    audit?: TestAuditProvider;
    authn?: AuthTokenProvider;
    overrides?: Partial<FailClosedSecurityProviders>;
  } = {},
): FailClosedSecurityProviders {
  const audit = options.audit ?? new TestAuditProvider();
  return testSecurity(log, {
    audit,
    policy: new TestPolicyProvider(),
    network: new TestNetworkProvider(),
    sandbox: new TestSandboxProvider(),
    model: new TestModelProvider(),
    crypto: new TestCryptoProvider(),
    ...(options.authn !== undefined ? { authn: options.authn } : {}),
    authz: createOpaAuthorizationProvider({
      log,
      audit,
      policyDir: options.policyDir ?? DEFAULT_POLICY_DIR,
      policyVersion: options.policyVersion ?? DEFAULT_POLICY_VERSION,
    }),
    ...(options.overrides ?? {}),
  });
}

class FakeUsersRepository implements UsersRepository {
  readonly users: UserRecord[] = [];

  async create(input: {
    userId: string;
    email: string;
    passwordHash: string;
    scopes: readonly string[];
  }): Promise<UserRecord> {
    const now = isoNow();
    const record: UserRecord = {
      userId: input.userId,
      email: input.email.toLowerCase(),
      passwordHash: input.passwordHash,
      scopes: [...input.scopes],
      tsCreated: now,
      tsUpdated: now,
    };
    this.users.push(record);
    return record;
  }

  async getByEmail(email: string): Promise<UserRecord | null> {
    return this.users.find((u) => u.email === email.toLowerCase()) ?? null;
  }

  async get(userId: string): Promise<UserRecord | null> {
    return this.users.find((u) => u.userId === userId) ?? null;
  }

  seed(record: UserRecord): void {
    this.users.push(record);
  }
}

class FakeRunsRepository implements RunsRepository {
  private readonly records = new Map<string, RunRecord>();
  readonly created: RunRecord[] = [];

  async create(input: RunCreateInput): Promise<RunRecord> {
    const now = isoNow();
    const record: RunRecord = {
      runId: newId(),
      name: input.name,
      scope: { targets: [...input.scope.targets] },
      ...(input.userId !== undefined ? { userId: input.userId } : {}),
      ...(input.tenantId !== undefined ? { tenantId: input.tenantId } : {}),
      config: input.config ?? {},
      state: "CREATED",
      timeline: [{ state: "CREATED", ts: now }],
      tsCreated: now,
      tsUpdated: now,
    };
    this.records.set(record.runId, record);
    this.created.push(record);
    return record;
  }

  async get(runId: string): Promise<RunRecord | null> {
    return this.records.get(runId);
  }

  async setState(runId: string, state: RunState, ts?: string): Promise<void> {
    const record = this.records.get(runId);
    if (!record) return;
    const tsValue = ts ?? isoNow();
    record.state = state;
    record.tsUpdated = tsValue;
    record.timeline = [...record.timeline, { state, ts: tsValue }];
  }
}

class FakeTasksRepository implements TasksRepository {
  readonly tasks: TaskRecord[] = [];

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
    const record: TaskRecord = {
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
    this.tasks.push(record);
    return record;
  }

  async get(taskId: string): Promise<TaskRecord | null> {
    return this.tasks.find((t) => t.taskId === taskId) ?? null;
  }

  async setStatus(
    taskId: string,
    status: TaskStatus,
    detail?: { output?: unknown; error?: string },
  ): Promise<void> {
    const record = this.tasks.find((t) => t.taskId === taskId);
    if (!record) return;
    record.status = status;
    record.tsUpdated = isoNow();
    if (detail?.output !== undefined) record.output = detail.output;
    if (detail?.error !== undefined) record.error = detail.error;
  }

  async listByRun(runId: string): Promise<readonly TaskRecord[]> {
    return this.tasks.filter((t) => t.runId === runId);
  }
}

class FakeFindingsRepository implements FindingsRepository {
  readonly findings: FindingRecord[] = [];

  async getByHash(hash: string): Promise<FindingRecord | null> {
    return this.findings.find((f) => f.hash === hash) ?? null;
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
    const existing = await this.getByHash(input.hash);
    if (existing) return existing;
    const now = isoNow();
    const record: FindingRecord = {
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
    this.findings.push(record);
    return record;
  }

  async listByRun(runId: string, filter: { severity?: FindingSeverity; limit?: number }): Promise<readonly FindingRecord[]> {
    return this.findings
      .filter((f) => f.runId === runId && (!filter.severity || f.severity === filter.severity))
      .slice(0, filter.limit ?? 100);
  }

  seed(record: FindingRecord): void {
    this.findings.push(record);
  }
}

class FakeReportsRepository implements ReportsRepository {
  readonly reports: ReportRecord[] = [];

  async getLatest(runId: string): Promise<ReportRecord | null> {
    const matches = this.reports.filter((r) => r.runId === runId).sort((a, b) => b.version - a.version);
    return matches[0] ?? null;
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
    const record: ReportRecord = {
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
    this.reports.push(record);
    return record;
  }

  seed(record: ReportRecord): void {
    this.reports.push(record);
  }
}

class FakeDocumentsRepository implements DocumentsRepository {
  readonly documents: DocumentRecord[] = [];

  async get(docId: string): Promise<DocumentRecord | null> {
    return this.documents.find((d) => d.docId === docId) ?? null;
  }

  async getByContentHash(contentHash: string): Promise<DocumentRecord | null> {
    return this.documents.find((d) => d.contentHash === contentHash) ?? null;
  }

  async create(input: {
    docId: string;
    source: string;
    title: string;
    contentType: string;
    contentHash: string;
    runId?: string;
    ownerUserId?: string;
    tenantId?: string;
    metadata: Record<string, unknown>;
  }): Promise<DocumentRecord> {
    const now = isoNow();
    const record: DocumentRecord = {
      docId: input.docId,
      source: input.source,
      title: input.title,
      contentType: input.contentType,
      contentHash: input.contentHash,
      chunkCount: 0,
      status: "pending",
      runId: input.runId,
      ownerUserId: input.ownerUserId,
      tenantId: input.tenantId,
      metadata: input.metadata,
      tsCreated: now,
      tsUpdated: now,
    };
    this.documents.push(record);
    return record;
  }

  async markIndexed(docId: string, chunkCount: number): Promise<void> {
    const record = this.documents.find((d) => d.docId === docId);
    if (record) {
      record.status = "indexed";
      record.chunkCount = chunkCount;
      record.tsUpdated = isoNow();
    }
  }
}

class FakeKnowledgeVectorStore implements KnowledgeVectorStore {
  readonly chunks: UpsertChunksInput[] = [];

  async upsertChunks(input: UpsertChunksInput): Promise<void> {
    this.chunks.push(input);
  }

  async search(
    _queryVector: readonly number[],
    limit: number,
    _filter?: VectorSearchFilter,
  ): Promise<readonly VectorHit[]> {
    const docIds = [...new Set(this.chunks.map((c) => c.docId))];
    return docIds.slice(0, limit).map((docId) => ({ docId, score: 1 }));
  }
}

function memoryVisible(record: MemoryRecord, isolation: MemoryIsolation): boolean {
  if (record.ownerUserId !== isolation.ownerUserId) return false;
  if (!isolation.scopes.includes(record.scope)) return false;
  if (isolation.tenantId !== undefined && isolation.tenantId !== "") {
    if (record.tenantId !== isolation.tenantId) return false;
  } else if (record.tenantId !== undefined && record.tenantId !== "") {
    return false;
  }
  if (record.scope === "run" && isolation.runId !== undefined && record.runId !== isolation.runId) return false;
  if (record.scope === "agent" && isolation.agent !== undefined && record.agent !== isolation.agent) return false;
  return true;
}

export class FakeMemoriesRepository implements MemoriesRepository {
  readonly records: MemoryRecord[] = [];

  async insert(record: MemoryRecord): Promise<MemoryRecord> {
    this.records.push(record);
    return record;
  }

  async get(memoryId: string): Promise<MemoryRecord | null> {
    return this.records.find((record) => record.memoryId === memoryId) ?? null;
  }

  async findLatestByKey(input: {
    ownerUserId: string;
    tenantId?: string;
    scope: MemoryRecord["scope"];
    collection: string;
    key: string;
    runId?: string;
    agent?: string;
  }): Promise<MemoryRecord | null> {
    const matches = this.records
      .filter(
        (record) =>
          record.ownerUserId === input.ownerUserId &&
          record.scope === input.scope &&
          record.collection === input.collection &&
          record.key === input.key &&
          (input.tenantId !== undefined
            ? record.tenantId === input.tenantId
            : record.tenantId === undefined || record.tenantId === "") &&
          (input.runId === undefined || record.runId === input.runId) &&
          (input.agent === undefined || record.agent === input.agent),
      )
      .sort((a, b) => b.integrity.version - a.integrity.version);
    return matches[0] ?? null;
  }

  async update(
    memoryId: string,
    isolation: MemoryIsolation,
    patch: MemoryUpdatePatch,
  ): Promise<MemoryRecord | null> {
    const index = this.records.findIndex(
      (record) => record.memoryId === memoryId && memoryVisible(record, isolation),
    );
    if (index < 0) return null;
    const current = this.records[index]!;
    if (patch.previousVersion !== undefined && current.integrity.version !== patch.previousVersion) {
      return null;
    }
    const updated: MemoryRecord = {
      ...current,
      ...(patch.content !== undefined ? { content: patch.content } : {}),
      ...(patch.contentHash !== undefined ? { contentHash: patch.contentHash } : {}),
      ...(patch.key !== undefined && patch.key !== null ? { key: patch.key } : {}),
      ...(patch.tags !== undefined ? { tags: [...patch.tags] } : {}),
      ...(patch.conflict !== undefined ? { conflict: patch.conflict } : {}),
      ...(patch.injection !== undefined ? { injection: patch.injection } : {}),
      ...(patch.expiresAt !== undefined && patch.expiresAt !== null ? { expiresAt: patch.expiresAt } : {}),
      integrity: {
        version: patch.version,
        ...(patch.previousVersion !== undefined ? { previousVersion: patch.previousVersion } : {}),
      },
      tsUpdated: isoNow(),
    };
    if (patch.key === null) delete (updated as { key?: string }).key;
    if (patch.expiresAt === null) delete (updated as { expiresAt?: string }).expiresAt;
    this.records[index] = updated;
    return updated;
  }

  async remove(memoryId: string, isolation: MemoryIsolation): Promise<boolean> {
    const index = this.records.findIndex(
      (record) => record.memoryId === memoryId && memoryVisible(record, isolation),
    );
    if (index < 0) return false;
    this.records.splice(index, 1);
    return true;
  }

  async search(query: MemoryQuery): Promise<readonly MemoryRecord[]> {
    const now = Date.now();
    return this.records
      .filter(
        (record) =>
          memoryVisible(record, query) &&
          (record.expiresAt === undefined || Date.parse(record.expiresAt) > now) &&
          (query.collection === undefined || record.collection === query.collection) &&
          (query.key === undefined || record.key === query.key) &&
          (query.q === undefined || query.q === "" || record.content.toLowerCase().includes(query.q.toLowerCase())),
      )
      .sort((a, b) => b.tsUpdated.localeCompare(a.tsUpdated))
      .slice(0, Math.min(Math.max(query.limit, 1), 20));
  }
}

export class FakeCoordinator implements Coordinator {
  private readonly holdings = new Set<string>();

  readonly seen = new Set<string>();

  async acquireLock(key: string): Promise<boolean> {
    if (this.holdings.has(key)) return false;
    this.holdings.add(key);
    return true;
  }

  async releaseLock(key: string): Promise<void> {
    this.holdings.delete(key);
  }

  async ensureSeen(key: string): Promise<boolean> {
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }
}

export interface FakeBrokerOutcome {
  status: A2AStatus;
  result?: unknown;
  error?: string;
}

export class FakeChildBroker implements ChildTaskBroker {
  readonly submitted: TaskInit[] = [];
  readonly cancelled: string[] = [];
  readonly polls: string[] = [];
  private readonly byKind = new Map<string, FakeBrokerOutcome>();

  constructor(outcomes: Record<string, FakeBrokerOutcome> = {}) {
    for (const [kind, outcome] of Object.entries(outcomes)) this.byKind.set(kind, outcome);
  }

  async submit(task: TaskInit, _token?: string): Promise<A2ATask> {
    this.submitted.push(task);
    const outcome = this.byKind.get(task.kind);
    const base: A2ATask = {
      taskId: task.taskId,
      runId: task.runId,
      ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
      kind: task.kind,
      input: task.input,
      status: "submitted",
    };
    if (outcome !== undefined && (outcome.status === "failed" || outcome.status === "canceled")) {
      return {
        ...base,
        status: outcome.status,
        ...(outcome.error !== undefined ? { error: outcome.error } : {}),
      };
    }
    return base;
  }

  async poll(taskId: string): Promise<A2ATask> {
    this.polls.push(taskId);
    const task = this.submitted.find((t) => t.taskId === taskId);
    if (!task) return { taskId, runId: taskId, kind: "recon.run", input: {}, status: "failed", error: "unknown task" };
    const outcome = this.byKind.get(task.kind);
    if (outcome !== undefined && outcome.status === "failed") {
      return {
        taskId: task.taskId,
        runId: task.runId,
        ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
        kind: task.kind,
        input: task.input,
        status: "failed",
        ...(outcome.error !== undefined ? { error: outcome.error } : {}),
      };
    }
    if (outcome !== undefined && outcome.status === "canceled") {
      return {
        taskId: task.taskId,
        runId: task.runId,
        ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
        kind: task.kind,
        input: task.input,
        status: "canceled",
      };
    }
    if (outcome !== undefined && outcome.status === "working") {
      return {
        taskId: task.taskId,
        runId: task.runId,
        ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
        kind: task.kind,
        input: task.input,
        status: "working",
      };
    }
    return {
      taskId: task.taskId,
      runId: task.runId,
      ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
      kind: task.kind,
      input: task.input,
      status: "completed",
      artifact: { artifactId: "result", text: JSON.stringify(outcome?.result ?? null) },
    };
  }

  async cancel(taskId: string): Promise<A2ATask> {
    this.cancelled.push(taskId);
    const task = this.submitted.find((t) => t.taskId === taskId);
    if (!task) return { taskId, runId: taskId, kind: "recon.run", input: {}, status: "canceled" };
    return {
      taskId: task.taskId,
      runId: task.runId,
      ...(task.parentTaskId !== undefined ? { parentTaskId: task.parentTaskId } : {}),
      kind: task.kind,
      input: task.input,
      status: "canceled",
    };
  }
}

export class FakeRepositories implements Repositories {
  readonly runs = new FakeRunsRepository();
  readonly users = new FakeUsersRepository();
  readonly tasks = new FakeTasksRepository();
  readonly findings = new FakeFindingsRepository();
  readonly reports = new FakeReportsRepository();
  readonly documents = new FakeDocumentsRepository();
  readonly knowledge = new FakeKnowledgeVectorStore();
}