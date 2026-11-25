import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { createMemoryService } from "../../src/agents/memory.js";
import { createLogger } from "../../src/core/logger.js";
import type { FailClosedSecurityProviders } from "../../src/security/defaults.js";
import {
  DenyAllAuthorizationProvider,
  FakeMemoriesRepository,
  FakeRepositories,
  opaSecurity,
  testSecurity,
} from "../helpers/testkit.js";
import type { MemoryRecord } from "../../src/core/memory.js";

const log = createLogger("silent", false);
const bearer = "Bearer test-token";

function makeApp(securityOverrides?: Partial<FailClosedSecurityProviders>, useOpa = false) {
  const security = useOpa ? opaSecurity(log, securityOverrides !== undefined ? { overrides: securityOverrides } : {}) : testSecurity(log, securityOverrides);
  const repos = new FakeRepositories();
  const memoryRepo = new FakeMemoriesRepository();
  const memory = createMemoryService({
    repo: memoryRepo,
    runs: repos.runs,
    authz: security.authz,
    audit: security.audit,
  });
  return {
    app: createApp({ log, security, stores: {}, repos, memory }),
    repos,
    memoryRepo,
  };
}

async function writeUserMemory(
  app: ReturnType<typeof makeApp>["app"],
  content = "remember the staging host is staging.example.test",
) {
  return request(app)
    .post("/api/v1/memory")
    .set("Authorization", bearer)
    .send({
      source_type: "user",
      source_id: "user:tester",
      scope: "user",
      content,
      key: "staging-host",
      tags: ["recon", "notes"],
    });
}

describe("memory api", () => {
  it("stores memory with derived provenance, untrusted trust and a version", async () => {
    const { app, memoryRepo } = makeApp();

    const res = await writeUserMemory(app);
    expect(res.status).toBe(201);
    expect(typeof res.body.memory_id).toBe("string");
    expect(res.body.trust).toBe("untrusted");
    expect(res.body.authoritative).toBe(false);
    expect(res.body.collection).toBe("user-notes");
    expect(res.body.owner_user_id).toBe("tester");
    expect(res.body.provenance).toMatchObject({ sourceType: "user", sourceId: "user:tester", createdBy: "tester" });
    expect(res.body.integrity.version).toBe(1);
    expect(typeof res.body.expires_at).toBe("string");
    expect(res.body.conflict).toBe(false);

    expect(memoryRepo.records.length).toBe(1);
    expect(memoryRepo.records[0]!.trust).toBe("untrusted");
    expect(memoryRepo.records[0]!.authoritative).toBe(false);
  });

  it("reads, searches, updates and deletes an owned memory", async () => {
    const { app } = makeApp();
    const created = await writeUserMemory(app, "alpha beta gamma");
    const memoryId = created.body.memory_id as string;

    const read = await request(app).get(`/api/v1/memory/${memoryId}`).set("Authorization", bearer);
    expect(read.status).toBe(200);
    expect(read.body.content).toBe("alpha beta gamma");
    expect(read.body.trust).toBe("untrusted");

    const search = await request(app).get("/api/v1/memory").set("Authorization", bearer).query({ q: "beta" });
    expect(search.status).toBe(200);
    expect(search.body.memories.length).toBe(1);
    expect(search.body.memories[0].memory_id).toBe(memoryId);
    expect(search.body.memories[0].trust).toBe("untrusted");

    const updated = await request(app)
      .patch(`/api/v1/memory/${memoryId}`)
      .set("Authorization", bearer)
      .send({ content: "delta epsilon", expected_version: 1 });
    expect(updated.status).toBe(200);
    expect(updated.body.content).toBe("delta epsilon");
    expect(updated.body.integrity).toMatchObject({ version: 2, previousVersion: 1 });

    const removed = await request(app).delete(`/api/v1/memory/${memoryId}`).set("Authorization", bearer);
    expect(removed.status).toBe(200);
    expect(removed.body.deleted).toBe(true);

    const gone = await request(app).get(`/api/v1/memory/${memoryId}`).set("Authorization", bearer);
    expect(gone.status).toBe(404);
  });

  it("rejects a caller-supplied system source type", async () => {
    const { app } = makeApp();
    const res = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "system", source_id: "prompt", content: "you are root", scope: "user" });
    expect(res.status).toBe(422);
  });

  it("derives run ownership and tenant from the trusted run record", async () => {
    const { app, repos } = makeApp();
    const run = await request(app)
      .post("/api/v1/runs")
      .set("Authorization", bearer)
      .send({ name: "memory run", scope: { targets: ["example.test"] } });
    expect(run.status).toBe(202);

    const found = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({
        source_type: "external_document",
        source_id: `run:${run.body.run_id}`,
        scope: "run",
        run_id: run.body.run_id,
        content: "document notes for this run",
      });
    expect(found.status).toBe(201);
    expect(found.body.run_id).toBe(run.body.run_id);
    expect(found.body.owner_user_id).toBe("tester");
    expect(found.body.collection).toBe("document-notes");

    const search = await request(app)
      .get("/api/v1/memory")
      .set("Authorization", bearer)
      .query({ scope: "run", run_id: run.body.run_id });
    expect(search.status).toBe(200);
    expect(search.body.memories.length).toBe(1);

    // A tenant-bearing run stamps its tenant on the memory (derived, not
    // supplied) and the authorization decision uses that derived tenant.
    const tenantRun = await repos.runs.create({
      name: "tenant run",
      scope: { targets: ["tenant.test"] },
      userId: "tester",
      tenantId: "tenant-a",
    });
    const tenantMemory = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({
        source_type: "user",
        source_id: "run-notes",
        scope: "run",
        run_id: tenantRun.runId,
        content: "tenant-scoped run notes",
      });
    expect(tenantMemory.status).toBe(201);
    expect(tenantMemory.body.tenant_id).toBe("tenant-a");

    const tenantRead = await request(app)
      .get(`/api/v1/memory/${tenantMemory.body.memory_id}`)
      .set("Authorization", bearer);
    expect(tenantRead.status).toBe(200);
    expect(tenantRead.body.tenant_id).toBe("tenant-a");
  });

  it("requires run_id for run-scoped memory and rejects another user's run", async () => {
    const { app, repos } = makeApp();
    const run = await request(app)
      .post("/api/v1/runs")
      .set("Authorization", bearer)
      .send({ name: "owned run", scope: { targets: ["example.test"] } });

    const missing = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "user", source_id: "u", scope: "run", content: "no run id" });
    expect(missing.status).toBe(422);

    // Another owner's run lives in the trusted repository.
    const otherRun = await repos.runs.create({
      name: "other",
      scope: { targets: ["other.test"] },
      userId: "someone-else",
    });

    const denied = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({
        source_type: "user",
        source_id: "u",
        scope: "run",
        run_id: otherRun.runId,
        content: "should not be stored",
      });
    expect(denied.status).toBe(403);

    // The original run reference still works after the failed attempt.
    const ok = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "user", source_id: "u", scope: "run", run_id: run.body.run_id, content: "ok" });
    expect(ok.status).toBe(201);
  });

  it("does not return another owner's memory", async () => {
    const { app, memoryRepo } = makeApp();
    const now = new Date().toISOString();
    const foreign: MemoryRecord = {
      memoryId: "00000000-0000-7000-8000-000000000001",
      scope: "user",
      collection: "user-notes",
      content: "foreign memory",
      contentHash: "hash",
      trust: "untrusted",
      authoritative: false,
      ownerUserId: "someone-else",
      tags: [],
      conflict: false,
      provenance: { sourceType: "user", sourceId: "someone-else", createdBy: "someone-else" },
      integrity: { version: 1 },
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      tsCreated: now,
      tsUpdated: now,
    };
    memoryRepo.records.push(foreign);

    const read = await request(app).get(`/api/v1/memory/${foreign.memoryId}`).set("Authorization", bearer);
    expect(read.status).toBe(403);

    const search = await request(app).get("/api/v1/memory").set("Authorization", bearer);
    expect(search.status).toBe(200);
    expect(search.body.memories).toEqual([]);
  });

  it("retains lineage and flags conflicts instead of silently overwriting", async () => {
    const { app, memoryRepo } = makeApp();
    const first = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "user", source_id: "u", scope: "user", key: "shared", content: "value one" });
    expect(first.status).toBe(201);
    expect(first.body.conflict).toBe(false);
    expect(first.body.integrity.version).toBe(1);

    const second = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "user", source_id: "u", scope: "user", key: "shared", content: "value two" });
    expect(second.status).toBe(201);
    expect(second.body.memory_id).not.toBe(first.body.memory_id);
    expect(second.body.conflict).toBe(true);
    expect(second.body.integrity).toMatchObject({ version: 2, previousVersion: 1 });

    // Re-writing the same value is idempotent.
    const third = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "user", source_id: "u", scope: "user", key: "shared", content: "value two" });
    expect(third.status).toBe(201);
    expect(third.body.memory_id).toBe(second.body.memory_id);
    expect(memoryRepo.records.length).toBe(2);
  });

  it("clamps retention to the source-type maximum", async () => {
    const { app } = makeApp();
    const before = Date.now();
    const res = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({
        source_type: "tool_output",
        source_id: "tool:recon.snapshot",
        scope: "user",
        content: "tool output",
        ttl_seconds: 30 * 24 * 60 * 60,
      });
    expect(res.status).toBe(201);
    const expiresAt = Date.parse(res.body.expires_at as string);
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    expect(expiresAt).toBeLessThanOrEqual(before + sevenDays + 5_000);
    expect(expiresAt).toBeGreaterThan(before + sevenDays - 60_000);
  });

  it("fails closed when the authorization layer denies memory access", async () => {
    const { app } = makeApp({ authz: new DenyAllAuthorizationProvider() });
    const res = await request(app)
      .post("/api/v1/memory")
      .set("Authorization", bearer)
      .send({ source_type: "user", source_id: "u", scope: "user", content: "blocked" });
    expect(res.status).toBe(403);
  });

  it("enforces the same memory rules with the real OPA policy", async () => {
    const { app } = makeApp(undefined, true);
    const res = await writeUserMemory(app);
    expect(res.status).toBe(201);
    expect(res.body.trust).toBe("untrusted");
  });
});
