import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/api/app.js";
import { createLogger } from "../../src/core/logger.js";
import { FakeRepositories, testSecurity } from "../helpers/testkit.js";

const log = createLogger("silent", false);
const bearer = "Bearer test-token";

function makeApp() {
  const security = testSecurity(log);
  const repos = new FakeRepositories();
  return { app: createApp({ log, security, stores: {}, repos }), repos };
}

describe("knowledge api", () => {
  it("ingests a document and indexes it", async () => {
    const { app, repos } = makeApp();
    const res = await request(app)
      .post("/api/v1/knowledge/documents")
      .set("Authorization", bearer)
      .send({ source: "https://example.test/kb", content: "the quick brown fox jumps over the lazy dog", title: "fox doc" });

    expect(res.status).toBe(201);
    expect(typeof res.body.doc_id).toBe("string");
    expect(res.body.chunk_count).toBeGreaterThan(0);

    expect(repos.documents.documents.length).toBe(1);
    expect(repos.documents.documents[0]!.status).toBe("indexed");
    expect(repos.knowledge.chunks.length).toBe(1);
  });

  it("dedupes identical content", async () => {
    const { app } = makeApp();
    const body = { source: "https://example.test/kb", content: "same content exactly repeated" };

    const first = await request(app).post("/api/v1/knowledge/documents").set("Authorization", bearer).send(body);
    const second = await request(app).post("/api/v1/knowledge/documents").set("Authorization", bearer).send(body);

    expect(first.status).toBe(201);
    expect(second.status).toBe(200);
    expect(second.body.deduped).toBe(true);
    expect(second.body.doc_id).toBe(first.body.doc_id);
  });

  it("rejects ingest without content", async () => {
    const { app } = makeApp();
    const res = await request(app)
      .post("/api/v1/knowledge/documents")
      .set("Authorization", bearer)
      .send({ source: "https://example.test/kb", content: "" });
    expect(res.status).toBe(422);
  });

  it("searches after ingest", async () => {
    const { app } = makeApp();
    await request(app)
      .post("/api/v1/knowledge/documents")
      .set("Authorization", bearer)
      .send({ source: "https://example.test/kb", content: "alpha beta gamma delta epsilon", title: "t" });

    const res = await request(app).get("/api/v1/knowledge/search").set("Authorization", bearer).query({ q: "alpha" });
    expect(res.status).toBe(200);
    expect(res.body.hits.length).toBe(1);
    expect(typeof res.body.hits[0].doc_id).toBe("string");
    expect(typeof res.body.hits[0].score).toBe("number");
  });

  it("rejects search without a query", async () => {
    const { app } = makeApp();
    const res = await request(app).get("/api/v1/knowledge/search").set("Authorization", bearer);
    expect(res.status).toBe(422);
  });
});