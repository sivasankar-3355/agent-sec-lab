import { describe, expect, it } from "vitest";
import { ValidationError } from "../../src/core/errors.js";
import {
  A2A_PROTOCOL_VERSION,
  a2aMethods,
  a2aStatusOf,
  artifactFor,
  domainStatusOf,
  jsonRpcRequestSchema,
  parseArtifact,
  taskSchema,
  validateTaskInput,
} from "../../src/a2a/schema.js";
import { createAgentCard } from "../../src/a2a/agentCard.js";

describe("A2A protocol contract", () => {
  it("pins the protocol version", () => {
    expect(A2A_PROTOCOL_VERSION).toBe("0.3.0");
  });

  it("exposes the minimal method surface", () => {
    expect(a2aMethods).toEqual([
      "initialize",
      "agentCard",
      "message/send",
      "tasks/send",
      "tasks/get",
      "tasks/cancel",
    ]);
  });

  it("validates per-kind task inputs", () => {
    const runStart = validateTaskInput("run.start", { scope: { targets: ["host-a"] } });
    expect(runStart.scope.targets[0]).toBe("host-a");

    const recon = validateTaskInput("recon.run", { target: "host-a", rulesRef: "R-1" });
    expect(recon.target).toBe("host-a");

    const index = validateTaskInput("knowledge.index", { docIds: ["d1"] });
    expect(index.docIds[0]).toBe("d1");

    const search = validateTaskInput("knowledge.search", { query: "tls?" });
    expect(search.query).toBe("tls?");

    const report = validateTaskInput("report.generate", { reportKind: "overview" });
    expect(report.reportKind).toBe("overview");

    expect(() => validateTaskInput("run.start", { scope: { targets: [] } })).toThrow(ValidationError);
    expect(() => validateTaskInput("knowledge.search", { query: "" })).toThrow(ValidationError);
    expect(() => validateTaskInput("report.generate", { reportKind: "bogus" })).toThrow(ValidationError);
    expect(() => validateTaskInput("recon.run", {})).toThrow(ValidationError);
  });

  it("accepts a valid tasks/send JSON-RPC envelope", () => {
    const envelope = jsonRpcRequestSchema.safeParse({
      jsonrpc: "2.0",
      id: "abc-123",
      method: "tasks/send",
      params: {
        task: {
          taskId: "0195aabb-aabb-aabb-aabb-0195aabb0195",
          runId: "0195ccdd-ccdd-ccdd-ccdd-0195ccdd0195",
          kind: "run.start",
          input: { scope: { targets: ["host-a"] } },
        },
      },
    });
    expect(envelope.success).toBe(true);
  });

  it("rejects malformed envelopes", () => {
    expect(jsonRpcRequestSchema.safeParse({ jsonrpc: "2.1", method: "x" }).success).toBe(false);
    expect(jsonRpcRequestSchema.safeParse({}).success).toBe(false);
    expect(jsonRpcRequestSchema.safeParse({ jsonrpc: "2.0", id: "1", method: "tasks/send", params: null }).success).toBe(false);
    expect(jsonRpcRequestSchema.safeParse({ jsonrpc: "2.0", id: "1", method: "", params: {} }).success).toBe(false);
  });

  it("enforces task status and kind on the task schema", () => {
    const ok = taskSchema.safeParse({
      taskId: "0195aabb-aabb-aabb-aabb-0195aabb0195",
      runId: "0195ccdd-ccdd-ccdd-ccdd-0195ccdd0195",
      kind: "run.start",
      status: "submitted",
      input: {},
    });
    expect(ok.success).toBe(true);
    expect(
      taskSchema.safeParse({
        taskId: "0195aabb-aabb-aabb-aabb-0195aabb0195",
        runId: "0195ccdd-ccdd-ccdd-ccdd-0195ccdd0195",
        kind: "run.start",
        status: "bogus",
        input: {},
      }).success,
    ).toBe(false);
  });

  it("round-trips A2A <-> domain task status", () => {
    expect(domainStatusOf(a2aStatusOf("PENDING"))).toBe("PENDING");
    expect(domainStatusOf(a2aStatusOf("RUNNING"))).toBe("RUNNING");
    expect(domainStatusOf(a2aStatusOf("SUCCEEDED"))).toBe("SUCCEEDED");
    expect(domainStatusOf("failed")).toBe("FAILED");
    expect(domainStatusOf("canceled")).toBe("CANCELLED");
    expect(domainStatusOf("input-required")).toBe("ASSIGNED");
  });

  it("serializes results as text artifacts and parses them back", () => {
    const artifact = artifactFor({ reportId: "r1" });
    expect(parseArtifact<{ reportId: string }>(artifact).reportId).toBe("r1");
  });

  it("shapes agent cards with pinned capabilities", () => {
    const card = createAgentCard("orchestrator");
    expect(card.agentId).toBe("orchestrator");
    expect(card.version).toBe(A2A_PROTOCOL_VERSION);
    expect(card.capabilities.streaming).toBe(false);
    expect(card.capabilities.pushNotifications).toBe(false);
    expect(card.skills.length).toBeGreaterThan(0);
    expect(createAgentCard("knowledge").skills.length).toBeGreaterThan(0);
  });
});