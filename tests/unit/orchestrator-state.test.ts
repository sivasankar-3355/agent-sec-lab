import { describe, expect, it } from "vitest";
import { AppError } from "../../src/core/errors.js";
import { assertTransition, canTransition } from "../../src/agents/orchestrator/state.js";
import { phaseFor, planRun } from "../../src/agents/orchestrator/workflows.js";
import type { RunRecord } from "../../src/core/domain.js";

describe("run state machine", () => {
  it("allows the forward pipeline", () => {
    expect(canTransition("CREATED", "STARTED")).toBe(true);
    expect(canTransition("CREATED", "FAILED")).toBe(true);
    expect(canTransition("CREATED", "CANCELLED")).toBe(true);
    expect(canTransition("STARTED", "RECON")).toBe(true);
    expect(canTransition("RECON", "KNOWLEDGE")).toBe(true);
    expect(canTransition("KNOWLEDGE", "REPORT")).toBe(true);
    expect(canTransition("REPORT", "COMPLETED")).toBe(true);
    expect(canTransition("REPORT", "FAILED")).toBe(true);
  });

  it("rejects invalid transitions", () => {
    expect(canTransition("CREATED", "COMPLETED")).toBe(false);
    expect(canTransition("REPORT", "CREATED")).toBe(false);
    expect(canTransition("RECON", "STARTED")).toBe(false);
    expect(() => assertTransition("CREATED", "COMPLETED")).toThrow(AppError);
  });

  it("freezes terminal states", () => {
    expect(canTransition("COMPLETED", "FAILED")).toBe(false);
    expect(canTransition("CANCELLED", "STARTED")).toBe(false);
    expect(canTransition("FAILED", "REPORT")).toBe(false);
  });
});

describe("run workflow planning", () => {
  const makeRun = (targets: string[]): RunRecord => ({
    runId: "0195cccc-cccc-cccc-cccc-0195cccc0195",
    name: "demo",
    scope: { targets },
    config: {},
    state: "CREATED",
    timeline: [],
    tsCreated: "2026-01-01T00:00:00.000Z",
    tsUpdated: "2026-01-01T00:00:00.000Z",
  });

  it("plans recon per target plus knowledge.search and report.generate", () => {
    const plan = planRun(makeRun(["host-a", "host-b"]), "root-task");
    expect(plan.length).toBe(4);
    expect(plan[0]!.kind).toBe("recon.run");
    expect(plan[0]!.input.target).toBe("host-a");
    expect(plan[1]!.kind).toBe("recon.run");
    expect(plan[1]!.input.target).toBe("host-b");
    expect(plan[2]!.kind).toBe("knowledge.search");
    expect(plan[3]!.kind).toBe("report.generate");
    expect(plan.every((t) => t.parentTaskId === "root-task")).toBe(true);
    expect(plan.every((t) => t.runId === "0195cccc-cccc-cccc-cccc-0195cccc0195")).toBe(true);
  });

  it("maps task kinds to run phases", () => {
    expect(phaseFor("recon.run")).toBe("RECON");
    expect(phaseFor("knowledge.index")).toBe("KNOWLEDGE");
    expect(phaseFor("knowledge.search")).toBe("KNOWLEDGE");
    expect(phaseFor("report.generate")).toBe("REPORT");
  });
});