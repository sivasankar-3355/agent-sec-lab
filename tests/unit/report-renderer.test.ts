import { describe, expect, it } from "vitest";
import { renderReport } from "../../src/agents/report/renderer.js";
import type { FindingRecord, RunRecord } from "../../src/core/domain.js";

const run: RunRecord = {
  runId: "0195aaaa-aaaa-aaaa-aaaa-0195aaaa0195",
  name: "demo",
  scope: { targets: ["host-a"] },
  config: {},
  state: "CREATED",
  timeline: [],
  tsCreated: "2026-01-01T00:00:00.000Z",
  tsUpdated: "2026-01-01T00:00:00.000Z",
};

const finding: FindingRecord = {
  findingId: "0195bbbb-bbbb-bbbb-bbbb-0195bbbb0195",
  runId: run.runId,
  taskId: "0195cccc-cccc-cccc-cccc-0195cccc0195",
  agent: "recon",
  severity: "high",
  title: "Open TLS port",
  description: "The target exposed TLS on an unexpected port.",
  refs: [],
  tags: ["recon"],
  status: "open",
  hash: "abc",
  tsCreated: "2026-01-01T00:00:00.000Z",
  tsUpdated: "2026-01-01T00:00:00.000Z",
};

describe("report renderer", () => {
  it("renders findings with counts and severity", () => {
    const rendered = renderReport(run, [finding]);
    expect(rendered.summary).toContain("1 findings");
    expect(rendered.summary).toContain("1 open");
    expect(rendered.content).toContain("# Reconnaissance Report");
    expect(rendered.content).toContain("HIGH");
    expect(rendered.content).toContain("Open TLS port");
    expect(rendered.content).toContain(run.runId);
  });

  it("renders an empty findings section when there are none", () => {
    const rendered = renderReport(run, []);
    expect(rendered.content).toContain("No findings were recorded");
    expect(rendered.summary).toContain("0 findings");
  });

  it("is deterministic for the same inputs", () => {
    expect(renderReport(run, [finding]).content).toBe(renderReport(run, [finding]).content);
  });
});