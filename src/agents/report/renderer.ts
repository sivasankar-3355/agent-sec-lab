import type { FindingRecord, RunRecord } from "../../core/domain.js";

export interface RenderedReport {
  summary: string;
  content: string;
}

export function renderReport(run: RunRecord, findings: readonly FindingRecord[]): RenderedReport {
  const open = findings.filter((f) => f.status === "open").length;
  const bySeverity = openCounts(findings);

  const lines: string[] = [];
  lines.push(`# Reconnaissance Report — ${run.name}`);
  lines.push("");
  lines.push(`- run_id: ${run.runId}`);
  lines.push(`- targets: ${run.scope.targets.join(", ")}`);
  lines.push(`- findings: ${findings.length} total (${open} open)`);
  lines.push(`- severity: info=${bySeverity.info}, low=${bySeverity.low}, medium=${bySeverity.medium}, high=${bySeverity.high}, critical=${bySeverity.critical}`);
  lines.push("");

  lines.push("## Findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("No findings were recorded for this run.");
  } else {
    for (const finding of findings) {
      lines.push(`### ${finding.severity.toUpperCase()} — ${finding.title}`);
      lines.push("");
      lines.push(`- finding_id: ${finding.findingId}`);
      lines.push(`- agent: ${finding.agent}`);
      lines.push(`- status: ${finding.status}`);
      lines.push("");
      lines.push(finding.description);
      lines.push("");
    }
  }

  const content = lines.join("\n").trim();
  return { summary: `Reconnaissance summary for ${run.name}: ${findings.length} findings (${open} open).`, content };
}

function openCounts(findings: readonly FindingRecord[]): Record<FindingRecord["severity"], number> {
  const counts: Record<FindingRecord["severity"], number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const finding of findings) {
    if (finding.status === "open") counts[finding.severity]++;
  }
  return counts;
}