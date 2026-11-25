import type { FindingRecord, RunRecord } from "../../core/domain.js";
import { asDataText } from "../../security/prompt/trust.js";

export interface RenderedReport {
  summary: string;
  content: string;
}

export function renderReport(run: RunRecord, findings: readonly FindingRecord[]): RenderedReport {
  const open = findings.filter((f) => f.status === "open").length;
  const bySeverity = openCounts(findings);

  // Run names, targets, titles and descriptions are untrusted data. They are
  // rendered verbatim in meaning but stripped of control/boundary tokens so a
  // finding cannot forge prompt or report structure.
  const runName = asDataText(run.name, 200);
  const targets = run.scope.targets.map((target) => asDataText(target, 256)).join(", ");

  const lines: string[] = [];
  lines.push(`# Reconnaissance Report — ${runName}`);
  lines.push("");
  lines.push(`- run_id: ${run.runId}`);
  lines.push(`- targets: ${targets}`);
  lines.push(`- findings: ${findings.length} total (${open} open)`);
  lines.push(`- severity: info=${bySeverity.info}, low=${bySeverity.low}, medium=${bySeverity.medium}, high=${bySeverity.high}, critical=${bySeverity.critical}`);
  lines.push("");

  lines.push("## Findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("No findings were recorded for this run.");
  } else {
    for (const finding of findings) {
      const title = asDataText(finding.title, 200);
      const description = asDataText(finding.description, 4000);
      lines.push(`### ${finding.severity.toUpperCase()} — ${title}`);
      lines.push("");
      lines.push(`- finding_id: ${finding.findingId}`);
      lines.push(`- agent: ${finding.agent}`);
      lines.push(`- status: ${finding.status}`);
      lines.push("");
      lines.push(description);
      lines.push("");
    }
  }

  const content = lines.join("\n").trim();
  return { summary: `Reconnaissance summary for ${runName}: ${findings.length} findings (${open} open).`, content };
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