import type { RunRecord, RunState } from "../../core/domain.js";
import { newId } from "../../core/ids.js";
import type { TaskKind, TaskInit } from "../../a2a/schema.js";

export interface ReconResult {
  findings: string[];
}

export interface KnowledgeIndexResult {
  indexed: string[];
}

export interface KnowledgeSearchHit {
  docId: string;
  score: number;
}

export interface KnowledgeSearchResult {
  hits: KnowledgeSearchHit[];
}

export interface ReportResult {
  reportId: string;
}

export function phaseFor(kind: TaskKind): RunState {
  if (kind.startsWith("recon.")) return "RECON";
  if (kind.startsWith("knowledge.")) return "KNOWLEDGE";
  if (kind.startsWith("report.")) return "REPORT";
  return "RECON";
}

export function planRun(run: RunRecord, rootTaskId: string): readonly TaskInit[] {
  const children: TaskInit[] = [];

  for (const target of run.scope.targets) {
    children.push({
      taskId: newId(),
      runId: run.runId,
      parentTaskId: rootTaskId,
      kind: "recon.run",
      input: { target },
    });
  }

  if (run.scope.targets.length > 0) {
    children.push({
      taskId: newId(),
      runId: run.runId,
      parentTaskId: rootTaskId,
      kind: "knowledge.search",
      input: { query: run.scope.targets[0] },
    });
  }

  children.push({
    taskId: newId(),
    runId: run.runId,
    parentTaskId: rootTaskId,
    kind: "report.generate",
    input: { reportKind: "overview" },
  });

  return children;
}