import { AppError, ValidationError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { reportGenerateTool } from "../tools.js";
import type { ToolOperation } from "../tool-operation.js";
import { toolActorOf } from "../tool-actor.js";
import { inspectUntrustedContent } from "../../security/prompt/index.js";
import { renderReport } from "./renderer.js";

export const reportAcceptedKinds: readonly ["report.generate"] = ["report.generate"];

/**
 * Code-owned report operation. It receives the trusted run record from the
 * broker and never re-reads caller-selected run metadata.
 */
export const reportGenerateOperation: ToolOperation = async (ctx) => {
  const run = ctx.request.run;
  const args = ctx.request.args as { reportKind: "overview" | "detailed" };
  const findings = await ctx.repos.findings.listByRun(run.runId, {});

  // Findings are untrusted data (recon output / external observations).
  // Inspect them for reporting/audit without ever treating them as commands.
  for (const finding of findings) {
    await inspectUntrustedContent(ctx.audit, {
      tier: "agent-output",
      source: `finding:${finding.findingId}`,
      content: `${finding.title}\n${finding.description}`,
      agent: "report",
      runId: run.runId,
      taskId: ctx.request.actor.taskId,
      ...(ctx.request.actor.userId !== "" ? { principal: ctx.request.actor.userId } : {}),
    });
  }

  const { summary, content } = renderReport(run, findings);
  const checksum = stableHash(content);
  const signature = await ctx.crypto.sign(Buffer.from(content, "utf8"));
  const latest = await ctx.repos.reports.getLatest(run.runId);
  const version = (latest?.version ?? 0) + 1;
  const reportId = newId();

  if (ctx.request.signal.aborted) {
    throw new AppError("tool_cancelled", "report generation was cancelled", 499);
  }

  await ctx.repos.reports.create({
    reportId,
    runId: run.runId,
    status: "ready",
    kind: args.reportKind,
    summary,
    content,
    checksum,
    ...(signature !== undefined ? { signature: signature.value } : {}),
    format: "text/markdown",
    version,
  });

  return { reportId };
};

export class ReportExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    if (
      task.input.reportKind !== undefined &&
      task.input.reportKind !== "overview" &&
      task.input.reportKind !== "detailed"
    ) {
      throw new ValidationError("report kind must be 'overview' or 'detailed'");
    }
    const actor = toolActorOf("report", task);

    // The Tool Broker enforces the allowlist, verified identity, run
    // ownership/tenant, strict schema, OPA grant and execution limits. The
    // code-owned operation is selected from the sealed catalog.
    const result = await ctx.tools.execute(
      actor,
      { name: reportGenerateTool.name, args: { reportKind: task.input.reportKind ?? "overview" } },
      { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
    );

    return result.data as Record<string, unknown>;
  }
}
