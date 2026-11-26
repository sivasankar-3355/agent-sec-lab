import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { reportGenerateTool } from "../tools.js";
import { toolActorOf } from "../tool-actor.js";
import { inspectUntrustedContent } from "../../security/prompt/index.js";
import { renderReport } from "./renderer.js";

export const reportAcceptedKinds: readonly ["report.generate"] = ["report.generate"];

export class ReportExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    const actor = toolActorOf("report", task);

    // The Tool Broker enforces the report.generate allowlist, verified
    // identity, run ownership/tenant, strict report-kind schema, OPA grant and
    // execution limits. The broker also supplies the trusted run record, so
    // the handler never re-reads caller-selected run metadata.
    const result = await ctx.tools.execute(
      reportGenerateTool,
      actor,
      { name: reportGenerateTool.name, args: { reportKind: task.input.reportKind ?? "overview" } },
      async (call) => {
        const run = call.run;
        const findings = await ctx.repos.findings.listByRun(run.runId, {});
        // Findings are untrusted data (recon output / external observations).
        // Inspect them for reporting/audit without ever treating them as commands.
        for (const finding of findings) {
          await inspectUntrustedContent(ctx.audit, {
            tier: "agent-output",
            source: `finding:${finding.findingId}`,
            content: `${finding.title}\n${finding.description}`,
            agent: "report",
            runId: task.runId,
            taskId: task.taskId,
            ...(task.authz !== undefined && task.authz.userId !== "" ? { principal: task.authz.userId } : {}),
          });
        }

        const { summary, content } = renderReport(run, findings);
        const checksum = stableHash(content);
        const signature = await ctx.security.crypto.sign(Buffer.from(content, "utf8"));
        const latest = await ctx.repos.reports.getLatest(run.runId);
        const version = (latest?.version ?? 0) + 1;
        const reportId = newId();

        await ctx.repos.reports.create({
          reportId,
          runId: run.runId,
          status: "ready",
          kind: call.args.reportKind,
          summary,
          content,
          checksum,
          ...(signature !== undefined ? { signature: signature.value } : {}),
          format: "text/markdown",
          version,
        });

        return { reportId };
      },
      { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
    );

    return result.data;
  }
}
