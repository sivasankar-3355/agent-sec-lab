import { NotFoundError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { assertAuthorized, workloadOfCaller } from "../authz.js";
import { reportGenerateTool } from "../tools.js";
import { inspectUntrustedContent, validateToolCall } from "../../security/prompt/index.js";
import { renderReport } from "./renderer.js";

export const reportAcceptedKinds: readonly ["report.generate"] = ["report.generate"];

export class ReportExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    const run = await ctx.repos.runs.get(task.runId);
    if (!run) throw new NotFoundError("run not found");

    const authorization =
      task.authz !== undefined
        ? await assertAuthorized(ctx.security.authz, "report.generate", {
            kind: "operation",
            workload: workloadOfCaller(task.authz.caller),
            agent: "report",
            ...(task.authz.userId !== "" ? { user: task.authz.userId } : {}),
            runId: task.runId,
            approvedTargets: task.authz.scopeTargets,
            approvedActions: task.authz.permittedActions,
            requestedAction: "report.generate",
            requestedRunId: task.runId,
            resourceOwner: run.userId ?? "",
            resourceTenantId: run.tenantId ?? "",
            ...(task.authz.tenantId !== undefined ? { tenantId: task.authz.tenantId } : {}),
          })
        : undefined;

    // Independent tool gate: only the code-owned report renderer can run, with
    // a strict report-kind schema and the signed run grant bound to it.
    const reportCall = validateToolCall(
      reportGenerateTool,
      { reportKind: task.input.reportKind ?? "overview" },
      {
        ...(task.authz !== undefined ? { grant: task.authz } : {}),
        ...(authorization !== undefined ? { decision: authorization } : {}),
      },
    );

    const findings = await ctx.repos.findings.listByRun(task.runId, {});
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
    const latest = await ctx.repos.reports.getLatest(task.runId);
    const version = (latest?.version ?? 0) + 1;
    const reportId = newId();

    await ctx.repos.reports.create({
      reportId,
      runId: task.runId,
      status: "ready",
      kind: reportCall.reportKind,
      summary,
      content,
      checksum,
      ...(signature !== undefined ? { signature: signature.value } : {}),
      format: "text/markdown",
      version,
    });

    return { reportId };
  }
}