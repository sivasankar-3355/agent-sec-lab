import { NotFoundError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { assertAuthorized, workloadOfCaller } from "../authz.js";
import { renderReport } from "./renderer.js";

export const reportAcceptedKinds: readonly ["report.generate"] = ["report.generate"];

export class ReportExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    const run = await ctx.repos.runs.get(task.runId);
    if (!run) throw new NotFoundError("run not found");

    if (task.authz !== undefined) {
      // Independent agent PEP: report may only use run data the signed grant
      // authorizes (resource owner must be the token subject).
      await assertAuthorized(ctx.security.authz, "report.generate", {
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
      });
    }

    const findings = await ctx.repos.findings.listByRun(task.runId, {});
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
      kind: String(task.input.reportKind ?? "overview"),
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