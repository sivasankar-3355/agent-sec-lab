import { Router } from "express";
import { NotFoundError } from "../../core/errors.js";
import type { RouterDeps } from "./contract.js";
import { parseId, requireAuthorized } from "./contract.js";

export function createReportsRouter(deps: RouterDeps): Router {
  const router = Router();

  router.get("/runs/:runId/report", async (req, res) => {
    const runId = parseId(req.params.runId, "run");
    // Report content is derived from run memory/context. Resolve the trusted
    // run record first so ownership and tenant are enforced for the report,
    // not just the "runs:read" scope.
    const run = await deps.repos.runs.get(runId);
    if (!run) throw new NotFoundError("run not found");
    await requireAuthorized(deps.authz, "runs:read", res, {
      runId,
      ...(run.userId !== undefined ? { resourceOwner: run.userId } : {}),
      ...(run.tenantId !== undefined ? { resourceTenantId: run.tenantId } : {}),
    });

    const report = await deps.repos.reports.getLatest(runId);
    if (!report) throw new NotFoundError("report not generated for this run");

    res.status(200).json({
      report_id: report.reportId,
      run_id: report.runId,
      status: report.status,
      summary: report.summary,
      content: report.content,
      checksum: report.checksum,
      signature: report.signature,
      format: report.format,
      version: report.version,
    });
  });

  return router;
}