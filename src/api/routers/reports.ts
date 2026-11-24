import { Router } from "express";
import { NotFoundError } from "../../core/errors.js";
import type { RouterDeps } from "./contract.js";
import { parseId, requireAuthorized } from "./contract.js";

export function createReportsRouter(deps: RouterDeps): Router {
  const router = Router();

  router.get("/runs/:runId/report", async (req, res) => {
    const runId = parseId(req.params.runId, "run");
    await requireAuthorized(deps.authz, "runs:read", res, { runId });

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