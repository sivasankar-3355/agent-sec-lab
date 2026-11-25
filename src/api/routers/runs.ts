import { Router } from "express";
import { z } from "zod";
import { NotFoundError } from "../../core/errors.js";
import { newId } from "../../core/ids.js";
import type { FindingSeverity } from "../../core/domain.js";
import type { TaskInit } from "../../a2a/schema.js";
import { A2AClient } from "../../a2a/client.js";
import { A2A_SCOPES, RUN_ACTIONS } from "../../security/audience.js";
import type { RouterDeps } from "./contract.js";
import { parseBody, parseId, readUserId, requireAuthorized } from "./contract.js";

const runCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    scope: z.object({ targets: z.array(z.string().trim().min(1).max(2048)).min(1) }).strict(),
    config: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

export function createRunsRouter(deps: RouterDeps): Router {
  const router = Router();

  router.post("/runs", async (req, res) => {
    await requireAuthorized(deps.authz, "runs:create", res);
    const body = parseBody(runCreateSchema, req.body);
    const userId = readUserId(res);
    const run = await deps.repos.runs.create({
      name: body.name,
      scope: { targets: [...body.scope.targets] },
      ...(userId.length > 0 ? { userId } : {}),
      ...(body.config ? { config: body.config } : {}),
    });

    if (deps.orchestrator !== undefined) {
      let dispatchToken = deps.orchestrator.token;
      // The gateway never signs workload tokens: the run token is minted by
      // the STS (via deps.sts), which validates the trusted run record.
      if (dispatchToken === undefined && deps.sts !== undefined && userId.length > 0) {
        try {
          dispatchToken = await deps.sts.mintRun({
            userId,
            runId: run.runId,
            targets: [...body.scope.targets],
            actions: [...RUN_ACTIONS],
            correlationId: newId(),
            scopes: [...A2A_SCOPES],
          });
        } catch (err) {
          deps.log.warn({ err, runId: run.runId }, "STS refused to mint a run token; dispatch skipped");
        }
      }
      if (dispatchToken === undefined) {
        deps.log.warn({ runId: run.runId }, "no dispatch token available; run.start not dispatched");
        deps.log.info({ runId: run.runId }, "run created");
        res.status(202).json({ run_id: run.runId, state: run.state });
        return;
      }
      const task: TaskInit = {
        taskId: newId(),
        runId: run.runId,
        kind: "run.start",
        input: {
          scope: { targets: [...body.scope.targets] },
          ...(body.config ? { config: body.config } : {}),
        },
      };
      try {
        const client = new A2AClient(deps.orchestrator.base, { token: dispatchToken });
        await client.taskSend(task);
        deps.log.info({ runId: run.runId }, "run.start dispatched to orchestrator");
      } catch (err) {
        deps.log.warn({ err, runId: run.runId }, "run.start dispatch failed; run remains CREATED");
      }
    }

    deps.log.info({ runId: run.runId }, "run created");
    res.status(202).json({ run_id: run.runId, state: run.state });
  });

  router.get("/runs/:runId", async (req, res) => {
    const runId = parseId(req.params.runId, "run");
    const run = await deps.repos.runs.get(runId);
    if (!run) throw new NotFoundError("run not found");
    await requireAuthorized(deps.authz, "runs:read", res, {
      runId,
      ...(run.userId !== undefined ? { resourceOwner: run.userId } : {}),
      ...(run.tenantId !== undefined ? { resourceTenantId: run.tenantId } : {}),
    });

    const tasks = await deps.repos.tasks.listByRun(runId);
    const taskSummary = {
      total: tasks.length,
      running: tasks.filter((t) => t.status === "RUNNING").length,
      succeeded: tasks.filter((t) => t.status === "SUCCEEDED").length,
      failed: tasks.filter((t) => t.status === "FAILED").length,
      cancelled: tasks.filter((t) => t.status === "CANCELLED").length,
    };

    res.status(200).json({
      run_id: run.runId,
      state: run.state,
      timeline: run.timeline,
      task_summary: taskSummary,
    });
  });

  router.get("/runs/:runId/findings", async (req, res) => {
    const runId = parseId(req.params.runId, "run");
    const run = await deps.repos.runs.get(runId);
    if (!run) throw new NotFoundError("run not found");
    await requireAuthorized(deps.authz, "runs:read", res, {
      runId,
      ...(run.userId !== undefined ? { resourceOwner: run.userId } : {}),
      ...(run.tenantId !== undefined ? { resourceTenantId: run.tenantId } : {}),
    });

    const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
    const severity: FindingSeverity | undefined =
      typeof req.query.severity === "string" && severitySchema.safeParse(req.query.severity).success
        ? (req.query.severity as FindingSeverity)
        : undefined;

    const limitRaw = typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 100;
    const limit = Number.isNaN(limitRaw) ? 100 : Math.min(Math.max(limitRaw, 1), 500);

    const findings = await deps.repos.findings.listByRun(runId, {
      ...(severity !== undefined ? { severity } : {}),
      limit,
    });
    res.status(200).json({
      findings: findings.map((f) => ({ finding_id: f.findingId, severity: f.severity, title: f.title, status: f.status })),
    });
  });

  return router;
}