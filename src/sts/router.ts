import { Router } from "express";
import { z } from "zod";
import type { Logger } from "pino";
import { AppError, UnauthenticatedError } from "../core/errors.js";
import type { Repositories } from "../db/repositories/build.js";
import type { AuthTokenProvider, SecretProvider, TokenIssuer } from "../security/protocols.js";
import {
  A2A_SCOPES,
  ACTIONS_BY_AUDIENCE,
  ALLOWED_CHILD_AUDIENCES,
  INTERNAL_EXCHANGE_SCOPE,
  INTERNAL_ISSUE_SCOPE,
  INTERNAL_MINT_SCOPE,
  RUN_ACTIONS,
} from "../security/audience.js";

export interface STSDeps {
  log: Logger;
  authn: AuthTokenProvider;
  tokenIssuer?: TokenIssuer;
  secrets?: SecretProvider;
  repos: Repositories;
}

const exchangeSchema = z
  .object({
    runToken: z.string().trim().min(1).max(8192),
    audience: z.enum(["a2a:recon", "a2a:knowledge", "a2a:report"]),
    actions: z.array(z.string().trim().min(1).max(128)).min(1),
  })
  .strict();

const mintSchema = z
  .object({
    runId: z.string().uuid(),
    targets: z.array(z.string().trim().min(1).max(2048)).min(1),
    actions: z.array(z.string().trim().min(1).max(128)).min(1),
    correlationId: z.string().trim().min(1).max(256),
  })
  .strict();

const issueSchema = z
  .object({
    workload: z.string().trim().min(1).max(128).regex(/^[a-z0-9-]+$/),
    scopes: z.array(z.string().trim().min(1).max(128)).default([]),
  })
  .strict();

function readBearer(header: string | undefined): string {
  return header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((value, index) => value === sortedB[index]);
}

export function createSTSRouter(deps: STSDeps): Router {
  const router = Router();

  const requireWorkload = async (authorization: string | undefined, scope: string, caller: string) => {
    const token = readBearer(authorization);
    const verdict = await deps.authn.verifyToken(token);
    if (!verdict.valid || verdict.context === undefined) {
      throw new UnauthenticatedError(verdict.reason ?? "missing or invalid workload token");
    }
    const ctx = verdict.context;
    if (!ctx.scopes.includes(scope)) {
      throw new AppError("forbidden", `workload token lacks '${scope}' scope`, 403);
    }
    if (ctx.caller !== caller || ctx.userId !== "") {
      throw new AppError("forbidden", `only the '${caller}' workload may call this endpoint`, 403);
    }
    return ctx;
  };

  // Gateway workload -> mint a run-bound token from the trusted run record.
  router.post("/internal/token-mint", async (req, res) => {
    await requireWorkload(req.headers.authorization, INTERNAL_MINT_SCOPE, "workload:gateway");
    const parsed = mintSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError("validation_error", "invalid token-mint request", 422);
    }
    if (deps.tokenIssuer === undefined) {
      throw new AppError("internal_error", "token issuer is not configured", 500);
    }

    const run = await deps.repos.runs.get(parsed.data.runId);
    if (!run) throw new AppError("not_found", "run not found", 404);
    if (run.state === "FAILED" || run.state === "CANCELLED" || run.state === "COMPLETED") {
      throw new AppError("forbidden", `run '${run.runId}' is ${run.state}; cannot mint a token`, 403);
    }
    if (run.userId === undefined || run.userId.length === 0) {
      throw new AppError("forbidden", "run is not bound to an authenticated user", 403);
    }
    // The gateway must never expand permissions: targets must match the
    // user-approved run scope exactly, and actions stay within the run grant.
    if (!sameSet(parsed.data.targets, [...run.scope.targets])) {
      throw new AppError("forbidden", "requested targets do not match the run's approved scope", 403);
    }
    if (parsed.data.actions.some((action) => !RUN_ACTIONS.includes(action))) {
      throw new AppError("forbidden", "requested actions exceed the allowed run grant", 403);
    }

    const token = await deps.tokenIssuer.mintRunToken({
      userId: run.userId,
      ...(run.tenantId !== undefined ? { tenantId: run.tenantId } : {}),
      runId: run.runId,
      targets: [...run.scope.targets],
      actions: [...parsed.data.actions],
      correlationId: parsed.data.correlationId,
      scopes: [...A2A_SCOPES],
    });
    res.status(200).json({ token });
  });

  // Orchestrator workload -> per-hop child token (delegation).
  router.post("/internal/token-exchange", async (req, res) => {
    await requireWorkload(req.headers.authorization, INTERNAL_EXCHANGE_SCOPE, "workload:orchestrator");

    const parsed = exchangeSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError("validation_error", "invalid token-exchange request", 422);
    }
    const { runToken, audience, actions } = parsed.data;
    if (!ALLOWED_CHILD_AUDIENCES.includes(audience)) {
      throw new AppError("forbidden", `audience '${audience}' is not exchangeable`, 403);
    }
    const allowed = ACTIONS_BY_AUDIENCE[audience] ?? [];
    if (actions.some((action) => !allowed.includes(action))) {
      throw new AppError("forbidden", `actions for '${audience}' exceed the allowed set`, 403);
    }

    const runVerdict = await deps.authn.verifyToken(runToken, { audience: "a2a:orchestrator" });
    if (!runVerdict.valid || runVerdict.context === undefined || runVerdict.context.runId === "") {
      throw new AppError("forbidden", "invalid run token presented for exchange", 403);
    }
    const grantedActions = runVerdict.context.permittedActions;
    if (grantedActions.some((action) => !RUN_ACTIONS.includes(action))) {
      throw new AppError("forbidden", "run token carries actions beyond the run grant", 403);
    }
    // The orchestrator can never widen its own grant: every child action must
    // already be present in the presented run token's permitted actions.
    if (actions.some((action) => !grantedActions.includes(action))) {
      throw new AppError("forbidden", "requested child actions exceed the run token grant", 403);
    }
    const run = await deps.repos.runs.get(runVerdict.context.runId);
    if (!run) throw new AppError("not_found", "run not found", 404);
    if (run.state === "FAILED" || run.state === "CANCELLED") {
      throw new AppError("forbidden", `run '${run.runId}' is ${run.state}; cannot exchange tokens`, 403);
    }

    if (deps.tokenIssuer === undefined) {
      throw new AppError("internal_error", "token issuer is not configured", 500);
    }
    const child = await deps.tokenIssuer.exchangeRunToken(runToken, { audience, actions, actor: "workload:orchestrator" });
    res.status(200).json({ token: child });
  });

  // Any workload with the bootstrap secret -> its own short-lived workload token.
  router.post("/internal/token-issue", async (req, res) => {
    const parsed = issueSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError("validation_error", "invalid token-issue request", 422);
    }
    if (deps.tokenIssuer === undefined || deps.secrets === undefined) {
      throw new AppError("internal_error", "token issuer is not configured", 500);
    }
    const secret = await deps.secrets.get("WORKLOAD_BOOTSTRAP");
    const presented = req.headers["x-bootstrap"] as string | undefined;
    if (presented !== secret.value) {
      throw new UnauthenticatedError("invalid bootstrap secret");
    }
    const token = await deps.tokenIssuer.mintWorkloadToken(parsed.data.workload, [
      INTERNAL_ISSUE_SCOPE,
      ...parsed.data.scopes,
    ]);
    res.status(200).json({ token });
  });

  return router;
}
