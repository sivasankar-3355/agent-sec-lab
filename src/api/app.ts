import express, { type Application, type NextFunction, type Request, type Response } from "express";
import type { Logger } from "pino";
import { AppError } from "../core/errors.js";
import { newId } from "../core/ids.js";
import type { Repositories } from "../db/repositories/build.js";
import type { RunTokenMinter } from "../security/protocols.js";
import type { SecurityProviders } from "../security/container.js";
import { createRequireAuth } from "./auth.js";
import { createAuthRouter } from "./routers/auth.js";
import { createHealthRouter, type HealthStores } from "./routers/health.js";
import { createKnowledgeRouter } from "./routers/knowledge.js";
import { createMeRouter } from "./routers/me.js";
import { createReportsRouter } from "./routers/reports.js";
import { createRunsRouter } from "./routers/runs.js";
import type { OrchestratorLink } from "./routers/contract.js";

export interface AppDeps {
  log: Logger;
  security: SecurityProviders;
  stores: HealthStores;
  repos: Repositories;
  orchestrator?: OrchestratorLink;
  /** STS client used to mint run-bound workload tokens (gateway side). */
  sts?: RunTokenMinter;
}

export function createApp(deps: AppDeps): Application {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", false);
  app.use(express.json({ limit: "256kb" }));

  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = (req.headers["x-request-id"] as string | undefined)?.slice(0, 64) || newId();
    res.locals.requestId = requestId;
    res.setHeader("x-request-id", requestId);
    next();
  });

  app.use(createHealthRouter(deps.stores));

  // Open user authentication endpoints (registration + login). These mint
  // HS256 user JWTs; they are the only unauthenticated API routes.
  app.use(
    "/api/v1",
    createAuthRouter({
      log: deps.log,
      users: deps.repos.users,
      ...(deps.security.userAuth !== undefined ? { userAuth: deps.security.userAuth } : {}),
    }),
  );

  // Everything below requires a valid user JWT (HS256) when user auth is
  // configured, otherwise it fails closed.
  const requireAuth = createRequireAuth(deps.security.userAuth ?? deps.security.authn);
  const api = express.Router();
  api.use(requireAuth);

  const routerDeps = {
    log: deps.log,
    authz: deps.security.authz,
    embedding: deps.security.embedding,
    repos: deps.repos,
    ...(deps.orchestrator !== undefined ? { orchestrator: deps.orchestrator } : {}),
    ...(deps.sts !== undefined ? { sts: deps.sts } : {}),
  };

  api.use(createRunsRouter(routerDeps));
  api.use(createReportsRouter(routerDeps));
  api.use(createKnowledgeRouter(routerDeps));
  api.use(createMeRouter());

  app.use("/api/v1", api);

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: { code: "not_found", message: "route not found" }, request_id: res.locals.requestId });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const requestId: string = res.locals.requestId ?? "";
    if (err instanceof AppError) {
      deps.log.warn({ code: err.code, status: err.status }, "request rejected");
      res.status(err.status).json({ error: err.toResponse(), request_id: requestId });
      return;
    }
    const status = typeof (err as { status?: unknown })?.status === "number" ? (err as { status: number }).status : 500;
    deps.log.error({ err }, "unhandled request error");
    res.status(status).json({ error: { code: "internal_error", message: "internal error" }, request_id: requestId });
  });

  return app;
}
