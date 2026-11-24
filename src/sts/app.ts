import express, { type Application, type NextFunction, type Request, type Response } from "express";
import type { Logger } from "pino";
import { AppError } from "../core/errors.js";
import { newId } from "../core/ids.js";
import type { Repositories } from "../db/repositories/build.js";
import type { SecurityProviders } from "../security/container.js";
import { createHealthRouter, type HealthStores } from "../api/routers/health.js";
import { createSTSRouter } from "./router.js";

export interface STSAppDeps {
  log: Logger;
  security: SecurityProviders;
  stores: HealthStores;
  repos: Repositories;
}

/**
 * The Security Token Service (STS). The only process that holds the workload
 * signing key. Authenticates gateway/orchestrator workload identities, then
 * mints short-lived asymmetric workload JWTs validated against the trusted
 * run record in MongoDB.
 */
export function createSTSApp(deps: STSAppDeps): Application {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", false);
  app.use(express.json({ limit: "64kb" }));

  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = (req.headers["x-request-id"] as string | undefined)?.slice(0, 64) || newId();
    res.locals.requestId = requestId;
    res.setHeader("x-request-id", requestId);
    next();
  });

  app.use(createHealthRouter(deps.stores));

  app.use(
    "/api/v1",
    createSTSRouter({
      log: deps.log,
      authn: deps.security.authn,
      ...(deps.security.tokenIssuer !== undefined ? { tokenIssuer: deps.security.tokenIssuer } : {}),
      ...(deps.security.secrets !== undefined ? { secrets: deps.security.secrets } : {}),
      repos: deps.repos,
    }),
  );

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: { code: "not_found", message: "route not found" }, request_id: res.locals.requestId });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const requestId: string = res.locals.requestId ?? "";
    if (err instanceof AppError) {
      deps.log.warn({ code: err.code, status: err.status }, "sts request rejected");
      res.status(err.status).json({ error: err.toResponse(), request_id: requestId });
      return;
    }
    deps.log.error({ err }, "unhandled sts error");
    res.status(500).json({ error: { code: "internal_error", message: "internal error" }, request_id: requestId });
  });

  return app;
}
