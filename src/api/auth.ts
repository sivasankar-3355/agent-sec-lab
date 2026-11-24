import type { NextFunction, Request, Response } from "express";
import { UnauthenticatedError } from "../core/errors.js";
import type { AuthTokenProvider } from "../security/protocols.js";

export interface PrincipalContext {
  principal: string;
  scopes: readonly string[];
}

export function readPrincipal(res: Response): PrincipalContext | undefined {
  return res.locals.principal as PrincipalContext | undefined;
}

export function createRequireAuth(authn: AuthTokenProvider) {
  return async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";

    const verdict = await authn.verifyToken(token);
    if (!verdict.valid || !verdict.principal) {
      throw new UnauthenticatedError(verdict.reason ?? "missing or invalid token");
    }

    res.locals.principal = { principal: verdict.principal, scopes: verdict.scopes ?? [] };
    next();
  };
}
