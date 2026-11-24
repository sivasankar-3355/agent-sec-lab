import type { Logger } from "pino";
import type { Response } from "express";
import { z } from "zod";
import { ValidationError, AuthorizationDeniedError } from "../../core/errors.js";
import type { Repositories } from "../../db/repositories/build.js";
import type {
  AuthzResource,
  AuthorizationProvider,
  EmbeddingProvider,
  RunTokenMinter,
} from "../../security/protocols.js";
import { readPrincipal } from "../auth.js";

export interface OrchestratorLink {
  base: string;
  token?: string;
}

export interface RouterDeps {
  log: Logger;
  authz: AuthorizationProvider;
  embedding: EmbeddingProvider;
  repos: Repositories;
  orchestrator?: OrchestratorLink;
  /** Mints run-bound workload tokens by calling the STS (gateway side only). */
  sts?: RunTokenMinter;
}

export function parseBody<T>(schema: z.ZodType<T, z.ZodTypeDef, unknown>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    const detail = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new ValidationError(detail);
  }
  return result.data;
}

const uuidSchema = z.string().uuid();

export function parseId(raw: string, label: string): string {
  try {
    return uuidSchema.parse(raw);
  } catch {
    throw new ValidationError(`invalid ${label} id`);
  }
}

export function readUserId(res: Response): string {
  return readPrincipal(res)?.userId ?? "";
}

export async function requireAuthorized(
  authz: AuthorizationProvider,
  action: string,
  res: Response,
  resource: AuthzResource = {},
): Promise<void> {
  const principal = readPrincipal(res);
  const decision = await authz.authorize(action, {
    ...(principal ? { principal: principal.principal, scopes: principal.scopes } : {}),
    ...resource,
  });
  if (!decision.allowed) {
    throw new AuthorizationDeniedError(decision.reason ?? "authorization denied");
  }
}