import type { Logger } from "pino";
import type { Response } from "express";
import { z } from "zod";
import { ValidationError, AuthorizationDeniedError } from "../../core/errors.js";
import type { Repositories } from "../../db/repositories/build.js";
import type {
  AuditProvider,
  AuthzResource,
  AuthorizationProvider,
  EmbeddingProvider,
  RunTokenMinter,
} from "../../security/protocols.js";
import type { MemoryActor, MemoryService } from "../../agents/memory.js";
import type { CircuitBreaker } from "../../core/resilience/circuit.js";
import type { RetryPolicy } from "../../core/resilience/retry.js";
import { readPrincipal } from "../auth.js";

export interface OrchestratorLink {
  base: string;
  token?: string;
  timeoutMs?: number;
  retry?: Partial<RetryPolicy>;
  /** Shared per-orchestrator circuit breaker (gateway-side dispatch). */
  breaker?: CircuitBreaker;
}

export interface RouterDeps {
  log: Logger;
  authz: AuthorizationProvider;
  embedding: EmbeddingProvider;
  repos: Repositories;
  /** Audit sink for prompt-injection inspections and trust decisions. */
  audit: AuditProvider;
  /** Single authorized path for durable memory (Phase 4). */
  memory?: MemoryService;
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

/** Build the verified API memory actor from the authenticated principal. */
export function readMemoryActor(res: Response): MemoryActor {
  const principal = readPrincipal(res);
  return {
    kind: "api",
    principal: principal?.principal ?? "",
    userId: readUserId(res),
    scopes: principal?.scopes ?? [],
  };
}

export async function requireAuthorized(
  authz: AuthorizationProvider,
  action: string,
  res: Response,
  resource: AuthzResource = {},
): Promise<void> {
  const principal = readPrincipal(res);
  const decision = await authz.authorize(action, {
    kind: "api",
    ...(principal ? { principal: principal.principal, scopes: principal.scopes } : {}),
    ...(principal !== undefined && principal.userId !== undefined ? { user: principal.userId } : {}),
    ...resource,
  });
  if (!decision.allowed) {
    throw new AuthorizationDeniedError(decision.reason ?? "authorization denied");
  }
}