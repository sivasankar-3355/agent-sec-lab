import { Router, type Request } from "express";
import type { Logger } from "pino";
import type { z } from "zod";
import { A2AError, AppError, NotFoundError, UnauthenticatedError } from "../core/errors.js";
import { newId } from "../core/ids.js";
import type {
  AuditProvider,
  AuthTokenProvider,
  AuthorizationProvider,
  VerifiedContext,
} from "../security/protocols.js";
import type { AgentKind } from "./schema.js";
import type { A2AHandler, CallContext } from "./handler.js";
import {
  a2aMethods,
  initializeParamsSchema,
  jsonRpcRequestSchema,
  messageSendParamsSchema,
  taskCancelParamsSchema,
  taskGetParamsSchema,
  taskInitSchema,
  type A2AMethod,
  type A2AMessage,
  type TaskInit,
} from "./schema.js";

export interface AgentServerDeps {
  log: Logger;
  authn: AuthTokenProvider;
  authz: AuthorizationProvider;
  audit: AuditProvider;
  agent?: AgentKind;
  audience?: string;
  replay?: (nonce: string) => Promise<boolean>;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

const JSONRPC_CODES = {
  parse: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internal: -32000,
  unauthenticated: -32001,
  forbidden: -32003,
  notFound: -32004,
} as const;

const PARAM_SCHEMAS: Record<A2AMethod, z.ZodTypeAny | null> = {
  initialize: initializeParamsSchema,
  agentCard: null,
  "message/send": messageSendParamsSchema,
  "tasks/send": taskInitSchema,
  "tasks/get": taskGetParamsSchema,
  "tasks/cancel": taskCancelParamsSchema,
};

const RUN_BOUND_METHODS: readonly A2AMethod[] = ["tasks/send", "tasks/get", "tasks/cancel", "message/send"];

function errorMap(err: unknown): JsonRpcError {
  if (err instanceof UnauthenticatedError) {
    return { code: JSONRPC_CODES.unauthenticated, message: err.message };
  }
  if (err instanceof NotFoundError) {
    return { code: JSONRPC_CODES.notFound, message: err.message };
  }
  if (err instanceof A2AError) {
    return { code: err.status === 403 ? JSONRPC_CODES.forbidden : JSONRPC_CODES.internal, message: err.message };
  }
  if (err instanceof AppError) {
    if (err.status === 403) return { code: JSONRPC_CODES.forbidden, message: err.message };
    return { code: JSONRPC_CODES.internal, message: err.message };
  }
  return { code: JSONRPC_CODES.internal, message: "internal error" };
}

function firstErrorCode(err: unknown): number {
  if (err instanceof AppError) {
    if (err.status === 401) return JSONRPC_CODES.unauthenticated;
    if (err.status === 403) return JSONRPC_CODES.forbidden;
    if (err.status === 404) return JSONRPC_CODES.notFound;
    return JSONRPC_CODES.internal;
  }
  return JSONRPC_CODES.internal;
}

function httpStatusForCode(code: number): number {
  if (code === JSONRPC_CODES.unauthenticated) return 401;
  if (code === JSONRPC_CODES.forbidden) return 403;
  if (code === JSONRPC_CODES.notFound) return 404;
  return 200;
}

function bindAudienceContext(ctx: VerifiedContext, audienceName: string): VerifiedContext {
  return { ...ctx, agent: audienceName };
}

/** Calling workload identity derived from the verified actor/principal. */
function workloadOf(principal: string, ctx?: VerifiedContext): string {
  const caller = ctx?.caller ?? "";
  if (caller.startsWith("workload:")) return caller.slice("workload:".length);
  if (principal.startsWith("workload:")) return principal.slice("workload:".length);
  return "";
}

export function createA2ARouter(handler: A2AHandler, deps: AgentServerDeps): Router {
  const router = Router();
  const audienceName =
    deps.audience ?? (deps.agent !== undefined ? `a2a:${deps.agent}` : undefined);

  router.get("/agent-card", async (_req, res) => {
    res.status(200).json(await handler.agentCard());
  });

  router.post("/a2a", async (req: Request, res) => {
    const requestId = newId();

    const envelope = jsonRpcRequestSchema.safeParse(req.body);
    const rpcId = typeof req.body?.id === "string" ? req.body.id : null;
    if (!envelope.success) {
      res.status(200).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: JSONRPC_CODES.invalidRequest, message: "invalid JSON-RPC request" },
      });
      return;
    }

    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
    const verdict = await deps.authn.verifyToken(
      token,
      audienceName !== undefined ? { audience: audienceName } : undefined,
    );
    if (!verdict.valid || !verdict.principal) {
      await deps.audit.emit({
        type: "a2a.request.rejected",
        ts: new Date().toISOString(),
        traceId: requestId,
        data: { method: envelope.data.method, reason: verdict.reason ?? "unauthenticated" },
      });
      res.status(401).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: JSONRPC_CODES.unauthenticated, message: verdict.reason ?? "unauthenticated" },
      });
      return;
    }

    const { method, params } = envelope.data;
    const parsedCtx = verdict.context !== undefined ? bindAudienceContext(verdict.context, audienceName ?? "") : undefined;
    const runBound = RUN_BOUND_METHODS.includes(method as A2AMethod);
    const hasRunGrant = parsedCtx !== undefined && parsedCtx.runId !== "";

    if (audienceName !== undefined && runBound && (parsedCtx === undefined || !hasRunGrant)) {
      await deps.audit.emit({
        type: "a2a.request.rejected",
        ts: new Date().toISOString(),
        traceId: requestId,
        data: { method, reason: "run-scoped token required" },
      });
      res.status(403).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: JSONRPC_CODES.forbidden, message: "run-scoped token required for this method" },
      });
      return;
    }

    if (deps.replay !== undefined && parsedCtx !== undefined && parsedCtx.nonce.length > 0) {
      const fresh = await deps.replay(parsedCtx.nonce);
      if (!fresh) {
        await deps.audit.emit({
          type: "a2a.request.rejected",
          ts: new Date().toISOString(),
          traceId: requestId,
          data: { method, reason: "token already used" },
        });
        res.status(403).json({
          jsonrpc: "2.0",
          id: rpcId,
          error: { code: JSONRPC_CODES.forbidden, message: "token already used" },
        });
        return;
      }
    }

    res.locals.principal = { principal: verdict.principal, scopes: verdict.scopes ?? [] };
    res.locals.ctx = parsedCtx;

    if (!a2aMethods.includes(method)) {
      res.status(200).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: JSONRPC_CODES.methodNotFound, message: `method not found: ${method}` },
      });
      return;
    }

    const schema = PARAM_SCHEMAS[method as A2AMethod];
    if (schema != null && schema !== undefined) {
      const parsed = schema.safeParse(params);
      if (!parsed.success) {
        res.status(200).json({
          jsonrpc: "2.0",
          id: rpcId,
          error: { code: JSONRPC_CODES.invalidParams, message: "invalid method parameters" },
        });
        return;
      }
    }

    const resource: { runId?: string; taskId?: string } = {};
    const intent: {
      requestedAction?: string;
      requestedTarget?: string;
      requestedRunId?: string;
      requestedDocIds?: string[];
    } = {};
    if (hasRunGrant) {
      resource.runId = parsedCtx.runId;
      intent.requestedRunId = parsedCtx.runId;
    } else if (typeof params === "object" && params !== null) {
      const task = (params as { task?: { runId?: string; taskId?: string; kind?: string; input?: Record<string, unknown> } }).task;
      const idParam = (params as { id?: string }).id;
      if (task?.runId) resource.runId = task.runId;
      if (task?.taskId) resource.taskId = task.taskId;
      if (typeof idParam === "string") resource.taskId = idParam;
    }

    // Untrusted call intent (from the request body) — the OPA policy bounds it
    // against the approved attributes from the *verified* token context.
    if (typeof params === "object" && params !== null) {
      const task = (params as { task?: { kind?: string; runId?: string; input?: Record<string, unknown> } }).task;
      if (task?.kind !== undefined && typeof task.kind === "string") intent.requestedAction = task.kind;
      if (task?.runId !== undefined && typeof task.runId === "string") intent.requestedRunId = task.runId;
      if (task?.input !== undefined && typeof task.input === "object" && task.input !== null) {
        const input = task.input as Record<string, unknown>;
        if (typeof input.target === "string") intent.requestedTarget = input.target;
        if (Array.isArray(input.docIds)) intent.requestedDocIds = input.docIds.filter((d): d is string => typeof d === "string");
      }
      const message = (params as { message?: { runId?: string } }).message;
      if (message?.runId !== undefined && typeof message.runId === "string") intent.requestedRunId = message.runId;
    }

    const workload = workloadOf(verdict.principal, parsedCtx);
    const policyAgent =
      deps.agent ??
      (audienceName !== undefined && audienceName.startsWith("a2a:") ? audienceName.slice("a2a:".length) : (audienceName ?? ""));

    const decision = await deps.authz.authorize(`a2a:${method}`, {
      kind: "a2a",
      ...(res.locals.principal
        ? { principal: res.locals.principal.principal, scopes: res.locals.principal.scopes }
        : {}),
      ...(workload.length > 0 ? { workload } : {}),
      ...(parsedCtx !== undefined && parsedCtx.userId.length > 0 ? { user: parsedCtx.userId } : {}),
      ...(policyAgent.length > 0 ? { agent: policyAgent } : {}),
      ...(parsedCtx !== undefined && parsedCtx.audience.length > 0 ? { audience: parsedCtx.audience } : {}),
      ...(parsedCtx !== undefined && parsedCtx.scopeTargets.length > 0 ? { approvedTargets: parsedCtx.scopeTargets } : {}),
      ...(parsedCtx !== undefined && parsedCtx.permittedActions.length > 0 ? { approvedActions: parsedCtx.permittedActions } : {}),
      ...(parsedCtx !== undefined && parsedCtx.tenantId !== undefined ? { tenantId: parsedCtx.tenantId } : {}),
      ...(resource.runId !== undefined ? { runId: resource.runId } : {}),
      ...(resource.taskId !== undefined ? { taskId: resource.taskId } : {}),
      ...(intent.requestedAction !== undefined ? { requestedAction: intent.requestedAction } : {}),
      ...(intent.requestedTarget !== undefined ? { requestedTarget: intent.requestedTarget } : {}),
      ...(intent.requestedRunId !== undefined ? { requestedRunId: intent.requestedRunId } : {}),
      ...(intent.requestedDocIds !== undefined ? { requestedDocIds: intent.requestedDocIds } : {}),
    });
    if (!decision.allowed) {
      await deps.audit.emit({
        type: "a2a.request.rejected",
        ts: new Date().toISOString(),
        traceId: requestId,
        ...(resource.runId !== undefined ? { runId: resource.runId } : {}),
        ...(resource.taskId !== undefined ? { taskId: resource.taskId } : {}),
        data: { method, reason: decision.reason ?? "forbidden" },
      });
      res.status(403).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: JSONRPC_CODES.forbidden, message: decision.reason ?? "forbidden" },
      });
      return;
    }

    const callCtx: CallContext | undefined =
      parsedCtx !== undefined ? { verified: parsedCtx, token } : undefined;

    try {
      let result: unknown;
      switch (method) {
        case "initialize":
          result = await handler.initialize((params as { agentId?: string } | undefined) ?? {}, callCtx);
          break;
        case "agentCard":
          result = await handler.agentCard();
          break;
        case "message/send":
          result = await handler.messageSend((params as { message: A2AMessage }).message, callCtx);
          break;
        case "tasks/send":
          result = await handler.taskSend((params as { task: TaskInit }).task, callCtx);
          break;
        case "tasks/get":
          result = await handler.taskGet((params as { id: string }).id, callCtx);
          break;
        case "tasks/cancel":
          result = await handler.taskCancel((params as { id: string }).id, callCtx);
          break;
      }

      void deps.audit.emit({
        type: "a2a.request.accepted",
        ts: new Date().toISOString(),
        traceId: requestId,
        ...(resource.runId !== undefined ? { runId: resource.runId } : {}),
        ...(resource.taskId !== undefined ? { taskId: resource.taskId } : {}),
        data: {
          method,
          ...(parsedCtx !== undefined ? { user: parsedCtx.userId, agent: parsedCtx.agent } : {}),
        },
      });

      res.status(200).json({ jsonrpc: "2.0", id: rpcId, result });
    } catch (err) {
      const jrpcError = errorMap(err);
      void deps.audit.emit({
        type: "a2a.request.failed",
        ts: new Date().toISOString(),
        traceId: requestId,
        ...(resource.runId !== undefined ? { runId: resource.runId } : {}),
        ...(resource.taskId !== undefined ? { taskId: resource.taskId } : {}),
        data: { method, code: jrpcError.code, message: jrpcError.message },
      });
      const status = httpStatusForCode(firstErrorCode(err));
      res.status(status).json({ jsonrpc: "2.0", id: rpcId, error: jrpcError });
    }
  });

  return router;
}