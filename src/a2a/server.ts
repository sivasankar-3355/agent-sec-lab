import { Router, type Request } from "express";
import type { Logger } from "pino";
import type { z } from "zod";
import { A2AError, AppError, NotFoundError, UnauthenticatedError } from "../core/errors.js";
import { newId } from "../core/ids.js";
import type {
  AuditProvider,
  AuthTokenProvider,
  AuthorizationProvider,
} from "../security/protocols.js";
import type { A2AHandler } from "./handler.js";
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

export function createA2ARouter(handler: A2AHandler, deps: AgentServerDeps): Router {
  const router = Router();

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

    const { method, params } = envelope.data;
    const resource: { runId?: string; taskId?: string } = {};
    if (typeof params === "object" && params !== null) {
      const task = (params as { task?: { runId?: string; taskId?: string } }).task;
      const idParam = (params as { id?: string }).id;
      if (task?.runId) resource.runId = task.runId;
      if (task?.taskId) resource.taskId = task.taskId;
      if (typeof idParam === "string") resource.taskId = idParam;
    }

    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
    const verdict = await deps.authn.verifyToken(token);
    if (!verdict.valid || !verdict.principal) {
      await deps.audit.emit({
        type: "a2a.request.rejected",
        ts: new Date().toISOString(),
        traceId: requestId,
        data: { method, reason: "unauthenticated" },
      });
      res.status(401).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: JSONRPC_CODES.unauthenticated, message: verdict.reason ?? "unauthenticated" },
      });
      return;
    }
    res.locals.principal = { principal: verdict.principal, scopes: verdict.scopes ?? [] };

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

    const decision = await deps.authz.authorize(`a2a:${method}`, {
      ...(res.locals.principal ? { principal: res.locals.principal.principal, scopes: res.locals.principal.scopes } : {}),
      ...(resource.runId !== undefined ? { runId: resource.runId } : {}),
      ...(resource.taskId !== undefined ? { taskId: resource.taskId } : {}),
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

    try {
      let result: unknown;
      switch (method) {
        case "initialize":
          result = await handler.initialize((params as { agentId?: string } | undefined) ?? {});
          break;
        case "agentCard":
          result = await handler.agentCard();
          break;
        case "message/send":
          result = await handler.messageSend((params as { message: A2AMessage }).message);
          break;
        case "tasks/send":
          result = await handler.taskSend((params as { task: TaskInit }).task);
          break;
        case "tasks/get":
          result = await handler.taskGet((params as { id: string }).id);
          break;
        case "tasks/cancel":
          result = await handler.taskCancel((params as { id: string }).id);
          break;
      }

      void deps.audit.emit({
        type: "a2a.request.accepted",
        ts: new Date().toISOString(),
        traceId: requestId,
        ...(resource.runId !== undefined ? { runId: resource.runId } : {}),
        ...(resource.taskId !== undefined ? { taskId: resource.taskId } : {}),
        data: { method },
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