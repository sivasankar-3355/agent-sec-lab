import type { A2AMessage, A2ATask, InitializeResult, TaskInit } from "./schema.js";
import type { AgentCard } from "./agentCard.js";
import type { VerifiedContext } from "../security/protocols.js";

/** Per-call identity context produced by the A2A server after verification. */
export interface CallContext {
  verified: VerifiedContext;
  token?: string;
  /** Aborted when the client disconnects or the server request deadline wins. */
  signal?: AbortSignal;
}

export interface A2AHandler {
  agentCard(): Promise<AgentCard>;
  initialize(params: { agentId?: string }, ctx?: CallContext): Promise<InitializeResult>;
  messageSend(message: A2AMessage, ctx?: CallContext): Promise<{ message: A2AMessage }>;
  taskSend(task: TaskInit, ctx?: CallContext): Promise<{ task: A2ATask }>;
  taskGet(id: string, ctx?: CallContext): Promise<{ task: A2ATask }>;
  taskCancel(id: string, ctx?: CallContext): Promise<{ task: A2ATask }>;
}