import { A2AError } from "../core/errors.js";
import { newId } from "../core/ids.js";
import {
  A2A_PROTOCOL_VERSION,
  jsonRpcResponseSchema,
  type A2AMessage,
  type A2ATask,
  type InitializeResult,
  type TaskInit,
} from "./schema.js";
import type { AgentCard } from "./agentCard.js";

export interface A2AClientOptions {
  token?: string;
  timeoutMs?: number;
  retries?: number;
}

export class A2AClient {
  private readonly base: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  private readonly retries: number;

  constructor(baseUrl: string, options: A2AClientOptions = {}) {
    this.base = baseUrl.replace(/\/+$/, "");
    if (options.token !== undefined && options.token.length > 0) this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.retries = options.retries ?? 3;
  }

  async agentCard(): Promise<AgentCard> {
    const response = await this.fetch(`${this.base}/agent-card`);
    const text = await response.text();
    if (!response.ok) throw new A2AError(`A2A endpoint returned ${response.status}`, response.status);
    if (text.length === 0) throw new A2AError("A2A endpoint returned an empty card");
    return JSON.parse(text) as unknown as AgentCard;
  }

  async initialize(agentId?: string): Promise<InitializeResult> {
    const result = await this.rpc("initialize", agentId === undefined ? {} : { agentId });
    return result as InitializeResult;
  }

  async messageSend(message: A2AMessage): Promise<{ message: A2AMessage }> {
    const result = await this.rpc("message/send", { message });
    return result as { message: A2AMessage };
  }

  async taskSend(task: TaskInit): Promise<A2ATask> {
    const result = await this.rpc("tasks/send", { task });
    return (result as { task: A2ATask }).task;
  }

  async taskGet(id: string): Promise<A2ATask> {
    const result = await this.rpcWithRetry("tasks/get", { id });
    return (result as { task: A2ATask }).task;
  }

  async taskCancel(id: string): Promise<A2ATask> {
    const result = await this.rpcWithRetry("tasks/cancel", { id });
    return (result as { task: A2ATask }).task;
  }

  private async rpc(method: string, params: object): Promise<unknown> {
    const response = await this.fetch(`${this.base}/a2a`, {
      jsonrpc: "2.0",
      id: newId(),
      method,
      params,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new A2AError(`A2A peer returned ${response.status}`, response.status);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new A2AError("A2A peer returned malformed JSON");
    }
    const envelope = jsonRpcResponseSchema.safeParse(parsed);
    if (!envelope.success) {
      throw new A2AError("A2A peer returned an invalid JSON-RPC envelope");
    }
    if (envelope.data.error !== undefined) {
      throw new A2AError(`${envelope.data.error.code}: ${envelope.data.error.message}`);
    }
    return envelope.data.result;
  }

  private async rpcWithRetry(method: string, params: object): Promise<unknown> {
    let last: unknown;
    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        return await this.rpc(method, params);
      } catch (err) {
        last = err;
        if (attempt < this.retries - 1) await this.sleep(50 * (attempt + 1));
      }
    }
    throw last;
  }

  private async fetch(url: string, body?: object): Promise<Response> {
    const init: RequestInit = {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "content-type": "application/json",
        "x-a2a-version": A2A_PROTOCOL_VERSION,
        ...(this.token !== undefined ? { authorization: `Bearer ${this.token}` } : {}),
      },
      signal: AbortSignal.timeout(this.timeoutMs),
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    return globalThis.fetch(url, init);
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}