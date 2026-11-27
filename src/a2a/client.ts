import { A2AError } from "../core/errors.js";
import { newId } from "../core/ids.js";
import { withDeadline } from "../core/resilience/abort.js";
import type { CircuitBreaker } from "../core/resilience/circuit.js";
import { CircuitOpenError } from "../core/resilience/errors.js";
import { classifyError, isRetryable, retry } from "../core/resilience/retry.js";
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
  /**
   * Optional per-peer circuit breaker. The client admits one request, records
   * a transport success/failure, and refuses when the circuit is open.
   */
  breaker?: CircuitBreaker;
  /**
   * Extra client-internal attempts for `taskGet`/`taskCancel`. Default 0: the
   * orchestrator owns polling/retry, so the default avoids nested retries.
   */
  retries?: number;
}

export interface A2ACallOptions {
  signal?: AbortSignal;
}

export class A2AClient {
  private readonly base: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  private readonly breaker: CircuitBreaker | undefined;
  private readonly retries: number;

  constructor(baseUrl: string, options: A2AClientOptions = {}) {
    this.base = baseUrl.replace(/\/+$/, "");
    if (options.token !== undefined && options.token.length > 0) this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.breaker = options.breaker;
    this.retries = Math.max(0, Math.trunc(options.retries ?? 0));
  }

  async agentCard(options: A2ACallOptions = {}): Promise<AgentCard> {
    const response = await this.request(
      `${this.base}/agent-card`,
      { method: "GET" },
      "agent-card",
      options,
    );
    if (!response.ok) throw new A2AError(`A2A endpoint returned ${response.status}`, response.status);
    if (response.text.length === 0) throw new A2AError("A2A endpoint returned an empty card");
    return JSON.parse(response.text) as unknown as AgentCard;
  }

  async initialize(agentId?: string, options: A2ACallOptions = {}): Promise<InitializeResult> {
    const result = await this.rpc("initialize", agentId === undefined ? {} : { agentId }, options);
    return result as InitializeResult;
  }

  async messageSend(message: A2AMessage, options: A2ACallOptions = {}): Promise<{ message: A2AMessage }> {
    const result = await this.rpc("message/send", { message }, options);
    return result as { message: A2AMessage };
  }

  /**
   * Submitting a task is idempotent at the receiver by `task.taskId`; callers
   * that retry must reuse the same task object. The client does not retry
   * `tasks/send` by itself.
   */
  async taskSend(task: TaskInit, options: A2ACallOptions = {}): Promise<A2ATask> {
    const result = await this.rpc("tasks/send", { task }, options);
    return (result as { task: A2ATask }).task;
  }

  async taskGet(id: string, options: A2ACallOptions = {}): Promise<A2ATask> {
    const result = await this.rpcWithOptionalRetry("tasks/get", { id }, options);
    return (result as { task: A2ATask }).task;
  }

  async taskCancel(id: string, options: A2ACallOptions = {}): Promise<A2ATask> {
    const result = await this.rpcWithOptionalRetry("tasks/cancel", { id }, options);
    return (result as { task: A2ATask }).task;
  }

  private async rpcWithOptionalRetry(
    method: string,
    params: object,
    options: A2ACallOptions,
  ): Promise<unknown> {
    if (this.retries === 0) return this.rpc(method, params, options);
    return retry(() => this.rpc(method, params, options), {
      policy: { maxAttempts: this.retries + 1 },
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      shouldRetry: (err) => isRetryable(err, { retryTimeouts: true }),
    });
  }

  private async rpc(method: string, params: object, options: A2ACallOptions): Promise<unknown> {
    const response = await this.request(
      `${this.base}/a2a`,
      {
        method: "POST",
        body: {
          jsonrpc: "2.0",
          id: newId(),
          method,
          params,
        },
      },
      method,
      options,
    );
    if (!response.ok) {
      throw new A2AError(`A2A peer returned ${response.status}`, response.status);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.text) as unknown;
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

  private async request(
    url: string,
    request: { method: "GET" | "POST"; body?: object },
    label: string,
    options: A2ACallOptions,
  ): Promise<{ ok: boolean; status: number; text: string }> {
    if (this.breaker !== undefined && !this.breaker.allowRequest()) {
      throw new CircuitOpenError(this.breaker.name);
    }
    const admitted = this.breaker !== undefined;
    try {
      // The deadline covers the response body too, not just the header.
      const response = await withDeadline(
        async (signal) => {
          const init: RequestInit = {
            method: request.method,
            headers: {
              "content-type": "application/json",
              "x-a2a-version": A2A_PROTOCOL_VERSION,
              ...(this.token !== undefined ? { authorization: `Bearer ${this.token}` } : {}),
            },
            // Internal A2A endpoints never need redirects; a redirect would
            // hide the real destination and could create a loop.
            redirect: "error",
            signal,
          };
          if (request.body !== undefined) init.body = JSON.stringify(request.body);
          const raw = await globalThis.fetch(url, init);
          const text = await raw.text();
          return { ok: raw.ok, status: raw.status, text };
        },
        {
          timeoutMs: this.timeoutMs,
          ...(options.signal !== undefined ? { signal: options.signal } : {}),
          label: `a2a.${label}`,
        },
      );
      if (this.breaker !== undefined) {
        if (response.status >= 500) this.breaker.recordFailure();
        else this.breaker.recordSuccess();
      }
      return response;
    } catch (err) {
      if (this.breaker !== undefined && admitted) {
        const kind = classifyError(err);
        if (kind === "transient" || kind === "timeout") this.breaker.recordFailure();
        else this.breaker.recordSuccess();
      }
      throw err;
    }
  }
}
