import { A2AError } from "../../core/errors.js";
import type { A2ATask, TaskInit } from "../../a2a/schema.js";
import { A2AClient, type A2ACallOptions } from "../../a2a/client.js";
import { CircuitBreaker, type CircuitState } from "../../core/resilience/circuit.js";
import type { TokenExchangeRequest } from "../../security/protocols.js";

export interface ChildTaskBroker {
  submit(task: TaskInit, token?: string, options?: A2ACallOptions): Promise<A2ATask>;
  poll(taskId: string, options?: A2ACallOptions): Promise<A2ATask>;
  cancel(taskId: string, options?: A2ACallOptions): Promise<A2ATask>;
}

/** Exchanges a run token for a per-hop child token (delegation). */
export interface TokenExchanger {
  exchange(runToken: string, request: TokenExchangeRequest): Promise<string>;
}

export type ChildAgent = "recon" | "knowledge" | "report";

export interface AgentLink {
  base: string;
  token?: string;
}

export interface AgentClients {
  recon?: AgentLink;
  knowledge?: AgentLink;
  report?: AgentLink;
}

export interface AgentClientsBrokerOptions {
  timeoutMs?: number;
  circuit?: {
    failureThreshold?: number;
    recoveryIntervalMs?: number;
    halfOpenMaxCalls?: number;
  };
  onCircuitStateChange?: (agent: ChildAgent, from: CircuitState, to: CircuitState) => void;
}

export function agentForKind(kind: string): ChildAgent {
  if (kind === "recon.run") return "recon";
  if (kind === "knowledge.index" || kind === "knowledge.search") return "knowledge";
  if (kind === "report.generate") return "report";
  throw new A2AError(`no A2A route for task kind '${kind}'`);
}

/**
 * A2A child dispatcher with one circuit breaker per child agent and a single
 * HTTP timeout per call. It deliberately does not retry; the orchestrator owns
 * the bounded retry layer so retries are budgeted and never nested here.
 */
export class AgentClientsBroker implements ChildTaskBroker {
  private readonly links: AgentClients;
  private readonly options: AgentClientsBrokerOptions;
  private readonly clients = new Map<string, A2AClient>();
  private readonly breakers = new Map<ChildAgent, CircuitBreaker>();

  constructor(clients: AgentClients, options: AgentClientsBrokerOptions = {}) {
    this.links = clients;
    this.options = options;
  }

  async submit(task: TaskInit, token?: string, options: A2ACallOptions = {}): Promise<A2ATask> {
    const agent = agentForKind(task.kind);
    const link = this.links[agent];
    if (link === undefined) {
      throw new A2AError(`no A2A link configured for agent '${agent}'`, 503);
    }
    const resolved = token ?? link.token;
    if (resolved === undefined) {
      throw new A2AError(`no token available for child dispatch to '${agent}'`, 503);
    }
    const client = new A2AClient(link.base, {
      token: resolved,
      ...(this.options.timeoutMs !== undefined ? { timeoutMs: this.options.timeoutMs } : {}),
      breaker: this.breakerFor(agent),
    });
    this.clients.set(task.taskId, client);
    try {
      const submitted = await client.taskSend(task, options);
      if (submitted.status === "failed" || submitted.status === "canceled") {
        this.clients.delete(task.taskId);
      }
      return submitted;
    } catch (err) {
      // No terminal task is known on this path; do not retain the route. A
      // caller retry re-creates the client for the same idempotent taskId.
      this.clients.delete(task.taskId);
      throw err;
    }
  }

  async poll(taskId: string, options: A2ACallOptions = {}): Promise<A2ATask> {
    const task = await this.clientFor(taskId).taskGet(taskId, options);
    if (task.status === "completed" || task.status === "failed" || task.status === "canceled") {
      // The task is terminal; drop the per-task client route so the map does
      // not grow for the lifetime of the orchestrator process.
      this.clients.delete(taskId);
    }
    return task;
  }

  async cancel(taskId: string, options: A2ACallOptions = {}): Promise<A2ATask> {
    const task = await this.clientFor(taskId).taskCancel(taskId, options);
    this.clients.delete(taskId);
    return task;
  }

  private clientFor(taskId: string): A2AClient {
    const client = this.clients.get(taskId);
    if (client === undefined) {
      throw new A2AError(`no A2A route known for task '${taskId}'`);
    }
    return client;
  }

  private breakerFor(agent: ChildAgent): CircuitBreaker {
    const existing = this.breakers.get(agent);
    if (existing !== undefined) return existing;
    const circuit = this.options.circuit ?? {};
    const onStateChange = this.options.onCircuitStateChange;
    const breaker = new CircuitBreaker({
      name: `a2a:${agent}`,
      ...(circuit.failureThreshold !== undefined ? { failureThreshold: circuit.failureThreshold } : {}),
      ...(circuit.recoveryIntervalMs !== undefined
        ? { recoveryIntervalMs: circuit.recoveryIntervalMs }
        : {}),
      ...(circuit.halfOpenMaxCalls !== undefined
        ? { halfOpenMaxCalls: circuit.halfOpenMaxCalls }
        : {}),
      ...(onStateChange !== undefined
        ? { onStateChange: (from, to) => onStateChange(agent, from, to) }
        : {}),
    });
    this.breakers.set(agent, breaker);
    return breaker;
  }
}
