import { A2AError } from "../../core/errors.js";
import type { A2ATask, TaskInit } from "../../a2a/schema.js";
import { A2AClient } from "../../a2a/client.js";
import type { TokenExchangeRequest } from "../../security/protocols.js";

export interface ChildTaskBroker {
  submit(task: TaskInit, token?: string): Promise<A2ATask>;
  poll(taskId: string): Promise<A2ATask>;
  cancel(taskId: string): Promise<A2ATask>;
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

export function agentForKind(kind: string): ChildAgent {
  if (kind === "recon.run") return "recon";
  if (kind === "knowledge.index" || kind === "knowledge.search") return "knowledge";
  if (kind === "report.generate") return "report";
  throw new A2AError(`no A2A route for task kind '${kind}'`);
}

export class AgentClientsBroker implements ChildTaskBroker {
  private readonly links: AgentClients;
  private readonly clients = new Map<string, A2AClient>();

  constructor(clients: AgentClients) {
    this.links = clients;
  }

  async submit(task: TaskInit, token?: string): Promise<A2ATask> {
    const agent = agentForKind(task.kind);
    const link = this.links[agent];
    if (link === undefined) {
      throw new A2AError(`no A2A link configured for agent '${agent}'`, 503);
    }
    const resolved = token ?? link.token;
    if (resolved === undefined) {
      throw new A2AError(`no token available for child dispatch to '${agent}'`, 503);
    }
    const client = new A2AClient(link.base, { token: resolved });
    this.clients.set(task.taskId, client);
    return client.taskSend(task);
  }

  async poll(taskId: string): Promise<A2ATask> {
    const client = this.clientFor(taskId);
    return client.taskGet(taskId);
  }

  async cancel(taskId: string): Promise<A2ATask> {
    const client = this.clientFor(taskId);
    return client.taskCancel(taskId);
  }

  private clientFor(taskId: string): A2AClient {
    const client = this.clients.get(taskId);
    if (client === undefined) {
      throw new A2AError(`no A2A route known for task '${taskId}'`);
    }
    return client;
  }
}