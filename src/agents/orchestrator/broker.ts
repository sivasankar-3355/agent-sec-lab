import { A2AError } from "../../core/errors.js";
import type { A2ATask, TaskInit } from "../../a2a/schema.js";
import type { A2AClient } from "../../a2a/client.js";

export interface ChildTaskBroker {
  submit(task: TaskInit): Promise<A2ATask>;
  poll(taskId: string): Promise<A2ATask>;
  cancel(taskId: string): Promise<A2ATask>;
}

export interface AgentClients {
  recon?: A2AClient;
  knowledge?: A2AClient;
  report?: A2AClient;
}

export class AgentClientsBroker implements ChildTaskBroker {
  private readonly clients: AgentClients;
  private readonly routes = new Map<string, "recon" | "knowledge" | "report">();

  constructor(clients: AgentClients) {
    this.clients = clients;
  }

  async submit(task: TaskInit): Promise<A2ATask> {
    const agent = this.agentFor(task);
    const client = this.clients[agent];
    if (client === undefined) {
      throw new A2AError(`no A2A link configured for agent '${agent}'`, 503);
    }
    this.routes.set(task.taskId, agent);
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

  private agentFor(task: TaskInit): "recon" | "knowledge" | "report" {
    if (task.kind === "recon.run") return "recon";
    if (task.kind === "knowledge.index" || task.kind === "knowledge.search") return "knowledge";
    if (task.kind === "report.generate") return "report";
    throw new A2AError(`no A2A route for task kind '${task.kind}'`);
  }

  private clientFor(taskId: string): A2AClient {
    const agent = this.routes.get(taskId);
    if (agent === undefined) {
      throw new A2AError(`no A2A route known for task '${taskId}'`);
    }
    const client = this.clients[agent];
    if (client === undefined) {
      throw new A2AError(`no A2A link configured for agent '${agent}'`, 503);
    }
    return client;
  }
}