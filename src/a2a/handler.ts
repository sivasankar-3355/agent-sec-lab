import type { A2AMessage, A2ATask, InitializeResult, TaskInit } from "./schema.js";
import type { AgentCard } from "./agentCard.js";

export interface A2AHandler {
  agentCard(): Promise<AgentCard>;
  initialize(params: { agentId?: string }): Promise<InitializeResult>;
  messageSend(message: A2AMessage): Promise<{ message: A2AMessage }>;
  taskSend(task: TaskInit): Promise<{ task: A2ATask }>;
  taskGet(id: string): Promise<{ task: A2ATask }>;
  taskCancel(id: string): Promise<{ task: A2ATask }>;
}