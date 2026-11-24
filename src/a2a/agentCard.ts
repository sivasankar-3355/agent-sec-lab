import { A2A_PROTOCOL_VERSION, type AgentKind } from "./schema.js";

export interface AgentSkill {
  id: string;
  name: string;
  description: string;
  tags: readonly string[];
}

export interface AgentCapabilities {
  streaming: boolean;
  pushNotifications: boolean;
}

export interface AgentCard {
  version: string;
  agentId: AgentKind;
  name: string;
  description: string;
  skills: readonly AgentSkill[];
  capabilities: AgentCapabilities;
  defaultInputModes: readonly string[];
  defaultOutputModes: readonly string[];
}

const SKILLS: Record<AgentKind, readonly AgentSkill[]> = {
  orchestrator: [
    {
      id: "run-lifecycle",
      name: "run lifecycle",
      description: "drives a run through recon/knowledge/report by submitting and polling child A2A tasks",
      tags: ["orchestration", "state-machine"],
    },
  ],
  recon: [
    {
      id: "recon-steps",
      name: "recon steps",
      description: "executes sandbox-gated reconnaissance steps against a declared scope and produces findings",
      tags: ["recon", "findings"],
    },
  ],
  knowledge: [
    {
      id: "knowledge-index",
      name: "knowledge index",
      description: "chunks, embeds, and indexes documents into the semantic store",
      tags: ["index", "embeddings"],
    },
    {
      id: "knowledge-search",
      name: "knowledge search",
      description: "semantic retrieval over indexed documents",
      tags: ["search", "retrieval"],
    },
  ],
  report: [
    {
      id: "report-generate",
      name: "report generate",
      description: "assembles a run's findings into a versioned, checksummed report artifact",
      tags: ["report", "artifact"],
    },
  ],
};

export function createAgentCard(agent: AgentKind): AgentCard {
  const description: Record<AgentKind, string> = {
    orchestrator: "orchestrates the reconnaissance/knowledge/report run pipeline",
    recon: "executes policy-checked reconnaissance and writes findings",
    knowledge: "semantic document index and retrieval",
    report: "renders and signs run reports",
  };
  return {
    version: A2A_PROTOCOL_VERSION,
    agentId: agent,
    name: `${agent} agent`,
    description: description[agent],
    skills: SKILLS[agent],
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
  };
}