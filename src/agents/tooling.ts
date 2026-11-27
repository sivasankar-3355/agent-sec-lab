import type { Repositories } from "../db/repositories/build.js";
import type { FailClosedSecurityProviders } from "../security/defaults.js";
import { createToolBroker, type ToolBroker } from "../security/tools/index.js";
import { RunGovernor } from "../core/resilience/index.js";
import { LocalToolExecutor } from "./tool-executor.js";
import { agentToolCatalog } from "./tool-catalog.js";
import type { MemoryService } from "./memory.js";

export interface AgentToolingOptions {
  /** Shared governor; production wires the Redis-backed budget store. */
  governor?: RunGovernor;
  llmTimeoutMs?: number;
}

/**
 * Wire the in-process Tool Broker for a worker. The broker receives the
 * trusted registry, OPA provider, audit, network policy, run governor and a
 * trusted run loader. The local executor receives the sealed operation catalog
 * and tool dependencies; no DB client, credential or unrestricted sandbox is
 * exposed to the broker.
 */
export function createAgentToolBroker(
  security: FailClosedSecurityProviders,
  repos: Repositories,
  memory?: MemoryService,
  options: AgentToolingOptions = {},
): ToolBroker {
  const governor = options.governor ?? new RunGovernor();
  const executor = new LocalToolExecutor(agentToolCatalog, {
    audit: security.audit,
    policy: security.policy,
    model: security.model,
    crypto: security.crypto,
    repos,
    sandbox: security.sandbox,
    ...(memory !== undefined ? { memory } : {}),
    governor,
    ...(options.llmTimeoutMs !== undefined ? { llmTimeoutMs: options.llmTimeoutMs } : {}),
  });

  return createToolBroker({
    registry: agentToolCatalog.registry,
    executor,
    authz: security.authz,
    audit: security.audit,
    network: security.network,
    resolveRun: (runId) => repos.runs.get(runId),
    governor,
  });
}
