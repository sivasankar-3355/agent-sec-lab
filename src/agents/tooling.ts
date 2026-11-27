import type { Repositories } from "../db/repositories/build.js";
import type { FailClosedSecurityProviders } from "../security/defaults.js";
import { createToolBroker, type ToolBroker } from "../security/tools/index.js";
import { LocalToolExecutor } from "./tool-executor.js";
import { agentToolCatalog } from "./tool-catalog.js";
import type { MemoryService } from "./memory.js";

/**
 * Wire the in-process Tool Broker for a worker. The broker receives the
 * trusted registry, OPA provider, audit, network policy and a trusted run
 * loader. The local executor receives the sealed operation catalog and tool
 * dependencies; no DB client, credential or unrestricted sandbox is exposed to
 * the broker.
 */
export function createAgentToolBroker(
  security: FailClosedSecurityProviders,
  repos: Repositories,
  memory?: MemoryService,
): ToolBroker {
  const executor = new LocalToolExecutor(agentToolCatalog, {
    audit: security.audit,
    policy: security.policy,
    model: security.model,
    crypto: security.crypto,
    repos,
    sandbox: security.sandbox,
    ...(memory !== undefined ? { memory } : {}),
  });

  return createToolBroker({
    registry: agentToolCatalog.registry,
    executor,
    authz: security.authz,
    audit: security.audit,
    network: security.network,
    resolveRun: (runId) => repos.runs.get(runId),
  });
}
