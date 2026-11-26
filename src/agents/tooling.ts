import type { Repositories } from "../db/repositories/build.js";
import type { FailClosedSecurityProviders } from "../security/defaults.js";
import { createToolBroker, type ToolBroker } from "../security/tools/index.js";
import { agentToolRegistry } from "./tools.js";

/**
 * Wire the in-process Tool Broker for a worker. The broker receives only the
 * trusted registry, the shared OPA provider, audit, network policy and a
 * trusted run loader. No tool implementation, DB client or credential is
 * exposed through this wiring.
 */
export function createAgentToolBroker(
  security: FailClosedSecurityProviders,
  repos: Repositories,
): ToolBroker {
  return createToolBroker({
    registry: agentToolRegistry,
    authz: security.authz,
    audit: security.audit,
    network: security.network,
    resolveRun: (runId) => repos.runs.get(runId),
  });
}
