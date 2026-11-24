import type { Logger } from "pino";
import type { Config } from "../core/config.js";
import { failClosedProviders, type FailClosedSecurityProviders } from "./defaults.js";

export type SecurityProviders = FailClosedSecurityProviders;

export interface Container {
  config: Config;
  log: Logger;
  security: SecurityProviders;
}

export function createContainer(
  config: Config,
  log: Logger,
  security?: SecurityProviders,
): Container {
  return { config, log, security: security ?? failClosedProviders(log) };
}
