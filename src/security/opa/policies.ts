import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export const DEFAULT_POLICY_DIR = "policies";
export const DEFAULT_POLICY_VERSION = "v1";

export interface PolicyBundle {
  version: string;
  directory: string;
  source: string;
}

export function policyFilePath(dir: string, version: string): string {
  return resolve(dir, version, "authz.rego");
}

/**
 * Load a versioned policy bundle from disk. The directory is resolved against
 * the process working directory (local dev/tests). Remote deployments can
 * provide the policy source directly or point OPA_URL at a real OPA.
 */
export function loadPolicyBundle(dir: string, version: string): PolicyBundle {
  const file = policyFilePath(dir, version);
  return { version, directory: dir, source: readFileSync(file, "utf8") };
}
