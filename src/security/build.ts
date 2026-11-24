import { readFileSync } from "node:fs";
import type { Logger } from "pino";
import type { Config } from "../core/config.js";
import { failClosedProviders, type FailClosedSecurityProviders } from "./defaults.js";
import { JwtTokenService, JwtVerifier, publicKeyFromPrivate } from "./jwt-issuer.js";
import { UserAuthService } from "./user-jwt.js";

/** Resolve a PEM from inline text or a `file:`-prefixed path. */
export function resolvePem(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.startsWith("file:")) {
    return readFileSync(trimmed.replace(/^file:/, ""), "utf8").trim();
  }
  return trimmed;
}

function asPublicPem(pem: string): string {
  return pem.includes("PRIVATE KEY") ? publicKeyFromPrivate(pem) : pem;
}

function parsePublicKeyMap(
  encoded: string,
  keyId: string,
  singlePem?: string,
  signingPem?: string,
): Map<string, string> {
  const keys = new Map<string, string>();
  const raw = encoded.trim();
  if (raw.length > 0) {
    const parsed = JSON.parse(raw) as Record<string, string>;
    for (const [kid, pem] of Object.entries(parsed)) keys.set(kid, asPublicPem(pem));
  }
  if (singlePem !== undefined && !keys.has(keyId)) keys.set(keyId, asPublicPem(singlePem));
  if (keys.size === 0 && signingPem !== undefined) keys.set(keyId, asPublicPem(signingPem));
  return keys;
}

/**
 * Build security providers from configuration. Key separation (Phase 1):
 * - `USER_JWT_SECRET`      -> `userAuth`  (gateway-only, HS256 user tokens)
 * - `STS_PRIVATE_KEY`      -> `tokenIssuer` (STS-only, asymmetric workload tokens)
 * - `STS_PUBLIC_KEY(S)`    -> `authn` (shared workload verifier)
 * Absent key material keeps every interface fail-closed: no token is accepted
 * and no token can be issued.
 */
export function buildSecurityProviders(config: Config, log: Logger): FailClosedSecurityProviders {
  const base = failClosedProviders(log);

  const signingPem = resolvePem(config.STS_PRIVATE_KEY);
  const publicKeys = parsePublicKeyMap(
    config.STS_PUBLIC_KEYS,
    config.STS_KEY_ID,
    resolvePem(config.STS_PUBLIC_KEY),
    signingPem,
  );

  const userSecret = config.USER_JWT_SECRET.trim();
  const userAuth =
    userSecret.length > 0
      ? new UserAuthService({
          secret: userSecret,
          issuer: config.USER_JWT_ISS,
          audience: config.USER_JWT_AUD,
          ttlSec: config.USER_TOKEN_TTL,
        })
      : undefined;

  if (publicKeys.size === 0 && userAuth === undefined) return base;

  const providers: FailClosedSecurityProviders = { ...base };
  if (userAuth !== undefined) providers.userAuth = userAuth;

  if (publicKeys.size > 0) {
    const options = {
      issuer: config.STS_ISS,
      keyId: config.STS_KEY_ID,
      signingKeyPem: signingPem ?? "",
      publicKeys,
      workloadTtlSec: config.WORKLOAD_TOKEN_TTL,
      runTtlSec: config.RUN_TOKEN_TTL,
      childTtlSec: config.CHILD_TOKEN_TTL,
      allowedAlgorithms: ["RS256"],
    };
    if (signingPem !== undefined) {
      const service = new JwtTokenService(options);
      providers.authn = service;
      providers.tokenIssuer = service;
    } else {
      providers.authn = new JwtVerifier(options);
    }
  }

  return providers;
}
