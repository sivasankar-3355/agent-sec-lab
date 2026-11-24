import type { Logger } from "pino";
import {
  SandboxUnavailableError,
  NotConfiguredError,
  AuthorizationDeniedError,
  PolicyViolationError,
  EgressDeniedError,
} from "../core/errors.js";
import type {
  AuditProvider,
  AuditEvent,
  AuthTokenProvider,
  AuthorizationProvider,
  CryptoProvider,
  Decision,
  EgressDecision,
  EmbeddingProvider,
  ModelProvider,
  NetworkPolicyProvider,
  PolicyProvider,
  SandboxProvider,
  Secret,
  SecretProvider,
  Signature,
  TokenVerdict,
  Violation,
  SandboxStep,
  SandboxResult,
  Completion,
} from "./protocols.js";

class DenyAuthorizationProvider implements AuthorizationProvider {
  async authorize(): Promise<Decision> {
    return { allowed: false, reason: "no authorization control is configured" };
  }
}

class UnavailableSandboxProvider implements SandboxProvider {
  async run(_step: SandboxStep): Promise<SandboxResult> {
    throw new SandboxUnavailableError();
  }
}

class DenyPolicyProvider implements PolicyProvider {
  async evaluate(_target: string, action: string, ruleRefs: readonly string[]): Promise<readonly Violation[]> {
    return [{ rule: "default-deny", reason: `no policy control is configured for action '${action}' (rules: ${ruleRefs.join(",")})` }];
  }
}

class DenyNetworkPolicyProvider implements NetworkPolicyProvider {
  async assertEgress(target: string): Promise<EgressDecision> {
    return { allowed: false, reason: `egress to '${target}' not permitted: no network policy control is configured` };
  }
}

class MissingSecretProvider implements SecretProvider {
  async get(name: string): Promise<Secret> {
    throw new NotConfiguredError(`no secret provider is configured; cannot retrieve '${name}'`);
  }
}

class UnsignedCryptoProvider implements CryptoProvider {
  async sign(_data: Buffer): Promise<Signature> {
    throw new NotConfiguredError("no signing control is configured");
  }

  async verify(_data: Buffer, _signature: Signature, _purpose: string): Promise<boolean> {
    return false;
  }
}

class UnconfiguredEmbeddingProvider implements EmbeddingProvider {
  async embed(_texts: readonly string[]): Promise<number[][]> {
    throw new NotConfiguredError("no embedding control is configured");
  }
}

class UnconfiguredModelProvider implements ModelProvider {
  async complete(_prompt: string, _context: Record<string, unknown>): Promise<Completion> {
    throw new NotConfiguredError("no model control is configured");
  }
}

class NoAuthTokenProvider implements AuthTokenProvider {
  async createToken(_principal: string, _scopes: readonly string[]): Promise<string> {
    throw new NotConfiguredError("no token issuer is configured");
  }

  async verifyToken(_token: string): Promise<TokenVerdict> {
    return { valid: false, reason: "no token verifier is configured" };
  }
}

class LocalAuditProvider implements AuditProvider {
  constructor(private readonly log: Logger) {}

  async emit(event: AuditEvent): Promise<void> {
    this.log.info({ audit: event }, "audit");
  }
}

export interface FailClosedSecurityProviders {
  authz: AuthorizationProvider;
  sandbox: SandboxProvider;
  policy: PolicyProvider;
  network: NetworkPolicyProvider;
  secrets: SecretProvider;
  crypto: CryptoProvider;
  embedding: EmbeddingProvider;
  model: ModelProvider;
  authn: AuthTokenProvider;
  audit: AuditProvider;
}

export function failClosedProviders(logger: Logger): FailClosedSecurityProviders {
  return {
    authz: new DenyAuthorizationProvider(),
    sandbox: new UnavailableSandboxProvider(),
    policy: new DenyPolicyProvider(),
    network: new DenyNetworkPolicyProvider(),
    secrets: new MissingSecretProvider(),
    crypto: new UnsignedCryptoProvider(),
    embedding: new UnconfiguredEmbeddingProvider(),
    model: new UnconfiguredModelProvider(),
    authn: new NoAuthTokenProvider(),
    audit: new LocalAuditProvider(logger),
  };
}

export { AuthorizationDeniedError, PolicyViolationError, EgressDeniedError, SandboxUnavailableError };
