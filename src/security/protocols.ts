export interface AuthzResource {
  principal?: string;
  scopes?: readonly string[];
  runId?: string;
  taskId?: string;
  user?: string;
  agent?: string;
  audience?: readonly string[];
}

export interface Decision {
  allowed: boolean;
  reason?: string;
}

export interface SandboxStep {
  name: string;
  input: unknown;
}

export interface SandboxResult {
  ok: boolean;
  output: unknown;
}

export interface Violation {
  rule: string;
  reason: string;
}

export interface EgressDecision {
  allowed: boolean;
  reason?: string;
}

export interface Secret {
  name: string;
  value: string;
}

export interface Signature {
  algorithm: string;
  value: string;
}

export interface Completion {
  text: string;
}

export interface AuditEvent {
  type: string;
  ts: string;
  traceId: string;
  principal?: string;
  runId?: string;
  taskId?: string;
  data?: Record<string, unknown>;
}

export interface AuthorizationProvider {
  authorize(action: string, resource: AuthzResource): Promise<Decision>;
}

export interface SandboxProvider {
  run(step: SandboxStep): Promise<SandboxResult>;
}

export interface PolicyProvider {
  evaluate(target: string, action: string, ruleRefs: readonly string[]): Promise<readonly Violation[]>;
}

export interface NetworkPolicyProvider {
  assertEgress(target: string): Promise<EgressDecision>;
}

export interface SecretProvider {
  get(name: string): Promise<Secret>;
}

export interface CryptoProvider {
  sign(data: Buffer): Promise<Signature>;
  verify(data: Buffer, signature: Signature, purpose: string): Promise<boolean>;
}

export interface EmbeddingProvider {
  embed(texts: readonly string[]): Promise<number[][]>;
}

export interface ModelProvider {
  complete(prompt: string, context: Record<string, unknown>): Promise<Completion>;
}

export interface TokenVerdict {
  valid: boolean;
  principal?: string;
  scopes?: readonly string[];
  reason?: string;
  context?: VerifiedContext;
}

export interface AuthTokenProvider {
  createToken(principal: string, scopes: readonly string[]): Promise<string>;
  verifyToken(token: string, options?: { audience?: string }): Promise<TokenVerdict>;
}

/**
 * Run-scoped authorization context carried by a verified token.
 * A workload/persona token (no run grant) has an empty `runId`, empty
 * `scopeTargets` and empty `permittedActions`; run tokens carry the full grant.
 * Field values come from the signed claims and are never trusted from request
 * bodies. `agent` (this receiver) and `caller` (the presenting workload) are
 * bound during verification, not supplied by the caller.
 */
export interface AuthorizationContext {
  userId: string;
  tenantId?: string;
  runId: string;
  scopeTargets: readonly string[];
  permittedActions: readonly string[];
  agent: string;
  audience: readonly string[];
  correlationId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

export interface VerifiedContext extends AuthorizationContext {
  caller: string;
  scopes: readonly string[];
  algorithm: string;
  keyId: string;
}

/** Per-hop permission gathered from the verified context. */
export type VerifiedCallContext = VerifiedContext;

export interface MintRunTokenInput {
  userId: string;
  tenantId?: string;
  runId: string;
  targets: readonly string[];
  actions: readonly string[];
  correlationId: string;
  scopes?: readonly string[];
}

export interface TokenExchangeRequest {
  audience: string;
  actions: readonly string[];
  actor?: string;
}

/**
 * Internal workload token service. Only the STS implements it (holds the
 * asymmetric private signing key); the gateway and workers never do.
 */
export interface TokenIssuer {
  mintWorkloadToken(workload: string, scopes: readonly string[]): Promise<string>;
  mintRunToken(input: MintRunTokenInput): Promise<string>;
  exchangeRunToken(runToken: string, request: TokenExchangeRequest): Promise<string>;
}

/**
 * Requests a run-bound workload token from the STS. Implemented by the
 * gateway-side STS client; the STS serves it server-side.
 */
export interface RunTokenMinter {
  mintRun(input: MintRunTokenInput): Promise<string>;
}

/**
 * User authentication (API gateway only). User tokens are HS256 with a
 * dedicated symmetric secret and must NEVER be accepted as workload tokens or
 * vice versa.
 */
export interface UserAuthProvider extends AuthTokenProvider {
  mintUserToken(userId: string, scopes: readonly string[]): Promise<string>;
}

export interface AuditProvider {
  emit(event: AuditEvent): Promise<void>;
}
