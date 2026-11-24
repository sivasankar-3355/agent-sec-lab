export interface AuthzResource {
  principal?: string;
  scopes?: readonly string[];
  runId?: string;
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
}

export interface AuthTokenProvider {
  createToken(principal: string, scopes: readonly string[]): Promise<string>;
  verifyToken(token: string): Promise<TokenVerdict>;
}

export interface AuditProvider {
  emit(event: AuditEvent): Promise<void>;
}
