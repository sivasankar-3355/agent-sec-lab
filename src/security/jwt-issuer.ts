import { randomBytes } from "node:crypto";
import { b64url, encodeJwt, verifyJwtSignature, publicKeyFromPrivate } from "./jwt.js";
import type {
  AuthTokenProvider,
  MintRunTokenInput,
  TokenExchangeRequest,
  TokenIssuer,
  TokenVerdict,
  VerifiedContext,
} from "./protocols.js";

export type TokenKind = "workload" | "run";

interface RunReg {
  runId: string;
  tenantId?: string;
  targets: readonly string[];
  actions: readonly string[];
  correlationId: string;
}

export interface JwtIdentityOptions {
  issuer: string;
  keyId: string;
  signingKeyPem: string;
  publicKeys: ReadonlyMap<string, string>;
  workloadTtlSec: number;
  runTtlSec: number;
  childTtlSec: number;
  /** Algorithm allowlist (default: RS256 only). HS* is never allowed. */
  allowedAlgorithms?: readonly string[];
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function isoFromEpoch(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString();
}

function newNonce(): string {
  return b64url(randomBytes(16));
}

function audAsList(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud) && aud.every((a) => typeof a === "string")) return aud as string[];
  return [];
}

function readReg(claims: Record<string, unknown>): RunReg | undefined {
  const reg = claims.reg;
  if (typeof reg !== "object" || reg === null) return undefined;
  const r = reg as Record<string, unknown>;
  if (typeof r.runId !== "string") return undefined;
  return {
    runId: r.runId,
    ...(typeof r.tenantId === "string" ? { tenantId: r.tenantId } : {}),
    targets: Array.isArray(r.targets) ? (r.targets as string[]) : [],
    actions: Array.isArray(r.actions) ? (r.actions as string[]) : [],
    correlationId: typeof r.correlationId === "string" ? r.correlationId : "",
  };
}

function contextFromClaims(
  claims: Record<string, unknown>,
  algorithm: string,
  keyId: string,
): VerifiedContext {
  const reg = readReg(claims);
  const aud = audAsList(claims.aud);
  const scopes = Array.isArray(claims.scopes) ? (claims.scopes as string[]) : [];
  const actor = typeof claims.actor === "string" ? claims.actor : String(claims.sub ?? "");
  return {
    userId: reg !== undefined ? String(claims.sub ?? "") : "",
    ...(reg?.tenantId !== undefined ? { tenantId: reg.tenantId } : {}),
    runId: reg?.runId ?? "",
    scopeTargets: reg?.targets ?? [],
    permittedActions: reg?.actions ?? [],
    agent: "",
    audience: aud,
    correlationId: reg?.correlationId ?? "",
    issuedAt: typeof claims.iat === "number" ? isoFromEpoch(claims.iat) : new Date(0).toISOString(),
    expiresAt: typeof claims.exp === "number" ? isoFromEpoch(claims.exp) : new Date(0).toISOString(),
    nonce: typeof claims.jti === "string" ? claims.jti : "",
    caller: actor,
    scopes,
    algorithm,
    keyId,
  };
}

/** Verifier-only peer. Holds public keys; can never issue tokens. */
export class JwtVerifier implements AuthTokenProvider {
  protected readonly issuer: string;
  protected readonly keyId: string;
  protected readonly publicKeys: ReadonlyMap<string, string>;
  protected readonly allowedAlgorithms: readonly string[];

  constructor(options: JwtIdentityOptions) {
    this.issuer = options.issuer;
    this.keyId = options.keyId;
    this.publicKeys = options.publicKeys;
    this.allowedAlgorithms = options.allowedAlgorithms ?? ["RS256"];
  }

  async createToken(_principal: string, _scopes: readonly string[]): Promise<string> {
    throw new Error("this verifier cannot issue tokens");
  }

  async verifyToken(token: string, options?: { audience?: string }): Promise<TokenVerdict> {
    const verified = this.verifyJwt(token);
    if (!verified.ok) {
      return { valid: false, ...(verified.reason.length > 0 ? { reason: verified.reason } : {}) };
    }
    const { claims, algorithm, keyId } = verified;
    if (typeof claims.iss !== "string" || claims.iss !== this.issuer) {
      return { valid: false, reason: "unknown issuer" };
    }
    const now = nowSec();
    const iat = typeof claims.iat === "number" ? claims.iat : Number.NaN;
    const exp = typeof claims.exp === "number" ? claims.exp : Number.NaN;
    if (Number.isNaN(iat) || Number.isNaN(exp)) return { valid: false, reason: "missing timestamps" };
    if (iat > now + 60) return { valid: false, reason: "token issued in the future" };
    if (exp <= now) return { valid: false, reason: "token expired" };
    const aud = audAsList(claims.aud);
    if (options?.audience !== undefined && !aud.includes(options.audience)) {
      return { valid: false, reason: `token audience does not include '${options.audience}'` };
    }
    const context = contextFromClaims(claims, algorithm, keyId);
    return {
      valid: true,
      principal: String(claims.sub ?? ""),
      scopes: context.scopes,
      context,
    };
  }

  protected verifyJwt(token: string):
    | { ok: true; claims: Record<string, unknown>; algorithm: string; keyId: string; kind: TokenKind }
    | { ok: false; reason: string } {
    const result = verifyJwtSignature(token, this.publicKeys, this.allowedAlgorithms);
    if (!result.ok) return { ok: false, reason: result.reason };
    return {
      ok: true,
      claims: result.claims as Record<string, unknown>,
      algorithm: result.algorithm,
      keyId: result.keyId,
      kind: this.kindOf(result.claims as Record<string, unknown>),
    };
  }

  protected kindOf(claims: Record<string, unknown>): TokenKind {
    return claims.kind === "run" ? "run" : "workload";
  }
}

/** Issuer. Only the gateway should ever hold the signing key. */
export class JwtTokenService extends JwtVerifier implements TokenIssuer {
  private readonly signingKeyPem: string;
  private readonly workloadTtlSec: number;
  private readonly runTtlSec: number;
  private readonly childTtlSec: number;

  constructor(options: JwtIdentityOptions) {
    super(options);
    this.signingKeyPem = options.signingKeyPem;
    this.workloadTtlSec = options.workloadTtlSec;
    this.runTtlSec = options.runTtlSec;
    this.childTtlSec = options.childTtlSec;
  }

  override async createToken(principal: string, scopes: readonly string[]): Promise<string> {
    return this.sign(
      { kind: "workload", sub: principal, actor: principal, aud: [], scopes: [...scopes] },
      this.workloadTtlSec,
    );
  }

  async mintWorkloadToken(workload: string, scopes: readonly string[]): Promise<string> {
    return this.sign(
      { kind: "workload", sub: `workload:${workload}`, actor: `workload:${workload}`, aud: [], scopes: [...scopes] },
      this.workloadTtlSec,
    );
  }

  async mintRunToken(input: MintRunTokenInput): Promise<string> {
    return this.sign(
      {
        kind: "run",
        sub: input.userId,
        actor: "workload:gateway",
        aud: ["a2a:orchestrator"],
        reg: {
          runId: input.runId,
          ...(input.tenantId !== undefined ? { tenantId: input.tenantId } : {}),
          targets: [...input.targets],
          actions: [...input.actions],
          correlationId: input.correlationId,
        },
        scopes: [...(input.scopes ?? [])],
      },
      this.runTtlSec,
    );
  }

  async exchangeRunToken(runToken: string, request: TokenExchangeRequest): Promise<string> {
    const verified = this.verifyJwt(runToken);
    if (!verified.ok) throw new Error(verified.reason);
    if (verified.kind !== "run") throw new Error("not a run token");
    const reg = readReg(verified.claims);
    if (!reg) throw new Error("run token has no run grant");
    const exp = typeof verified.claims.exp === "number" ? verified.claims.exp : nowSec();
    const remainingSec = Math.max(0, exp - nowSec());
    if (remainingSec <= 0) throw new Error("run token expired");
    const actor = request.actor ?? (typeof verified.claims.actor === "string" ? verified.claims.actor : "");
    const nonce = newNonce();
    return this.sign(
      {
        kind: "run",
        sub: String(verified.claims.sub ?? ""),
        actor,
        aud: [request.audience],
        reg: { ...reg, actions: [...request.actions] },
        scopes: Array.isArray(verified.claims.scopes) ? [...(verified.claims.scopes as string[])] : [],
        prev: typeof verified.claims.jti === "string" ? verified.claims.jti : undefined,
        jti: nonce,
      },
      Math.min(this.childTtlSec, remainingSec),
    );
  }

  private sign(payload: Record<string, unknown>, ttlSec: number): string {
    const iat = nowSec();
    const claims = { ...payload, iss: this.issuer, iat, exp: iat + ttlSec, jti: newNonce() };
    return encodeJwt(claims, this.signingKeyPem, this.keyId, "RS256");
  }
}

export { publicKeyFromPrivate };