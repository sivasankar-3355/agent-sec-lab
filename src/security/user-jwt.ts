import { randomBytes } from "node:crypto";
import type { AuthTokenProvider, TokenVerdict, VerifiedContext } from "./protocols.js";
import { b64url, encodeJwt, verifyJwtSignature } from "./jwt.js";

export interface UserJwtOptions {
  /** Dedicated symmetric secret, HS256. Never shared with the STS or workers. */
  secret: string;
  issuer: string;
  audience: string;
  ttlSec: number;
}

/** The only algorithm accepted for user tokens. */
const USER_ALGORITHMS: readonly string[] = ["HS256"];
const USER_KEY_ID = "user-key";

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function isoFromEpoch(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString();
}

/**
 * Gateway-side user authentication. Mints and verifies HS256 user JWTs with a
 * dedicated symmetric secret. The verifier is intentionally narrow:
 * - algorithm allowlisted to HS256 only (workload RS256 tokens can never pass)
 * - issuer, audience, subject prefix and expiry all enforced
 */
export class UserAuthService implements AuthTokenProvider {
  private readonly secret: string;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly ttlSec: number;

  constructor(options: UserJwtOptions) {
    this.secret = options.secret;
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.ttlSec = options.ttlSec;
  }

  async mintUserToken(userId: string, scopes: readonly string[]): Promise<string> {
    const iat = nowSec();
    const claims = {
      kind: "user",
      iss: this.issuer,
      sub: userId,
      aud: [this.audience],
      iat,
      exp: iat + this.ttlSec,
      jti: b64url(randomBytes(16)),
      scopes: [...scopes],
    };
    return encodeJwt(claims, this.secret, USER_KEY_ID, "HS256");
  }

  async createToken(principal: string, scopes: readonly string[]): Promise<string> {
    return this.mintUserToken(principal, scopes);
  }

  async verifyToken(token: string): Promise<TokenVerdict> {
    const result = verifyJwtSignature(token, new Map([[USER_KEY_ID, this.secret]]), USER_ALGORITHMS);
    if (!result.ok) return { valid: false, reason: result.reason };

    const claims = result.claims as Record<string, unknown>;
    if (typeof claims.iss !== "string" || claims.iss !== this.issuer) {
      return { valid: false, reason: "unknown issuer" };
    }
    const now = nowSec();
    const iat = typeof claims.iat === "number" ? claims.iat : Number.NaN;
    const exp = typeof claims.exp === "number" ? claims.exp : Number.NaN;
    if (Number.isNaN(iat) || Number.isNaN(exp)) return { valid: false, reason: "missing timestamps" };
    if (iat > now + 60) return { valid: false, reason: "token issued in the future" };
    if (exp <= now) return { valid: false, reason: "token expired" };

    const aud = claims.aud;
    if (!Array.isArray(aud) || !aud.includes(this.audience)) {
      return { valid: false, reason: `token audience does not include '${this.audience}'` };
    }
    const sub = typeof claims.sub === "string" ? claims.sub : "";
    if (!sub.startsWith("user:")) return { valid: false, reason: "token subject is not a user" };

    const scopes = Array.isArray(claims.scopes) ? (claims.scopes as string[]) : [];
    const context: VerifiedContext = {
      userId: sub,
      runId: "",
      scopeTargets: [],
      permittedActions: [],
      agent: "",
      audience: [this.audience],
      correlationId: "",
      issuedAt: isoFromEpoch(iat),
      expiresAt: isoFromEpoch(exp),
      nonce: typeof claims.jti === "string" ? claims.jti : "",
      caller: "",
      scopes,
      algorithm: "HS256",
      keyId: USER_KEY_ID,
    };
    return { valid: true, principal: sub, scopes, context };
  }
}
