import { createHmac, createPrivateKey, createPublicKey, sign, timingSafeEqual, verify } from "node:crypto";

export interface JwtHeader {
  alg: string;
  kid: string;
  typ: string;
}

export interface JwtClaims {
  [key: string]: unknown;
}

export interface JwtVerificationError {
  reason: string;
}

function encodeB64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function decodeB64Url(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64");
}

export function b64url(input: string | Buffer): string {
  return encodeB64Url(Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8"));
}

/**
 * Sign a JWT. For asymmetric algorithms (RS256) `signingMaterial` is a PEM
 * private key; for symmetric algorithms (HS256) it is the raw shared secret.
 */
export function encodeJwt(
  claims: JwtClaims,
  signingMaterial: string,
  kid: string,
  algorithm: "RS256" | "HS256" = "RS256",
): string {
  const header: JwtHeader = { alg: algorithm, kid, typ: "JWT" };
  const segments = [b64url(JSON.stringify(header)), b64url(JSON.stringify(claims))];
  const signingInput = segments.join(".");
  if (algorithm === "HS256") {
    const signature = createHmac("sha256", signingMaterial).update(signingInput, "utf8").digest();
    return `${signingInput}.${encodeB64Url(signature)}`;
  }
  const key = createPrivateKey(signingMaterial);
  const signature = sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), key);
  return `${signingInput}.${encodeB64Url(signature)}`;
}

export interface DecodedJwt {
  header: JwtHeader;
  claims: JwtClaims;
}

export function decodeJwt(token: string): DecodedJwt | JwtVerificationError {
  const parts = token.split(".");
  if (parts.length !== 3) return { reason: "malformed token" };
  let header: JwtHeader;
  let claims: JwtClaims;
  try {
    header = JSON.parse(decodeB64Url(parts[0]!).toString("utf8")) as JwtHeader;
    claims = JSON.parse(decodeB64Url(parts[1]!).toString("utf8")) as JwtClaims;
  } catch {
    return { reason: "malformed token" };
  }
  return { header, claims };
}

export interface VerifyOk {
  ok: true;
  claims: JwtClaims;
  algorithm: string;
  keyId: string;
}

export interface VerifyError {
  ok: false;
  reason: string;
}

/**
 * Verify the signature of a JWT against a key map (kid -> PEM for asymmetric,
 * kid -> shared secret for symmetric) and an explicit algorithm allowlist.
 * Fail-closed: any algorithm outside the allowlist is rejected before any
 * key material is used.
 */
export function verifyJwtSignature(
  token: string,
  keyMap: ReadonlyMap<string, string>,
  allowedAlgorithms?: readonly string[],
): VerifyOk | VerifyError {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed token" };
  const decoded = decodeJwt(token);
  if (!("claims" in decoded)) return { ok: false, reason: (decoded as JwtVerificationError).reason };
  const alg = decoded.header.alg;
  if (allowedAlgorithms !== undefined && !allowedAlgorithms.includes(alg)) {
    return { ok: false, reason: `algorithm '${alg}' not allowed` };
  }
  const material = keyMap.get(decoded.header.kid);
  if (material === undefined) return { ok: false, reason: `unknown key id '${decoded.header.kid}'` };
  const signature = decodeB64Url(parts[2]!);
  const signingInput = `${parts[0]!}.${parts[1]!}`;

  if (alg === "HS256") {
    const expected = createHmac("sha256", material).update(signingInput, "utf8").digest();
    if (expected.length !== signature.length || !timingSafeEqual(expected, signature)) {
      return { ok: false, reason: "invalid signature" };
    }
    return { ok: true, claims: decoded.claims, algorithm: alg, keyId: decoded.header.kid };
  }

  if (alg === "RS256") {
    const key = createPublicKey(material);
    const valid = verify("RSA-SHA256", Buffer.from(signingInput, "utf8"), key, signature);
    if (!valid) return { ok: false, reason: "invalid signature" };
    return { ok: true, claims: decoded.claims, algorithm: alg, keyId: decoded.header.kid };
  }

  return { ok: false, reason: `unsupported algorithm '${alg}'` };
}

export function publicKeyFromPrivate(privateKeyPem: string): string {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(privateKey);
  return publicKey.export({ type: "pkcs1", format: "pem" }) as string;
}
