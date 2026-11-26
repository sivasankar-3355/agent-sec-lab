import { AppError } from "../../core/errors.js";

const SECRET_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer [redacted]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[redacted-jwt]"],
  [/\bsk-[A-Za-z0-9_-]{8,}\b/g, "[redacted-api-key]"],
  [/\bgh[pousr]_[A-Za-z0-9]{8,}\b/g, "[redacted-token]"],
  [/\bAKIA[0-9A-Z]{12,}\b/g, "[redacted-access-key]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted-private-key]"],
];

/** Best-effort redaction for error messages returned across a trust boundary. */
export function redactSecrets(text: string): string {
  let value = text;
  for (const [pattern, replacement] of SECRET_PATTERNS) value = value.replace(pattern, replacement);
  return value;
}

/**
 * Serialize tool output for size checks and prompt-injection inspection. The
 * returned value is untrusted data; callers must never interpret it as
 * instructions. Unserializable output is rejected rather than coerced.
 */
export function serializeToolOutput(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "null";
  try {
    const text = JSON.stringify(value);
    if (text === undefined) throw new Error("not serializable");
    return text;
  } catch {
    throw new AppError("tool_output_invalid", "tool output could not be serialized", 502);
  }
}

export function outputBytes(value: unknown): { text: string; bytes: number } {
  const text = serializeToolOutput(value);
  return { text, bytes: Buffer.byteLength(text, "utf8") };
}

export function assertOutputSize(bytes: number, maxBytes: number): void {
  if (bytes > maxBytes) {
    throw new AppError(
      "tool_output_too_large",
      `tool output exceeds the ${maxBytes}-byte limit`,
      502,
    );
  }
}
