import type { DetectionCategory, DetectionResult, DetectionSignal } from "./types.js";

/**
 * Deterministic, multi-signal prompt-injection detector.
 *
 * This is a *supplementary* defense. The primary boundary is structural:
 * untrusted content never enters a privileged instruction section (see
 * `assemblePrompt`), and no content can grant permissions because
 * authorization only reads signed tokens and trusted repositories.
 *
 * The detector combines independent signal families so a single keyword does
 * not decide anything:
 *  - lexical: instruction override / policy bypass / tool / exfiltration phrases
 *  - structural: chat-template control tokens, role headers, trust delimiters
 *  - encoding: long base64/hex blobs and escape sequences
 *  - unicode: zero-width and bidirectional control characters
 */

const SUSPICIOUS_THRESHOLD = 0.6;

interface Rule {
  category: DetectionCategory;
  weight: number;
  evidence: string;
  pattern: RegExp;
}

const RULES: readonly Rule[] = [
  // Instruction override (lexical).
  {
    category: "instruction-override",
    weight: 0.55,
    evidence: "instruction-override phrase",
    pattern:
      /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,60}\b(instruction|direction|prompt|rule|guardrail|polic)/i,
  },
  {
    category: "instruction-override",
    weight: 0.5,
    evidence: "role reassignment phrase",
    pattern: /\b(you are now|from now on you|new (system )?(instructions?|rules?)|act as (the )?(system|developer|admin))\b/i,
  },
  {
    category: "instruction-override",
    weight: 0.5,
    evidence: "system-prompt extraction phrase",
    pattern: /\b(reveal|print|show|repeat|leak)\b[^.\n]{0,40}\b(system|developer) (prompt|message|instructions?)\b/i,
  },
  // Policy bypass (lexical; still only a signal).
  {
    category: "policy-bypass",
    weight: 0.55,
    evidence: "authorization-bypass phrase",
    pattern:
      /\b(ignore|skip|disable|bypass|circumvent)\b[^.\n]{0,50}\b(auth(?:orization|entication)?|policy|permission|access control|approval)\b/i,
  },
  {
    category: "policy-bypass",
    weight: 0.45,
    evidence: "permission-grant phrase",
    pattern: /\b(grant|elevate|escalate|widen)\b[^.\n]{0,40}\b(permission|privilege|scope|access|role)\b/i,
  },
  // Role impersonation / chat-template tokens (structural).
  {
    category: "role-impersonation",
    weight: 0.7,
    evidence: "chat-template control token",
    pattern: /<\|[^|\n]{0,64}\|>/,
  },
  {
    category: "role-impersonation",
    weight: 0.6,
    evidence: "instruction-template marker",
    pattern: /\[(?:\/?INST)\]|<<\/?SYS>>|<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>/i,
  },
  {
    category: "role-impersonation",
    weight: 0.5,
    evidence: "role header at line start",
    pattern: /^\s*(system|developer|assistant|tool|function)\s*:/im,
  },
  // Delimiter escape (structural).
  {
    category: "delimiter-escape",
    weight: 0.7,
    evidence: "trust-boundary marker",
    pattern: /(?:<<<\s*(?:END_)?UNTRUSTED_DATA|END\s+UNTRUSTED\s+(?:CONTENT|DATA)|BEGIN\s+TRUSTED\s+INSTRUCTIONS)/i,
  },
  {
    category: "delimiter-escape",
    weight: 0.45,
    evidence: "markdown instruction fence",
    pattern: /```(?:system|instructions?|prompt)\b/i,
  },
  // Tool directives (lexical; low weight on its own, common in recon data).
  {
    category: "tool-directive",
    weight: 0.3,
    evidence: "tool invocation phrase",
    pattern:
      /\b(call|invoke|run|execute|trigger)\b[^.\n]{0,40}\b(tool|command|shell|script|function|sandbox|agent)\b/i,
  },
  {
    category: "tool-directive",
    weight: 0.25,
    evidence: "privileged-command phrase",
    pattern: /\b(sudo|rm\s+-rf|chmod\s+777|curl\s+[^\n]*\|\s*(?:sh|bash)|base64\s+-d)\b/i,
  },
  // Exfiltration (lexical).
  {
    category: "exfiltration",
    weight: 0.4,
    evidence: "secret-exfiltration phrase",
    pattern:
      /\b(exfiltrate|send|post|upload|forward)\b[^.\n]{0,60}\b(secret|credential|password|api[ _-]?key|token|private key)\b/i,
  },
  // Encoding (structural).
  {
    category: "encoded-payload",
    weight: 0.4,
    evidence: "long base64 blob",
    pattern: /\b[A-Za-z0-9+/]{80,}={0,2}\b/,
  },
  {
    category: "encoded-payload",
    weight: 0.35,
    evidence: "long hex blob",
    pattern: /\b[0-9a-fA-F]{80,}\b/,
  },
  {
    category: "encoded-payload",
    weight: 0.35,
    evidence: "escape-sequence cluster",
    pattern: /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){8,}/,
  },
  // Unicode obfuscation (structural).
  {
    category: "unicode-obfuscation",
    weight: 0.5,
    evidence: "zero-width or bidi control characters",
    pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/,
  },
];

function signalsOf(content: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  for (const rule of RULES) {
    if (!rule.pattern.test(content)) continue;
    signals.push({ category: rule.category, weight: rule.weight, evidence: rule.evidence });
  }
  return signals;
}

/**
 * Inspect content and return a bounded risk score. Signals are deduplicated by
 * category (first match per category) so repeated keywords cannot inflate the
 * score unboundedly.
 */
export function detectPromptInjection(content: string): DetectionResult {
  if (content.length === 0) return { suspicious: false, score: 0, signals: [] };

  const raw = signalsOf(content);
  const byCategory = new Map<DetectionCategory, DetectionSignal>();
  for (const signal of raw) {
    if (!byCategory.has(signal.category)) byCategory.set(signal.category, signal);
  }
  const signals = [...byCategory.values()];
  const score = Math.min(1, signals.reduce((total, signal) => total + signal.weight, 0));
  return { suspicious: score >= SUSPICIOUS_THRESHOLD, score: Math.round(score * 100) / 100, signals };
}
