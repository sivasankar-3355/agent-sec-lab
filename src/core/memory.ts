/**
 * Memory domain model (Phase 4).
 *
 * Memory is durable, cross-task context (agent notes, run context, user notes).
 * It is deliberately kept separate from the code-owned system/developer
 * instructions in `src/agents/prompts.ts`: system instructions are never stored
 * as memory and no memory write path can produce or alter them.
 *
 * Trust classification is derived, never caller-supplied:
 * - every memory written through an application path is `untrusted`;
 * - `system` provenance exists in the vocabulary for classification, but there
 *   is no writable system-memory API;
 * - no stored memory is `authoritative`.
 */

export const MEMORY_SOURCE_TYPES = [
  "user",
  "external_document",
  "tool_output",
  "agent_output",
  "system",
] as const;

export type MemorySourceType = (typeof MEMORY_SOURCE_TYPES)[number];

/** Sources an application caller may submit. `system` is intentionally absent. */
export const WRITABLE_MEMORY_SOURCES = [
  "user",
  "external_document",
  "tool_output",
  "agent_output",
] as const;

export type WritableMemorySource = (typeof WRITABLE_MEMORY_SOURCES)[number];

export const MEMORY_SCOPES = ["user", "tenant", "run", "agent"] as const;

export type MemoryScope = (typeof MEMORY_SCOPES)[number];

export type MemoryTrust = "trusted" | "untrusted";

/**
 * Server-derived memory type. Callers cannot choose it; it is derived from the
 * source that produced the content (and therefore from the admission path).
 */
export const MEMORY_TYPES = [
  "user-note",
  "document-context",
  "tool-observation",
  "agent-context",
  "system",
] as const;

export type MemoryType = (typeof MEMORY_TYPES)[number];

/** Lifecycle/conflict status. `expired` rows are removed by the TTL index. */
export type MemoryStatus = "active" | "conflicted";

/** Content-free detection summary stored alongside the memory. */
export interface MemoryInjectionSummary {
  suspicious: boolean;
  score: number;
  categories: readonly string[];
}

/** Where the memory came from and who created it. */
export interface MemoryProvenance {
  sourceType: MemorySourceType;
  /** Source identifier: document id, tool name, agent name, user id, system key. */
  sourceId: string;
  /** Creating identity (user id or agent name). */
  createdBy: string;
  /** Conversation/thread identifier when applicable. */
  conversationId?: string;
}

/** Integrity/version metadata. Never trusts a client-supplied version. */
export interface MemoryIntegrity {
  version: number;
  previousVersion?: number;
  /** Id of the record this version supersedes (append-only lineage). */
  supersedes?: string;
}

export interface MemoryRecord {
  memoryId: string;
  scope: MemoryScope;
  /** Code-owned logical collection (derived from source type). */
  collection: string;
  /** Server-derived memory type (derived from source type). */
  memoryType: MemoryType;
  /** Server-derived status (`conflicted` when a key collision occurred). */
  status: MemoryStatus;
  /** Optional logical key used for conflict detection. */
  key?: string;
  content: string;
  contentHash: string;
  trust: MemoryTrust;
  /** Stored memory is never authoritative; system instructions are code-owned. */
  authoritative: false;
  ownerUserId: string;
  tenantId?: string;
  runId?: string;
  agent?: string;
  tags: readonly string[];
  /** A different value already existed for the same logical key. */
  conflict: boolean;
  provenance: MemoryProvenance;
  integrity: MemoryIntegrity;
  injection?: MemoryInjectionSummary;
  expiresAt?: string;
  tsCreated: string;
  tsUpdated: string;
}

export const MEMORY_LIMITS = {
  /** Maximum stored memory content. */
  maxContentChars: 8000,
  /** Maximum content returned by search (context minimization). */
  maxSnippetChars: 1200,
  /** Maximum search query length. */
  maxQueryChars: 200,
  maxKeyChars: 200,
  maxSourceIdChars: 512,
  maxConversationIdChars: 200,
  maxTags: 16,
  maxTagChars: 64,
  defaultResults: 5,
  maxResults: 20,
  minTtlSeconds: 60,
} as const;

/** Maximum retention per source type (seconds). */
export const MEMORY_RETENTION_SECONDS: Record<WritableMemorySource, number> = {
  user: 30 * 24 * 60 * 60,
  external_document: 90 * 24 * 60 * 60,
  tool_output: 7 * 24 * 60 * 60,
  agent_output: 14 * 24 * 60 * 60,
};

const COLLECTION_BY_SOURCE: Record<WritableMemorySource, string> = {
  user: "user-notes",
  external_document: "document-notes",
  tool_output: "tool-notes",
  agent_output: "agent-notes",
};

const MEMORY_TYPE_BY_SOURCE: Record<WritableMemorySource, MemoryType> = {
  user: "user-note",
  external_document: "document-context",
  tool_output: "tool-observation",
  agent_output: "agent-context",
};

const KNOWN_COLLECTIONS: ReadonlySet<string> = new Set(Object.values(COLLECTION_BY_SOURCE));

export function isWritableMemorySource(value: string): value is WritableMemorySource {
  return (WRITABLE_MEMORY_SOURCES as readonly string[]).includes(value);
}

/** Collections are code-owned and derived; callers never choose a collection. */
export function memoryCollectionFor(sourceType: MemorySourceType): string {
  if (!isWritableMemorySource(sourceType)) return "system";
  return COLLECTION_BY_SOURCE[sourceType];
}

export function isKnownMemoryCollection(collection: string): boolean {
  return KNOWN_COLLECTIONS.has(collection);
}

/** Memory type is code-owned and derived; callers never choose it. */
export function memoryTypeFor(sourceType: MemorySourceType): MemoryType {
  if (!isWritableMemorySource(sourceType)) return "system";
  return MEMORY_TYPE_BY_SOURCE[sourceType];
}

export function memoryStatusFor(conflict: boolean): MemoryStatus {
  return conflict ? "conflicted" : "active";
}

/**
 * Trust is derived from provenance, not accepted from the caller. Only the
 * (non-writable) `system` provenance is trusted; all application memory is
 * untrusted data.
 */
export function derivedMemoryTrust(sourceType: MemorySourceType): MemoryTrust {
  return sourceType === "system" ? "trusted" : "untrusted";
}

/** Clamp a requested TTL to the source-type maximum. */
export function retentionSecondsFor(sourceType: WritableMemorySource, requested?: number): number {
  const max = MEMORY_RETENTION_SECONDS[sourceType];
  if (requested === undefined || !Number.isFinite(requested)) return max;
  return Math.min(Math.max(Math.trunc(requested), MEMORY_LIMITS.minTtlSeconds), max);
}

export function isMemoryExpired(record: Pick<MemoryRecord, "expiresAt">, now: number = Date.now()): boolean {
  if (record.expiresAt === undefined || record.expiresAt === "") return false;
  const expiry = Date.parse(record.expiresAt);
  if (Number.isNaN(expiry)) return true;
  return expiry <= now;
}

/** Bound and normalize free-form content before it is stored. */
export function limitMemoryContent(content: string): string {
  return content.length <= MEMORY_LIMITS.maxContentChars
    ? content
    : `${content.slice(0, MEMORY_LIMITS.maxContentChars)}\n[memory truncated]`;
}

/**
 * Best-effort minimization of high-risk secrets before durable storage.
 * Memory is not a secret store; this reduces accidental retention of signing
 * keys, bearer credentials and cloud/API keys. It is not a substitute for not
 * submitting secrets in the first place.
 */
const SENSITIVE_MEMORY_PATTERNS: ReadonlyArray<{ pattern: RegExp; replacement: string }> = [
  {
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replacement: "[redacted private key]",
  },
  {
    pattern: /(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
    replacement: "$1[redacted]",
  },
  { pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g, replacement: "[redacted api key]" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, replacement: "[redacted aws key]" },
];

export function redactSensitiveMemoryContent(content: string): string {
  let redacted = content;
  for (const { pattern, replacement } of SENSITIVE_MEMORY_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

/** Return a bounded snippet for search results. */
export function memorySnippet(content: string): { content: string; truncated: boolean } {
  if (content.length <= MEMORY_LIMITS.maxSnippetChars) {
    return { content, truncated: false };
  }
  return { content: content.slice(0, MEMORY_LIMITS.maxSnippetChars), truncated: true };
}
