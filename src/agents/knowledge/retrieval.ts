import type { Repositories } from "../../db/repositories/build.js";
import type {
  AuditProvider,
  AuthorizationProvider,
  EmbeddingProvider,
} from "../../security/protocols.js";
import type { UntrustedInspection } from "../../security/prompt/types.js";
import { inspectUntrustedContent } from "../../security/prompt/audit.js";
import { authorizeDocumentAccess } from "../authz.js";

/** Upper bound on retrieved chunks; code-owned, never model-selected. */
export const MAX_RETRIEVAL_LIMIT = 50;

export interface RetrievalProvenance {
  source: string;
  title: string;
  contentHash: string;
  ownerUserId?: string;
  tenantId?: string;
}

export interface RetrievedDocument {
  docId: string;
  score: number;
  /** Retrieved content is always untrusted data. */
  trust: "untrusted";
  provenance: RetrievalProvenance;
}

export interface SecureRetrievalInput {
  repos: Repositories;
  embedding: EmbeddingProvider;
  audit: AuditProvider;
  query: string;
  limit?: number;
  user: string;
  /**
   * Authorization layer. When a verified grant is present, every candidate
   * document is independently checked (owner/tenant) before it is returned.
   */
  authz?: AuthorizationProvider;
  tenantId?: string;
  runId?: string;
  taskId?: string;
  principal?: string;
}

export interface SecureRetrievalResult {
  documents: readonly RetrievedDocument[];
  /** Candidates filtered out by the authorization layer. */
  denied: number;
  inspection: UntrustedInspection;
}

/**
 * Secure RAG retrieval boundary.
 *
 * - The query is treated as untrusted data and inspected/audited.
 * - Retrieval is bounded by a code-owned limit (the caller cannot ask for an
 *   unbounded dump, and the LLM never chooses the collection or filter).
 * - Every candidate is authorized with the existing document-access policy
 *   (owner + tenant) before its provenance is returned.
 * - Returned content is tagged `trust: "untrusted"` with source attribution;
 *   callers must place it in an UNTRUSTED_DATA envelope if they build a prompt.
 * - Retrieval only produces data; it cannot authorize or trigger a tool call.
 */
export async function retrieveAuthorizedDocuments(input: SecureRetrievalInput): Promise<SecureRetrievalResult> {
  const requested = input.limit ?? 10;
  const limit = Math.min(Math.max(1, requested), MAX_RETRIEVAL_LIMIT);

  const inspection = await inspectUntrustedContent(input.audit, {
    tier: "user-request",
    source: "knowledge.query",
    content: input.query,
    agent: "knowledge",
    ...(input.runId !== undefined ? { runId: input.runId } : {}),
    ...(input.taskId !== undefined ? { taskId: input.taskId } : {}),
    ...(input.principal !== undefined ? { principal: input.principal } : {}),
  });

  const vectors = await input.embedding.embed([input.query]);
  const queryVector = vectors[0];
  if (queryVector === undefined || queryVector.length === 0) {
    return { documents: [], denied: 0, inspection };
  }

  const hits = await input.repos.knowledge.search(queryVector, limit);
  const documents: RetrievedDocument[] = [];
  let denied = 0;

  for (const hit of hits) {
    const doc = await input.repos.documents.get(hit.docId);
    if (!doc) continue;

    if (input.authz !== undefined) {
      const allowed = await authorizeDocumentAccess({
        authz: input.authz,
        kind: "operation",
        action: "knowledge.search",
        user: input.user,
        requestedObject: hit.docId,
        resourceOwner: doc.ownerUserId ?? "",
        resourceTenantId: doc.tenantId ?? "",
        ...(input.tenantId !== undefined ? { tenantId: input.tenantId } : {}),
      });
      if (!allowed) {
        denied += 1;
        continue;
      }
    }

    const provenance: RetrievalProvenance = {
      source: doc.source,
      title: doc.title,
      contentHash: doc.contentHash,
      ...(doc.ownerUserId !== undefined ? { ownerUserId: doc.ownerUserId } : {}),
      ...(doc.tenantId !== undefined ? { tenantId: doc.tenantId } : {}),
    };
    documents.push({ docId: hit.docId, score: hit.score, trust: "untrusted", provenance });
  }

  await input.audit.emit({
    type: "knowledge.retrieval",
    ts: new Date().toISOString(),
    traceId: input.taskId ?? input.runId ?? "knowledge-retrieval",
    ...(input.runId !== undefined ? { runId: input.runId } : {}),
    ...(input.taskId !== undefined ? { taskId: input.taskId } : {}),
    ...(input.principal !== undefined ? { principal: input.principal } : {}),
    data: {
      trust: "untrusted",
      query_source: "knowledge.query",
      query_suspicious: inspection.result.suspicious,
      returned: documents.length,
      denied,
      doc_ids: documents.map((document) => document.docId),
    },
  });

  return { documents, denied, inspection };
}
