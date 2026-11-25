import { newId } from "../../core/ids.js";
import type { AuditProvider } from "../protocols.js";
import { detectPromptInjection } from "./detect.js";
import type { PromptAssembly, UntrustedInspection, UntrustedTier } from "./types.js";

export interface UntrustedAuditInput {
  tier: UntrustedTier;
  /** Provenance label (document id, tool name, agent name, ...). */
  source: string;
  content: string;
  agent?: string;
  runId?: string;
  taskId?: string;
  traceId?: string;
  principal?: string;
}

function detectionData(inspection: UntrustedInspection, extra: Record<string, unknown>): Record<string, unknown> {
  return {
    trust: "untrusted",
    tier: inspection.tier,
    source: inspection.source,
    score: inspection.result.score,
    suspicious: inspection.result.suspicious,
    categories: inspection.result.signals.map((signal) => signal.category),
    ...extra,
  };
}

/**
 * Inspect content that enters the system outside a model prompt (RAG ingest,
 * inbound A2A messages, child artifacts) and audit suspicious content. This is
 * supplementary detection only; callers still treat the content as data.
 */
export async function inspectUntrustedContent(
  audit: AuditProvider,
  input: UntrustedAuditInput,
): Promise<UntrustedInspection> {
  const result = detectPromptInjection(input.content);
  const inspection: UntrustedInspection = { tier: input.tier, source: input.source, result };
  if (result.suspicious) {
    await audit.emit({
      type: "prompt.injection.detected",
      ts: new Date().toISOString(),
      traceId: input.traceId ?? newId(),
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      ...(input.taskId !== undefined ? { taskId: input.taskId } : {}),
      ...(input.principal !== undefined ? { principal: input.principal } : {}),
      data: detectionData(inspection, {
        ...(input.agent !== undefined ? { agent: input.agent } : {}),
        phase: "ingest",
      }),
    });
  }
  return inspection;
}

export interface PromptAuditMeta {
  runId?: string;
  taskId?: string;
  traceId?: string;
  principal?: string;
}

/**
 * Record how a prompt was assembled (trusted sections + attributed untrusted
 * segments/detections) without logging raw untrusted content.
 */
export async function auditPromptAssembly(
  audit: AuditProvider,
  assembly: PromptAssembly,
  meta: PromptAuditMeta = {},
): Promise<void> {
  const traceId = meta.traceId ?? meta.taskId ?? newId();
  await audit.emit({
    type: "prompt.assembled",
    ts: new Date().toISOString(),
    traceId,
    ...(meta.runId !== undefined ? { runId: meta.runId } : {}),
    ...(meta.taskId !== undefined ? { taskId: meta.taskId } : {}),
    ...(meta.principal !== undefined ? { principal: meta.principal } : {}),
    data: {
      agent: assembly.context.agent,
      prompt_boundary: assembly.context.prompt_boundary,
      segments: assembly.segments.map((segment) => ({
        id: segment.id,
        tier: segment.tier,
        trust: segment.trust,
        source: segment.source,
        chars: segment.chars,
        suspicious: segment.suspicious,
        score: segment.score,
      })),
      suspicious: assembly.suspicious,
    },
  });

  for (const detection of assembly.detections) {
    if (!detection.result.suspicious) continue;
    const inspection: UntrustedInspection = {
      tier: detection.tier,
      source: detection.source,
      result: detection.result,
    };
    await audit.emit({
      type: "prompt.injection.detected",
      ts: new Date().toISOString(),
      traceId,
      ...(meta.runId !== undefined ? { runId: meta.runId } : {}),
      ...(meta.taskId !== undefined ? { taskId: meta.taskId } : {}),
      ...(meta.principal !== undefined ? { principal: meta.principal } : {}),
      data: detectionData(inspection, {
        agent: String(assembly.context.agent ?? ""),
        phase: "prompt",
        segment_id: detection.id,
      }),
    });
  }
}
