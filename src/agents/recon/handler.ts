import { AppError, PolicyViolationError, ValidationError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { agentDeveloperPrompt, agentSystemPrompt } from "../prompts.js";
import { reconSnapshotTool } from "../tools.js";
import type { ToolOperation } from "../tool-operation.js";
import { toolActorOf } from "../tool-actor.js";
import {
  asDataText,
  assemblePrompt,
  auditPromptAssembly,
} from "../../security/prompt/index.js";

export const reconAcceptedKinds: readonly ["recon.run"] = ["recon.run"];

function toolOutputText(output: unknown): string {
  if (typeof output === "string") return output;
  try {
    return JSON.stringify(output) ?? String(output);
  } catch {
    return String(output);
  }
}

/**
 * Code-owned recon business logic. Runs only after the Tool Broker has
 * authorized the call, validated the arguments and pinned the target. The only
 * external effect is `runtime.runStep`, whose local implementation delegates to
 * the configured SandboxProvider behind a pinned-target contract.
 */
export const reconSnapshotOperation: ToolOperation = async (ctx) => {
  const target = ctx.request.target;
  if (target === undefined) {
    throw new AppError("tool_target_denied", "recon snapshot requires a resolved target", 403);
  }
  if (ctx.request.signal.aborted) {
    throw new AppError("tool_cancelled", "recon execution was cancelled", 499);
  }

  const args = ctx.request.args as { target: string; rulesRef?: string };
  const rulesRef =
    typeof args.rulesRef === "string" && args.rulesRef.length > 0 ? args.rulesRef : undefined;
  const approvedTarget = target.canonical;

  const violations = await ctx.policy.evaluate(
    approvedTarget,
    "recon.snapshot",
    rulesRef === undefined ? [] : [rulesRef],
  );
  if (violations.length > 0) {
    throw new PolicyViolationError(violations.map((v) => `${v.rule}: ${v.reason}`).join("; "));
  }

  // The sandbox receives the pinned, canonical target envelope. It must
  // connect only to those addresses and must not follow redirects. The local
  // executor re-checks the envelope before dispatching it.
  const step = await ctx.runtime.runStep({
    name: reconSnapshotTool.name,
    input: { target: approvedTarget },
    target,
    constraints: { maxRedirects: 0, allowPrivate: false, pinAddresses: true },
  });
  if (!step.ok) {
    // Do not surface adapter output in the error: it is untrusted and may
    // contain sensitive data. The broker audits only the failure.
    throw new PolicyViolationError("recon sandbox step failed");
  }

  // The target and the sandbox output are untrusted data. They are rendered
  // inside an attributed UNTRUSTED_DATA envelope, never into instructions.
  const assembly = assemblePrompt({
    agent: "recon",
    system: agentSystemPrompt("recon"),
    developer: agentDeveloperPrompt("recon"),
    task: "Summarize the reconnaissance observations for the approved target.",
    untrusted: [
      { tier: "user-request", source: "run.scope.target", content: approvedTarget, maxChars: 2048 },
      {
        tier: "tool-output",
        source: `tool:${reconSnapshotTool.name}`,
        content: toolOutputText(step.output),
      },
    ],
  });
  void auditPromptAssembly(ctx.audit, assembly, {
    runId: ctx.request.run.runId,
    taskId: ctx.request.actor.taskId,
    ...(ctx.request.actor.userId !== "" ? { principal: ctx.request.actor.userId } : {}),
  });

  let note = "";
  try {
    const completion = await ctx.model.complete(assembly.prompt, assembly.context);
    // Model output is also untrusted: normalize it before persistence so it
    // cannot smuggle prompt-boundary or chat-template tokens into reports.
    note = asDataText(completion.text, 2000);
  } catch {
    // model control not wired; reasoning is optional
  }

  if (ctx.request.signal.aborted) {
    throw new AppError("tool_cancelled", "recon execution was cancelled", 499);
  }

  const hash = stableHash(`recon:${approvedTarget}:${note}`);
  const existing = await ctx.repos.findings.getByHash(hash);
  const findingId = existing?.findingId ?? newId();
  if (!existing) {
    await ctx.repos.findings.create({
      findingId,
      runId: ctx.request.run.runId,
      taskId: ctx.request.actor.taskId,
      agent: "recon",
      severity: "medium",
      title: `recon snapshot of ${approvedTarget}`,
      description: note.length > 0 ? note : `recon snapshot completed for ${approvedTarget}`,
      // Provenance only; the raw sandbox output is not persisted here.
      evidence: {
        tool: reconSnapshotTool.name,
        trust: "untrusted",
        authoritative: false,
        target: approvedTarget,
      },
      refs: [`tool:${reconSnapshotTool.name}`],
      tags: ["recon"],
      status: "open",
      hash,
    });
  }

  return { findings: [findingId] };
};

export class ReconExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    if (typeof task.input.target !== "string" || task.input.target.trim().length === 0) {
      throw new ValidationError("recon target is required");
    }
    const actor = toolActorOf("recon", task);

    // The Tool Broker is the only execution path. The code-owned operation is
    // selected from the sealed catalog; this executor cannot supply a handler.
    const result = await ctx.tools.execute(
      actor,
      {
        name: reconSnapshotTool.name,
        args: {
          target: task.input.target,
          ...(typeof task.input.rulesRef === "string" && task.input.rulesRef.length > 0
            ? { rulesRef: task.input.rulesRef }
            : {}),
        },
      },
      { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
    );

    return result.data as Record<string, unknown>;
  }
}
