import { PolicyViolationError, ValidationError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { agentDeveloperPrompt, agentSystemPrompt } from "../prompts.js";
import { reconSnapshotTool } from "../tools.js";
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

export class ReconExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    if (typeof task.input.target !== "string" || task.input.target.trim().length === 0) {
      throw new ValidationError("recon target is required");
    }
    const target = task.input.target;
    const actor = toolActorOf("recon", task);

    // The Tool Broker is the only execution path. It verifies the registry
    // allowlist, the verified identity, the trusted run record's scope, the
    // signed grant, DNS/IP safety, the OPA decision and all execution limits.
    // The handler below runs only after every gate has passed.
    const snapshot = await ctx.tools.execute(
      reconSnapshotTool,
      actor,
      { name: reconSnapshotTool.name, args: { target } },
      async (call) => {
        const rulesRef =
          typeof task.input.rulesRef === "string" && task.input.rulesRef.length > 0
            ? task.input.rulesRef
            : undefined;
        const approvedTarget = call.target?.canonical ?? target;

        const violations = await ctx.security.policy.evaluate(
          approvedTarget,
          "recon.snapshot",
          rulesRef === undefined ? [] : [rulesRef],
        );
        if (violations.length > 0) {
          throw new PolicyViolationError(violations.map((v) => `${v.rule}: ${v.reason}`).join("; "));
        }

        // The sandbox receives the pinned, canonical target envelope. It must
        // connect only to those addresses and must not follow redirects.
        const step = await ctx.security.sandbox.run({
          name: reconSnapshotTool.name,
          input: call.args,
          ...(call.target !== undefined ? { target: call.target } : {}),
          constraints: { maxRedirects: 0, allowPrivate: false },
        });
        if (!step.ok) {
          // Do not surface adapter output in the error: it is untrusted and
          // may contain sensitive data. The broker audits only the failure.
          throw new PolicyViolationError("recon sandbox step failed");
        }
        return step.output;
      },
      { ...(task.signal !== undefined ? { signal: task.signal } : {}) },
    );

    // The canonical, broker-validated target is the authoritative spelling for
    // the prompt and the finding. The raw task value is only a fallback.
    const approvedTarget = snapshot.provenance.target ?? target;

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
          source: `tool:${snapshot.tool}`,
          content: toolOutputText(snapshot.data),
        },
      ],
    });
    void auditPromptAssembly(ctx.audit, assembly, {
      runId: task.runId,
      taskId: task.taskId,
      ...(task.authz !== undefined && task.authz.userId !== "" ? { principal: task.authz.userId } : {}),
    });

    let note = "";
    try {
      const completion = await ctx.security.model.complete(assembly.prompt, assembly.context);
      // Model output is also untrusted: normalize it before persistence so it
      // cannot smuggle prompt-boundary or chat-template tokens into reports.
      note = asDataText(completion.text, 2000);
    } catch {
      // model control not wired; reasoning is optional
    }

    const hash = stableHash(`recon:${approvedTarget}:${note}`);
    const existing = await ctx.repos.findings.getByHash(hash);
    const findingId = existing?.findingId ?? newId();
    if (!existing) {
      await ctx.repos.findings.create({
        findingId,
        runId: task.runId,
        taskId: task.taskId,
        agent: "recon",
        severity: "medium",
        title: `recon snapshot of ${approvedTarget}`,
        description: note.length > 0 ? note : `recon snapshot completed for ${approvedTarget}`,
        // Provenance only; the raw sandbox output is not persisted here.
        evidence: {
          tool: snapshot.tool,
          trust: snapshot.trust,
          authoritative: snapshot.authoritative,
          ...(snapshot.provenance.target !== undefined ? { target: snapshot.provenance.target } : {}),
          bytes: snapshot.bytes,
        },
        refs: [`tool:${snapshot.tool}`],
        tags: ["recon"],
        status: "open",
        hash,
      });
    }

    return { findings: [findingId] };
  }
}
