import { AppError, EgressDeniedError, PolicyViolationError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";
import { assertAuthorized, workloadOfCaller } from "../authz.js";
import { agentDeveloperPrompt, agentSystemPrompt } from "../prompts.js";
import { reconSnapshotTool } from "../tools.js";
import {
  asDataText,
  assemblePrompt,
  auditPromptAssembly,
  validateToolCall,
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
    const target = String(task.input.target);

    if (task.authz !== undefined && task.authz.runId !== "") {
      if (task.runId !== task.authz.runId) {
        throw new AppError("forbidden", `recon run '${task.runId}' outside authorized run '${task.authz.runId}'`, 403);
      }
      if (!task.authz.scopeTargets.includes(target)) {
        throw new AppError(
          "forbidden",
          `recon target '${target}' is outside the approved scope [${task.authz.scopeTargets.join(", ")}]`,
          403,
        );
      }
    }

    const authorization =
      task.authz !== undefined
        ? await assertAuthorized(ctx.security.authz, "recon.run", {
            kind: "operation",
            workload: workloadOfCaller(task.authz.caller),
            agent: "recon",
            ...(task.authz.userId !== "" ? { user: task.authz.userId } : {}),
            runId: task.runId,
            approvedTargets: task.authz.scopeTargets,
            approvedActions: task.authz.permittedActions,
            requestedAction: "recon.run",
            requestedTarget: target,
            ...(task.authz.tenantId !== undefined ? { tenantId: task.authz.tenantId } : {}),
          })
        : undefined;

    // Independent tool gate: the target is code-selected, but its arguments are
    // still validated against a strict schema and the signed run grant before
    // any sandbox step runs. Prompt content never participates in this call.
    const snapshotCall = validateToolCall(reconSnapshotTool, { target }, {
      ...(task.authz !== undefined ? { grant: task.authz } : {}),
      ...(authorization !== undefined ? { decision: authorization } : {}),
    });

    const rulesRef = typeof task.input.rulesRef === "string" && task.input.rulesRef.length > 0 ? task.input.rulesRef : undefined;

    const violations = await ctx.security.policy.evaluate(target, "recon.snapshot", rulesRef === undefined ? [] : [rulesRef]);
    if (violations.length > 0) {
      throw new PolicyViolationError(violations.map((v) => `${v.rule}: ${v.reason}`).join("; "));
    }

    const egress = await ctx.security.network.assertEgress(target);
    if (!egress.allowed) {
      throw new EgressDeniedError(egress.reason ?? `egress to '${target}' denied`);
    }

    const step = await ctx.security.sandbox.run({ name: reconSnapshotTool.name, input: snapshotCall });
    if (!step.ok) {
      throw new PolicyViolationError(`recon step failed: ${String(step.output)}`);
    }

    // The target and the sandbox output are untrusted data. They are rendered
    // inside an attributed UNTRUSTED_DATA envelope, never into instructions.
    const assembly = assemblePrompt({
      agent: "recon",
      system: agentSystemPrompt("recon"),
      developer: agentDeveloperPrompt("recon"),
      task: "Summarize the reconnaissance observations for the approved target.",
      untrusted: [
        { tier: "user-request", source: "run.scope.target", content: target, maxChars: 2048 },
        {
          tier: "tool-output",
          source: `tool:${reconSnapshotTool.name}`,
          content: toolOutputText(step.output),
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

    const hash = stableHash(`recon:${target}:${note}`);
    const existing = await ctx.repos.findings.getByHash(hash);
    const findingId = existing?.findingId ?? newId();
    if (!existing) {
      await ctx.repos.findings.create({
        findingId,
        runId: task.runId,
        taskId: task.taskId,
        agent: "recon",
        severity: "medium",
        title: `recon snapshot of ${target}`,
        description: note.length > 0 ? note : `recon snapshot completed for ${target}`,
        refs: [],
        tags: ["recon"],
        status: "open",
        hash,
      });
    }

    return { findings: [findingId] };
  }
}