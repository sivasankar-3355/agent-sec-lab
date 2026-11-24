import { EgressDeniedError, PolicyViolationError } from "../../core/errors.js";
import { newId, stableHash } from "../../core/ids.js";
import type { WorkerContext, WorkerExecuteInput, WorkerExecutor } from "../base.js";

export const reconAcceptedKinds: readonly ["recon.run"] = ["recon.run"];

export class ReconExecutor implements WorkerExecutor {
  async execute(ctx: WorkerContext, task: WorkerExecuteInput): Promise<Record<string, unknown>> {
    const target = String(task.input.target);
    const rulesRef = typeof task.input.rulesRef === "string" && task.input.rulesRef.length > 0 ? task.input.rulesRef : undefined;

    const violations = await ctx.security.policy.evaluate(target, "recon.snapshot", rulesRef === undefined ? [] : [rulesRef]);
    if (violations.length > 0) {
      throw new PolicyViolationError(violations.map((v) => `${v.rule}: ${v.reason}`).join("; "));
    }

    const egress = await ctx.security.network.assertEgress(target);
    if (!egress.allowed) {
      throw new EgressDeniedError(egress.reason ?? `egress to '${target}' denied`);
    }

    const step = await ctx.security.sandbox.run({ name: "recon.snapshot", input: { target } });
    if (!step.ok) {
      throw new PolicyViolationError(`recon step failed: ${String(step.output)}`);
    }

    let note = "";
    try {
      const completion = await ctx.security.model.complete(
        `Summarize the reconnaissance observations for target ${target}.`,
        { target },
      );
      note = completion.text.slice(0, 2000);
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