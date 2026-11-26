# AgentSecLab authorization policy — v1
#
# Input document (see src/security/opa/types.ts / input.ts):
#   { "kind": "a2a" | "api" | "operation",
#     "version": "<policy bundle version>",
#     "attributes": {
#       "action", "workload", "agent", "user", "runId",
#       "approvedTargets", "approvedActions",
#       "requestedAction", "requestedTool", "requestedTarget", "requestedRunId",
#       "requestedDocIds", "requestedObject",
#       "resourceOwner", "resourceTenantId", "tenantId", "scopes" },
#     "context": { "decisionId", "source", "policy" } }
#
# The embedded engine (src/security/opa/rego.ts) evaluates a restricted
# subset: boolean rules with conjunctive bodies, `==`/`!=`/`in`, and
# single-line collections. Keep this file within that subset so the embedded
# engine and a real OPA (same file via /v1/data/agentseclab/authz) agree.
package agentseclab.authz

import rego.v1

version := "1.0.0"

default allow := false

# ---------- RBAC data ----------
task_senders := {"orchestrator"}
child_agents := {"recon", "knowledge", "report"}
recon_actions := {"recon.run"}
knowledge_actions := {"knowledge.search", "knowledge.index"}
report_actions := {"report.generate"}
api_scopes := {"runs:create", "runs:read", "knowledge:write", "knowledge:read"}

# ---------------------------------------------------------------- Memory -----
# Memory is durable, untrusted context. Each operation has a separate scope
# and is never covered by the generic API rule above: a memory record must have
# a non-empty owner that matches the user (no "unowned means public" shortcut).
memory_api_scopes := {"memory:search", "memory:read", "memory:insert", "memory:update", "memory:delete"}
memory_actions := {"memory.search", "memory.read", "memory.insert", "memory.update", "memory.delete"}

# ---------- A2A: discovery methods (any authenticated workload) ----------
allow if {
  input.kind == "a2a"
  input.attributes.action in {"initialize", "agentCard"}
  input.attributes.workload != ""
}

# ---------- A2A: gateway dispatches run.start to the orchestrator ----------
# (Tenant/resource checks happen at the operation stage, where the resource is
#  known; at the A2A stage only the signed run grant is available.)
allow if {
  input.kind == "a2a"
  input.attributes.action == "tasks/send"
  input.attributes.workload == "gateway"
  input.attributes.agent == "orchestrator"
  input.attributes.requestedAction == "run.start"
  input.attributes.requestedAction in input.attributes.approvedActions
  input.attributes.requestedRunId == input.attributes.runId
}

# ---------- A2A: run-bound message/send to child agents ----------
allow if {
  input.kind == "a2a"
  input.attributes.action == "message/send"
  input.attributes.workload == "orchestrator"
  input.attributes.agent in child_agents
  input.attributes.runId != ""
  input.attributes.requestedRunId == input.attributes.runId
}

# ---------- A2A: orchestrator polls / cancels child tasks of a held run ----------
allow if {
  input.kind == "a2a"
  input.attributes.action in {"tasks/get", "tasks/cancel"}
  input.attributes.workload == "orchestrator"
  input.attributes.agent in child_agents
  input.attributes.runId != ""
  input.attributes.requestedRunId == input.attributes.runId
}

# ---------- A2A: orchestrator -> recon ----------
allow if {
  input.kind == "a2a"
  input.attributes.action == "tasks/send"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "recon"
  input.attributes.requestedAction in recon_actions
  input.attributes.requestedAction in input.attributes.approvedActions
  input.attributes.requestedTarget in input.attributes.approvedTargets
}

# ---------- A2A: orchestrator -> knowledge ----------
allow if {
  input.kind == "a2a"
  input.attributes.action == "tasks/send"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "knowledge"
  input.attributes.requestedAction in knowledge_actions
  input.attributes.requestedAction in input.attributes.approvedActions
}

# ---------- A2A: orchestrator -> report ----------
allow if {
  input.kind == "a2a"
  input.attributes.action == "tasks/send"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "report"
  input.attributes.requestedAction in report_actions
  input.attributes.requestedAction in input.attributes.approvedActions
  input.attributes.requestedRunId == input.attributes.runId
}

# ---------- Operation level (receiving agents enforce independently) ----------

# Recon: the requested target must be inside the signed run scope and the
# action must be present in the signed run grant. The Tool Broker additionally
# requires the target to be inside the trusted run record's scope.
allow if {
  input.kind == "operation"
  input.attributes.action == "recon.run"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "recon"
  input.attributes.requestedAction == "recon.run"
  input.attributes.requestedAction in input.attributes.approvedActions
  input.attributes.requestedTarget in input.attributes.approvedTargets
}

# Knowledge: search is scoped to the actor's tenant; per-document ownership is
# checked with the same rule (resourceOwner/resourceTenantId set per document).
allow if {
  input.kind == "operation"
  input.attributes.action == "knowledge.search"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "knowledge"
  input.attributes.requestedAction == "knowledge.search"
  input.attributes.requestedAction in input.attributes.approvedActions
  resource_owned
  tenant_matched
}

# Knowledge: indexing a specific document requires ownership + tenant match.
allow if {
  input.kind == "operation"
  input.attributes.action == "knowledge.index"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "knowledge"
  input.attributes.requestedAction == "knowledge.index"
  input.attributes.requestedAction in input.attributes.approvedActions
  resource_owned
  tenant_matched
}

# Report: only the run's owner (and tenant) may have a report generated.
allow if {
  input.kind == "operation"
  input.attributes.action == "report.generate"
  input.attributes.workload == "orchestrator"
  input.attributes.agent == "report"
  input.attributes.requestedAction == "report.generate"
  input.attributes.requestedAction in input.attributes.approvedActions
  input.attributes.requestedRunId == input.attributes.runId
  resource_owned
  tenant_matched
}

# ---------- API (gateway, acting for the user): role scope + ownership ----------
allow if {
  input.kind == "api"
  input.attributes.action in api_scopes
  input.attributes.action in input.attributes.scopes
  resource_owned
}

# ---------- Memory API: explicit scope + strict owner/tenant match ----------
allow if {
  input.kind == "api"
  input.attributes.action in memory_api_scopes
  input.attributes.action in input.attributes.scopes
  memory_owned
  memory_tenant_matched
}

# ---------- Memory operations: run-bound agent context ----------
# An agent may only touch memory granted by its run token, for its own run,
# and only memory owned by the run's user. Memory content never appears in the
# policy input, so it can never influence a decision.
allow if {
  input.kind == "operation"
  input.attributes.action in memory_actions
  input.attributes.agent != ""
  input.attributes.requestedAction == input.attributes.action
  input.attributes.requestedAction in input.attributes.approvedActions
  input.attributes.requestedRunId == input.attributes.runId
  memory_owned
  memory_tenant_matched
}

# ---------- ABAC helpers ----------
tenant_matched if {
  input.attributes.tenantId == ""
  input.attributes.resourceTenantId == ""
}

tenant_matched if {
  input.attributes.resourceTenantId == input.attributes.tenantId
}

resource_owned if {
  input.attributes.resourceOwner == ""
}

resource_owned if {
  input.attributes.resourceOwner == input.attributes.user
}

# Memory is never "unowned": an empty resource owner does not make it public.
memory_owned if {
  input.attributes.resourceOwner != ""
  input.attributes.resourceOwner == input.attributes.user
}

memory_tenant_matched if {
  input.attributes.tenantId == ""
  input.attributes.resourceTenantId == ""
}

memory_tenant_matched if {
  input.attributes.resourceTenantId == input.attributes.tenantId
}
