# Authorization policies (OPA / Rego)

Versioned policy bundles evaluated by the central policy engine
(`src/security/opa/`). Each version lives in its own directory and is selected
with `OPA_POLICY_VERSION` (default `v1`).

- `v1/authz.rego` — package `agentseclab.authz`, decision `allow`.

The same file is valid for a real Open Policy Agent. Deploy it and query:

```bash
curl -s localhost:8181/v1/data/agentseclab/authz -d '{"input": {...}}'
```

The embedded engine (`src/security/opa/rego.ts`) supports a restricted Rego
subset; keep policies within it so embedded and OPA evaluation agree:

- `package`, `import rego.v1`, `default <rule> := <bool>`
- constant rules: `name := "literal" | {"a","b"} | ["a"]`
- boolean rules: `name if { … }` / `name := true if { … }`, conjunctive
  bodies, multiple clauses
- comparisons `==`, `!=`, membership `x in collection`
- terms: literals, `input.a.b`, bare constant/boolean rule names,
  single-line `[...]` / `{...}` collections

Do not use `not`, `some`, `every`, comprehensions, functions, `else`, or
multi-line collections in this subset.

See `docs/phase2-authorization.md` for the RBAC/ABAC model and PEP placement.
