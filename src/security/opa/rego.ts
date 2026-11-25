/**
 * A deliberately small, deterministic evaluator for the restricted Rego subset
 * used by AgentSecLab authorization policies.
 *
 * Supported subset (see policies/v1/authz.rego — both are kept in lockstep):
 *   - `package <name>` / `import ...` (ignored)
 *   - `default <rule> := <value>`
 *   - `<rule> := <literal-or-collection>`          (constant data)
 *   - `<rule> := true if { <body> }` or `<rule> if { <body> }` (boolean rules)
 *   - bodies: newline-separated expressions:
 *       * `term == term`, `term != term`
 *       * `term in collection`
 *       * bare rule reference (conjunct that must be true)
 *   - terms: string/number/boolean literals, `input.a.b.c` paths, bare rule
 *     names, array `[...]` / set `{...}` literals (single-line)
 *
 * Anything outside this subset raises a parse error, which callers turn into a
 * fail-closed denial. This keeps the embedded engine and a real OPA (same
 * file, same semantics for the supported constructs) consistent.
 */

export interface RegoParseError extends Error {
  line: number;
}

export type RegoPrimitive = string | number | boolean | null;
export type RegoValue = RegoPrimitive | RegoValue[] | RegoRecord;
export interface RegoRecord {
  [key: string]: RegoValue;
}

type RegoInput = Record<string, unknown>;

interface TermAst {
  type: "literal" | "path" | "rule";
  value?: RegoValue;
  parts?: string[];
  name?: string;
}

type Expr =
  | { op: "ref"; name: string }
  | { op: "eq"; left: TermAst; right: TermAst }
  | { op: "neq"; left: TermAst; right: TermAst }
  | { op: "in"; left: TermAst; right: TermAst };

interface Clause {
  exprs: Expr[];
}

interface RuleDef {
  name: string;
  kind: "default" | "constant" | "boolean";
  value: RegoValue | undefined;
  clauses: Clause[];
  defaultValue: boolean | undefined;
}

export class RegoEngine {
  private readonly rules = new Map<string, RuleDef>();
  private readonly visiting = new Set<string>();
  readonly source: string;

  constructor(source: string) {
    this.source = source;
    this.parse(source);
  }

  /** Evaluate the `allow` decision for `input`. Fail-closed: throws on error. */
  evaluate(input: RegoInput): boolean {
    return this.ruleTrue("allow", input);
  }

  /** Read a constant rule's value (used for policy metadata/versioning). */
  constant(name: string): RegoValue | undefined {
    return this.rules.get(name)?.value;
  }

  private parse(source: string): void {
    const lines = source.split(/\r?\n/);
    let i = 0;
    while (i < lines.length) {
      const line = this.stripComment(lines[i]!).trim();
      i += 1;
      if (line.length === 0) continue;
      if (line.startsWith("package ") || line.startsWith("import ")) continue;

      if (/if\s*\{\s*$/.test(line)) {
        // Boolean rule with a body that follows.
        const header = line.replace(/if\s*\{\s*$/, "").trim();
        const { name, assignValue } = this.parseHeader(header);
        const clauses: Clause[] = [];
        const body: string[] = [];
        while (i < lines.length) {
          const raw = this.stripComment(lines[i]!).trim();
          i += 1;
          if (raw === "}") break;
          if (raw.length > 0) body.push(raw);
        }
        clauses.push(this.parseClause(body));
        this.addRule(name, "boolean", assignValue, clauses);
        continue;
      }

      if (/^default\s+/.test(line)) {
        const rest = line.replace(/^default\s+/, "");
        const eq = rest.indexOf(":=");
        if (eq < 0) throw this.error(`invalid default rule: ${line}`, i);
        const name = rest.slice(0, eq).trim();
        const value = this.parseTerm(rest.slice(eq + 2).trim(), i).value;
        this.addRule(name, "default", value ?? null, []);
        continue;
      }

      const eq = line.indexOf(":=");
      if (eq > 0) {
        const name = line.slice(0, eq).trim();
        const raw = line.slice(eq + 2).trim();
        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw this.error(`invalid rule name '${name}'`, i);
        const value = this.parseTerm(raw, i).value;
        this.addRule(name, "constant", value ?? null, []);
        continue;
      }

      throw this.error(`unsupported rule declaration: ${line}`, i);
    }
  }

  private parseHeader(header: string): { name: string; assignValue: RegoValue | undefined } {
    const eq = header.indexOf(":=");
    if (eq < 0) return { name: header.trim(), assignValue: undefined };
    const name = header.slice(0, eq).trim();
    const value = this.parseTerm(header.slice(eq + 2).trim(), 0).value;
    return { name, assignValue: value };
  }

  private parseClause(lines: string[]): Clause {
    const exprs: Expr[] = [];
    for (const line of lines) {
      const parts = this.splitTopLevel(line, ";");
      for (const part of parts) {
        const exprPart = part.trim();
        if (exprPart.length === 0) continue;
        exprs.push(this.parseExpr(exprPart));
      }
    }
    if (exprs.length === 0) throw this.error("empty rule body", 0);
    return { exprs };
  }

  private parseExpr(line: string): Expr {
    const match = /^(.*?)\s+(==|!=|in)\s+(.*)$/.exec(line);
    if (match) {
      const op = match[2] as "==" | "!=" | "in";
      const left = this.parseTerm(match[1]!.trim(), 0);
      const right = this.parseTerm(match[3]!.trim(), 0);
      if (op === "==") return { op: "eq", left, right };
      if (op === "!=") return { op: "neq", left, right };
      return { op: "in", left, right };
    }
    if (/^(not\b)/.test(line)) throw this.error("`not` is outside the supported subset", 0);
    const name = line.trim();
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw this.error(`unsupported expression: ${line}`, 0);
    return { op: "ref", name };
  }

  private parseTerm(input: string, line: number): TermAst {
    const text = input.trim();
    if (text.startsWith('"')) {
      const value = this.parseString(text);
      return { type: "literal", value };
    }
    if (text === "true" || text === "false") return { type: "literal", value: text === "true" };
    if (text === "null") return { type: "literal", value: null };
    if (/^-?\d+$/.test(text)) return { type: "literal", value: Number.parseInt(text, 10) };
    if (/^-?\d*\.\d+$/.test(text)) return { type: "literal", value: Number.parseFloat(text) };
    if (text.startsWith("[")) {
      const inner = text.slice(1, -1).trim();
      const values: RegoValue[] = [];
      for (const item of this.splitTopLevel(inner, ",").map((s) => s.trim())) {
        if (item.length > 0) {
          const t = this.parseTerm(item, line);
          values.push(t.value ?? this.resolveName(t.name!, line));
        }
      }
      return { type: "literal", value: values };
    }
    if (text.startsWith("{")) {
      const inner = text.slice(1, -1).trim();
      const values: RegoValue[] = [];
      for (const item of this.splitTopLevel(inner, ",").map((s) => s.trim())) {
        if (item.length > 0) {
          const t = this.parseTerm(item, line);
          values.push(t.value ?? this.resolveName(t.name!, line));
        }
      }
      return { type: "literal", value: values };
    }
    if (text.startsWith("input.")) {
      const parts = text.split(".").map((p) => p.trim());
      return { type: "path", parts };
    }
    if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(text)) {
      return { type: "rule", name: text };
    }
    throw this.error(`unsupported term: ${text}`, line);
  }

  private resolveName(name: string, line: number): RegoValue {
    const rule = this.rules.get(name);
    if (!rule) throw this.error(`unknown rule reference '${name}'`, line);
    if (rule.kind === "boolean") throw this.error(`boolean rule '${name}' is not a constant`, line);
    return rule.value ?? null;
  }

  private parseString(text: string): string {
    if (!text.endsWith('"') || text.length < 2) throw this.error(`unterminated string: ${text}`, 0);
    const inner = text.slice(1, -1);
    let out = "";
    for (let i = 0; i < inner.length; i += 1) {
      const ch = inner[i]!;
      if (ch === "\\") {
        const next = inner[i + 1];
        if (next === undefined) throw this.error(`unterminated escape`, 0);
        out += next === "n" ? "\n" : next;
        i += 1;
      } else {
        out += ch;
      }
    }
    return out;
  }

  private splitTopLevel(input: string, delimiter: "," | ";"): string[] {
    const parts: string[] = [];
    let depth = 0;
    let inString = false;
    let current = "";
    for (const ch of input) {
      if (ch === '"') inString = !inString;
      if (!inString && (ch === "[" || ch === "{")) depth += 1;
      if (!inString && (ch === "]" || ch === "}")) depth -= 1;
      if (!inString && depth === 0 && ch === delimiter) {
        parts.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
    if (current.trim().length > 0) parts.push(current);
    return parts;
  }

  private stripComment(line: string): string {
    const idx = line.indexOf(" #");
    const hash = line.indexOf("#");
    // A `#` that starts a comment is preceded by whitespace or at line start.
    if (hash === 0) return "";
    if (idx >= 0) return line.slice(0, idx);
    return line;
  }

  private addRule(name: string, kind: RuleDef["kind"], value: RegoValue | undefined, clauses: Clause[]): void {
    if (kind === "default") {
      const existing = this.rules.get(name);
      if (existing !== undefined) {
        existing.defaultValue = value === true;
      } else {
        this.rules.set(name, { name, kind: "default", value: undefined, clauses, defaultValue: value === true });
      }
      return;
    }
    const existing = this.rules.get(name);
    if (existing !== undefined && existing.kind === "boolean") {
      existing.clauses.push(...clauses);
      return;
    }
    if (existing !== undefined && existing.kind === "constant" && kind === "constant") {
      existing.value = value;
      return;
    }
    if (existing !== undefined && existing.kind === "default") {
      existing.kind = "boolean";
      existing.clauses.push(...clauses);
      return;
    }
    this.rules.set(name, { name, kind, value, clauses, defaultValue: undefined });
  }

  private error(message: string, line: number): RegoParseError {
    const err = new Error(`${message} (rego line ${line})`) as RegoParseError;
    err.line = line;
    return err;
  }

  private ruleTrue(name: string, input: RegoInput): boolean {
    if (this.visiting.has(name)) return false;
    const rule = this.rules.get(name);
    if (rule === undefined) return false;
    this.visiting.add(name);
    try {
      if (rule.kind === "constant") return rule.value === true;
      if (rule.kind === "default") return rule.defaultValue === true;
      for (const clause of rule.clauses) {
        if (this.clauseTrue(clause, input)) return true;
      }
      return rule.defaultValue === true;
    } finally {
      this.visiting.delete(name);
    }
  }

  private clauseTrue(clause: Clause, input: RegoInput): boolean {
    for (const expr of clause.exprs) {
      if (!this.exprTrue(expr, input)) return false;
    }
    return true;
  }

  private exprTrue(expr: Expr, input: RegoInput): boolean {
    switch (expr.op) {
      case "ref":
        return this.ruleTrue(expr.name, input);
      case "eq":
        return this.deepEqual(this.termValue(expr.left, input), this.termValue(expr.right, input));
      case "neq":
        return !this.deepEqual(this.termValue(expr.left, input), this.termValue(expr.right, input));
      case "in": {
        const value = this.termValue(expr.left, input);
        const collection = this.termValue(expr.right, input);
        if (!Array.isArray(collection)) return false;
        return collection.some((item) => this.deepEqual(item, value));
      }
    }
  }

  private termValue(term: TermAst, input: RegoInput): RegoValue | undefined {
    if (term.type === "literal" || term.type === "rule") {
      if (term.type === "literal") return term.value;
      const rule = this.rules.get(term.name!);
      if (rule === undefined) return undefined;
      if (rule.kind === "boolean") return this.ruleTrue(term.name!, input);
      return rule.value;
    }
    // path
    let current: unknown = input;
    for (const part of term.parts!.slice(1)) {
      if (typeof current !== "object" || current === null) return undefined;
      current = (current as Record<string, unknown>)[part];
    }
    return current as RegoValue | undefined;
  }

  private deepEqual(a: RegoValue | undefined, b: RegoValue | undefined): boolean {
    if (a === b) return true;
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      return a.every((value, index) => this.deepEqual(value, b[index]));
    }
    if (typeof a === "object" && a !== null && typeof b === "object" && b !== null) {
      const aKeys = Object.keys(a as Record<string, RegoValue>);
      const bKeys = Object.keys(b as Record<string, RegoValue>);
      if (aKeys.length !== bKeys.length) return false;
      return aKeys.every((key) => this.deepEqual((a as Record<string, RegoValue>)[key], (b as Record<string, RegoValue>)[key]));
    }
    return false;
  }
}
